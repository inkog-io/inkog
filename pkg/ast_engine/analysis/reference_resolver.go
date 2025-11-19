package analysis

import (
	"sync"

	"github.com/inkog-io/inkog/action/pkg/ast_engine/ast"
)

// ReferenceResolver links variable usages to definitions for data flow analysis
type ReferenceResolver struct {
	root      *ast.Node
	symTable  *SymbolTable
	mu        sync.RWMutex
	cache     map[string][]*DataFlowPath
}

// DataFlowPath represents the flow from a variable definition to its usage
type DataFlowPath struct {
	Variable   string
	Definition *ast.Node  // Variable definition node
	Usage      *ast.Node  // Usage/reference node
	Path       []*ast.Node // Intermediate nodes
	IsTainted  bool
}

// NewReferenceResolver creates a new reference resolver
func NewReferenceResolver(root *ast.Node, symTable *SymbolTable) *ReferenceResolver {
	return &ReferenceResolver{
		root:     root,
		symTable: symTable,
		cache:    make(map[string][]*DataFlowPath),
	}
}

// ResolveDefinition finds the definition of a variable
func (rr *ReferenceResolver) ResolveDefinition(varName string) *ast.VariableInfo {
	rr.mu.RLock()
	defer rr.mu.RUnlock()

	if rr.symTable == nil || rr.symTable.CurrentScope == nil {
		return nil
	}

	return rr.symTable.CurrentScope.GetVariable(varName)
}

// GetReferencesTo finds all usages of a variable
func (rr *ReferenceResolver) GetReferencesTo(varName string) []*ast.Node {
	rr.mu.RLock()
	defer rr.mu.RUnlock()

	var references []*ast.Node
	rr.findReferencesRecursive(rr.root, varName, &references)
	return references
}

// findReferencesRecursive recursively finds references to a variable
func (rr *ReferenceResolver) findReferencesRecursive(node *ast.Node, varName string, refs *[]*ast.Node) {
	if node == nil {
		return
	}

	// Check if this node is a reference to the variable
	if node.Type == ast.NodeTypeIdentifier {
		if name, ok := node.GetProperty("name"); ok {
			if name == varName {
				*refs = append(*refs, node)
			}
		}
	}

	// Recurse through children
	children := node.GetChildren()
	for _, child := range children {
		rr.findReferencesRecursive(child, varName, refs)
	}
}

// TraceDataFlow traces the data flow from a usage back to its definition
func (rr *ReferenceResolver) TraceDataFlow(usageNode *ast.Node) *DataFlowPath {
	rr.mu.RLock()
	defer rr.mu.RUnlock()

	if usageNode == nil || usageNode.Type != ast.NodeTypeIdentifier {
		return nil
	}

	varName, ok := usageNode.GetProperty("name")
	if !ok {
		return nil
	}

	// Find the definition
	def := rr.findDefinitionForUsage(rr.root, varName.(string), usageNode)
	if def == nil {
		return nil
	}

	return &DataFlowPath{
		Variable:   varName.(string),
		Definition: def,
		Usage:      usageNode,
		IsTainted:  true, // Conservative assumption
	}
}

// findDefinitionForUsage finds the definition that corresponds to a usage
func (rr *ReferenceResolver) findDefinitionForUsage(node *ast.Node, varName string, usage *ast.Node) *ast.Node {
	if node == nil {
		return nil
	}

	if node.Type == ast.NodeTypeAssignment {
		if name, ok := node.GetProperty("variable"); ok {
			if name == varName {
				// Check if this assignment is in scope for the usage
				if node.StartLine <= usage.StartLine {
					return node
				}
			}
		}
	}

	// Recurse (but prioritize more recent definitions)
	var mostRecentDef *ast.Node
	children := node.GetChildren()
	for _, child := range children {
		if def := rr.findDefinitionForUsage(child, varName, usage); def != nil {
			if mostRecentDef == nil || def.StartLine > mostRecentDef.StartLine {
				mostRecentDef = def
			}
		}
	}

	return mostRecentDef
}

// FindAllDataFlows finds all data flows in the code
func (rr *ReferenceResolver) FindAllDataFlows() []DataFlowPath {
	rr.mu.RLock()
	defer rr.mu.RUnlock()

	var flows []DataFlowPath

	// For each identifier in the tree
	rr.findAllIdentifiersRecursive(rr.root, &flows)
	return flows
}

// findAllIdentifiersRecursive finds all identifiers and traces their data flow
func (rr *ReferenceResolver) findAllIdentifiersRecursive(node *ast.Node, flows *[]DataFlowPath) {
	if node == nil {
		return
	}

	if node.Type == ast.NodeTypeIdentifier {
		varName, ok := node.GetProperty("name")
		if ok {
			// Trace this identifier
			def := rr.findDefinitionForUsage(rr.root, varName.(string), node)
			if def != nil {
				*flows = append(*flows, DataFlowPath{
					Variable:   varName.(string),
					Definition: def,
					Usage:      node,
					IsTainted:  true,
				})
			}
		}
	}

	children := node.GetChildren()
	for _, child := range children {
		rr.findAllIdentifiersRecursive(child, flows)
	}
}

// IsVariableTainted determines if a variable is tainted (from untrusted source)
func (rr *ReferenceResolver) IsVariableTainted(varName string) bool {
	rr.mu.RLock()
	defer rr.mu.RUnlock()

	// Look for untrusted sources: input(), request, argv, etc.
	untrustedSources := []string{"input", "request", "argv", "stdin", "args"}

	refs := rr.GetReferencesTo(varName)
	for _, ref := range refs {
		// Check if assigned from untrusted source
		parent := rr.findParentAssignment(rr.root, ref)
		if parent != nil {
			if val, ok := parent.GetProperty("value"); ok {
				for _, source := range untrustedSources {
					if val == source || (val != nil && val.(string) != "") {
						return true
					}
				}
			}
		}
	}

	return false
}

// findParentAssignment finds the assignment node that contains this usage
func (rr *ReferenceResolver) findParentAssignment(node *ast.Node, target *ast.Node) *ast.Node {
	if node == nil {
		return nil
	}

	if node == target {
		return nil
	}

	if node.Type == ast.NodeTypeAssignment {
		// Check if target is a child of this assignment
		if rr.isNodeDescendant(node, target) {
			return node
		}
	}

	children := node.GetChildren()
	for _, child := range children {
		if result := rr.findParentAssignment(child, target); result != nil {
			return result
		}
	}

	return nil
}

// isNodeDescendant checks if target is a descendant of node
func (rr *ReferenceResolver) isNodeDescendant(node *ast.Node, target *ast.Node) bool {
	if node == target {
		return true
	}

	children := node.GetChildren()
	for _, child := range children {
		if rr.isNodeDescendant(child, target) {
			return true
		}
	}

	return false
}
