package ast

import (
	"sync"
)

// Language represents supported languages for AST parsing
type Language string

const (
	LanguagePython     Language = "python"
	LanguageJavaScript Language = "javascript"
	LanguageTypeScript Language = "typescript"
)

// NodeType represents the type of an AST node
type NodeType string

const (
	// General
	NodeTypeRoot           NodeType = "root"
	NodeTypeModule         NodeType = "module"
	NodeTypeBlock          NodeType = "block"
	NodeTypeIdentifier     NodeType = "identifier"
	NodeTypeString         NodeType = "string"
	NodeTypeStringLiteral  NodeType = "string_literal"
	NodeTypeNumber         NodeType = "number"
	NodeTypeBoolean        NodeType = "boolean"

	// Functions & Calls
	NodeTypeFunctionDef    NodeType = "function_definition"
	NodeTypeFunctionCall   NodeType = "function_call"
	NodeTypeMethodCall     NodeType = "method_call"
	NodeTypeArguments      NodeType = "arguments"
	NodeTypeArgument       NodeType = "argument"
	NodeTypeParameter      NodeType = "parameter"
	NodeTypeParameterList  NodeType = "parameter_list"

	// Variables & Assignment
	NodeTypeVariableDef    NodeType = "variable_definition"
	NodeTypeAssignment     NodeType = "assignment"
	NodeTypeVariableRef    NodeType = "variable_reference"
	NodeTypeMember         NodeType = "member_access"
	NodeTypeSubscript      NodeType = "subscript"

	// Control Flow
	NodeTypeIfStatement    NodeType = "if_statement"
	NodeTypeForStatement   NodeType = "for_statement"
	NodeTypeWhileStatement NodeType = "while_statement"
	NodeTypeReturnStmt     NodeType = "return_statement"
	NodeTypeBreakStmt      NodeType = "break_statement"
	NodeTypeContinueStmt   NodeType = "continue_statement"

	// Control Flow (Consolidated for Logic Analysis)
	NodeTypeLoop           NodeType = "loop"           // while/for/for-in statements (Phase 3: Infinite loops)
	NodeTypeConditional    NodeType = "conditional"    // if/switch statements (Phase 3: Dead code)
	NodeTypeErrorHandling  NodeType = "error_handling" // try/catch/finally statements (Phase 3: Exception safety)

	// Imports
	NodeTypeImport       NodeType = "import_statement"
	NodeTypeImportFrom   NodeType = "import_from_statement"
	NodeTypeRequire      NodeType = "require_statement"

	// Expressions
	NodeTypeUnaryOp               NodeType = "unary_operation"
	NodeTypeBinaryOp              NodeType = "binary_operation"
	NodeTypeConditionalExpression NodeType = "conditional_expression"
	NodeTypeLambda                NodeType = "lambda"
	NodeTypeArrowFunc             NodeType = "arrow_function"

	// Containers
	NodeTypeList         NodeType = "list"
	NodeTypeDict         NodeType = "dict"
	NodeTypeObject       NodeType = "object"
	NodeTypeArray        NodeType = "array"
	NodeTypeTuple        NodeType = "tuple"

	// Classes
	NodeTypeClass        NodeType = "class_definition"
	NodeTypeClassBody    NodeType = "class_body"

	// JSX (TypeScript/JavaScript)
	NodeTypeJSXElement   NodeType = "jsx_element"

	// Exception Handling
	NodeTypeTryStatement     NodeType = "try_statement"
	NodeTypeExceptHandler    NodeType = "except_handler"
	NodeTypeThrowStatement   NodeType = "throw_statement"

	// Other
	NodeTypeComment      NodeType = "comment"
	NodeTypeUnknown      NodeType = "unknown"
)

// VariableType represents the scope/kind of a variable
type VariableType string

const (
	VarTypeLocal      VariableType = "local"
	VarTypeParameter  VariableType = "parameter"
	VarTypeGlobal     VariableType = "global"
	VarTypeImported   VariableType = "imported"
	VarTypeExternal   VariableType = "external"
	VarTypeUnknown    VariableType = "unknown"
)

// Node represents a single AST node
type Node struct {
	// Identity
	ID       string
	Type     NodeType
	Language Language

	// Content
	Text string
	Kind string // Raw tree-sitter kind

	// Location
	StartLine   int
	StartColumn int
	EndLine     int
	EndColumn   int

	// Relationships
	Parent   *Node
	Children []*Node

	// Metadata
	Properties map[string]interface{} // Custom properties
	mu         sync.RWMutex            // Thread-safe access
}

// NewNode creates a new AST node
func NewNode(id string, nodeType NodeType, language Language) *Node {
	return &Node{
		ID:         id,
		Type:       nodeType,
		Language:   language,
		Children:   make([]*Node, 0),
		Properties: make(map[string]interface{}),
	}
}

// AddChild adds a child node
func (n *Node) AddChild(child *Node) {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.Children = append(n.Children, child)
	child.Parent = n
}

// GetProperty retrieves a property value
func (n *Node) GetProperty(key string) (interface{}, bool) {
	n.mu.RLock()
	defer n.mu.RUnlock()

	val, exists := n.Properties[key]
	return val, exists
}

// SetProperty sets a property value
func (n *Node) SetProperty(key string, value interface{}) {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.Properties[key] = value
}

// FindChildByType finds first child with given type
func (n *Node) FindChildByType(nodeType NodeType) *Node {
	n.mu.RLock()
	defer n.mu.RUnlock()

	for _, child := range n.Children {
		if child.Type == nodeType {
			return child
		}
	}
	return nil
}

// FindChildrenByType finds all children with given type
func (n *Node) FindChildrenByType(nodeType NodeType) []*Node {
	n.mu.RLock()
	defer n.mu.RUnlock()

	var result []*Node
	for _, child := range n.Children {
		if child.Type == nodeType {
			result = append(result, child)
		}
	}
	return result
}

// GetText returns the node's text content
func (n *Node) GetText() string {
	n.mu.RLock()
	defer n.mu.RUnlock()

	return n.Text
}

// SetText sets the node's text content
func (n *Node) SetText(text string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.Text = text
}

// GetChildren returns a copy of the children list with proper thread-safety
func (n *Node) GetChildren() []*Node {
	n.mu.RLock()
	defer n.mu.RUnlock()

	// Return a copy to prevent external modification
	children := make([]*Node, len(n.Children))
	copy(children, n.Children)
	return children
}

// ParseResult represents the result of parsing a file
type ParseResult struct {
	Root           *Node
	Language       Language
	FilePath       string
	SourceCode     string
	ErrorMsg       string
	HasError       bool
	ParseTimeMs    int64
	SourceLength   int
	mu             sync.RWMutex
}

// GetRoot safely retrieves the root node
func (pr *ParseResult) GetRoot() *Node {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	return pr.Root
}

// FunctionCallInfo represents information about a function call
type FunctionCallInfo struct {
	FunctionName   string     // Name of function being called
	FunctionObject string     // Object if method call (e.g., "os" in os.system)
	Arguments      []string   // Argument expressions
	ArgumentNodes  []*Node    // Argument AST nodes
	CallerNode     *Node      // The call node itself
	Line           int
	Column         int
	FullText       string
	mu             sync.RWMutex
}

// NewFunctionCallInfo creates function call info
func NewFunctionCallInfo(name string, line, column int) *FunctionCallInfo {
	return &FunctionCallInfo{
		FunctionName:  name,
		Arguments:     make([]string, 0),
		ArgumentNodes: make([]*Node, 0),
		Line:          line,
		Column:        column,
	}
}

// AddArgument adds an argument to the call
func (fci *FunctionCallInfo) AddArgument(arg string, node *Node) {
	fci.mu.Lock()
	defer fci.mu.Unlock()

	fci.Arguments = append(fci.Arguments, arg)
	fci.ArgumentNodes = append(fci.ArgumentNodes, node)
}

// VariableInfo represents information about a variable
type VariableInfo struct {
	Name          string
	Type          VariableType
	DefinedAtLine int
	DefinedAtCol  int
	SourceNode    *Node
	Assignments   []*Node // All nodes where this variable is assigned
	References    []*Node // All nodes where this variable is referenced
	TaintState    string  // For taint analysis: "clean", "tainted", "unknown"
	mu            sync.RWMutex
}

// NewVariableInfo creates new variable info
func NewVariableInfo(name string, varType VariableType, line, col int) *VariableInfo {
	return &VariableInfo{
		Name:          name,
		Type:          varType,
		DefinedAtLine: line,
		DefinedAtCol:  col,
		Assignments:   make([]*Node, 0),
		References:    make([]*Node, 0),
		TaintState:    "unknown",
	}
}

// AddAssignment adds an assignment node
func (vi *VariableInfo) AddAssignment(node *Node) {
	vi.mu.Lock()
	defer vi.mu.Unlock()

	vi.Assignments = append(vi.Assignments, node)
}

// AddReference adds a reference node
func (vi *VariableInfo) AddReference(node *Node) {
	vi.mu.Lock()
	defer vi.mu.Unlock()

	vi.References = append(vi.References, node)
}

// GetTaintState safely retrieves taint state
func (vi *VariableInfo) GetTaintState() string {
	vi.mu.RLock()
	defer vi.mu.RUnlock()

	return vi.TaintState
}

// SetTaintState safely sets taint state
func (vi *VariableInfo) SetTaintState(state string) {
	vi.mu.Lock()
	defer vi.mu.Unlock()

	vi.TaintState = state
}
