package parser

import (
	"context"
	"fmt"
	"sync"
	"time"

	sitter "github.com/smacker/go-tree-sitter"

	"github.com/inkog-io/inkog/action/pkg/ast_engine/analysis"
	"github.com/inkog-io/inkog/action/pkg/ast_engine/ast"
	"github.com/inkog-io/inkog/action/pkg/ast_engine/query"
)

// PythonParser implements the Parser interface for Python code using Tree-sitter
type PythonParser struct {
	languageType ast.Language
	initialized  bool
	config       *ParserConfig
	queryEngine  *query.Engine
	mu           sync.RWMutex

	// Tree-sitter parser (shared for all parses)
	treeParser *sitter.Parser
}

// NewPythonParser creates a new Python parser instance using Tree-sitter
func NewPythonParser(config *ParserConfig) (*PythonParser, error) {
	if config == nil {
		config = DefaultConfig()
	}

	parser := &PythonParser{
		languageType: ast.LanguagePython,
		initialized:  false,
		config:       config,
		queryEngine:  query.NewEngine(),
		treeParser:   sitter.NewParser(),
	}

	// Set Python language grammar
	parser.treeParser.SetLanguage(GetPythonLanguage())

	parser.initialized = true
	return parser, nil
}

// ParseFile parses Python source code using Tree-sitter
func (pp *PythonParser) ParseFile(filePath string, content []byte) (*ast.ParseResult, error) {
	pp.mu.RLock()
	if !pp.initialized {
		pp.mu.RUnlock()
		return nil, ErrParserNotInitialized
	}
	pp.mu.RUnlock()

	startTime := time.Now()
	sourceCode := string(content)

	// Tree-sitter parser is not fully thread-safe, so lock during parse
	pp.mu.Lock()
	// Parse with Tree-sitter (error-tolerant)
	tree, err := pp.treeParser.ParseCtx(context.Background(), nil, content)
	pp.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("tree-sitter parse error: %w", err)
	}

	// Create root node for our AST
	root := ast.NewNode("root_0", ast.NodeTypeModule, ast.LanguagePython)
	root.Text = sourceCode
	root.StartLine = 1

	// Walk the Tree-sitter CST and build our AST
	pp.walkPythonTree(tree.RootNode(), root, sourceCode)

	parseTimeMs := time.Since(startTime).Milliseconds()

	return &ast.ParseResult{
		Root:         root,
		Language:     ast.LanguagePython,
		FilePath:     filePath,
		SourceCode:   sourceCode,
		HasError:     false,
		ParseTimeMs:  parseTimeMs,
		SourceLength: len(content),
	}, nil
}

// walkPythonTree recursively walks Tree-sitter CST and builds AST
func (pp *PythonParser) walkPythonTree(tsNode *sitter.Node, astParent *ast.Node, sourceCode string) {
	if tsNode == nil {
		return
	}

	nodeType := tsNode.Type()
	childCount := tsNode.ChildCount()
	startLine := int(tsNode.StartPoint().Row) + 1
	startCol := int(tsNode.StartPoint().Column)
	text := tsNode.Content([]byte(sourceCode))

	// Map Tree-sitter node types to our AST node types
	var astNodeType ast.NodeType
	switch nodeType {
	// Function definitions
	case "function_definition":
		astNodeType = ast.NodeTypeFunctionDef
	case "decorated_definition":
		// Could be decorated function or class
		if childCount > 0 {
			firstChild := tsNode.Child(int(childCount) - 1)
			if firstChild != nil {
				if firstChild.Type() == "function_definition" {
					astNodeType = ast.NodeTypeFunctionDef
				} else if firstChild.Type() == "class_definition" {
					astNodeType = ast.NodeTypeClass
				}
			}
		}

	// Classes
	case "class_definition":
		astNodeType = ast.NodeTypeClass

	// Function/method calls
	case "call":
		astNodeType = ast.NodeTypeFunctionCall

	// Assignments
	case "assignment", "augmented_assignment":
		astNodeType = ast.NodeTypeAssignment

	// Imports
	case "import_statement":
		astNodeType = ast.NodeTypeImport
	case "import_from":
		astNodeType = ast.NodeTypeImportFrom

	// Control flow (CRITICAL for Phase 3: Logic Analysis)
	case "if_statement":
		astNodeType = ast.NodeTypeConditional

	case "while_statement":
		astNodeType = ast.NodeTypeLoop

	case "for_statement":
		astNodeType = ast.NodeTypeLoop

	// Exception handling
	case "try_statement":
		astNodeType = ast.NodeTypeErrorHandling

	// Other important nodes
	case "identifier":
		astNodeType = ast.NodeTypeIdentifier

	case "string":
		astNodeType = ast.NodeTypeString

	case "number":
		astNodeType = ast.NodeTypeNumber

	case "boolean":
		astNodeType = ast.NodeTypeBoolean

	case "lambda":
		astNodeType = ast.NodeTypeLambda

	// Skip internal nodes
	case "ERROR":
		// Tree-sitter error node - skip but continue with children
		for i := uint32(0); i < childCount; i++ {
			child := tsNode.Child(int(i))
			if child != nil {
				pp.walkPythonTree(child, astParent, sourceCode)
			}
		}
		return

	default:
		// Unknown/unhandled node type - process children but don't create AST node
		for i := uint32(0); i < childCount; i++ {
			child := tsNode.Child(int(i))
			if child != nil {
				pp.walkPythonTree(child, astParent, sourceCode)
			}
		}
		return
	}

	// Create AST node for recognized node types
	astNode := ast.NewNode(
		fmt.Sprintf("py_%s_%d", nodeType, startLine),
		astNodeType,
		ast.LanguagePython,
	)
	astNode.Text = text
	astNode.StartLine = startLine
	astNode.StartColumn = startCol
	astNode.EndLine = int(tsNode.EndPoint().Row) + 1
	astNode.EndColumn = int(tsNode.EndPoint().Column)

	// Extract specific properties based on node type
	pp.extractPythonProperties(astNode, tsNode, sourceCode)

	// Add to parent
	astParent.AddChild(astNode)

	// Recursively process children
	for i := uint32(0); i < childCount; i++ {
		child := tsNode.Child(int(i))
		if child != nil {
			pp.walkPythonTree(child, astNode, sourceCode)
		}
	}
}

// extractPythonProperties extracts important properties from Tree-sitter nodes
func (pp *PythonParser) extractPythonProperties(astNode *ast.Node, tsNode *sitter.Node, sourceCode string) {
	switch astNode.Type {
	case ast.NodeTypeFunctionDef:
		// Extract function name (usually second child: "def" name "(" ...)
		if tsNode.ChildCount() >= 2 {
			nameNode := tsNode.Child(1)
			if nameNode != nil {
				astNode.SetProperty("name", nameNode.Content([]byte(sourceCode)))
			}
		}

	case ast.NodeTypeClass:
		// Extract class name
		if tsNode.ChildCount() >= 2 {
			nameNode := tsNode.Child(1)
			if nameNode != nil {
				astNode.SetProperty("name", nameNode.Content([]byte(sourceCode)))
			}
		}

	case ast.NodeTypeFunctionCall:
		// Extract function name - in a call, the first child is usually the function
		if tsNode.ChildCount() > 0 {
			funcNode := tsNode.Child(0)
			if funcNode != nil {
				funcName := funcNode.Content([]byte(sourceCode))
				astNode.SetProperty("function", funcName)
			}
		}

	case ast.NodeTypeAssignment:
		// Extract variable name and value
		// Assignment structure: target "=" value
		if tsNode.ChildCount() >= 3 {
			targetNode := tsNode.Child(0)
			if targetNode != nil {
				astNode.SetProperty("variable", targetNode.Content([]byte(sourceCode)))
			}
			valueNode := tsNode.Child(2)
			if valueNode != nil {
				astNode.SetProperty("value", valueNode.Content([]byte(sourceCode)))
			}
		}

	case ast.NodeTypeImport, ast.NodeTypeImportFrom:
		// Extract module name
		childCount := tsNode.ChildCount()
		for i := uint32(0); i < childCount; i++ {
			child := tsNode.Child(int(i))
			if child != nil && child.Type() == "dotted_name" {
				astNode.SetProperty("module", child.Content([]byte(sourceCode)))
				break
			}
		}

	case ast.NodeTypeString:
		astNode.SetProperty("value", tsNode.Content([]byte(sourceCode)))

	case ast.NodeTypeIdentifier:
		astNode.SetProperty("name", tsNode.Content([]byte(sourceCode)))
	}
}

// Query finds nodes matching an S-expression
func (pp *PythonParser) Query(root *ast.Node, queryStr string) ([]*ast.Node, error) {
	if root == nil {
		return nil, ErrNilNode
	}
	return pp.queryEngine.Query(root, queryStr)
}

// Language returns the language
func (pp *PythonParser) Language() ast.Language {
	pp.mu.RLock()
	defer pp.mu.RUnlock()
	return pp.languageType
}

// IsInitialized checks if parser is ready
func (pp *PythonParser) IsInitialized() bool {
	pp.mu.RLock()
	defer pp.mu.RUnlock()
	return pp.initialized
}

// BuildSymbolTable builds the symbol table
func (pp *PythonParser) BuildSymbolTable(root *ast.Node) (*analysis.SymbolTable, error) {
	if root == nil {
		return nil, ErrNilNode
	}

	symTable := analysis.NewSymbolTable()
	pp.buildSymbolTableRecursive(root, symTable)

	return symTable, nil
}

// buildSymbolTableRecursive recursively builds symbol table
func (pp *PythonParser) buildSymbolTableRecursive(node *ast.Node, symTable *analysis.SymbolTable) {
	if node == nil {
		return
	}

	switch node.Type {
	case ast.NodeTypeFunctionDef:
		funcName, ok := node.GetProperty("name")
		if ok && funcName != nil {
			scope := analysis.NewScope(
				fmt.Sprintf("func_%s", funcName),
				analysis.ScopeTypeFunction,
				funcName.(string),
			)
			symTable.PushScope(scope)
		}

	case ast.NodeTypeAssignment:
		varName, _ := node.GetProperty("variable")
		if varName != nil {
			varInfo := ast.NewVariableInfo(
				varName.(string),
				ast.VarTypeLocal,
				node.StartLine,
				0,
			)
			varInfo.SourceNode = node
			symTable.AddVariable(varInfo)
		}

	case ast.NodeTypeImport, ast.NodeTypeImportFrom:
		moduleName, _ := node.GetProperty("module")
		if moduleName != nil {
			importInfo := &analysis.ImportInfo{
				Module:       moduleName.(string),
				SourceModule: moduleName.(string),
			}
			symTable.CurrentScope.AddImport(moduleName.(string), importInfo)
		}
	}

	// Recursively process children
	children := node.GetChildren()
	for _, child := range children {
		pp.buildSymbolTableRecursive(child, symTable)
	}

	// Pop scope if we pushed one
	if node.Type == ast.NodeTypeFunctionDef {
		funcName, ok := node.GetProperty("name")
		if ok && funcName != nil {
			symTable.PopScope()
		}
	}
}

// FindFunctionCalls finds all function calls in the tree
func (pp *PythonParser) FindFunctionCalls(root *ast.Node) ([]*ast.FunctionCallInfo, error) {
	var calls []*ast.FunctionCallInfo
	pp.findFunctionCallsRecursive(root, &calls)
	return calls, nil
}

// findFunctionCallsRecursive recursively finds function calls
func (pp *PythonParser) findFunctionCallsRecursive(node *ast.Node, calls *[]*ast.FunctionCallInfo) {
	if node == nil {
		return
	}

	if node.Type == ast.NodeTypeFunctionCall {
		funcName, _ := node.GetProperty("function")
		if funcName != nil {
			callInfo := ast.NewFunctionCallInfo(funcName.(string), node.StartLine, 0)
			callInfo.FullText = node.GetText()
			callInfo.CallerNode = node

			// Add argument nodes as call info arguments
			children := node.GetChildren()
			for _, child := range children {
				if child.Type == ast.NodeTypeArgument {
					argText := child.GetText()
					callInfo.AddArgument(argText, child)
				}
			}

			*calls = append(*calls, callInfo)
		}
	}

	// Recurse
	children := node.GetChildren()
	for _, child := range children {
		pp.findFunctionCallsRecursive(child, calls)
	}
}

// FindVariableRefs finds all variable references
func (pp *PythonParser) FindVariableRefs(root *ast.Node) ([]*ast.VariableInfo, error) {
	var refs []*ast.VariableInfo
	pp.findVariableRefsRecursive(root, &refs)
	return refs, nil
}

// findVariableRefsRecursive recursively finds variable references
func (pp *PythonParser) findVariableRefsRecursive(node *ast.Node, refs *[]*ast.VariableInfo) {
	if node == nil {
		return
	}

	if node.Type == ast.NodeTypeIdentifier {
		name, _ := node.GetProperty("name")
		if name != nil {
			varInfo := ast.NewVariableInfo(
				name.(string),
				ast.VarTypeUnknown,
				node.StartLine,
				0,
			)
			varInfo.SourceNode = node
			*refs = append(*refs, varInfo)
		}
	}

	// Recurse
	children := node.GetChildren()
	for _, child := range children {
		pp.findVariableRefsRecursive(child, refs)
	}
}

// GetSourceLocation returns source location
func (pp *PythonParser) GetSourceLocation(node *ast.Node) (line, col int) {
	if node == nil {
		return 0, 0
	}
	return node.StartLine, node.StartColumn
}

// ExtractDocstringRanges extracts docstring ranges from parsed Python code
// Docstrings are string literals that are statements (not assignments or arguments)
// and typically appear as the first statement in modules, functions, or classes
func (pp *PythonParser) ExtractDocstringRanges(sourceCode string) *analysis.IgnoredRanges {
	ignoredRanges := analysis.NewIgnoredRanges()

	// Parse the code to find docstring candidates
	pp.mu.Lock()
	tree, err := pp.treeParser.ParseCtx(context.Background(), nil, []byte(sourceCode))
	pp.mu.Unlock()

	if err != nil || tree == nil {
		return ignoredRanges
	}

	// Walk the tree and identify docstrings
	pp.extractDocstringsRecursive(tree.RootNode(), sourceCode, ignoredRanges, true)

	return ignoredRanges
}

// extractDocstringsRecursive recursively finds ALL docstrings in the AST
// It traverses the entire tree and marks all string expression statements as docstrings
func (pp *PythonParser) extractDocstringsRecursive(
	tsNode *sitter.Node,
	sourceCode string,
	ignoredRanges *analysis.IgnoredRanges,
	isFirstStatement bool,
) {
	if tsNode == nil {
		return
	}

	nodeType := tsNode.Type()
	childCount := tsNode.ChildCount()

	// Strategy 1: Catch expression_statement nodes that contain only a string
	// This is the most reliable way to find ALL docstrings (including nested ones)
	if nodeType == "expression_statement" {
		// Check if the first child is a string
		if childCount > 0 {
			firstChild := tsNode.Child(0)
			if firstChild != nil && firstChild.Type() == "string" {
				startByte := int(firstChild.StartByte())
				endByte := int(firstChild.EndByte())
				ignoredRanges.Add(
					startByte,
					endByte,
					analysis.RangeTypeDocstring,
					"Python docstring or string literal as statement",
				)
			}
		}
	}

	// Strategy 2: For function/class definitions, explicitly mark first statement in body as docstring
	// This handles the common pattern where docstrings appear right after the function/class line
	if nodeType == "function_definition" || nodeType == "class_definition" {
		bodyStarted := false
		isFirstBodyStatement := true

		for i := uint32(0); i < childCount; i++ {
			child := tsNode.Child(int(i))
			if child == nil {
				continue
			}

			childType := child.Type()

			// Skip until we find the body (after the ':')
			if childType == ":" {
				bodyStarted = true
				continue
			}

			if bodyStarted && isFirstBodyStatement {
				// Mark the first statement in a function/class body as a docstring
				// (even if we already caught it via Strategy 1)
				if childType == "expression_statement" {
					// Ensure it contains a string
					exprChild := child.Child(0)
					if exprChild != nil && exprChild.Type() == "string" {
						startByte := int(exprChild.StartByte())
						endByte := int(exprChild.EndByte())
						ignoredRanges.Add(
							startByte,
							endByte,
							analysis.RangeTypeDocstring,
							"Function/class docstring",
						)
					}
				} else if childType == "block" || childType == "indent" {
					// If we hit a block, look inside for the first statement
					blockChild := child.Child(0)
					if blockChild != nil && blockChild.Type() == "expression_statement" {
						exprChild := blockChild.Child(0)
						if exprChild != nil && exprChild.Type() == "string" {
							startByte := int(exprChild.StartByte())
							endByte := int(exprChild.EndByte())
							ignoredRanges.Add(
								startByte,
								endByte,
								analysis.RangeTypeDocstring,
								"Function/class docstring in block",
							)
						}
					}
				}
				isFirstBodyStatement = false
			}

			// Recursively process all children
			pp.extractDocstringsRecursive(child, sourceCode, ignoredRanges, false)
		}
		return
	}

	// For all other node types, recursively traverse all children
	for i := uint32(0); i < childCount; i++ {
		child := tsNode.Child(int(i))
		if child != nil {
			pp.extractDocstringsRecursive(child, sourceCode, ignoredRanges, false)
		}
	}
}
