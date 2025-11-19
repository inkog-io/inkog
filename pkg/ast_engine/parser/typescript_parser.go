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

// TypeScriptParser implements Parser for TypeScript using Tree-sitter
type TypeScriptParser struct {
	languageType ast.Language
	initialized  bool
	config       *ParserConfig
	queryEngine  *query.Engine
	mu           sync.RWMutex
	treeParser   *sitter.Parser
	isTSX        bool
}

// NewTypeScriptParser creates a TypeScript parser using Tree-sitter
func NewTypeScriptParser(config *ParserConfig) (*TypeScriptParser, error) {
	if config == nil {
		config = DefaultConfig()
	}

	parser := &TypeScriptParser{
		languageType: ast.LanguageTypeScript,
		initialized:  false,
		config:       config,
		queryEngine:  query.NewEngine(),
		treeParser:   sitter.NewParser(),
	}

	parser.treeParser.SetLanguage(GetTypeScriptLanguage())
	parser.initialized = true
	return parser, nil
}

// ParseFile parses TypeScript source code using Tree-sitter
func (tp *TypeScriptParser) ParseFile(filePath string, content []byte) (*ast.ParseResult, error) {
	tp.mu.RLock()
	if !tp.initialized {
		tp.mu.RUnlock()
		return nil, ErrParserNotInitialized
	}
	tp.mu.RUnlock()

	startTime := time.Now()
	sourceCode := string(content)

	// Detect if TSX based on file extension
	tp.isTSX = len(filePath) >= 4 && filePath[len(filePath)-4:] == ".tsx"

	// Tree-sitter parser is not fully thread-safe, so lock during parse
	tp.mu.Lock()
	tree, err := tp.treeParser.ParseCtx(context.Background(), nil, content)
	tp.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("tree-sitter parse error: %w", err)
	}

	root := ast.NewNode("root_0", ast.NodeTypeModule, ast.LanguageTypeScript)
	root.Text = sourceCode
	root.StartLine = 1

	tp.walkTypeScriptTree(tree.RootNode(), root, sourceCode)

	parseTimeMs := time.Since(startTime).Milliseconds()

	return &ast.ParseResult{
		Root:         root,
		Language:     ast.LanguageTypeScript,
		FilePath:     filePath,
		SourceCode:   sourceCode,
		HasError:     false,
		ParseTimeMs:  parseTimeMs,
		SourceLength: len(content),
	}, nil
}

// walkTypeScriptTree recursively walks Tree-sitter CST and builds AST
func (tp *TypeScriptParser) walkTypeScriptTree(tsNode *sitter.Node, astParent *ast.Node, sourceCode string) {
	if tsNode == nil {
		return
	}

	nodeType := tsNode.Type()
	childCount := tsNode.ChildCount()
	startLine := int(tsNode.StartPoint().Row) + 1
	startCol := int(tsNode.StartPoint().Column)
	text := tsNode.Content([]byte(sourceCode))

	var astNodeType ast.NodeType
	switch nodeType {
	case "function_declaration", "function":
		astNodeType = ast.NodeTypeFunctionDef
	case "arrow_function":
		astNodeType = ast.NodeTypeFunctionDef
	case "class_declaration", "class":
		astNodeType = ast.NodeTypeClass
	case "call_expression":
		astNodeType = ast.NodeTypeFunctionCall
	case "variable_declarator":
		astNodeType = ast.NodeTypeAssignment
	case "import_statement":
		astNodeType = ast.NodeTypeImport
	case "if_statement":
		astNodeType = ast.NodeTypeConditional
	case "while_statement":
		astNodeType = ast.NodeTypeLoop
	case "for_statement", "for_in_statement":
		astNodeType = ast.NodeTypeLoop
	case "try_statement":
		astNodeType = ast.NodeTypeErrorHandling
	case "identifier":
		astNodeType = ast.NodeTypeIdentifier
	case "string", "string_fragment", "template_string":
		astNodeType = ast.NodeTypeString
	case "number":
		astNodeType = ast.NodeTypeNumber
	case "jsx_element", "jsx_self_closing_element":
		return // JSX nodes processed as children
	case "ERROR":
		for i := uint32(0); i < childCount; i++ {
			if child := tsNode.Child(int(i)); child != nil {
				tp.walkTypeScriptTree(child, astParent, sourceCode)
			}
		}
		return
	default:
		for i := uint32(0); i < childCount; i++ {
			if child := tsNode.Child(int(i)); child != nil {
				tp.walkTypeScriptTree(child, astParent, sourceCode)
			}
		}
		return
	}

	astNode := ast.NewNode(
		fmt.Sprintf("ts_%s_%d", nodeType, startLine),
		astNodeType,
		ast.LanguageTypeScript,
	)
	astNode.Text = text
	astNode.StartLine = startLine
	astNode.StartColumn = startCol
	astNode.EndLine = int(tsNode.EndPoint().Row) + 1
	astNode.EndColumn = int(tsNode.EndPoint().Column)

	tp.extractTypeScriptProperties(astNode, tsNode, sourceCode)
	astParent.AddChild(astNode)

	for i := uint32(0); i < childCount; i++ {
		if child := tsNode.Child(int(i)); child != nil {
			tp.walkTypeScriptTree(child, astNode, sourceCode)
		}
	}
}

// extractTypeScriptProperties extracts properties from TS nodes
func (tp *TypeScriptParser) extractTypeScriptProperties(astNode *ast.Node, tsNode *sitter.Node, sourceCode string) {
	switch astNode.Type {
	case ast.NodeTypeFunctionDef:
		if tsNode.ChildCount() >= 2 {
			if nameNode := tsNode.Child(1); nameNode != nil {
				astNode.SetProperty("name", nameNode.Content([]byte(sourceCode)))
			}
		}
	case ast.NodeTypeClass:
		if tsNode.ChildCount() >= 2 {
			if nameNode := tsNode.Child(1); nameNode != nil {
				astNode.SetProperty("name", nameNode.Content([]byte(sourceCode)))
			}
		}
	case ast.NodeTypeFunctionCall:
		if tsNode.ChildCount() > 0 {
			if funcNode := tsNode.Child(0); funcNode != nil {
				astNode.SetProperty("function", funcNode.Content([]byte(sourceCode)))
			}
		}
	case ast.NodeTypeAssignment:
		if tsNode.ChildCount() >= 1 {
			if varNode := tsNode.Child(0); varNode != nil {
				astNode.SetProperty("variable", varNode.Content([]byte(sourceCode)))
			}
		}
	case ast.NodeTypeImport:
		for i := uint32(0); i < tsNode.ChildCount(); i++ {
			if child := tsNode.Child(int(i)); child != nil && child.Type() == "string" {
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

func (tp *TypeScriptParser) Query(root *ast.Node, queryStr string) ([]*ast.Node, error) {
	if root == nil {
		return nil, ErrNilNode
	}
	return tp.queryEngine.Query(root, queryStr)
}

func (tp *TypeScriptParser) Language() ast.Language {
	tp.mu.RLock()
	defer tp.mu.RUnlock()
	return tp.languageType
}

func (tp *TypeScriptParser) IsInitialized() bool {
	tp.mu.RLock()
	defer tp.mu.RUnlock()
	return tp.initialized
}

func (tp *TypeScriptParser) BuildSymbolTable(root *ast.Node) (*analysis.SymbolTable, error) {
	if root == nil {
		return nil, ErrNilNode
	}
	symTable := analysis.NewSymbolTable()
	tp.buildSymbolTableRecursive(root, symTable)
	return symTable, nil
}

func (tp *TypeScriptParser) buildSymbolTableRecursive(node *ast.Node, symTable *analysis.SymbolTable) {
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
	case ast.NodeTypeImport:
		moduleName, _ := node.GetProperty("module")
		if moduleName != nil {
			importInfo := &analysis.ImportInfo{
				Module:       moduleName.(string),
				SourceModule: moduleName.(string),
			}
			symTable.CurrentScope.AddImport(moduleName.(string), importInfo)
		}
	}

	children := node.GetChildren()
	for _, child := range children {
		tp.buildSymbolTableRecursive(child, symTable)
	}

	if node.Type == ast.NodeTypeFunctionDef {
		funcName, ok := node.GetProperty("name")
		if ok && funcName != nil {
			symTable.PopScope()
		}
	}
}

func (tp *TypeScriptParser) FindFunctionCalls(root *ast.Node) ([]*ast.FunctionCallInfo, error) {
	var calls []*ast.FunctionCallInfo
	tp.findFunctionCallsRecursive(root, &calls)
	return calls, nil
}

func (tp *TypeScriptParser) findFunctionCallsRecursive(node *ast.Node, calls *[]*ast.FunctionCallInfo) {
	if node == nil {
		return
	}

	if node.Type == ast.NodeTypeFunctionCall {
		funcName, _ := node.GetProperty("function")
		if funcName != nil {
			callInfo := ast.NewFunctionCallInfo(funcName.(string), node.StartLine, 0)
			callInfo.FullText = node.GetText()
			callInfo.CallerNode = node

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

	children := node.GetChildren()
	for _, child := range children {
		tp.findFunctionCallsRecursive(child, calls)
	}
}

func (tp *TypeScriptParser) FindVariableRefs(root *ast.Node) ([]*ast.VariableInfo, error) {
	var refs []*ast.VariableInfo
	tp.findVariableRefsRecursive(root, &refs)
	return refs, nil
}

func (tp *TypeScriptParser) findVariableRefsRecursive(node *ast.Node, refs *[]*ast.VariableInfo) {
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

	children := node.GetChildren()
	for _, child := range children {
		tp.findVariableRefsRecursive(child, refs)
	}
}

func (tp *TypeScriptParser) GetSourceLocation(node *ast.Node) (line, col int) {
	if node == nil {
		return 0, 0
	}
	return node.StartLine, node.StartColumn
}
