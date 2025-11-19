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

// JavaScriptParser implements Parser for JavaScript using Tree-sitter
type JavaScriptParser struct {
	languageType ast.Language
	initialized  bool
	config       *ParserConfig
	queryEngine  *query.Engine
	mu           sync.RWMutex
	treeParser   *sitter.Parser
}

// NewJavaScriptParser creates a JavaScript parser using Tree-sitter
func NewJavaScriptParser(config *ParserConfig) (*JavaScriptParser, error) {
	if config == nil {
		config = DefaultConfig()
	}

	parser := &JavaScriptParser{
		languageType: ast.LanguageJavaScript,
		initialized:  false,
		config:       config,
		queryEngine:  query.NewEngine(),
		treeParser:   sitter.NewParser(),
	}

	parser.treeParser.SetLanguage(GetJavaScriptLanguage())
	parser.initialized = true
	return parser, nil
}

// ParseFile parses JavaScript source code using Tree-sitter
func (jp *JavaScriptParser) ParseFile(filePath string, content []byte) (*ast.ParseResult, error) {
	jp.mu.RLock()
	if !jp.initialized {
		jp.mu.RUnlock()
		return nil, ErrParserNotInitialized
	}
	jp.mu.RUnlock()

	startTime := time.Now()
	sourceCode := string(content)

	// Tree-sitter parser is not fully thread-safe, so lock during parse
	jp.mu.Lock()
	tree, err := jp.treeParser.ParseCtx(context.Background(), nil, content)
	jp.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("tree-sitter parse error: %w", err)
	}

	root := ast.NewNode("root_0", ast.NodeTypeModule, ast.LanguageJavaScript)
	root.Text = sourceCode
	root.StartLine = 1

	jp.walkJavaScriptTree(tree.RootNode(), root, sourceCode)

	parseTimeMs := time.Since(startTime).Milliseconds()

	return &ast.ParseResult{
		Root:         root,
		Language:     ast.LanguageJavaScript,
		FilePath:     filePath,
		SourceCode:   sourceCode,
		HasError:     false,
		ParseTimeMs:  parseTimeMs,
		SourceLength: len(content),
	}, nil
}

// walkJavaScriptTree recursively walks Tree-sitter CST and builds AST
func (jp *JavaScriptParser) walkJavaScriptTree(tsNode *sitter.Node, astParent *ast.Node, sourceCode string) {
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
	case "ERROR":
		for i := uint32(0); i < childCount; i++ {
			if child := tsNode.Child(int(i)); child != nil {
				jp.walkJavaScriptTree(child, astParent, sourceCode)
			}
		}
		return
	default:
		for i := uint32(0); i < childCount; i++ {
			if child := tsNode.Child(int(i)); child != nil {
				jp.walkJavaScriptTree(child, astParent, sourceCode)
			}
		}
		return
	}

	astNode := ast.NewNode(
		fmt.Sprintf("js_%s_%d", nodeType, startLine),
		astNodeType,
		ast.LanguageJavaScript,
	)
	astNode.Text = text
	astNode.StartLine = startLine
	astNode.StartColumn = startCol
	astNode.EndLine = int(tsNode.EndPoint().Row) + 1
	astNode.EndColumn = int(tsNode.EndPoint().Column)

	jp.extractJavaScriptProperties(astNode, tsNode, sourceCode)
	astParent.AddChild(astNode)

	for i := uint32(0); i < childCount; i++ {
		if child := tsNode.Child(int(i)); child != nil {
			jp.walkJavaScriptTree(child, astNode, sourceCode)
		}
	}
}

// extractJavaScriptProperties extracts properties from JS nodes
func (jp *JavaScriptParser) extractJavaScriptProperties(astNode *ast.Node, tsNode *sitter.Node, sourceCode string) {
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

func (jp *JavaScriptParser) Query(root *ast.Node, queryStr string) ([]*ast.Node, error) {
	if root == nil {
		return nil, ErrNilNode
	}
	return jp.queryEngine.Query(root, queryStr)
}

func (jp *JavaScriptParser) Language() ast.Language {
	jp.mu.RLock()
	defer jp.mu.RUnlock()
	return jp.languageType
}

func (jp *JavaScriptParser) IsInitialized() bool {
	jp.mu.RLock()
	defer jp.mu.RUnlock()
	return jp.initialized
}

func (jp *JavaScriptParser) BuildSymbolTable(root *ast.Node) (*analysis.SymbolTable, error) {
	if root == nil {
		return nil, ErrNilNode
	}
	symTable := analysis.NewSymbolTable()
	jp.buildSymbolTableRecursive(root, symTable)
	return symTable, nil
}

func (jp *JavaScriptParser) buildSymbolTableRecursive(node *ast.Node, symTable *analysis.SymbolTable) {
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
		jp.buildSymbolTableRecursive(child, symTable)
	}

	if node.Type == ast.NodeTypeFunctionDef {
		funcName, ok := node.GetProperty("name")
		if ok && funcName != nil {
			symTable.PopScope()
		}
	}
}

func (jp *JavaScriptParser) FindFunctionCalls(root *ast.Node) ([]*ast.FunctionCallInfo, error) {
	var calls []*ast.FunctionCallInfo
	jp.findFunctionCallsRecursive(root, &calls)
	return calls, nil
}

func (jp *JavaScriptParser) findFunctionCallsRecursive(node *ast.Node, calls *[]*ast.FunctionCallInfo) {
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
		jp.findFunctionCallsRecursive(child, calls)
	}
}

func (jp *JavaScriptParser) FindVariableRefs(root *ast.Node) ([]*ast.VariableInfo, error) {
	var refs []*ast.VariableInfo
	jp.findVariableRefsRecursive(root, &refs)
	return refs, nil
}

func (jp *JavaScriptParser) findVariableRefsRecursive(node *ast.Node, refs *[]*ast.VariableInfo) {
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
		jp.findVariableRefsRecursive(child, refs)
	}
}

func (jp *JavaScriptParser) GetSourceLocation(node *ast.Node) (line, col int) {
	if node == nil {
		return 0, 0
	}
	return node.StartLine, node.StartColumn
}
