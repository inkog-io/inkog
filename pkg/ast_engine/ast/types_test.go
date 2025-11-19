package ast

import (
	"sync"
	"testing"
)

// TestNodeCreation verifies basic node creation
func TestNodeCreation(t *testing.T) {
	node := NewNode("test_node", NodeTypeFunctionDef, LanguagePython)

	if node.ID != "test_node" {
		t.Errorf("Expected ID 'test_node', got %s", node.ID)
	}
	if node.Type != NodeTypeFunctionDef {
		t.Errorf("Expected NodeTypeFunctionDef, got %v", node.Type)
	}
	if node.Language != LanguagePython {
		t.Errorf("Expected LanguagePython, got %v", node.Language)
	}
}

// TestNodeProperties verifies property setting and getting
func TestNodeProperties(t *testing.T) {
	node := NewNode("prop_test", NodeTypeFunctionCall, LanguageJavaScript)

	node.SetProperty("function", "eval")
	node.SetProperty("line", 42)

	funcProp, exists := node.GetProperty("function")
	if !exists {
		t.Error("Expected property 'function' to exist")
	}
	if funcProp != "eval" {
		t.Errorf("Expected 'eval', got %v", funcProp)
	}

	lineProp, exists := node.GetProperty("line")
	if !exists {
		t.Error("Expected property 'line' to exist")
	}
	if lineProp != 42 {
		t.Errorf("Expected 42, got %v", lineProp)
	}
}

// TestNodeHierarchy verifies parent-child relationships
func TestNodeHierarchy(t *testing.T) {
	parent := NewNode("parent", NodeTypeModule, LanguagePython)
	child1 := NewNode("child1", NodeTypeFunctionDef, LanguagePython)
	child2 := NewNode("child2", NodeTypeAssignment, LanguagePython)

	parent.AddChild(child1)
	parent.AddChild(child2)

	if len(parent.Children) != 2 {
		t.Errorf("Expected 2 children, got %d", len(parent.Children))
	}

	if child1.Parent != parent {
		t.Error("Expected child1 parent to be parent node")
	}
	if child2.Parent != parent {
		t.Error("Expected child2 parent to be parent node")
	}
}

// TestNodeText verifies text setting and retrieval
func TestNodeText(t *testing.T) {
	node := NewNode("text_node", NodeTypeFunctionDef, LanguagePython)
	sourceCode := "def myFunction():\n    pass"

	node.Text = sourceCode

	if node.GetText() != sourceCode {
		t.Errorf("Expected '%s', got '%s'", sourceCode, node.GetText())
	}
}

// TestNodeLineNumbers verifies line number tracking
func TestNodeLineNumbers(t *testing.T) {
	node := NewNode("line_node", NodeTypeFunctionCall, LanguageTypeScript)
	node.StartLine = 10
	node.EndLine = 15
	node.StartColumn = 5
	node.EndColumn = 25

	if node.StartLine != 10 {
		t.Errorf("Expected StartLine 10, got %d", node.StartLine)
	}
	if node.EndLine != 15 {
		t.Errorf("Expected EndLine 15, got %d", node.EndLine)
	}
	if node.StartColumn != 5 {
		t.Errorf("Expected StartColumn 5, got %d", node.StartColumn)
	}
	if node.EndColumn != 25 {
		t.Errorf("Expected EndColumn 25, got %d", node.EndColumn)
	}
}

// TestFunctionCallInfo verifies function call information tracking
func TestFunctionCallInfo(t *testing.T) {
	callInfo := NewFunctionCallInfo("evalFunc", 42, 8)

	if callInfo.FunctionName != "evalFunc" {
		t.Errorf("Expected function name 'evalFunc', got %s", callInfo.FunctionName)
	}
	if callInfo.Line != 42 {
		t.Errorf("Expected line 42, got %d", callInfo.Line)
	}
	if callInfo.Column != 8 {
		t.Errorf("Expected column 8, got %d", callInfo.Column)
	}
}

// TestFunctionCallArguments verifies argument tracking
func TestFunctionCallArguments(t *testing.T) {
	callInfo := NewFunctionCallInfo("eval", 10, 0)
	argNode1 := NewNode("arg1", NodeTypeArgument, LanguagePython)
	argNode2 := NewNode("arg2", NodeTypeArgument, LanguagePython)

	callInfo.AddArgument("userInput", argNode1)
	callInfo.AddArgument("secondArg", argNode2)

	if len(callInfo.Arguments) != 2 {
		t.Errorf("Expected 2 arguments, got %d", len(callInfo.Arguments))
	}
	if callInfo.Arguments[0] != "userInput" {
		t.Errorf("Expected first arg 'userInput', got %s", callInfo.Arguments[0])
	}
}

// TestVariableInfo verifies variable information tracking
func TestVariableInfo(t *testing.T) {
	varInfo := NewVariableInfo("userInput", VarTypeLocal, 5, 0)

	if varInfo.Name != "userInput" {
		t.Errorf("Expected name 'userInput', got %s", varInfo.Name)
	}
	if varInfo.Type != VarTypeLocal {
		t.Errorf("Expected VarTypeLocal, got %v", varInfo.Type)
	}
	if varInfo.DefinedAtLine != 5 {
		t.Errorf("Expected DefinedAtLine 5, got %d", varInfo.DefinedAtLine)
	}
}

// TestVariableReferences verifies reference tracking
func TestVariableReferences(t *testing.T) {
	varInfo := NewVariableInfo("data", VarTypeParameter, 1, 0)
	refNode1 := NewNode("ref1", NodeTypeArgument, LanguagePython)
	refNode2 := NewNode("ref2", NodeTypeArgument, LanguagePython)

	varInfo.AddReference(refNode1)
	varInfo.AddReference(refNode2)

	if len(varInfo.References) != 2 {
		t.Errorf("Expected 2 references, got %d", len(varInfo.References))
	}
}

// TestThreadSafeProperties verifies concurrent property access
func TestThreadSafeProperties(t *testing.T) {
	node := NewNode("thread_test", NodeTypeFunctionCall, LanguageJavaScript)
	var wg sync.WaitGroup
	numGoroutines := 100

	// Writer goroutines
	for i := 0; i < numGoroutines/2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			node.SetProperty("key_"+string(rune(idx)), idx*10)
		}(i)
	}

	// Reader goroutines
	for i := 0; i < numGoroutines/2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, _ = node.GetProperty("key_" + string(rune(idx)))
		}(i)
	}

	wg.Wait()
	// If we get here without a race condition, test passes
}

// TestThreadSafeHierarchy verifies concurrent hierarchy modifications
func TestThreadSafeHierarchy(t *testing.T) {
	parent := NewNode("parent", NodeTypeModule, LanguagePython)
	var wg sync.WaitGroup
	numChildren := 50

	// Add children concurrently
	for i := 0; i < numChildren; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			child := NewNode("child_"+string(rune(idx)), NodeTypeAssignment, LanguagePython)
			parent.AddChild(child)
		}(i)
	}

	wg.Wait()

	if len(parent.Children) != numChildren {
		t.Errorf("Expected %d children, got %d", numChildren, len(parent.Children))
	}
}

// TestParseResult verifies parse result structure
func TestParseResult(t *testing.T) {
	root := NewNode("root", NodeTypeModule, LanguagePython)
	root.Text = "x = 1"

	result := &ParseResult{
		Root:         root,
		Language:     LanguagePython,
		FilePath:     "/test/file.py",
		SourceCode:   "x = 1",
		HasError:     false,
		ParseTimeMs:  10,
		SourceLength: 5,
	}

	if result.Language != LanguagePython {
		t.Errorf("Expected LanguagePython, got %v", result.Language)
	}
	if result.FilePath != "/test/file.py" {
		t.Errorf("Expected '/test/file.py', got %s", result.FilePath)
	}
	if result.SourceLength != 5 {
		t.Errorf("Expected length 5, got %d", result.SourceLength)
	}
}

// TestNodeTypeConstants verifies all node types are defined
func TestNodeTypeConstants(t *testing.T) {
	nodeTypes := []NodeType{
		NodeTypeModule,
		NodeTypeFunctionDef,
		NodeTypeFunctionCall,
		NodeTypeAssignment,
		NodeTypeImport,
		NodeTypeIdentifier,
		NodeTypeArgument,
		NodeTypeMethodCall,
		NodeTypeForStatement,
		NodeTypeWhileStatement,
		NodeTypeIfStatement,
	}

	if len(nodeTypes) == 0 {
		t.Error("No node types found")
	}
}

// TestLanguageConstants verifies all language types are defined
func TestLanguageConstants(t *testing.T) {
	languages := []Language{
		LanguagePython,
		LanguageJavaScript,
		LanguageTypeScript,
	}

	if len(languages) == 0 {
		t.Error("No languages found")
	}
}

// TestVariableTypeConstants verifies all variable types are defined
func TestVariableTypeConstants(t *testing.T) {
	varTypes := []VariableType{
		VarTypeLocal,
		VarTypeGlobal,
		VarTypeParameter,
		VarTypeImported,
		VarTypeUnknown,
	}

	if len(varTypes) == 0 {
		t.Error("No variable types found")
	}
}
