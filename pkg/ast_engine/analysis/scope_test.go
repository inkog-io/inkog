package analysis

import (
	"sync"
	"testing"

	"github.com/inkog-io/inkog/action/pkg/ast_engine/ast"
)

// TestScopeCreation verifies scope initialization
func TestScopeCreation(t *testing.T) {
	scope := NewScope("test_scope", ScopeTypeFunction, "testFunc")

	if scope.ID != "test_scope" {
		t.Errorf("Expected ID 'test_scope', got %s", scope.ID)
	}
	if scope.ScopeType != ScopeTypeFunction {
		t.Errorf("Expected ScopeTypeFunction, got %v", scope.ScopeType)
	}
	if scope.Name != "testFunc" {
		t.Errorf("Expected name 'testFunc', got %s", scope.Name)
	}
}

// TestScopeVariable verifies variable addition and retrieval
func TestScopeVariable(t *testing.T) {
	scope := NewScope("scope", ScopeTypeFunction, "func")
	varInfo := ast.NewVariableInfo("myVar", ast.VarTypeLocal, 10, 0)

	scope.AddVariable(varInfo)

	retrieved := scope.LookupVariableLocal("myVar")
	if retrieved == nil {
		t.Error("Variable not found in scope")
	}
	if retrieved.Name != "myVar" {
		t.Errorf("Expected variable 'myVar', got %s", retrieved.Name)
	}
}

// TestScopeParentLookup verifies parent scope lookup
func TestScopeParentLookup(t *testing.T) {
	parentScope := NewScope("parent", ScopeTypeFile, "")
	childScope := NewScope("child", ScopeTypeFunction, "func")
	childScope.ParentScope = parentScope

	parentVar := ast.NewVariableInfo("globalVar", ast.VarTypeGlobal, 1, 0)
	parentScope.AddVariable(parentVar)

	// Child should find parent variable
	found := childScope.GetVariable("globalVar")
	if found == nil {
		t.Error("Should find variable in parent scope")
	}
}

// TestScopeVariableOverride verifies local variable overrides parent
func TestScopeVariableOverride(t *testing.T) {
	parentScope := NewScope("parent", ScopeTypeFile, "")
	childScope := NewScope("child", ScopeTypeFunction, "func")
	childScope.ParentScope = parentScope

	// Add to both scopes
	parentVar := ast.NewVariableInfo("x", ast.VarTypeGlobal, 1, 0)
	childVar := ast.NewVariableInfo("x", ast.VarTypeLocal, 5, 0)

	parentScope.AddVariable(parentVar)
	childScope.AddVariable(childVar)

	// Child should return local version
	found := childScope.GetVariable("x")
	if found.DefinedAtLine != 5 {
		t.Errorf("Expected local variable (line 5), got line %d", found.DefinedAtLine)
	}
}

// TestScopeFunction verifies function addition and retrieval
func TestScopeFunction(t *testing.T) {
	scope := NewScope("scope", ScopeTypeFile, "")

	funcInfo := &ScopeFunction{
		Name:       "myFunc",
		Parameters: []string{"x", "y"},
		ReturnType: "int",
	}

	scope.AddFunction("myFunc", funcInfo)
	retrieved := scope.GetFunction("myFunc")

	if retrieved == nil {
		t.Error("Function not found in scope")
	}
	if retrieved.Name != "myFunc" {
		t.Errorf("Expected function 'myFunc', got %s", retrieved.Name)
	}
	if len(retrieved.Parameters) != 2 {
		t.Errorf("Expected 2 parameters, got %d", len(retrieved.Parameters))
	}
}

// TestScopeImport verifies import statement tracking
func TestScopeImport(t *testing.T) {
	scope := NewScope("scope", ScopeTypeFile, "")

	importInfo := &ImportInfo{
		Module:       "os",
		Items:        []string{"system", "path"},
		SourceModule: "os",
	}

	scope.AddImport("os", importInfo)
	retrieved := scope.GetImport("os")

	if retrieved == nil {
		t.Error("Import not found in scope")
	}
	if retrieved.Module != "os" {
		t.Errorf("Expected module 'os', got %s", retrieved.Module)
	}
}

// TestScopeChildRelationship verifies parent-child scope relationships
func TestScopeChildRelationship(t *testing.T) {
	parentScope := NewScope("parent", ScopeTypeFile, "")
	childScope := NewScope("child", ScopeTypeFunction, "func")

	parentScope.AddChildScope(childScope)

	if childScope.ParentScope != parentScope {
		t.Error("Parent scope not set on child")
	}
	if len(parentScope.ChildScopes) != 1 {
		t.Errorf("Expected 1 child scope, got %d", len(parentScope.ChildScopes))
	}
}

// TestSymbolTableCreation verifies symbol table initialization
func TestSymbolTableCreation(t *testing.T) {
	symTable := NewSymbolTable()

	if symTable.FileScope == nil {
		t.Error("FileScope is nil")
	}
	if symTable.CurrentScope == nil {
		t.Error("CurrentScope is nil")
	}
	if symTable.CurrentScope != symTable.FileScope {
		t.Error("CurrentScope should equal FileScope on creation")
	}
}

// TestSymbolTablePushPop verifies scope stack operations
func TestSymbolTablePushPop(t *testing.T) {
	symTable := NewSymbolTable()

	// Push a function scope
	funcScope := NewScope("func1", ScopeTypeFunction, "myFunc")
	symTable.PushScope(funcScope)

	if symTable.CurrentScope != funcScope {
		t.Error("CurrentScope should be the pushed scope")
	}

	// Pop the scope
	err := symTable.PopScope()
	if err != nil {
		t.Errorf("PopScope failed: %v", err)
	}

	if symTable.CurrentScope != symTable.FileScope {
		t.Error("CurrentScope should be FileScope after pop")
	}
}

// TestSymbolTableVariable verifies variable operations
func TestSymbolTableVariable(t *testing.T) {
	symTable := NewSymbolTable()

	varInfo := ast.NewVariableInfo("myVar", ast.VarTypeLocal, 5, 0)
	node := ast.NewNode("node1", ast.NodeTypeAssignment, ast.LanguagePython)
	varInfo.SourceNode = node

	symTable.AddVariable(varInfo)

	retrieved := symTable.GetVariable("myVar")
	if retrieved == nil {
		t.Error("Variable not found")
	}
	if retrieved.Name != "myVar" {
		t.Errorf("Expected 'myVar', got %s", retrieved.Name)
	}
}

// TestSymbolTableMultipleLevels verifies nested scope variable resolution
func TestSymbolTableMultipleLevels(t *testing.T) {
	symTable := NewSymbolTable()

	// Add to file scope
	globalVar := ast.NewVariableInfo("global", ast.VarTypeGlobal, 1, 0)
	symTable.AddVariable(globalVar)

	// Create function scope
	funcScope := NewScope("func1", ScopeTypeFunction, "func1")
	symTable.PushScope(funcScope)

	// Add to function scope
	localVar := ast.NewVariableInfo("local", ast.VarTypeLocal, 10, 0)
	symTable.AddVariable(localVar)

	// Should find local variable
	found := symTable.GetVariable("local")
	if found == nil {
		t.Error("Local variable not found")
	}

	// Should find global variable through parent scope
	found = symTable.GetVariable("global")
	if found == nil {
		t.Error("Global variable not found from function scope")
	}
}

// TestTaintInfoCreation verifies taint information creation
func TestTaintInfoCreation(t *testing.T) {
	taintInfo := NewTaintInfo("userData", "tainted", "user_input()")

	if taintInfo.VariableName != "userData" {
		t.Errorf("Expected 'userData', got %s", taintInfo.VariableName)
	}
	if taintInfo.TaintState != "tainted" {
		t.Errorf("Expected 'tainted', got %s", taintInfo.TaintState)
	}
	if taintInfo.Source != "user_input()" {
		t.Errorf("Expected 'user_input()', got %s", taintInfo.Source)
	}
}

// TestTaintInfoSourceNode verifies adding source nodes
func TestTaintInfoSourceNode(t *testing.T) {
	taintInfo := NewTaintInfo("userData", "tainted", "input")

	node1 := ast.NewNode("node1", ast.NodeTypeFunctionCall, ast.LanguagePython)
	node2 := ast.NewNode("node2", ast.NodeTypeFunctionCall, ast.LanguagePython)

	taintInfo.AddSourceNode(node1)
	taintInfo.AddSourceNode(node2)

	if len(taintInfo.SourceNodes) != 2 {
		t.Errorf("Expected 2 source nodes, got %d", len(taintInfo.SourceNodes))
	}
}

// TestTaintInfoPropagation verifies taint propagation tracking
func TestTaintInfoPropagation(t *testing.T) {
	taintInfo := NewTaintInfo("result", "tainted", "propagated")

	taintInfo.AddPropagation("userData")
	taintInfo.AddPropagation("userInput")

	if len(taintInfo.PropagatedFrom) != 2 {
		t.Errorf("Expected 2 propagation sources, got %d", len(taintInfo.PropagatedFrom))
	}
}

// TestTaintInfoIsTainted verifies taint state checking
func TestTaintInfoIsTainted(t *testing.T) {
	taintedInfo := NewTaintInfo("userData", "tainted", "input")
	if !taintedInfo.IsTainted() {
		t.Error("Expected tainted variable to be marked as tainted")
	}

	cleanInfo := NewTaintInfo("cleanData", "clean", "")
	if cleanInfo.IsTainted() {
		t.Error("Expected clean variable to not be tainted")
	}

	unknownInfo := NewTaintInfo("unknownData", "unknown", "")
	if !unknownInfo.IsTainted() {
		t.Error("Expected unknown variable to be treated as tainted")
	}
}

// TestTaintInfoSetState verifies changing taint state
func TestTaintInfoSetState(t *testing.T) {
	taintInfo := NewTaintInfo("data", "clean", "")

	if taintInfo.TaintState != "clean" {
		t.Errorf("Expected 'clean', got %s", taintInfo.TaintState)
	}

	taintInfo.SetTaintState("tainted")
	if taintInfo.TaintState != "tainted" {
		t.Errorf("Expected 'tainted', got %s", taintInfo.TaintState)
	}
}

// TestSymbolTableTaintTracking verifies taint tracking in symbol table
func TestSymbolTableTaintTracking(t *testing.T) {
	symTable := NewSymbolTable()

	taintInfo := NewTaintInfo("userData", "tainted", "input()")
	symTable.AddTaintInfo("userData", taintInfo)

	retrieved := symTable.GetTaintInfo("userData")
	if retrieved == nil {
		t.Error("Taint info not found")
	}
	if !retrieved.IsTainted() {
		t.Error("Expected variable to be tainted")
	}
}

// TestScopeThreadSafety verifies concurrent access to scope
func TestScopeThreadSafety(t *testing.T) {
	scope := NewScope("scope", ScopeTypeFile, "")
	var wg sync.WaitGroup
	numGoroutines := 50

	// Writer goroutines
	for i := 0; i < numGoroutines/2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			varInfo := ast.NewVariableInfo("var"+string(rune(idx)), ast.VarTypeLocal, idx, 0)
			scope.AddVariable(varInfo)
		}(i)
	}

	// Reader goroutines
	for i := 0; i < numGoroutines/2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			scope.GetVariable("var" + string(rune(idx)))
		}(i)
	}

	wg.Wait()
	// If no race condition, test passes
}

// TestSymbolTableThreadSafety verifies concurrent symbol table operations
func TestSymbolTableThreadSafety(t *testing.T) {
	symTable := NewSymbolTable()
	var wg sync.WaitGroup
	numGoroutines := 50

	// Writer goroutines
	for i := 0; i < numGoroutines/2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			varInfo := ast.NewVariableInfo("var"+string(rune(idx)), ast.VarTypeLocal, idx, 0)
			symTable.AddVariable(varInfo)
		}(i)
	}

	// Reader goroutines
	for i := 0; i < numGoroutines/2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			symTable.GetVariable("var" + string(rune(idx)))
		}(i)
	}

	wg.Wait()
	// If no race condition, test passes
}

// TestGetAllVariables verifies retrieving all visible variables
func TestGetAllVariables(t *testing.T) {
	parentScope := NewScope("parent", ScopeTypeFile, "")
	childScope := NewScope("child", ScopeTypeFunction, "func")
	childScope.ParentScope = parentScope

	// Add to parent
	parentVar := ast.NewVariableInfo("global", ast.VarTypeGlobal, 1, 0)
	parentScope.AddVariable(parentVar)

	// Add to child
	childVar := ast.NewVariableInfo("local", ast.VarTypeLocal, 10, 0)
	childScope.AddVariable(childVar)

	// Child should see both
	allVars := childScope.GetAllVariables()
	if len(allVars) != 2 {
		t.Errorf("Expected 2 variables, got %d", len(allVars))
	}

	if _, exists := allVars["global"]; !exists {
		t.Error("Missing parent variable in GetAllVariables")
	}
	if _, exists := allVars["local"]; !exists {
		t.Error("Missing local variable in GetAllVariables")
	}
}

// TestIsGlobalScope verifies global scope detection
func TestIsGlobalScope(t *testing.T) {
	fileScope := NewScope("file", ScopeTypeFile, "")
	if !fileScope.IsGlobalScope() {
		t.Error("File scope should be global")
	}

	moduleScope := NewScope("module", ScopeTypeModule, "")
	if !moduleScope.IsGlobalScope() {
		t.Error("Module scope should be global")
	}

	funcScope := NewScope("func", ScopeTypeFunction, "myFunc")
	if funcScope.IsGlobalScope() {
		t.Error("Function scope should not be global")
	}
}

// TestGetParentFunctionScope verifies finding parent function scope
func TestGetParentFunctionScope(t *testing.T) {
	fileScope := NewScope("file", ScopeTypeFile, "")
	funcScope := NewScope("func", ScopeTypeFunction, "myFunc")
	blockScope := NewScope("block", ScopeTypeBlock, "")

	funcScope.ParentScope = fileScope
	blockScope.ParentScope = funcScope

	// From block scope, should find function scope
	found := blockScope.GetParentFunctionScope()
	if found != funcScope {
		t.Error("Should find parent function scope")
	}

	// From file scope, should find nothing
	found = fileScope.GetParentFunctionScope()
	if found != nil {
		t.Error("File scope should not find parent function scope")
	}
}

// TestPopEmptyStack verifies error on popping empty stack
func TestPopEmptyStack(t *testing.T) {
	symTable := NewSymbolTable()

	// Try to pop from initial state (only file scope)
	err := symTable.PopScope()
	if err == nil {
		t.Error("Expected error when popping root scope")
	}
}

// TestMultipleScopeLevels verifies handling multiple scope levels
func TestMultipleScopeLevels(t *testing.T) {
	symTable := NewSymbolTable()

	// Add at file level
	var1 := ast.NewVariableInfo("var1", ast.VarTypeGlobal, 1, 0)
	symTable.AddVariable(var1)

	// Create function scope
	func1 := NewScope("func1", ScopeTypeFunction, "func1")
	symTable.PushScope(func1)

	// Add at function level
	var2 := ast.NewVariableInfo("var2", ast.VarTypeLocal, 5, 0)
	symTable.AddVariable(var2)

	// Create nested block scope
	block1 := NewScope("block1", ScopeTypeBlock, "")
	symTable.PushScope(block1)

	// Add at block level
	var3 := ast.NewVariableInfo("var3", ast.VarTypeLocal, 10, 0)
	symTable.AddVariable(var3)

	// Should find all three
	if symTable.GetVariable("var1") == nil {
		t.Error("Should find var1 from global scope")
	}
	if symTable.GetVariable("var2") == nil {
		t.Error("Should find var2 from function scope")
	}
	if symTable.GetVariable("var3") == nil {
		t.Error("Should find var3 from block scope")
	}
}
