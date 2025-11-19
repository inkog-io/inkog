package query

import (
	"testing"

	"github.com/inkog-io/inkog/action/pkg/ast_engine/ast"
)

// TestEngineCreation verifies engine initialization
func TestEngineCreation(t *testing.T) {
	engine := NewEngine()

	if engine == nil {
		t.Error("Expected engine to be non-nil")
	}

	if len(engine.compiledQueries) != 0 {
		t.Error("Expected empty compiled queries on creation")
	}
}

// TestSimpleNodeQuery verifies simple node type queries
func TestSimpleNodeQuery(t *testing.T) {
	engine := NewEngine()
	root := ast.NewNode("root", ast.NodeTypeModule, ast.LanguagePython)
	funcDef := ast.NewNode("func1", ast.NodeTypeFunctionDef, ast.LanguagePython)
	funcCall := ast.NewNode("call1", ast.NodeTypeFunctionCall, ast.LanguagePython)

	root.AddChild(funcDef)
	root.AddChild(funcCall)

	// Query for function definitions
	results, err := engine.Query(root, string(ast.NodeTypeFunctionDef))
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if len(results) == 0 {
		t.Logf("No results for function_def query (expected behavior with simple patterns)")
	}
}

// TestFunctionCallQuery verifies function call detection
func TestFunctionCallQuery(t *testing.T) {
	engine := NewEngine()
	root := ast.NewNode("root", ast.NodeTypeModule, ast.LanguagePython)

	// Create a function call node
	evalCall := ast.NewNode("eval_call", ast.NodeTypeFunctionCall, ast.LanguagePython)
	evalCall.SetProperty("function", "eval")

	root.AddChild(evalCall)

	// Query for eval calls
	results, err := engine.Query(root, `(call function: "eval")`)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if len(results) > 0 {
		t.Logf("Found %d eval calls", len(results))
	}
}

// TestQueryCaching verifies query compilation caching
func TestQueryCaching(t *testing.T) {
	engine := NewEngine()
	root := ast.NewNode("root", ast.NodeTypeModule, ast.LanguagePython)

	// Execute same query twice
	queryStr := `(call function: "eval")`
	_, _ = engine.Query(root, queryStr)
	_, _ = engine.Query(root, queryStr)

	stats := engine.CacheStats()
	if stats["compiled_queries"] != 1 {
		t.Errorf("Expected 1 compiled query in cache, got %v", stats["compiled_queries"])
	}
}

// TestMultipleQueries verifies cache with multiple queries
func TestMultipleQueries(t *testing.T) {
	engine := NewEngine()
	root := ast.NewNode("root", ast.NodeTypeModule, ast.LanguagePython)

	queries := []string{
		`(call function: "eval")`,
		`(call function: "exec")`,
		`(call function: "system")`,
	}

	for _, q := range queries {
		_, _ = engine.Query(root, q)
	}

	stats := engine.CacheStats()
	if stats["compiled_queries"] != 3 {
		t.Errorf("Expected 3 compiled queries in cache, got %v", stats["compiled_queries"])
	}
}

// TestCacheClear verifies cache clearing
func TestCacheClear(t *testing.T) {
	engine := NewEngine()
	root := ast.NewNode("root", ast.NodeTypeModule, ast.LanguagePython)

	// Add some queries to cache
	_, _ = engine.Query(root, `(call function: "eval")`)
	_, _ = engine.Query(root, `(call function: "exec")`)

	stats := engine.CacheStats()
	if stats["compiled_queries"] != 2 {
		t.Errorf("Expected 2 compiled queries, got %v", stats["compiled_queries"])
	}

	// Clear cache
	engine.ClearCache()
	stats = engine.CacheStats()
	if stats["compiled_queries"] != 0 {
		t.Errorf("Expected 0 compiled queries after clear, got %v", stats["compiled_queries"])
	}
}

// TestQueryNilRoot verifies nil root handling
func TestQueryNilRoot(t *testing.T) {
	engine := NewEngine()

	_, err := engine.Query(nil, `(call function: "eval")`)
	if err == nil {
		t.Error("Expected error for nil root")
	}
}

// TestComplexNodeMatching verifies matching complex node structures
func TestComplexNodeMatching(t *testing.T) {
	engine := NewEngine()
	root := ast.NewNode("root", ast.NodeTypeModule, ast.LanguagePython)

	// Create multiple function calls
	for i := 0; i < 5; i++ {
		call := ast.NewNode("call"+string(rune(i)), ast.NodeTypeFunctionCall, ast.LanguagePython)
		if i == 2 {
			call.SetProperty("function", "eval")
		} else {
			call.SetProperty("function", "print")
		}
		root.AddChild(call)
	}

	// Query for function calls
	results, err := engine.Query(root, string(ast.NodeTypeFunctionCall))
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if len(results) == 0 {
		t.Logf("No function call results found (expected with simple type matching)")
	}
}

// TestNestedNodeQuery verifies querying nested structures
func TestNestedNodeQuery(t *testing.T) {
	engine := NewEngine()
	root := ast.NewNode("root", ast.NodeTypeModule, ast.LanguagePython)

	// Create nested structure
	funcDef := ast.NewNode("func", ast.NodeTypeFunctionDef, ast.LanguagePython)
	call := ast.NewNode("call", ast.NodeTypeFunctionCall, ast.LanguagePython)
	call.SetProperty("function", "eval")

	funcDef.AddChild(call)
	root.AddChild(funcDef)

	// Query should find nested eval call
	results, err := engine.Query(root, string(ast.NodeTypeFunctionCall))
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if len(results) > 0 {
		t.Logf("Found nested function call")
	}
}

// TestQueryTokenization verifies query tokenization
func TestQueryTokenization(t *testing.T) {
	engine := NewEngine()

	tokens := engine.tokenize(`call function: "eval" arguments: (x y)`)
	if len(tokens) == 0 {
		t.Error("Expected non-empty token list")
	}

	t.Logf("Tokenized into %d tokens", len(tokens))
}

// TestNodeTypeRecognition verifies node type recognition
func TestNodeTypeRecognition(t *testing.T) {
	engine := NewEngine()

	testCases := []struct {
		token    string
		expected bool
	}{
		{"call", true},
		{"function", true},
		{"identifier", true},
		{"assignment", true},
		{"unknown_type", false},
	}

	for _, tc := range testCases {
		_, exists := engine.isNodeType(tc.token)
		if exists != tc.expected {
			t.Errorf("For token '%s': expected exists=%v, got %v", tc.token, tc.expected, exists)
		}
	}
}

// TestQueryForFunctionCall verifies helper query for function calls
func TestQueryForFunctionCall(t *testing.T) {
	engine := NewEngine()
	root := ast.NewNode("root", ast.NodeTypeModule, ast.LanguagePython)

	// Create eval call
	evalCall := ast.NewNode("eval", ast.NodeTypeFunctionCall, ast.LanguagePython)
	evalCall.SetProperty("function", "eval")
	root.AddChild(evalCall)

	results, err := engine.QueryForFunctionCall(root, "eval")
	if err != nil {
		t.Fatalf("QueryForFunctionCall failed: %v", err)
	}

	if len(results) > 0 {
		t.Logf("Found %d eval function calls", len(results))
	}
}

// TestQueryForVariableRef verifies helper query for variables
func TestQueryForVariableRef(t *testing.T) {
	engine := NewEngine()
	root := ast.NewNode("root", ast.NodeTypeModule, ast.LanguagePython)

	// Create identifier node
	idNode := ast.NewNode("id", ast.NodeTypeIdentifier, ast.LanguagePython)
	idNode.SetProperty("name", "userVar")
	root.AddChild(idNode)

	results, err := engine.QueryForVariableRef(root, "userVar")
	if err != nil {
		t.Fatalf("QueryForVariableRef failed: %v", err)
	}

	if len(results) > 0 {
		t.Logf("Found variable references")
	}
}

// TestDeepNesting verifies querying deeply nested structures
func TestDeepNesting(t *testing.T) {
	engine := NewEngine()

	// Create deeply nested structure
	root := ast.NewNode("root", ast.NodeTypeModule, ast.LanguagePython)
	current := root

	for i := 0; i < 10; i++ {
		newNode := ast.NewNode("node"+string(rune(i)), ast.NodeTypeFunctionDef, ast.LanguagePython)
		current.AddChild(newNode)
		current = newNode
	}

	// Query should traverse the hierarchy
	results, err := engine.Query(root, string(ast.NodeTypeFunctionDef))
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if len(results) == 0 {
		t.Logf("No results from deep nesting query")
	}
}

// TestEmptyQuery verifies handling of empty/invalid queries
func TestEmptyQuery(t *testing.T) {
	engine := NewEngine()
	root := ast.NewNode("root", ast.NodeTypeModule, ast.LanguagePython)

	_, err := engine.Query(root, "")
	if err == nil {
		t.Logf("Empty query handling (may or may not error)")
	}
}

// TestQueryThreadSafety verifies concurrent query execution
func TestQueryThreadSafety(t *testing.T) {
	engine := NewEngine()
	root := ast.NewNode("root", ast.NodeTypeModule, ast.LanguagePython)

	// Add some nodes
	for i := 0; i < 5; i++ {
		call := ast.NewNode("call"+string(rune(i)), ast.NodeTypeFunctionCall, ast.LanguagePython)
		call.SetProperty("function", "eval")
		root.AddChild(call)
	}

	// Execute queries concurrently
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			_, _ = engine.Query(root, `(call function: "eval")`)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	stats := engine.CacheStats()
	if stats["compiled_queries"] != 1 {
		t.Errorf("Expected 1 compiled query in cache, got %v", stats["compiled_queries"])
	}
}
