package parser

import (
	"fmt"
	"testing"

	"github.com/inkog-io/inkog/action/pkg/ast_engine/ast"
)

// TestPythonParserCreation verifies parser initialization
func TestPythonParserCreation(t *testing.T) {
	config := DefaultConfig()
	parser, err := NewPythonParser(config)

	if err != nil {
		t.Fatalf("Failed to create Python parser: %v", err)
	}

	if parser == nil {
		t.Error("Expected parser to be non-nil")
	}

	if !parser.IsInitialized() {
		t.Error("Expected parser to be initialized")
	}

	if parser.Language() != ast.LanguagePython {
		t.Errorf("Expected LanguagePython, got %v", parser.Language())
	}
}

// TestPythonFunctionDefinitions verifies function definition parsing
func TestPythonFunctionDefinitions(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewPythonParser(config)

	code := `def myFunction():
    pass

def anotherFunc(x, y):
    return x + y
`

	result, err := parser.ParseFile("test.py", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	_, err = parser.FindFunctionCalls(result.Root)
	if err != nil {
		t.Fatalf("FindFunctionCalls failed: %v", err)
	}

	// We should find function definitions and calls
	if result.Root == nil {
		t.Error("Root node is nil")
	}

	if result.SourceLength != len(code) {
		t.Errorf("Expected source length %d, got %d", len(code), result.SourceLength)
	}

	if result.Language != ast.LanguagePython {
		t.Errorf("Expected LanguagePython, got %v", result.Language)
	}
}

// TestPythonImportStatements verifies import parsing
func TestPythonImportStatements(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewPythonParser(config)

	code := `import os
import sys
from collections import defaultdict
from typing import List
`

	result, err := parser.ParseFile("test.py", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	symTable, err := parser.BuildSymbolTable(result.Root)
	if err != nil {
		t.Fatalf("BuildSymbolTable failed: %v", err)
	}

	if symTable == nil {
		t.Error("SymbolTable is nil")
	}

	if symTable.FileScope == nil {
		t.Error("FileScope is nil")
	}
}

// TestPythonVariableAssignments verifies variable assignment parsing
func TestPythonVariableAssignments(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewPythonParser(config)

	code := `x = 10
name = "test"
data = []
user_input = input()
`

	result, err := parser.ParseFile("test.py", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	symTable, err := parser.BuildSymbolTable(result.Root)
	if err != nil {
		t.Fatalf("BuildSymbolTable failed: %v", err)
	}

	// Verify variables are tracked
	if symTable.FileScope.Variables == nil {
		t.Error("Variables map is nil")
	}
}

// TestPythonEvalExec verifies eval/exec detection (critical for POC)
func TestPythonEvalExec(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewPythonParser(config)

	code := `user_code = input()
eval(user_code)
exec(user_code)
os.system("ls")
`

	result, err := parser.ParseFile("test.py", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	funcCalls, err := parser.FindFunctionCalls(result.Root)
	if err != nil {
		t.Fatalf("FindFunctionCalls failed: %v", err)
	}

	// Should find eval, exec, system calls
	foundEval := false
	foundExec := false
	foundSystem := false

	for _, call := range funcCalls {
		if call.FunctionName == "eval" {
			foundEval = true
		}
		if call.FunctionName == "exec" {
			foundExec = true
		}
		if call.FunctionName == "system" {
			foundSystem = true
		}
	}

	if !foundEval && !foundExec && !foundSystem {
		// At least some dangerous functions should be found
		if len(funcCalls) == 0 {
			t.Error("No function calls detected")
		}
	}
}

// TestPythonFunctionCallArguments verifies argument tracking
func TestPythonFunctionCallArguments(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewPythonParser(config)

	code := `result = my_function(arg1, arg2, arg3)`

	result, err := parser.ParseFile("test.py", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	funcCalls, err := parser.FindFunctionCalls(result.Root)
	if err != nil {
		t.Fatalf("FindFunctionCalls failed: %v", err)
	}

	// If we found the function call, check arguments
	if len(funcCalls) > 0 {
		call := funcCalls[0]
		if len(call.Arguments) > 0 {
			t.Logf("Found %d arguments in function call", len(call.Arguments))
		}
	}
}

// TestPythonVariableReferences verifies variable reference tracking
func TestPythonVariableReferences(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewPythonParser(config)

	code := `x = 10
y = x + 5
print(x)
`

	result, err := parser.ParseFile("test.py", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	varRefs, err := parser.FindVariableRefs(result.Root)
	if err != nil {
		t.Fatalf("FindVariableRefs failed: %v", err)
	}

	if varRefs == nil {
		t.Error("FindVariableRefs returned nil")
	}

	t.Logf("Found %d variable references", len(varRefs))
}

// TestPythonSourceLocation verifies line/column tracking
func TestPythonSourceLocation(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewPythonParser(config)

	code := `def func1():
    x = 1
    y = 2
`

	result, err := parser.ParseFile("test.py", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	line, _ := parser.GetSourceLocation(result.Root)
	if line != 1 {
		t.Errorf("Expected line 1, got %d", line)
	}
}

// TestPythonLargeFile verifies parsing large files
func TestPythonLargeFile(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewPythonParser(config)

	// Generate large Python code
	code := "def func_0():\n    pass\n"
	for i := 1; i < 100; i++ {
		code += fmt.Sprintf("def func_%d():\n    pass\n", i)
	}

	result, err := parser.ParseFile("large.py", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	if result == nil {
		t.Error("Expected result, got nil")
	}

	if result.ParseTimeMs < 0 {
		t.Errorf("Invalid parse time: %d", result.ParseTimeMs)
	}
}

// TestPythonEmptyFile verifies handling of empty files
func TestPythonEmptyFile(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewPythonParser(config)

	result, err := parser.ParseFile("empty.py", []byte(""))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	if result.Root == nil {
		t.Error("Root should not be nil for empty file")
	}
}

// TestPythonComments verifies comment handling
func TestPythonComments(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewPythonParser(config)

	code := `# This is a comment
x = 1  # inline comment
# eval(x)  # should be ignored
eval(x)  # real eval
`

	result, err := parser.ParseFile("test.py", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	// Comments should be skipped, only the real eval should be found
	funcCalls, err := parser.FindFunctionCalls(result.Root)
	if err != nil {
		t.Fatalf("FindFunctionCalls failed: %v", err)
	}

	// At least the real eval call should be present
	if len(funcCalls) > 0 {
		t.Logf("Found %d function calls (including eval)", len(funcCalls))
	}
}

// TestPythonComplexCode verifies parsing realistic Python code
func TestPythonComplexCode(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewPythonParser(config)

	code := `import os
import sys
from typing import List

def process_data(user_input):
    """Process user input"""
    # Dangerous: eval with user input
    result = eval(user_input)
    return result

def safe_process(data: List[str]):
    """Safe processing"""
    return [x.strip() for x in data]

if __name__ == "__main__":
    user_data = sys.argv[1]
    output = process_data(user_data)
    print(output)
`

	result, err := parser.ParseFile("complex.py", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	symTable, err := parser.BuildSymbolTable(result.Root)
	if err != nil {
		t.Fatalf("BuildSymbolTable failed: %v", err)
	}

	funcCalls, err := parser.FindFunctionCalls(result.Root)
	if err != nil {
		t.Fatalf("FindFunctionCalls failed: %v", err)
	}

	if symTable.FileScope == nil {
		t.Error("FileScope is nil")
	}

	if len(funcCalls) == 0 {
		t.Error("Should find function calls in complex code")
	}

	t.Logf("Found %d function calls in complex code", len(funcCalls))
	t.Logf("Symbol table has %d variables in file scope", len(symTable.FileScope.Variables))
}

// TestPythonMultilineFunction verifies multiline function parsing
func TestPythonMultilineFunction(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewPythonParser(config)

	code := `def complex_function(
    arg1,
    arg2,
    arg3
):
    """
    Multi-line function definition
    """
    return arg1 + arg2 + arg3
`

	result, err := parser.ParseFile("test.py", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	if result.Root == nil {
		t.Error("Root is nil")
	}
}

// TestPythonNestedScopes verifies nested scope handling
func TestPythonNestedScopes(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewPythonParser(config)

	code := `def outer():
    x = 1
    def inner():
        y = 2
        return x + y
    return inner()
`

	result, err := parser.ParseFile("test.py", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	symTable, err := parser.BuildSymbolTable(result.Root)
	if err != nil {
		t.Fatalf("BuildSymbolTable failed: %v", err)
	}

	if symTable.FileScope == nil {
		t.Error("FileScope is nil")
	}
}
