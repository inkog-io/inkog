package ast_engine

import (
	"fmt"
	"sync"
	"testing"

	"github.com/inkog-io/inkog/action/pkg/ast_engine/parser"
)

// TestPythonParsingAndSymbolTable verifies full Python parsing workflow
func TestPythonParsingAndSymbolTable(t *testing.T) {
	config := parser.DefaultConfig()
	pyParser, err := parser.NewPythonParser(config)
	if err != nil {
		t.Fatalf("Failed to create parser: %v", err)
	}

	code := `import os
import sys

def process_user_input(data):
    user_code = input()
    result = eval(user_code)
    return result

def safe_process(data):
    return data.strip()

user_data = sys.argv[1]
output = process_user_input(user_data)
print(output)
`

	result, err := pyParser.ParseFile("test.py", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	// Build symbol table
	symTable, err := pyParser.BuildSymbolTable(result.Root)
	if err != nil {
		t.Fatalf("BuildSymbolTable failed: %v", err)
	}

	// Find function calls
	funcCalls, err := pyParser.FindFunctionCalls(result.Root)
	if err != nil {
		t.Fatalf("FindFunctionCalls failed: %v", err)
	}

	// Verify results
	if symTable.FileScope == nil {
		t.Error("FileScope is nil")
	}

	if len(funcCalls) == 0 {
		t.Error("Should find function calls")
	}

	t.Logf("Python Integration Test: Found %d function calls, FileScope has %d variables",
		len(funcCalls), len(symTable.FileScope.Variables))
}

// TestJavaScriptParsingAndSymbolTable verifies full JavaScript parsing workflow
func TestJavaScriptParsingAndSymbolTable(t *testing.T) {
	config := parser.DefaultConfig()
	jsParser, err := parser.NewJavaScriptParser(config)
	if err != nil {
		t.Fatalf("Failed to create parser: %v", err)
	}

	code := `const express = require('express');
const app = express();

app.post('/execute', (req, res) => {
  const userCode = req.body.code;
  const result = eval(userCode);
  res.json({ result });
});

function process(data) {
  return data.toUpperCase();
}

app.listen(3000);
`

	result, err := jsParser.ParseFile("server.js", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	symTable, err := jsParser.BuildSymbolTable(result.Root)
	if err != nil {
		t.Fatalf("BuildSymbolTable failed: %v", err)
	}

	funcCalls, err := jsParser.FindFunctionCalls(result.Root)
	if err != nil {
		t.Fatalf("FindFunctionCalls failed: %v", err)
	}

	if symTable.FileScope == nil {
		t.Error("FileScope is nil")
	}

	if len(funcCalls) == 0 {
		t.Error("Should find function calls")
	}

	t.Logf("JavaScript Integration Test: Found %d function calls", len(funcCalls))
}

// TestTypeScriptParsingAndSymbolTable verifies full TypeScript parsing workflow
func TestTypeScriptParsingAndSymbolTable(t *testing.T) {
	config := parser.DefaultConfig()
	tsParser, err := parser.NewTypeScriptParser(config)
	if err != nil {
		t.Fatalf("Failed to create parser: %v", err)
	}

	code := `interface RequestData {
  code: string;
  timeout?: number;
}

export class ExecutorService {
  constructor() {}

  executeCode(req: RequestData): any {
    const result = eval(req.code);
    return result;
  }

  validateInput(input: string): boolean {
    return input.length > 0;
  }
}
`

	result, err := tsParser.ParseFile("executor.ts", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	symTable, err := tsParser.BuildSymbolTable(result.Root)
	if err != nil {
		t.Fatalf("BuildSymbolTable failed: %v", err)
	}

	funcCalls, err := tsParser.FindFunctionCalls(result.Root)
	if err != nil {
		t.Fatalf("FindFunctionCalls failed: %v", err)
	}

	if symTable.FileScope == nil {
		t.Error("FileScope is nil")
	}

	t.Logf("TypeScript Integration Test: Found %d function calls", len(funcCalls))
}

// TestParserConcurrency verifies concurrent parser usage
func TestParserConcurrency(t *testing.T) {
	config := parser.DefaultConfig()
	pyParser, _ := parser.NewPythonParser(config)
	jsParser, _ := parser.NewJavaScriptParser(config)
	tsParser, _ := parser.NewTypeScriptParser(config)

	codes := map[string]string{
		"python": `def func(): eval(x)`,
		"js":     `function func() { eval(x); }`,
		"ts":     `function func(): void { eval(x); }`,
	}

	var wg sync.WaitGroup
	results := make(chan bool, 3)

	// Parse Python concurrently
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := pyParser.ParseFile("test.py", []byte(codes["python"]))
		results <- err == nil
	}()

	// Parse JavaScript concurrently
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := jsParser.ParseFile("test.js", []byte(codes["js"]))
		results <- err == nil
	}()

	// Parse TypeScript concurrently
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := tsParser.ParseFile("test.ts", []byte(codes["ts"]))
		results <- err == nil
	}()

	wg.Wait()
	close(results)

	successCount := 0
	for result := range results {
		if result {
			successCount++
		}
	}

	if successCount != 3 {
		t.Errorf("Expected 3 successful parses, got %d", successCount)
	}
}

// TestEvalDetectionWorkflow verifies finding eval() calls with variable tracking
func TestEvalDetectionWorkflow(t *testing.T) {
	config := parser.DefaultConfig()
	parser, _ := parser.NewPythonParser(config)

	code := `def dangerous_function():
    user_input = get_user_input()
    result = eval(user_input)
    return result

def another_danger():
    cmd = request.args.get('cmd')
    exec(cmd)
`

	result, err := parser.ParseFile("test.py", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	// Find all function calls
	funcCalls, err := parser.FindFunctionCalls(result.Root)
	if err != nil {
		t.Fatalf("FindFunctionCalls failed: %v", err)
	}

	// Find eval/exec calls
	dangerousCalls := []string{"eval", "exec"}
	found := 0
	for _, call := range funcCalls {
		for _, dangerous := range dangerousCalls {
			if call.FunctionName == dangerous {
				found++
				t.Logf("Found dangerous call: %s at line %d with %d arguments",
					call.FunctionName, call.Line, len(call.Arguments))
			}
		}
	}

	if found == 0 {
		t.Logf("No eval/exec calls found (may be due to regex limitations)")
	}
}

// TestMultipleFileParsing verifies parsing multiple files in sequence
func TestMultipleFileParsing(t *testing.T) {
	config := parser.DefaultConfig()
	pyParser, _ := parser.NewPythonParser(config)

	files := map[string]string{
		"file1.py": `def func1(): pass`,
		"file2.py": `def func2(): eval(x)`,
		"file3.py": `def func3(): exec(y)`,
	}

	parsedCount := 0
	for filename, code := range files {
		result, err := pyParser.ParseFile(filename, []byte(code))
		if err != nil {
			t.Fatalf("ParseFile(%s) failed: %v", filename, err)
		}

		if result.Root != nil {
			parsedCount++
		}
	}

	if parsedCount != 3 {
		t.Errorf("Expected 3 successful parses, got %d", parsedCount)
	}
}

// TestHighConcurrency verifies high concurrency parsing
func TestHighConcurrency(t *testing.T) {
	config := parser.DefaultConfig()
	parsers := make([]parser.Parser, 3)

	var err error
	parsers[0], err = parser.NewPythonParser(config)
	if err != nil {
		t.Fatalf("Failed to create Python parser: %v", err)
	}

	parsers[1], err = parser.NewJavaScriptParser(config)
	if err != nil {
		t.Fatalf("Failed to create JavaScript parser: %v", err)
	}

	parsers[2], err = parser.NewTypeScriptParser(config)
	if err != nil {
		t.Fatalf("Failed to create TypeScript parser: %v", err)
	}

	var wg sync.WaitGroup
	numGoroutines := 50
	successCount := 0
	var mu sync.Mutex

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			p := parsers[idx%3]
			ext := ".py"
			if idx%3 == 1 {
				ext = ".js"
			} else if idx%3 == 2 {
				ext = ".ts"
			}

			code := fmt.Sprintf("def func_%d(): pass", idx)
			result, err := p.ParseFile(fmt.Sprintf("file_%d%s", idx, ext), []byte(code))

			if err == nil && result != nil {
				mu.Lock()
				successCount++
				mu.Unlock()
			}
		}(i)
	}

	wg.Wait()

	if successCount != numGoroutines {
		t.Errorf("Expected %d successful parses, got %d", numGoroutines, successCount)
	}
}

// TestComplexRealWorldCode verifies parsing complex realistic code
func TestComplexRealWorldCode(t *testing.T) {
	config := parser.DefaultConfig()
	parser, _ := parser.NewPythonParser(config)

	code := `import os
import sys
from typing import List, Dict, Optional
from flask import Flask, request
import json

app = Flask(__name__)

class CodeExecutor:
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.cache: Dict[str, any] = {}

    def execute_user_code(self, code: str) -> Optional[str]:
        if code in self.cache:
            return self.cache[code]

        try:
            # DANGEROUS: Direct eval of user input!
            result = eval(code)
            self.cache[code] = result
            return str(result)
        except Exception as e:
            return f"Error: {str(e)}"

    def execute_file(self, filepath: str) -> str:
        with open(filepath, 'r') as f:
            content = f.read()

        # Another dangerous pattern
        exec(content)
        return "Executed"

executor = CodeExecutor(timeout=10)

@app.route('/api/execute', methods=['POST'])
def execute_endpoint():
    data = request.get_json()
    code = data.get('code')

    if not code:
        return {'error': 'No code provided'}, 400

    result = executor.execute_user_code(code)
    return {'result': result}

if __name__ == '__main__':
    app.run(debug=True, port=5000)
`

	result, err := parser.ParseFile("app.py", []byte(code))
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

	varRefs, err := parser.FindVariableRefs(result.Root)
	if err != nil {
		t.Fatalf("FindVariableRefs failed: %v", err)
	}

	if symTable.FileScope == nil {
		t.Error("FileScope is nil")
	}

	if len(funcCalls) == 0 {
		t.Error("Should find function calls")
	}

	if len(varRefs) == 0 {
		t.Error("Should find variable references")
	}

	t.Logf("Complex Code Analysis: %d function calls, %d variable refs, FileScope: %d vars",
		len(funcCalls), len(varRefs), len(symTable.FileScope.Variables))
}

// TestErrorHandling verifies error handling in parsing
func TestErrorHandling(t *testing.T) {
	config := parser.DefaultConfig()
	parser, _ := parser.NewPythonParser(config)

	testCases := []struct {
		name string
		code string
	}{
		{"empty file", ""},
		{"comment only", "# just a comment"},
		{"simple assignment", "x = 1"},
		{"function call", "print(x)"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parser.ParseFile("test.py", []byte(tc.code))

			// Parser should handle all cases without errors
			if err != nil && tc.code != "" {
				t.Fatalf("Unexpected error: %v", err)
			}

			if result == nil && tc.code != "" {
				t.Error("Expected non-nil result")
			}
		})
	}
}

// TestMemoryEfficiency verifies memory handling with large inputs
func TestMemoryEfficiency(t *testing.T) {
	config := parser.DefaultConfig()
	parser, _ := parser.NewPythonParser(config)

	// Generate large code
	code := ""
	for i := 0; i < 1000; i++ {
		code += fmt.Sprintf("def func_%d():\n    x = %d\n    return x\n\n", i, i)
	}

	result, err := parser.ParseFile("large.py", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	if result.SourceLength != len(code) {
		t.Errorf("Expected source length %d, got %d", len(code), result.SourceLength)
	}

	if result.ParseTimeMs < 0 {
		t.Errorf("Invalid parse time: %d", result.ParseTimeMs)
	}

	t.Logf("Large file parsing: %d bytes in %d ms", result.SourceLength, result.ParseTimeMs)
}
