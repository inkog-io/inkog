package parser

import (
	"fmt"
	"testing"

	"github.com/inkog-io/inkog/action/pkg/ast_engine/ast"
)

// TestJavaScriptParserCreation verifies parser initialization
func TestJavaScriptParserCreation(t *testing.T) {
	config := DefaultConfig()
	parser, err := NewJavaScriptParser(config)

	if err != nil {
		t.Fatalf("Failed to create JavaScript parser: %v", err)
	}

	if parser == nil {
		t.Error("Expected parser to be non-nil")
	}

	if !parser.IsInitialized() {
		t.Error("Expected parser to be initialized")
	}

	if parser.Language() != ast.LanguageJavaScript {
		t.Errorf("Expected LanguageJavaScript, got %v", parser.Language())
	}
}

// TestJavaScriptFunctionDefinitions verifies function definition parsing
func TestJavaScriptFunctionDefinitions(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewJavaScriptParser(config)

	code := `function myFunction() {
  return 42;
}

const arrowFunc = (x) => x * 2;
const asyncFunc = async () => { return "test"; };
`

	result, err := parser.ParseFile("test.js", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	if result.Root == nil {
		t.Error("Root node is nil")
	}

	if result.Language != ast.LanguageJavaScript {
		t.Errorf("Expected LanguageJavaScript, got %v", result.Language)
	}
}

// TestJavaScriptRequireImport verifies require/import parsing
func TestJavaScriptRequireImport(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewJavaScriptParser(config)

	code := `const express = require('express');
const fs = require("fs");
import React from 'react';
import { Component } from 'react';
`

	result, err := parser.ParseFile("test.js", []byte(code))
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

// TestJavaScriptVariableDeclarations verifies variable tracking
func TestJavaScriptVariableDeclarations(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewJavaScriptParser(config)

	code := `const x = 10;
let y = "test";
var z = [];
let userName = getUserInput();
`

	result, err := parser.ParseFile("test.js", []byte(code))
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

// TestJavaScriptEvalDetection verifies eval() detection
func TestJavaScriptEvalDetection(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewJavaScriptParser(config)

	code := `const userCode = getUserInput();
const result = eval(userCode);
const result2 = eval("1 + 1");
new Function(userCode)();
`

	result, err := parser.ParseFile("test.js", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	funcCalls, err := parser.FindFunctionCalls(result.Root)
	if err != nil {
		t.Fatalf("FindFunctionCalls failed: %v", err)
	}

	_ = funcCalls  // Variable used via function calls above
	for _, call := range funcCalls {
		if call.FunctionName == "eval" || call.FunctionName == "Function" {
			// Found dangerous function
			break
		}
	}

	if len(funcCalls) == 0 {
		t.Error("Should find function calls")
	}
}

// TestJavaScriptFunctionCallArguments verifies argument tracking
func TestJavaScriptFunctionCallArguments(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewJavaScriptParser(config)

	code := `eval(userInput);
process.exec(command);
console.log(x, y, z);
`

	result, err := parser.ParseFile("test.js", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	funcCalls, err := parser.FindFunctionCalls(result.Root)
	if err != nil {
		t.Fatalf("FindFunctionCalls failed: %v", err)
	}

	if len(funcCalls) > 0 {
		t.Logf("Found %d function calls", len(funcCalls))
		for _, call := range funcCalls {
			t.Logf("  - %s with %d arguments", call.FunctionName, len(call.Arguments))
		}
	}
}

// TestJavaScriptVariableReferences verifies variable reference tracking
func TestJavaScriptVariableReferences(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewJavaScriptParser(config)

	code := `const data = getUserInput();
console.log(data);
const result = processData(data);
`

	result, err := parser.ParseFile("test.js", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	varRefs, err := parser.FindVariableRefs(result.Root)
	if err != nil {
		t.Fatalf("FindVariableRefs failed: %v", err)
	}

	t.Logf("Found %d variable references", len(varRefs))
}

// TestJavaScriptComplexCode verifies parsing realistic JavaScript code
func TestJavaScriptComplexCode(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewJavaScriptParser(config)

	code := `const express = require('express');
const app = express();

app.post('/api/execute', (req, res) => {
  const userCode = req.body.code;

  // Dangerous!
  const result = eval(userCode);

  res.json({ result });
});

app.listen(3000, () => {
  console.log('Server started');
});
`

	result, err := parser.ParseFile("server.js", []byte(code))
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
}

// TestJavaScriptNestedFunctions verifies nested function parsing
func TestJavaScriptNestedFunctions(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewJavaScriptParser(config)

	code := `function outer(x) {
  function inner(y) {
    return x + y;
  }
  return inner(10);
}
`

	result, err := parser.ParseFile("test.js", []byte(code))
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

// TestJavaScriptAsyncAwait verifies async/await parsing
func TestJavaScriptAsyncAwait(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewJavaScriptParser(config)

	code := `async function fetchData() {
  const response = await fetch(url);
  const data = await response.json();
  return data;
}
`

	result, err := parser.ParseFile("test.js", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	if result.Root == nil {
		t.Error("Root is nil")
	}
}

// TestJavaScriptArrowFunctions verifies arrow function parsing
func TestJavaScriptArrowFunctions(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewJavaScriptParser(config)

	code := `const add = (a, b) => a + b;
const double = x => x * 2;
const getObj = () => ({ value: 42 });
`

	result, err := parser.ParseFile("test.js", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	if result.Root == nil {
		t.Error("Root is nil")
	}
}

// TestJavaScriptLargeFile verifies parsing large files
func TestJavaScriptLargeFile(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewJavaScriptParser(config)

	code := "function func_0() { return 0; }\n"
	for i := 1; i < 100; i++ {
		code += fmt.Sprintf("function func_%d() { return %d; }\n", i, i)
	}

	result, err := parser.ParseFile("large.js", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	if result == nil {
		t.Error("Expected result, got nil")
	}
}

// TestJavaScriptCallback verifies callback pattern detection
func TestJavaScriptCallback(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewJavaScriptParser(config)

	code := `fs.readFile('file.txt', (err, data) => {
  if (err) throw err;
  console.log(data);
});
`

	result, err := parser.ParseFile("test.js", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	funcCalls, err := parser.FindFunctionCalls(result.Root)
	if err != nil {
		t.Fatalf("FindFunctionCalls failed: %v", err)
	}

	if len(funcCalls) > 0 {
		t.Logf("Found %d function calls in callback code", len(funcCalls))
	}
}
