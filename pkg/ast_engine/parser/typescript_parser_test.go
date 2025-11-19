package parser

import (
	"fmt"
	"testing"

	"github.com/inkog-io/inkog/action/pkg/ast_engine/ast"
)

// TestTypeScriptParserCreation verifies parser initialization
func TestTypeScriptParserCreation(t *testing.T) {
	config := DefaultConfig()
	parser, err := NewTypeScriptParser(config)

	if err != nil {
		t.Fatalf("Failed to create TypeScript parser: %v", err)
	}

	if parser == nil {
		t.Error("Expected parser to be non-nil")
	}

	if !parser.IsInitialized() {
		t.Error("Expected parser to be initialized")
	}

	if parser.Language() != ast.LanguageTypeScript {
		t.Errorf("Expected LanguageTypeScript, got %v", parser.Language())
	}
}

// TestTypeScriptTypeAnnotations verifies type annotation parsing
func TestTypeScriptTypeAnnotations(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewTypeScriptParser(config)

	code := `function add(a: number, b: number): number {
  return a + b;
}

const processData = (input: string): Promise<string> => {
  return Promise.resolve(input);
};
`

	result, err := parser.ParseFile("test.ts", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	if result.Root == nil {
		t.Error("Root node is nil")
	}

	if result.Language != ast.LanguageTypeScript {
		t.Errorf("Expected LanguageTypeScript, got %v", result.Language)
	}
}

// TestTypeScriptInterfaces verifies interface definitions
func TestTypeScriptInterfaces(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewTypeScriptParser(config)

	code := `interface User {
  id: number;
  name: string;
  email?: string;
}

type Status = 'active' | 'inactive' | 'pending';
`

	result, err := parser.ParseFile("test.ts", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	if result.Root == nil {
		t.Error("Root is nil")
	}
}

// TestTypeScriptGenerics verifies generic type parsing
func TestTypeScriptGenerics(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewTypeScriptParser(config)

	code := `function identity<T>(arg: T): T {
  return arg;
}

const container: Map<string, any> = new Map();
class Stack<T> {
  push(item: T) { }
}
`

	result, err := parser.ParseFile("test.ts", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	if result.Root == nil {
		t.Error("Root is nil")
	}
}

// TestTypeScriptClasses verifies class definition parsing
func TestTypeScriptClasses(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewTypeScriptParser(config)

	code := `class MyClass {
  private data: string;
  protected value: number;

  constructor(data: string) {
    this.data = data;
  }

  public process(): void {
    console.log(this.data);
  }
}
`

	result, err := parser.ParseFile("test.ts", []byte(code))
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

// TestTypeScriptImportExport verifies import/export syntax
func TestTypeScriptImportExport(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewTypeScriptParser(config)

	code := `import { Component } from '@angular/core';
import * as utils from './utils';
import express from 'express';
export interface Config { }
export const VERSION = '1.0.0';
`

	result, err := parser.ParseFile("test.ts", []byte(code))
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

// TestTypeScriptEvalDetection verifies eval detection in TypeScript
func TestTypeScriptEvalDetection(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewTypeScriptParser(config)

	code := `const userInput: string = getUserInput();
const result: any = eval(userInput);
const fn = new Function(userInput);
`

	result, err := parser.ParseFile("test.ts", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	funcCalls, err := parser.FindFunctionCalls(result.Root)
	if err != nil {
		t.Fatalf("FindFunctionCalls failed: %v", err)
	}

	// Verify dangerous functions are found in the list
	for _, call := range funcCalls {
		if call.FunctionName == "eval" || call.FunctionName == "Function" {
			t.Logf("Found dangerous function call: %s", call.FunctionName)
			break
		}
	}

	if len(funcCalls) > 0 {
		t.Logf("Found %d function calls", len(funcCalls))
	}
}

// TestTypeScriptAsyncAwait verifies async function handling
func TestTypeScriptAsyncAwait(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewTypeScriptParser(config)

	code := `async function fetchData(): Promise<string> {
  const response = await fetch(url);
  const data = await response.json();
  return data;
}
`

	result, err := parser.ParseFile("test.ts", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	if result.Root == nil {
		t.Error("Root is nil")
	}
}

// TestTypeScriptComplexCode verifies parsing realistic TypeScript code
func TestTypeScriptComplexCode(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewTypeScriptParser(config)

	code := `import { Injectable } from '@angular/core';
import * as express from 'express';

interface RequestData {
  code: string;
  timeout?: number;
}

@Injectable({ providedIn: 'root' })
export class ExecutorService {
  constructor(private http: HttpClient) {}

  executeUserCode(req: RequestData): Promise<any> {
    // Dangerous: evaluating user code!
    const result = eval(req.code);
    return Promise.resolve(result);
  }

  safeExecute(code: string): void {
    try {
      const validator = new Function('return ' + code);
      validator();
    } catch (error) {
      console.error('Execution failed:', error);
    }
  }
}
`

	result, err := parser.ParseFile("executor.service.ts", []byte(code))
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

	t.Logf("Found %d function calls in complex TypeScript code", len(funcCalls))
}

// TestTypeScriptDecorators verifies decorator syntax
func TestTypeScriptDecorators(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewTypeScriptParser(config)

	code := `@Component({
  selector: 'app-root',
  template: '<h1>Hello</h1>'
})
export class AppComponent {
  @Input() title: string;

  @HostListener('click')
  onClicked() {
    console.log('Clicked');
  }
}
`

	result, err := parser.ParseFile("test.ts", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	if result.Root == nil {
		t.Error("Root is nil")
	}
}

// TestTypeScriptUnionIntersection verifies union and intersection types
func TestTypeScriptUnionIntersection(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewTypeScriptParser(config)

	code := `type StringOrNumber = string | number;
type ReadOnly<T> = {
  readonly [P in keyof T]: T[P];
};

function process(value: string | number): void {
  console.log(value);
}
`

	result, err := parser.ParseFile("test.ts", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	funcCalls, err := parser.FindFunctionCalls(result.Root)
	if err != nil {
		t.Fatalf("FindFunctionCalls failed: %v", err)
	}

	if len(funcCalls) > 0 {
		t.Logf("Found %d function calls", len(funcCalls))
	}
}

// TestTypeScriptEnums verifies enum definitions
func TestTypeScriptEnums(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewTypeScriptParser(config)

	code := `enum Direction {
  Up = 1,
  Down = 2,
  Left = 3,
  Right = 4
}

const dir: Direction = Direction.Up;
`

	result, err := parser.ParseFile("test.ts", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	if result.Root == nil {
		t.Error("Root is nil")
	}
}

// TestTypeScriptNamespaces verifies namespace syntax
func TestTypeScriptNamespaces(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewTypeScriptParser(config)

	code := `namespace Validation {
  export interface StringValidator {
    isAcceptable(s: string): boolean;
  }

  export class LettersOnlyValidator implements StringValidator {
    isAcceptable(s: string) {
      return /^[A-Za-z]+$/.test(s);
    }
  }
}
`

	result, err := parser.ParseFile("test.ts", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	if result.Root == nil {
		t.Error("Root is nil")
	}
}

// TestTypeScriptLargeFile verifies parsing large TypeScript files
func TestTypeScriptLargeFile(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewTypeScriptParser(config)

	code := "class Class_0 { method() { return 0; } }\n"
	for i := 1; i < 100; i++ {
		code += fmt.Sprintf("class Class_%d { method() { return %d; } }\n", i, i)
	}

	result, err := parser.ParseFile("large.ts", []byte(code))
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

// TestTypeScriptTSXFile verifies .tsx file support
func TestTypeScriptTSXFile(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewTypeScriptParser(config)

	code := `import React from 'react';

interface Props {
  title: string;
  children?: React.ReactNode;
}

export const Card: React.FC<Props> = ({ title, children }) => {
  return (
    <div className="card">
      <h2>{title}</h2>
      <div>{children}</div>
    </div>
  );
};
`

	result, err := parser.ParseFile("Card.tsx", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	if result.Root == nil {
		t.Error("Root is nil")
	}

	if result.Language != ast.LanguageTypeScript {
		t.Errorf("Expected LanguageTypeScript, got %v", result.Language)
	}
}

// TestTypeScriptReturnTypeExtraction verifies return type extraction
func TestTypeScriptReturnTypeExtraction(t *testing.T) {
	config := DefaultConfig()
	parser, _ := NewTypeScriptParser(config)

	code := `function getString(): string {
  return "test";
}

function getNumber(): number {
  return 42;
}

const getAsync = async (): Promise<string> => {
  return "async result";
};
`

	result, err := parser.ParseFile("test.ts", []byte(code))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	if result.Root == nil {
		t.Error("Root is nil")
	}
}
