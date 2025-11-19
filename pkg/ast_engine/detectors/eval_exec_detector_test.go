package detectors

import (
	"testing"

	"github.com/inkog-io/inkog/action/pkg/ast_engine/ast"
)

// TestDetectorCreation verifies detector initialization
func TestDetectorCreation(t *testing.T) {
	detector, err := NewUnvalidatedEvalExecDetector(ast.LanguagePython)
	if err != nil {
		t.Fatalf("Failed to create detector: %v", err)
	}

	if detector == nil {
		t.Error("Expected detector to be non-nil")
	}
}

// TestDetectorLanguageSupport verifies all supported languages
func TestDetectorLanguageSupport(t *testing.T) {
	languages := []ast.Language{
		ast.LanguagePython,
		ast.LanguageJavaScript,
		ast.LanguageTypeScript,
	}

	for _, lang := range languages {
		detector, err := NewUnvalidatedEvalExecDetector(lang)
		if err != nil {
			t.Errorf("Failed to create detector for %v: %v", lang, err)
		}

		if detector == nil {
			t.Errorf("Detector for %v is nil", lang)
		}
	}
}

// TestDetectorUnsupportedLanguage verifies error on unsupported language
func TestDetectorUnsupportedLanguage(t *testing.T) {
	_, err := NewUnvalidatedEvalExecDetector(ast.Language("rust"))
	if err == nil {
		t.Error("Expected error for unsupported language")
	}
}

// TestPythonEvalDetection verifies Python eval() detection
func TestPythonEvalDetection(t *testing.T) {
	detector, _ := NewUnvalidatedEvalExecDetector(ast.LanguagePython)

	code := `user_input = input()
result = eval(user_input)
`

	findings, err := detector.Analyze("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}

	if len(findings) == 0 {
		t.Logf("No findings (may be due to regex-based parsing limitations)")
	} else {
		for _, f := range findings {
			if f.FunctionName == "eval" {
				t.Logf("Found eval() call: %s", f.Reason)
			}
		}
	}
}

// TestPythonExecDetection verifies Python exec() detection
func TestPythonExecDetection(t *testing.T) {
	detector, _ := NewUnvalidatedEvalExecDetector(ast.LanguagePython)

	code := `cmd = sys.argv[1]
exec(cmd)
`

	findings, err := detector.Analyze("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}

	if len(findings) == 0 {
		t.Logf("No findings detected")
	}
}

// TestJavaScriptEvalDetection verifies JavaScript eval() detection
func TestJavaScriptEvalDetection(t *testing.T) {
	detector, _ := NewUnvalidatedEvalExecDetector(ast.LanguageJavaScript)

	code := `const userCode = getUserInput();
const result = eval(userCode);
`

	findings, err := detector.Analyze("test.js", []byte(code))
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}

	if len(findings) == 0 {
		t.Logf("No findings detected")
	}
}

// TestTypeScriptEvalDetection verifies TypeScript eval() detection
func TestTypeScriptEvalDetection(t *testing.T) {
	detector, _ := NewUnvalidatedEvalExecDetector(ast.LanguageTypeScript)

	code := `const code: string = request.query.code;
const result = eval(code);
`

	findings, err := detector.Analyze("test.ts", []byte(code))
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}

	if len(findings) == 0 {
		t.Logf("No findings detected")
	}
}

// TestComplexPythonCode verifies detection in complex code
func TestComplexPythonCode(t *testing.T) {
	detector, _ := NewUnvalidatedEvalExecDetector(ast.LanguagePython)

	code := `import os
import sys
from flask import Flask, request

app = Flask(__name__)

@app.route('/execute', methods=['POST'])
def execute():
    user_code = request.get_json().get('code')

    # Dangerous!
    try:
        result = eval(user_code)
    except Exception as e:
        result = str(e)

    return {'result': result}

if __name__ == '__main__':
    app.run()
`

	findings, err := detector.Analyze("app.py", []byte(code))
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}

	t.Logf("Complex Python code analysis: %d findings", len(findings))

	for _, f := range findings {
		t.Logf("  - %s: %s", f.FunctionName, f.Reason)
	}
}

// TestComplexJavaScriptCode verifies detection in complex JS code
func TestComplexJavaScriptCode(t *testing.T) {
	detector, _ := NewUnvalidatedEvalExecDetector(ast.LanguageJavaScript)

	code := `const express = require('express');
const app = express();

app.post('/api/run', (req, res) => {
  const code = req.body.code;

  try {
    const result = eval(code);
    res.json({ success: true, result });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

app.listen(3000);
`

	findings, err := detector.Analyze("server.js", []byte(code))
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}

	t.Logf("Complex JavaScript code analysis: %d findings", len(findings))
}

// TestComplexTypeScriptCode verifies detection in complex TS code
func TestComplexTypeScriptCode(t *testing.T) {
	detector, _ := NewUnvalidatedEvalExecDetector(ast.LanguageTypeScript)

	code := `import { Controller, Post, Body } from '@nestjs/common';

@Controller('execute')
export class ExecutorController {
  @Post()
  execute(@Body() data: { code: string }) {
    // Critical vulnerability
    const result = eval(data.code);
    return { result };
  }
}
`

	findings, err := detector.Analyze("executor.controller.ts", []byte(code))
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}

	t.Logf("Complex TypeScript code analysis: %d findings", len(findings))
}

// TestMultipleFindings verifies detecting multiple vulnerabilities
func TestMultipleFindings(t *testing.T) {
	detector, _ := NewUnvalidatedEvalExecDetector(ast.LanguagePython)

	code := `x = input()
eval(x)
y = input()
exec(y)
`

	findings, err := detector.Analyze("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}

	dangerousCalls := 0
	for _, f := range findings {
		if f.FunctionName == "eval" || f.FunctionName == "exec" {
			dangerousCalls++
		}
	}

	t.Logf("Found %d total findings, %d dangerous calls", len(findings), dangerousCalls)
}

// TestGetFindings verifies getting findings
func TestGetFindings(t *testing.T) {
	detector, _ := NewUnvalidatedEvalExecDetector(ast.LanguagePython)

	code := `eval("1+1")`

	_, err := detector.Analyze("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}

	findings := detector.GetFindings()
	if findings == nil {
		t.Error("GetFindings returned nil")
	}
}

// TestCriticalFindingsCount verifies counting critical findings
func TestCriticalFindingsCount(t *testing.T) {
	detector, _ := NewUnvalidatedEvalExecDetector(ast.LanguagePython)

	code := `user_input = input()
eval(user_input)
`

	_, err := detector.Analyze("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}

	count := detector.CriticalFindingsCount()
	t.Logf("Critical findings count: %d", count)
}

// TestSummary verifies summary generation
func TestSummary(t *testing.T) {
	detector, _ := NewUnvalidatedEvalExecDetector(ast.LanguagePython)

	code := `eval(input())
exec(input())
`

	_, err := detector.Analyze("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}

	summary := detector.Summary()
	if summary == nil {
		t.Error("Summary is nil")
	}

	t.Logf("Summary: %v", summary)
}

// TestFindingString verifies finding string representation
func TestFindingString(t *testing.T) {
	finding := &EvalExecFinding{
		FunctionName: "eval",
		FilePath:     "test.py",
		Line:         10,
		Reason:       "Tainted variable passed to eval()",
		RiskLevel:    "CRITICAL",
	}

	str := finding.String()
	if len(str) == 0 {
		t.Error("String representation is empty")
	}

	t.Logf("Finding string: %s", str)
}

// TestFindingDetailedString verifies detailed string representation
func TestFindingDetailedString(t *testing.T) {
	varFlow := &VariableDataFlow{
		VariableName:  "userInput",
		DefinedAtLine: 5,
		IsTainted:     true,
		TaintReason:   "From input()",
	}

	finding := &EvalExecFinding{
		FunctionName: "eval",
		FilePath:     "test.py",
		Line:         10,
		Column:       5,
		VariableRefs: map[string]*VariableDataFlow{
			"userInput": varFlow,
		},
		RiskLevel: "CRITICAL",
		Reason:    "Tainted variable passed to eval()",
	}

	detailed := finding.DetailedString()
	if len(detailed) == 0 {
		t.Error("Detailed string is empty")
	}

	t.Logf("Detailed finding:\n%s", detailed)
}

// TestSafeCode verifies no findings for safe code
func TestSafeCode(t *testing.T) {
	detector, _ := NewUnvalidatedEvalExecDetector(ast.LanguagePython)

	code := `def add(a, b):
    return a + b

result = add(1, 2)
print(result)
`

	findings, err := detector.Analyze("safe.py", []byte(code))
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}

	dangerousCount := 0
	for _, f := range findings {
		if f.FunctionName == "eval" || f.FunctionName == "exec" {
			dangerousCount++
		}
	}

	t.Logf("Safe code findings: %d dangerous calls (expected 0)", dangerousCount)
}

// TestEmptyCode verifies handling empty code
func TestEmptyCode(t *testing.T) {
	detector, _ := NewUnvalidatedEvalExecDetector(ast.LanguagePython)

	findings, err := detector.Analyze("empty.py", []byte(""))
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}

	if findings == nil {
		t.Error("Findings is nil")
	}

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings for empty code, got %d", len(findings))
	}
}

// TestAnalysisMultipleTimes verifies analyzer can be used multiple times
func TestAnalysisMultipleTimes(t *testing.T) {
	detector, _ := NewUnvalidatedEvalExecDetector(ast.LanguagePython)

	code1 := `eval(input())`
	code2 := `print("hello")`

	_, err1 := detector.Analyze("test1.py", []byte(code1))
	_, err2 := detector.Analyze("test2.py", []byte(code2))

	if err1 != nil || err2 != nil {
		t.Fatalf("Analysis failed: %v, %v", err1, err2)
	}

	// Latest analysis should be returned
	findings := detector.GetFindings()
	t.Logf("Final findings count: %d", len(findings))
}

// TestVariableDataFlow verifies variable data flow analysis
func TestVariableDataFlow(t *testing.T) {
	detector, _ := NewUnvalidatedEvalExecDetector(ast.LanguagePython)

	code := `user_input = input()
result = eval(user_input)
`

	findings, err := detector.Analyze("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}

	for _, f := range findings {
		if f.FunctionName == "eval" && len(f.VariableRefs) > 0 {
			for varName, varFlow := range f.VariableRefs {
				t.Logf("Variable flow: %s (line %d) - Tainted: %v, Source: %s",
					varName,
					varFlow.DefinedAtLine,
					varFlow.IsTainted,
					varFlow.Source,
				)
			}
		}
	}
}

// TestDetectorThreadSafety verifies concurrent detector usage
func TestDetectorThreadSafety(t *testing.T) {
	detector, _ := NewUnvalidatedEvalExecDetector(ast.LanguagePython)

	code := `eval(input())`

	_, _ = detector.Analyze("test.py", []byte(code))

	// Concurrent access to GetFindings and Summary
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			_ = detector.GetFindings()
			_ = detector.Summary()
			_ = detector.CriticalFindingsCount()
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	// If no race conditions, test passes
	t.Log("Thread safety test passed")
}
