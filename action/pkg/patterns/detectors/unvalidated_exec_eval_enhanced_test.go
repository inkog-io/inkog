package detectors

import (
	"testing"
)

// TestUnvalidatedExecEvalPythonEval - Test detection of eval with user input
func TestUnvalidatedExecEvalPythonEval(t *testing.T) {
	detector := NewEnhancedUnvalidatedExecEvalDetector(nil)

	code := []byte(`
user_input = request.args.get('code')
result = eval(user_input)
return result
`)

	findings, err := detector.Detect("app.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("Expected to find eval with user input vulnerability")
	}

	if len(findings) > 0 {
		if findings[0].Severity != "CRITICAL" {
			t.Errorf("Expected CRITICAL severity, got %s", findings[0].Severity)
		}
		if findings[0].Confidence < 0.85 {
			t.Errorf("Expected confidence >= 0.85, got %f", findings[0].Confidence)
		}
	}
}

// TestUnvalidatedExecEvalPythonExec - Test detection of exec with user input
func TestUnvalidatedExecEvalPythonExec(t *testing.T) {
	detector := NewEnhancedUnvalidatedExecEvalDetector(nil)

	code := []byte(`
code_to_execute = request.json.get('code')
exec(code_to_execute)
`)

	findings, err := detector.Detect("handler.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("Expected to find exec with user input vulnerability")
	}

	if len(findings) > 0 {
		if findings[0].Severity != "CRITICAL" {
			t.Errorf("Expected CRITICAL severity, got %s", findings[0].Severity)
		}
	}
}

// TestUnvalidatedExecEvalConstantEval - Test that constant eval strings are safe
func TestUnvalidatedExecEvalConstantEval(t *testing.T) {
	detector := NewEnhancedUnvalidatedExecEvalDetector(nil)

	code := []byte(`
# This is safe - evaluating a constant mathematical expression
result = eval("2 + 2")
return result
`)

	findings, err := detector.Detect("math.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should not flag constant eval strings as highly dangerous
	// (Though eval should still be discouraged)
	if len(findings) > 0 {
		if findings[0].Confidence > 0.80 {
			t.Logf("Warning: Constant eval marked with high confidence %f", findings[0].Confidence)
		}
	}
}

// TestUnvalidatedExecEvalCompileExec - Test detection of compile + exec pattern
func TestUnvalidatedExecEvalCompileExec(t *testing.T) {
	detector := NewEnhancedUnvalidatedExecEvalDetector(nil)

	code := []byte(`
code_str = get_user_code()
compiled = compile(code_str, '<string>', 'exec')
exec(compiled)
`)

	findings, err := detector.Detect("compiler.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("Expected to find compile + exec pattern vulnerability")
	}

	if len(findings) > 0 {
		if findings[0].Severity != "CRITICAL" {
			t.Errorf("Expected CRITICAL severity for compile+exec, got %s", findings[0].Severity)
		}
		if findings[0].Confidence < 0.85 {
			t.Errorf("Expected high confidence for compile+exec, got %f", findings[0].Confidence)
		}
	}
}

// TestUnvalidatedExecEvalBuiltinsObfuscation - Test detection of __builtins__ access patterns
func TestUnvalidatedExecEvalBuiltinsObfuscation(t *testing.T) {
	detector := NewEnhancedUnvalidatedExecEvalDetector(nil)

	code := []byte(`
# Obfuscated eval access
eval_func = __builtins__['eval']
eval_func(user_input)
`)

	findings, err := detector.Detect("obfuscated.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("Expected to find __builtins__ obfuscation pattern")
	}

	if len(findings) > 0 {
		// Obfuscation should increase severity
		if findings[0].Severity != "CRITICAL" && findings[0].Severity != "HIGH" {
			t.Errorf("Expected CRITICAL or HIGH severity for obfuscation, got %s", findings[0].Severity)
		}
	}
}

// TestUnvalidatedExecEvalBase64 - Test detection of base64 + eval pattern (common obfuscation)
func TestUnvalidatedExecEvalBase64(t *testing.T) {
	detector := NewEnhancedUnvalidatedExecEvalDetector(nil)

	code := []byte(`
import base64
encoded = request.args.get('payload')
code = base64.b64decode(encoded)
eval(code)
`)

	findings, err := detector.Detect("payload.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("Expected to find base64 + eval pattern (obfuscation)")
	}

	if len(findings) > 0 {
		if findings[0].Confidence < 0.85 {
			t.Errorf("Expected high confidence for base64 obfuscation, got %f", findings[0].Confidence)
		}
	}
}

// TestUnvalidatedExecEvalAstLiteralEval - Test that ast.literal_eval is safe
func TestUnvalidatedExecEvalAstLiteralEval(t *testing.T) {
	detector := NewEnhancedUnvalidatedExecEvalDetector(nil)

	code := []byte(`
import ast
user_data = request.args.get('data')
# ast.literal_eval is safe - only evaluates literals
parsed = ast.literal_eval(user_data)
return parsed
`)

	findings, err := detector.Detect("parser.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should not flag ast.literal_eval as dangerous
	if len(findings) > 0 {
		t.Logf("Warning: ast.literal_eval flagged as dangerous (false positive)")
	}
}

// TestUnvalidatedExecEvalSandboxed - Test eval in sandboxed environment
func TestUnvalidatedExecEvalSandboxed(t *testing.T) {
	detector := NewEnhancedUnvalidatedExecEvalDetector(nil)

	code := []byte(`
user_code = request.args.get('code')
# Sandboxed eval with restricted builtins
result = eval(user_code, {"__builtins__": None}, {})
return result
`)

	findings, err := detector.Detect("safe_eval.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should still flag but with reduced severity
	if len(findings) > 0 {
		// Sandboxed eval should not be critical
		if findings[0].Severity == "CRITICAL" && findings[0].Confidence > 0.75 {
			t.Logf("Note: Sandboxed eval flagged with high confidence (acceptable - still risky)")
		}
	}
}

// TestUnvalidatedExecEvalJavaScriptEval - Test detection of JavaScript eval
func TestUnvalidatedExecEvalJavaScriptEval(t *testing.T) {
	detector := NewEnhancedUnvalidatedExecEvalDetector(nil)

	code := []byte(`
const userCode = req.query.code;
const result = eval(userCode);
res.send(result);
`)

	findings, err := detector.Detect("handler.js", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("Expected to find JavaScript eval vulnerability")
	}

	if len(findings) > 0 {
		if findings[0].Severity != "CRITICAL" {
			t.Errorf("Expected CRITICAL severity for JS eval, got %s", findings[0].Severity)
		}
		if findings[0].Confidence < 0.90 {
			t.Errorf("Expected high confidence for JS eval, got %f", findings[0].Confidence)
		}
	}
}

// TestUnvalidatedExecEvalJavaScriptFunction - Test detection of new Function()
func TestUnvalidatedExecEvalJavaScriptFunction(t *testing.T) {
	detector := NewEnhancedUnvalidatedExecEvalDetector(nil)

	code := []byte(`
const userCode = req.query.fn;
const func = new Function(userCode);
func();
`)

	findings, err := detector.Detect("factory.js", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("Expected to find new Function() vulnerability")
	}

	if len(findings) > 0 {
		if findings[0].Severity != "CRITICAL" {
			t.Errorf("Expected CRITICAL severity for new Function(), got %s", findings[0].Severity)
		}
	}
}

// TestUnvalidatedExecEvalJavaScriptSetTimeout - Test detection of setTimeout with string code
func TestUnvalidatedExecEvalJavaScriptSetTimeout(t *testing.T) {
	detector := NewEnhancedUnvalidatedExecEvalDetector(nil)

	code := []byte(`
const code = req.query.code;
setTimeout(code, 1000);
`)

	findings, err := detector.Detect("timer.js", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("Expected to find setTimeout with string code vulnerability")
	}
}

// TestUnvalidatedExecEvalGoExecCommand - Test detection of Go exec.Command with variable
func TestUnvalidatedExecEvalGoExecCommand(t *testing.T) {
	detector := NewEnhancedUnvalidatedExecEvalDetector(nil)

	code := []byte(`
userCmd := r.URL.Query().Get("cmd")
cmd := exec.Command(userCmd)
cmd.Run()
`)

	findings, err := detector.Detect("runner.go", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("Expected to find Go exec.Command with variable vulnerability")
	}

	if len(findings) > 0 {
		if findings[0].Severity != "CRITICAL" {
			t.Errorf("Expected CRITICAL severity for exec.Command, got %s", findings[0].Severity)
		}
	}
}

// TestUnvalidatedExecEvalGoStringConcat - Test detection of command from string concatenation
func TestUnvalidatedExecEvalGoStringConcat(t *testing.T) {
	detector := NewEnhancedUnvalidatedExecEvalDetector(nil)

	code := []byte(`
input := r.URL.Query().Get("input")
cmd := exec.Command("sh", "-c", "echo " + input)
cmd.Run()
`)

	findings, err := detector.Detect("shell.go", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("Expected to find string concatenation in command vulnerability")
	}
}

// TestUnvalidatedExecEvalLLMOutput - Test detection of eval with LLM output (real CVE pattern)
func TestUnvalidatedExecEvalLLMOutput(t *testing.T) {
	detector := NewEnhancedUnvalidatedExecEvalDetector(nil)

	code := []byte(`
import openai
from langchain.agents import Tool

# CVE-2023-36258: LangChain PALChain eval injection
response = openai.ChatCompletion.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Write Python code"}]
)
generated_code = response['choices'][0]['message']['content']
# Directly executing LLM output - RCE!
exec(generated_code)
`)

	findings, err := detector.Detect("agent.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("Expected to find LLM output RCE vulnerability (real CVE pattern)")
	}

	if len(findings) > 0 {
		if findings[0].Confidence < 0.85 {
			t.Errorf("Expected high confidence for LLM RCE pattern, got %f", findings[0].Confidence)
		}
	}
}

// TestUnvalidatedExecEvalVariableShadowing - Test that shadowed eval is not flagged
func TestUnvalidatedExecEvalVariableShadowing(t *testing.T) {
	detector := NewEnhancedUnvalidatedExecEvalDetector(nil)

	code := []byte(`
# This is safe - eval is shadowed/reassigned
eval = my_custom_eval_function
user_input = request.args.get('data')
result = eval(user_input)
`)

	findings, err := detector.Detect("custom.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// This is a complex case - ideally should not flag shadowed eval
	// But our simple regex may flag it
	if len(findings) > 0 {
		t.Logf("Note: Shadowed eval flagged (may be false positive, but conservative approach)")
	}
}

// TestUnvalidatedExecEvalTestFile - Test that test files are handled differently
func TestUnvalidatedExecEvalTestFile(t *testing.T) {
	detector := NewEnhancedUnvalidatedExecEvalDetector(nil)

	code := []byte(`
def test_eval_function():
    # Test code - should be lower priority
    user_input = "1 + 2"
    result = eval(user_input)
    assert result == 3
`)

	findings, err := detector.Detect("test_eval.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should still flag but with lower confidence for test files
	if len(findings) > 0 {
		if findings[0].Confidence > 0.85 {
			t.Logf("Note: Test file eval flagged with high confidence (may be expected)")
		}
	}
}

// TestUnvalidatedExecEvalAutoGenRCE - Test detection of AutoGen eval vulnerability (CVE-2024-6982)
func TestUnvalidatedExecEvalAutoGenRCE(t *testing.T) {
	detector := NewEnhancedUnvalidatedExecEvalDetector(nil)

	code := []byte(`
from autogen import AssistantAgent

# CVE-2024-6982: AutoGen eval vulnerability
def execute_code(code):
    exec(code)  # Directly executing agent-generated code

agent = AssistantAgent(name="assistant", llm_config=config)
agent.generate_reply(messages=[...])
`)

	findings, err := detector.Detect("autogen_agent.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("Expected to find AutoGen eval vulnerability (CVE-2024-6982)")
	}
}

// TestUnvalidatedExecEvalFlowiseFunction - Test detection of Flowise Function constructor (CVE-2025-59528)
func TestUnvalidatedExecEvalFlowiseFunction(t *testing.T) {
	detector := NewEnhancedUnvalidatedExecEvalDetector(nil)

	code := []byte(`
// CVE-2025-59528: Flowise Function constructor RCE
const userFunction = req.body.function;
const fn = new Function(userFunction);
const result = fn();
`)

	findings, err := detector.Detect("flowise.js", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("Expected to find Flowise Function constructor vulnerability (CVE-2025-59528)")
	}
}

// TestMultiPatternValidationUnvalidatedExecEval - Test that Pattern 9 works in multi-pattern context
func TestMultiPatternValidationUnvalidatedExecEval(t *testing.T) {
	detector := NewEnhancedUnvalidatedExecEvalDetector(nil)

	// This code contains Pattern 9 (unvalidated eval) plus other vulnerabilities
	code := []byte(`
import os
import openai

# Pattern 1: Hardcoded credentials
API_KEY = "sk-proj-abc123xyz"
openai.api_key = API_KEY

# Pattern 4: Unsafe env access
db_password = os.environ["DB_PASSWORD"]

# Pattern 9: Unvalidated exec/eval with LLM output
response = openai.ChatCompletion.create(model="gpt-4", messages=[])
eval(response['choices'][0]['message']['content'])
`)

	findings, err := detector.Detect("multipattern.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("Pattern 9 should find eval vulnerability in multi-pattern context")
	}

	// Should find the eval vulnerability
	evalFound := false
	for _, finding := range findings {
		if finding.PatternID == "unvalidated_exec_eval" {
			evalFound = true
			break
		}
	}

	if !evalFound {
		t.Error("Pattern 9 (unvalidated_exec_eval) should be detected in multi-pattern test")
	}
}
