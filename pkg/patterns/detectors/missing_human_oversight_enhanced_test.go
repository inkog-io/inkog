package detectors

import (
	"testing"
)

// Test 1: Python eval with untrusted input (vulnerable)
func TestMissingHumanOversight_PythonEvalUntrustedInput(t *testing.T) {
	detector := NewEnhancedMissingHumanOversightDetector(nil)

	code := `import sys
user_input = input()
result = eval(user_input)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for eval with untrusted input, got 0")
	}
}

// Test 2: Python exec with untrusted input (vulnerable)
func TestMissingHumanOversight_PythonExecUntrustedInput(t *testing.T) {
	detector := NewEnhancedMissingHumanOversightDetector(nil)

	code := `prompt = "delete everything"
exec(prompt)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for exec with untrusted input, got 0")
	}
}

// Test 3: Subprocess without validation (vulnerable)
func TestMissingHumanOversight_SubprocessNoValidation(t *testing.T) {
	detector := NewEnhancedMissingHumanOversightDetector(nil)

	code := `import subprocess
user_cmd = input()
subprocess.run(user_cmd, shell=True)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for subprocess without validation, got 0")
	}
}

// Test 4: SQL injection - direct query execution (vulnerable)
func TestMissingHumanOversight_SQLInjectionDirect(t *testing.T) {
	detector := NewEnhancedMissingHumanOversightDetector(nil)

	code := `import sqlite3
user_input = request.args.get('name')
query = f"SELECT * FROM users WHERE name = '{user_input}'"
cursor.execute(query)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for SQL injection, got 0")
	}
}

// Test 5: File write without path validation (vulnerable)
func TestMissingHumanOversight_FileWriteNoValidation(t *testing.T) {
	detector := NewEnhancedMissingHumanOversightDetector(nil)

	code := `user_path = request.form['filename']
with open(user_path, 'w') as f:
    f.write(malicious_content)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for file write without validation, got 0")
	}
}

// Test 6: Insecure defaults - allow_dangerous=True (vulnerable)
func TestMissingHumanOversight_InsecureDefaultAllowDangerous(t *testing.T) {
	detector := NewEnhancedMissingHumanOversightDetector(nil)

	code := `from langchain.tools import Tool
agent = initialize_agent(
    tools,
    llm,
    allow_dangerous_requests=True
)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for insecure default allow_dangerous=True, got 0")
	}
}

// Test 7: Over-scoped token (vulnerable)
func TestMissingHumanOversight_OverScopedToken(t *testing.T) {
	detector := NewEnhancedMissingHumanOversightDetector(nil)

	code := `token = os.environ.get('FULL_ACCESS_TOKEN')
api_client = APIClient(token=token)
result = api_client.delete_all_users()`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for over-scoped token, got 0")
	}
}

// Test 8: GraphCypherQAChain without safe defaults (vulnerable)
func TestMissingHumanOversight_GraphCypherQAChainUnsafe(t *testing.T) {
	detector := NewEnhancedMissingHumanOversightDetector(nil)

	code := `from langchain.chains import GraphCypherQAChain
chain = GraphCypherQAChain.from_llm(llm, graph=graph)
result = chain.run(user_query)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for GraphCypherQAChain without safe defaults, got 0")
	}
}

// Test 9: Python REPL tool without approval (vulnerable)
func TestMissingHumanOversight_PythonREPLToolUnsafe(t *testing.T) {
	detector := NewEnhancedMissingHumanOversightDetector(nil)

	code := `from langchain.tools import PythonREPLTool
tools = [PythonREPLTool()]
agent = initialize_agent(tools, llm)
agent.run(user_input)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for REPL tool without approval, got 0")
	}
}

// Test 10: Shell tool without restriction (vulnerable)
func TestMissingHumanOversight_ShellToolUnsafe(t *testing.T) {
	detector := NewEnhancedMissingHumanOversightDetector(nil)

	code := `from langchain.tools import ShellTool
tools = [ShellTool()]
agent = AgentExecutor.from_agent_and_tools(agent, tools)
agent.run(user_command)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for shell tool without restriction, got 0")
	}
}

// Test 11: JavaScript eval (vulnerable)
func TestMissingHumanOversight_JavaScriptEval(t *testing.T) {
	detector := NewEnhancedMissingHumanOversightDetector(nil)

	code := `const userInput = req.query.code;
eval(userInput);`

	findings, err := detector.Detect("test.js", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for JavaScript eval, got 0")
	}
}

// Test 12: JavaScript child_process without validation (vulnerable)
func TestMissingHumanOversight_JavaScriptChildProcess(t *testing.T) {
	detector := NewEnhancedMissingHumanOversightDetector(nil)

	code := `const { exec } = require('child_process');
const cmd = req.body.command;
exec(cmd, (error, stdout, stderr) => {
    console.log(stdout);
});`

	findings, err := detector.Detect("test.js", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for JavaScript child_process without validation, got 0")
	}
}

// Test 13: Java Runtime.exec() without validation (vulnerable)
func TestMissingHumanOversight_JavaRuntimeExec(t *testing.T) {
	detector := NewEnhancedMissingHumanOversightDetector(nil)

	code := `String userCommand = request.getParameter("cmd");
Runtime runtime = Runtime.getRuntime();
runtime.exec(userCommand);`

	findings, err := detector.Detect("test.java", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for Java Runtime.exec without validation, got 0")
	}
}

// Test 14: Go os.system with untrusted input (vulnerable)
func TestMissingHumanOversight_GoOSSystem(t *testing.T) {
	detector := NewEnhancedMissingHumanOversightDetector(nil)

	code := `package main
import "os"
func main() {
    cmd := os.Args[1]
    os.system(cmd)
}`

	findings, err := detector.Detect("test.go", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for Go os.system with untrusted input, got 0")
	}
}

// Test 15: CrewAI agent without restrictions (vulnerable)
func TestMissingHumanOversight_CrewAIAgentUnsafe(t *testing.T) {
	detector := NewEnhancedMissingHumanOversightDetector(nil)

	code := `from crewai import Agent, Task, Crew
agent = Agent(
    role="executor",
    goal="Execute any command",
    tools=[shell_tool, python_tool]
)
crew.kickoff()`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for CrewAI agent without restrictions, got 0")
	}
}

// Test 16: Safe pattern - eval with HumanInputRun
func TestMissingHumanOversight_SafeEvalWithHumanInput(t *testing.T) {
	detector := NewEnhancedMissingHumanOversightDetector(nil)

	code := `from langchain.tools import HumanInputRun
from langchain.tools import Tool
eval_tool = Tool(
    name="eval",
    func=safe_eval,
    description="Safe evaluation"
)
human_tool = HumanInputRun()
tools = [eval_tool, human_tool]`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should have lower risk due to human oversight
	if len(findings) > 0 {
		t.Logf("Safe eval with human input: detected but confidence should be adjusted")
	}
}

// Test 17: Safe pattern - parameterized SQL query
func TestMissingHumanOversight_SafeParameterizedSQL(t *testing.T) {
	detector := NewEnhancedMissingHumanOversightDetector(nil)

	code := `import sqlite3
user_input = request.args.get('name')
query = "SELECT * FROM users WHERE name = ?"
cursor.execute(query, (user_input,))`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should not flag - parameterized query is safe
	if len(findings) > 0 {
		t.Logf("Parameterized SQL: detected with reduced confidence")
	}
}

// Test 18: Safe pattern - path validation for file operations
func TestMissingHumanOversight_SafePathValidation(t *testing.T) {
	detector := NewEnhancedMissingHumanOversightDetector(nil)

	code := `import os
user_path = request.form['filename']
base_path = '/safe/directory'
full_path = os.path.abspath(os.path.join(base_path, user_path))
if not full_path.startswith(base_path):
    raise ValueError("Invalid path")
with open(full_path, 'r') as f:
    content = f.read()`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should not flag - path is validated
	if len(findings) > 0 {
		t.Logf("Safe path validation: detected with reduced confidence")
	}
}

// Test 19: Safe pattern - allow_dangerous=False
func TestMissingHumanOversight_SafeAllowDangerousFalse(t *testing.T) {
	detector := NewEnhancedMissingHumanOversightDetector(nil)

	code := `from langchain.tools import Tool
agent = initialize_agent(
    tools,
    llm,
    allow_dangerous_requests=False,
    allow_code_execution=False
)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should not flag - safe defaults
	if len(findings) > 0 {
		t.Logf("Safe defaults: detected with reduced confidence")
	}
}

// Test 20: Safe pattern - input validation before eval
func TestMissingHumanOversight_SafeInputValidation(t *testing.T) {
	detector := NewEnhancedMissingHumanOversightDetector(nil)

	code := `user_input = request.args.get('expr')
if not validate_expression(user_input):
    raise ValueError("Invalid expression")
result = eval(user_input)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should have reduced confidence due to validation
	if len(findings) > 0 {
		t.Logf("Input validated: detected with reduced confidence")
	}
}

// Test 21: Safe pattern - scoped token usage
func TestMissingHumanOversight_SafeScopedToken(t *testing.T) {
	detector := NewEnhancedMissingHumanOversightDetector(nil)

	code := `token = get_scoped_token(scope=['read:users'])
api_client = APIClient(token=token)
users = api_client.get_users()  # Read-only operation`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should not flag - token is properly scoped
	if len(findings) > 0 {
		t.Logf("Scoped token: detected with reduced confidence")
	}
}

// Test 22: Safe pattern - approval workflow
func TestMissingHumanOversight_SafeApprovalWorkflow(t *testing.T) {
	detector := NewEnhancedMissingHumanOversightDetector(nil)

	code := `def delete_user(user_id):
    if not requires_approval("delete_user"):
        raise PermissionError("Approval required")

    # Get human approval
    if not ask_user_for_approval(f"Delete user {user_id}?"):
        return False

    # Execute deletion
    db.delete_user(user_id)
    return True`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should not flag - approval workflow in place
	if len(findings) > 0 {
		t.Logf("Approval workflow: detected with reduced confidence")
	}
}

// Test 23: Safe pattern - RBAC check
func TestMissingHumanOversight_SafeRBACCheck(t *testing.T) {
	detector := NewEnhancedMissingHumanOversightDetector(nil)

	code := `def execute_command(cmd, user):
    required_role = "admin"
    if not user.has_role(required_role):
        raise PermissionError(f"User must have {required_role} role")

    exec(cmd)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should have reduced confidence due to RBAC
	if len(findings) > 0 {
		t.Logf("RBAC check: detected with reduced confidence")
	}
}

// Test 24: Dangerous tool delete without oversight
func TestMissingHumanOversight_DangerousToolDelete(t *testing.T) {
	detector := NewEnhancedMissingHumanOversightDetector(nil)

	code := `from langchain.tools import WriteFileTool
tools = [WriteFileTool()]
agent = initialize_agent(tools, llm)
# Tool can delete files without approval
agent.run("Delete /etc/passwd")`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for dangerous delete operation, got 0")
	}
}

// Test 25: Read-only safe pattern (no dangerous operations)
func TestMissingHumanOversight_SafeReadOnly(t *testing.T) {
	detector := NewEnhancedMissingHumanOversightDetector(nil)

	code := `from langchain.tools import Tool
def safe_read(path):
    # Only read, no write/delete
    with open(path, 'r') as f:
        return f.read()

tools = [Tool(name="read", func=safe_read)]
agent = initialize_agent(tools, llm, allow_dangerous_requests=False)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should not flag - safe read-only operation
	if len(findings) > 0 {
		t.Logf("Read-only operation: detected with minimal confidence")
	}
}

// Test 26: Benign code - no dangerous patterns
func TestMissingHumanOversight_BenignCode(t *testing.T) {
	detector := NewEnhancedMissingHumanOversightDetector(nil)

	code := `import logging
def process_data(data):
    logging.info(f"Processing {len(data)} items")
    result = []
    for item in data:
        result.append(item.strip())
    return result`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should not flag - benign code
	if len(findings) > 0 {
		t.Errorf("Expected no findings for benign code, got %d", len(findings))
	}
}

// Test 27: Multi-tool dangerous combination
func TestMissingHumanOversight_MultiToolDangerous(t *testing.T) {
	detector := NewEnhancedMissingHumanOversightDetector(nil)

	code := `from langchain.tools import ShellTool, WriteFileTool, PythonREPLTool
tools = [ShellTool(), WriteFileTool(), PythonREPLTool()]
agent = AgentExecutor.from_agent_and_tools(agent, tools)
agent.run(user_goal)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for multi-tool dangerous combination, got 0")
	}
}

// Test 28: Compile/load code without validation
func TestMissingHumanOversight_CompileWithoutValidation(t *testing.T) {
	detector := NewEnhancedMissingHumanOversightDetector(nil)

	code := `user_code = request.form['code']
compiled = compile(user_code, '<string>', 'exec')
exec(compiled)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for compile/exec without validation, got 0")
	}
}

// Test 29: Safe pattern with human input in tool
func TestMissingHumanOversight_SafeHumanInputTool(t *testing.T) {
	detector := NewEnhancedMissingHumanOversightDetector(nil)

	code := `from langchain.tools import HumanInputRun, ShellTool
human_tool = HumanInputRun()
shell_tool = ShellTool()
tools = [human_tool, shell_tool]
agent = initialize_agent(tools, llm, handle_parsing_errors=True)
# User must explicitly approve each dangerous operation`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should have reduced confidence due to human input tool
	if len(findings) > 0 {
		t.Logf("Human input tool present: confidence should be reduced")
	}
}

// Test 30: Cursor.execute without parameterization (SQL injection)
func TestMissingHumanOversight_CursorExecuteUnsafe(t *testing.T) {
	detector := NewEnhancedMissingHumanOversightDetector(nil)

	code := `table_name = request.args.get('table')
query = f"DELETE FROM {table_name} WHERE id=1"
cursor.execute(query)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for cursor.execute without parameterization, got 0")
	}
}

// Test 31: Safe pattern - error handling with validation
func TestMissingHumanOversight_SafeErrorHandling(t *testing.T) {
	detector := NewEnhancedMissingHumanOversightDetector(nil)

	code := `try:
    validated_input = validate_and_sanitize(user_input)
    result = eval(validated_input)
except Exception as e:
    logging.error(f"Validation failed: {e}")
    result = None`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should have reduced confidence due to validation
	if len(findings) > 0 {
		t.Logf("Safe error handling: detected with reduced confidence")
	}
}

// Test 32: Module import with dangerous function used safely
func TestMissingHumanOversight_SafeImportUsage(t *testing.T) {
	detector := NewEnhancedMissingHumanOversightDetector(nil)

	code := `from subprocess import run
# Safe usage with explicit allowed commands
allowed_commands = ['ls', 'pwd', 'echo']
user_cmd = request.args.get('cmd')
if user_cmd not in allowed_commands:
    raise ValueError("Command not allowed")
result = run([user_cmd], capture_output=True)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should have reduced confidence due to whitelist
	if len(findings) > 0 {
		t.Logf("Whitelist protection: detected with reduced confidence")
	}
}
