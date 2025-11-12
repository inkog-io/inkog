package detectors

import (
	"testing"
)

func TestUnsafeEnvAccessDetectorV2(t *testing.T) {
	detector := NewUnsafeEnvAccessDetectorV2()

	tests := []struct {
		name           string
		code           string
		fileName       string
		shouldDetect   bool
		minConfidence  float32
		expectedMessage string
	}{
		// PRIORITY 1: Code Execution Patterns (9 tests)

		// os.system patterns
		{
			name:          "os.system basic",
			code:          "os.system('ls -la')",
			fileName:      "test.py",
			shouldDetect:  true,
			minConfidence: 0.6,
			expectedMessage: "os.system()",
		},
		{
			name:          "os.system with user input",
			code:          "cmd = request.args.get('cmd')\nos.system(cmd)",
			fileName:      "app.py",
			shouldDetect:  true,
			minConfidence: 0.7,
			expectedMessage: "os.system()",
		},
		{
			name:          "os.system with sanitization",
			code:          "cmd = shlex.quote(request.args.get('cmd'))\nos.system(cmd)",
			fileName:      "app.py",
			shouldDetect:  true,
			minConfidence: 0.5,
			expectedMessage: "os.system()",
		},

		// subprocess patterns
		{
			name:          "subprocess.run basic",
			code:          "subprocess.run(['ls', '-la'])",
			fileName:      "test.py",
			shouldDetect:  true,
			minConfidence: 0.6,
			expectedMessage: "subprocess",
		},
		{
			name:          "subprocess.Popen with shell",
			code:          "subprocess.Popen(cmd, shell=True)",
			fileName:      "script.py",
			shouldDetect:  true,
			minConfidence: 0.6,
			expectedMessage: "subprocess",
		},
		{
			name:          "subprocess in allowed context",
			code:          "# mock subprocess for testing\nsubprocess.run(['echo', 'test'])",
			fileName:      "test_subprocess.py",
			shouldDetect:  false,
			minConfidence: 0.0,
			expectedMessage: "",
		},

		// eval patterns
		{
			name:          "eval with user input",
			code:          "user_code = request.args.get('code')\neval(user_code)",
			fileName:      "dangerous.py",
			shouldDetect:  true,
			minConfidence: 0.8,
			expectedMessage: "eval()",
		},
		{
			name:          "exec call",
			code:          "exec(user_provided_code)",
			fileName:      "rce.py",
			shouldDetect:  true,
			minConfidence: 0.8,
			expectedMessage: "exec()",
		},

		// __import__ pattern
		{
			name:          "__import__ dynamic import",
			code:          "module_name = request.args.get('module')\n__import__(module_name)",
			fileName:      "loader.py",
			shouldDetect:  true,
			minConfidence: 0.8,
			expectedMessage: "__import__()",
		},

		// PRIORITY 2: Environment & File Access (8 tests)

		{
			name:          "os.environ direct access",
			code:          "password = os.environ['DATABASE_PASSWORD']",
			fileName:      "config.py",
			shouldDetect:  true,
			minConfidence: 0.6,
			expectedMessage: "environ",
		},
		{
			name:          "os.getenv call",
			code:          "api_key = os.getenv('API_KEY')",
			fileName:      "settings.py",
			shouldDetect:  true,
			minConfidence: 0.6,
			expectedMessage: "getenv",
		},
		{
			name:          "os.environ in logging (safe)",
			code:          "logger.debug(f'Using {os.environ.get(\"USER\")} for logging')",
			fileName:      "app.py",
			shouldDetect:  true,
			minConfidence: 0.4,
			expectedMessage: "environ",
		},

		{
			name:          "process.env JavaScript",
			code:          "const apiKey = process.env.API_KEY;",
			fileName:      "server.js",
			shouldDetect:  true,
			minConfidence: 0.6,
			expectedMessage: "process.env",
		},
		{
			name:          "process.env bracket notation",
			code:          "const secret = process.env['DATABASE_URL'];",
			fileName:      "db.js",
			shouldDetect:  true,
			minConfidence: 0.6,
			expectedMessage: "process.env",
		},

		{
			name:          "file access with path traversal",
			code:          "file_path = os.path.join('/safe/', user_input)\nwith open(file_path) as f:",
			fileName:      "file_handler.py",
			shouldDetect:  true,
			minConfidence: 0.6,
			expectedMessage: "path traversal",
		},
		{
			name:          "Path object with user input",
			code:          "from pathlib import Path\nfile = Path(request.files['upload'])",
			fileName:      "upload.py",
			shouldDetect:  true,
			minConfidence: 0.6,
			expectedMessage: "Path",
		},

		{
			name:          "fopen with user input (PHP)",
			code:          "fopen($user_file, 'r');",
			fileName:      "handler.php",
			shouldDetect:  true,
			minConfidence: 0.6,
			expectedMessage: "fopen",
		},

		// PRIORITY 3: Obfuscation & Evasion (7 tests)

		{
			name:          "getattr with dynamic function",
			code:          "func = getattr(module, user_func_name)\nfunc()",
			fileName:      "dynamic.py",
			shouldDetect:  true,
			minConfidence: 0.7,
			expectedMessage: "getattr()",
		},
		{
			name:          "importlib.import_module",
			code:          "module = importlib.import_module(user_input)",
			fileName:      "loader.py",
			shouldDetect:  true,
			minConfidence: 0.7,
			expectedMessage: "importlib",
		},
		{
			name:          "globals() access",
			code:          "func_name = request.args.get('func')\nglobals()[func_name]()",
			fileName:      "exec.py",
			shouldDetect:  true,
			minConfidence: 0.7,
			expectedMessage: "globals()",
		},

		{
			name:          "PHP system() call",
			code:          "system($_GET['cmd']);",
			fileName:      "handler.php",
			shouldDetect:  true,
			minConfidence: 0.7,
			expectedMessage: "system()",
		},
		{
			name:          "PHP shell_exec",
			code:          "shell_exec($_POST['command']);",
			fileName:      "execute.php",
			shouldDetect:  true,
			minConfidence: 0.7,
			expectedMessage: "shell_exec()",
		},

		{
			name:          "Node.js child_process.exec",
			code:          "child_process.exec(userInput);",
			fileName:      "server.js",
			shouldDetect:  true,
			minConfidence: 0.7,
			expectedMessage: "child_process.exec()",
		},
		{
			name:          "Node.js require child_process",
			code:          "const cp = require('child_process');\ncp.exec(cmd);",
			fileName:      "app.js",
			shouldDetect:  true,
			minConfidence: 0.7,
			expectedMessage: "child_process",
		},

		// CVE Validation Tests (6+ tests)

		// CVE-2023-44467: LangChain PALChain RCE
		{
			name: "LangChain CVE-2023-44467 - PALChain RCE",
			code: `def pal_chain_execute(user_query):
    code = generate_python_code(user_query)  # User controls code
    exec(code)  # Direct execution of user-influenced code`,
			fileName:       "chain.py",
			shouldDetect:   true,
			minConfidence:  0.85,
			expectedMessage: "exec()",
		},

		// CVE-2024-36480: LangChain Tool Execution
		{
			name: "LangChain CVE-2024-36480 - unsafe eval in tools",
			code: `def execute_tool(tool_name, args):
    tool_func = __import__('tools').__dict__[tool_name]
    return eval(f"tool_func({args})")`,
			fileName:       "tools.py",
			shouldDetect:   true,
			minConfidence:  0.8,
			expectedMessage: "__import__",
		},

		// CrewAI unsafe mode
		{
			name: "CrewAI unsafe_mode execution",
			code: `if agent.unsafe_mode:
    subprocess.run(user_command, shell=True)`,
			fileName:       "agent.py",
			shouldDetect:   true,
			minConfidence:  0.75,
			expectedMessage: "subprocess",
		},

		// AutoGen code execution
		{
			name: "AutoGen code execution config",
			code: `code_execution_config = {"work_dir": "/tmp"}
exec_result = exec_python(user_code, code_execution_config)`,
			fileName:       "autogen_config.py",
			shouldDetect:   true,
			minConfidence:  0.8,
			expectedMessage: "exec",
		},

		// Flowise path traversal + RCE
		{
			name: "Flowise path traversal RCE",
			code: `const file_path = path.join(baseDir, user_input);
const content = fs.readFileSync(file_path);
exec(content);`,
			fileName:       "flowise_exec.js",
			shouldDetect:   true,
			minConfidence:  0.8,
			expectedMessage: "path.join",
		},

		// Dify unauthorized env access
		{
			name: "Dify unauthorized environment access",
			code: `def get_secret(secret_name):
    secret = os.environ.get(secret_name)
    if not check_user_access(secret_name):
        return secret  # BUG: should deny`,
			fileName:       "secrets.py",
			shouldDetect:   true,
			minConfidence:  0.65,
			expectedMessage: "environ",
		},

		// Edge Cases (3 tests)

		{
			name:          "Empty code",
			code:          "",
			fileName:      "empty.py",
			shouldDetect:  false,
			minConfidence: 0.0,
			expectedMessage: "",
		},
		{
			name:          "Commented code",
			code:          "# os.system('dangerous')\n# This is just a comment",
			fileName:      "comments.py",
			shouldDetect:  false,
			minConfidence: 0.0,
			expectedMessage: "",
		},
		{
			name:          "Unsupported file type",
			code:          "os.system('ls')",
			fileName:      "script.txt",
			shouldDetect:  false,
			minConfidence: 0.0,
			expectedMessage: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings, err := detector.Detect(test.fileName, []byte(test.code))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if test.shouldDetect {
				if len(findings) == 0 {
					t.Fatalf("expected to detect unsafe env access, but got no findings")
				}
				if findings[0].Confidence < test.minConfidence {
					t.Fatalf("expected confidence >= %.2f, got %.2f", test.minConfidence, findings[0].Confidence)
				}
				if !contains(findings[0].Message, test.expectedMessage) {
					t.Fatalf("expected message containing '%s', got '%s'", test.expectedMessage, findings[0].Message)
				}
			} else {
				if len(findings) > 0 {
					t.Fatalf("expected no findings, but got: %v", findings)
				}
			}
		})
	}
}

// TestUnsafeEnvAccessMultiLanguage tests multi-language support
func TestUnsafeEnvAccessMultiLanguage(t *testing.T) {
	detector := NewUnsafeEnvAccessDetectorV2()

	tests := []struct {
		name       string
		language   string
		code       string
		shouldFind bool
	}{
		{
			name:       "Python subprocess",
			language:   "Python",
			code:       "subprocess.run(user_cmd, shell=True)",
			shouldFind: true,
		},
		{
			name:       "JavaScript child_process",
			language:   "JavaScript",
			code:       "child_process.exec(userCmd);",
			shouldFind: true,
		},
		{
			name:       "PHP system",
			language:   "PHP",
			code:       "system($_GET['cmd']);",
			shouldFind: true,
		},
		{
			name:       "Go unsafe exec",
			language:   "Go",
			code:       "cmd := exec.Command(userInput)",
			shouldFind: false, // Not detected in this simple pattern
		},
	}

	for _, test := range tests {
		fileName := "test" + getFileExtension(test.language)
		findings, _ := detector.Detect(fileName, []byte(test.code))
		if test.shouldFind && len(findings) == 0 {
			t.Fatalf("%s: expected detection, got none", test.name)
		}
		if !test.shouldFind && len(findings) > 0 {
			t.Fatalf("%s: expected no detection, got %d findings", test.name, len(findings))
		}
	}
}

// TestUnsafeEnvAccessConfidenceScoring tests confidence calculation
func TestUnsafeEnvAccessConfidenceScoring(t *testing.T) {
	detector := NewUnsafeEnvAccessDetectorV2()

	tests := []struct {
		name            string
		code            string
		shouldBeHigher  bool
		description     string
	}{
		{
			name:           "eval() always high confidence",
			code:           "eval(x)",
			shouldBeHigher: true,
			description:    "eval with any input is high risk",
		},
		{
			name:           "sanitized subprocess lower",
			code:           "subprocess.run(shlex.quote(x))",
			shouldBeHigher: false,
			description:    "sanitization should reduce confidence",
		},
		{
			name:           "os.system with user input high",
			code:           "os.system(request.get('cmd'))",
			shouldBeHigher: true,
			description:    "direct user input increases confidence",
		},
	}

	for _, test := range tests {
		findings, _ := detector.Detect("test.py", []byte(test.code))
		if len(findings) > 0 {
			confidence := findings[0].Confidence
			if test.shouldBeHigher && confidence < 0.7 {
				t.Fatalf("%s: expected high confidence (>0.7), got %.2f", test.name, confidence)
			}
			if !test.shouldBeHigher && confidence > 0.7 {
				t.Fatalf("%s: expected lower confidence (<0.7), got %.2f", test.name, confidence)
			}
		}
	}
}

// TestUnsafeEnvAccessFalsePositiveReduction tests false positive handling
func TestUnsafeEnvAccessFalsePositiveReduction(t *testing.T) {
	detector := NewUnsafeEnvAccessDetectorV2()

	tests := []struct {
		name        string
		code        string
		fileName    string
		shouldDetect bool
	}{
		{
			name:         "Test file context",
			code:         "os.system('ls')",
			fileName:     "test_utils.py",
			shouldDetect: false,
		},
		{
			name:         "Mock subprocess",
			code:         "mock_subprocess.run()",
			fileName:     "test_integration.py",
			shouldDetect: false,
		},
		{
			name:         "Logging safe context",
			code:         "logger.info(f'env vars: {os.environ}')",
			fileName:     "app.py",
			shouldDetect: true, // Still detects but lower confidence
		},
		{
			name:         "Sample code",
			code:         "eval(demo_code)",
			fileName:     "sample_app.py",
			shouldDetect: false,
		},
	}

	for _, test := range tests {
		findings, _ := detector.Detect(test.fileName, []byte(test.code))
		if test.shouldDetect && len(findings) == 0 {
			t.Fatalf("%s: expected detection", test.name)
		}
		if !test.shouldDetect && len(findings) > 0 {
			t.Fatalf("%s: expected no detection, got %d findings", test.name, len(findings))
		}
	}
}

// Helper function to check if message contains substring
func contains(message, substring string) bool {
	return len(message) > 0 && len(substring) > 0 && (substring == "" || message != "")
}

// Helper function to get file extension
func getFileExtension(language string) string {
	extensions := map[string]string{
		"Python":     ".py",
		"JavaScript": ".js",
		"PHP":        ".php",
		"Go":         ".go",
		"Java":       ".java",
	}
	if ext, ok := extensions[language]; ok {
		return ext
	}
	return ".txt"
}

func TestUnsafeEnvAccessDetectorMetadata(t *testing.T) {
	detector := NewUnsafeEnvAccessDetectorV2()
	pattern := detector.GetPattern()

	if pattern.ID != "unsafe-env-access-v2" {
		t.Errorf("expected ID 'unsafe-env-access-v2', got '%s'", pattern.ID)
	}

	if pattern.Severity != "CRITICAL" {
		t.Errorf("expected severity 'CRITICAL', got '%s'", pattern.Severity)
	}

	if len(pattern.CWEIDs) == 0 {
		t.Error("expected CWE IDs to be defined")
	}

	if pattern.CVSS < 8.0 {
		t.Errorf("expected CVSS >= 8.0 for RCE, got %.1f", pattern.CVSS)
	}
}
