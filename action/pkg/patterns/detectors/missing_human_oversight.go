package detectors

import (
	"regexp"
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// MissingHumanOversightDetector detects AI agents or automation taking high-impact actions without human oversight
// This pattern identifies: direct LLM output execution, dangerous tools without HITL, insecure defaults, over-scoped permissions
// CWE-94 (Code Injection), CWE-284/862 (Access Control), CWE-863 (Privilege Escalation), CWE-1188 (Insecure Default)
//
// Examples:
// - eval(llm_output) or exec(ai_generated_code) without checks
// - PythonREPLTool in agent without HumanInputRun
// - GraphCypherQAChain with allow_dangerous_requests=True
// - AutoGen with code_execution_config enabled by default
// - Agent with DELETE database access and no approval workflow
// - Flowise WriteFileTool with unrestricted paths
// - Over-scoped API tokens given to agents
type MissingHumanOversightDetector struct {
	// Direct execution patterns
	pythonEvalPattern                *regexp.Regexp // eval(...) in Python
	pythonExecPattern                *regexp.Regexp // exec(...) in Python
	pythonCompilePattern             *regexp.Regexp // compile() with user input
	subprocessRunPattern             *regexp.Regexp // subprocess.run, .Popen, .call
	osSystemPattern                  *regexp.Regexp // os.system, os.popen
	jsEvalPattern                    *regexp.Regexp // JavaScript eval()
	jsFunctionPattern                *regexp.Regexp // JavaScript Function() constructor
	jsExecPattern                    *regexp.Regexp // JavaScript exec()
	jsChildProcessPattern            *regexp.Regexp // child_process in Node.js
	javaRuntimeExecPattern           *regexp.Regexp // Java Runtime.exec()
	javaProcessBuilderPattern        *regexp.Regexp // Java ProcessBuilder

	// Dangerous tool patterns (frameworks)
	pythonREPLToolPattern            *regexp.Regexp // PythonREPLTool, PythonTool
	shellToolPattern                 *regexp.Regexp // ShellTool, BashTool
	writeFileToolPattern             *regexp.Regexp // WriteFileTool, FileTool with write
	readFileToolPattern              *regexp.Regexp // ReadFileTool (less dangerous but unrestricted)
	sqlToolPattern                   *regexp.Regexp // SQLDatabaseTool, QueryTool
	graphCypherQAChainPattern        *regexp.Regexp // GraphCypherQAChain
	customToolPattern                *regexp.Regexp // Tool(...) with potentially dangerous func

	// Human oversight safeguards (positive indicators)
	humanInputToolPattern            *regexp.Regexp // HumanInputRun, HumanInput, Confirm
	approvalWorkflowPattern          *regexp.Regexp // approval, confirm, review patterns
	allowDangerousFalsePattern       *regexp.Regexp // allow_dangerous_requests=False
	codeExecConfigFalsePattern       *regexp.Regexp // code_execution_config=False
	scopedTokenPattern               *regexp.Regexp // token_scope, scope=, limited permissions

	// Insecure defaults (negative indicators)
	allowDangerousTruePattern        *regexp.Regexp // allow_dangerous_requests=True
	codeExecConfigTruePattern        *regexp.Regexp // code_execution_config=None or True
	fulAccessTokenPattern            *regexp.Regexp // FULL_ACCESS, full_access in token names
	noAuthCheckPattern               *regexp.Regexp // Missing authentication/authorization checks

	// Variable naming that suggests untrusted input
	untrustedInputPattern            *regexp.Regexp // prompt, response, user_input, ai_output, llm_*, generated

	// Database/query patterns
	cursorExecutePattern             *regexp.Regexp // cursor.execute, db.execute, query()
	sqlConstructionPattern           *regexp.Regexp // String concatenation for SQL

	// File operation patterns (without restriction)
	openFilePattern                  *regexp.Regexp // open(..., 'w'), write_text
	deleteFilePattern                *regexp.Regexp // remove, unlink, delete

	// LLM chain/agent initialization without controls
	initializeAgentPattern           *regexp.Regexp // initialize_agent, create_agent
	agentExecutorPattern             *regexp.Regexp // AgentExecutor, Agent(...)

	// Over-privileged operation indicators
	deletePermissionPattern          *regexp.Regexp // DELETE privilege, drop, remove
	modifyPermissionPattern          *regexp.Regexp // ALTER, MODIFY, UPDATE privilege
}

// NewMissingHumanOversightDetector creates a new missing human oversight detector
func NewMissingHumanOversightDetector() *MissingHumanOversightDetector {
	return &MissingHumanOversightDetector{
		// Direct execution - Python
		pythonEvalPattern: regexp.MustCompile(
			`(?i)\beval\s*\(`,
		),
		pythonExecPattern: regexp.MustCompile(
			`(?i)\bexec\s*\(`,
		),
		pythonCompilePattern: regexp.MustCompile(
			`(?i)\bcompile\s*\(`,
		),

		// Subprocess/OS execution
		subprocessRunPattern: regexp.MustCompile(
			`(?i)\b(subprocess|sp)\.(run|Popen|popen|call|Call|spawn)\s*\(`,
		),
		osSystemPattern: regexp.MustCompile(
			`(?i)\b(os|system)\.(system|popen|Popen|startProcess|StartProcess)\s*\(`,
		),

		// JavaScript execution
		jsEvalPattern: regexp.MustCompile(
			`(?i)\beval\s*\(`,
		),
		jsFunctionPattern: regexp.MustCompile(
			`(?i)\bFunction\s*\(|new\s+Function\s*\(`,
		),
		jsExecPattern: regexp.MustCompile(
			`(?i)\bexec\s*\(`,
		),
		jsChildProcessPattern: regexp.MustCompile(
			`(?i)require\s*\(\s*['"](child_process|cp)['"]\s*\)|import\s+.*child_process`,
		),

		// Java execution
		javaRuntimeExecPattern: regexp.MustCompile(
			`(?i)Runtime\.getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(`,
		),
		javaProcessBuilderPattern: regexp.MustCompile(
			`(?i)new\s+ProcessBuilder\s*\(`,
		),

		// Dangerous tools (LangChain, Flowise, etc.)
		pythonREPLToolPattern: regexp.MustCompile(
			`(?i)(PythonREPLTool|PythonTool|python_repl|PythonInterpreter)\s*\(`,
		),
		shellToolPattern: regexp.MustCompile(
			`(?i)(ShellTool|BashTool|shell_tool|bash_tool|Terminal|terminal_tool)\s*\(`,
		),
		writeFileToolPattern: regexp.MustCompile(
			`(?i)(WriteFileTool|write_file|FileTool|file_tool).*\(`,
		),
		readFileToolPattern: regexp.MustCompile(
			`(?i)(ReadFileTool|read_file|FileReadTool).*\(`,
		),
		sqlToolPattern: regexp.MustCompile(
			`(?i)(SQLDatabaseTool|sql_tool|QueryTool|database_tool).*\(`,
		),
		graphCypherQAChainPattern: regexp.MustCompile(
			`(?i)GraphCypherQAChain\s*\(`,
		),
		customToolPattern: regexp.MustCompile(
			`(?i)Tool\s*\(\s*name\s*=\s*['"](execute|run|delete|remove|kill|shutdown|destroy)['"]\s*,`,
		),

		// Human oversight safeguards
		humanInputToolPattern: regexp.MustCompile(
			`(?i)(HumanInputRun|HumanInput|human_input|HumanApproval|ConfirmTool|approval|confirm)`,
		),
		approvalWorkflowPattern: regexp.MustCompile(
			`(?i)(approve|review|confirm|validate|authorize|permission|consent)`,
		),
		allowDangerousFalsePattern: regexp.MustCompile(
			`(?i)allow_dangerous_requests\s*=\s*(False|false|F)`,
		),
		codeExecConfigFalsePattern: regexp.MustCompile(
			`(?i)code_execution_config\s*=\s*(False|false|F|disable|disabled)`,
		),
		scopedTokenPattern: regexp.MustCompile(
			`(?i)(scope\s*=\s*"[^"]*|token.*scope|limited|read.only|read-only|minimal)`,
		),

		// Insecure defaults
		allowDangerousTruePattern: regexp.MustCompile(
			`(?i)allow_dangerous_requests\s*=\s*(True|true|T)`,
		),
		codeExecConfigTruePattern: regexp.MustCompile(
			`(?i)code_execution_config\s*=\s*(True|true|T|None|None|enable|enabled)`,
		),
		fulAccessTokenPattern: regexp.MustCompile(
			`(?i)(FULL_ACCESS|full_access|FULL_SCOPE|complete.*token|unrestricted.*token)`,
		),
		noAuthCheckPattern: regexp.MustCompile(
			`(?i)(no.*auth|skip.*auth|bypass.*auth|without.*permission|no.*permission|unauth)`,
		),

		// Untrusted input indicators
		untrustedInputPattern: regexp.MustCompile(
			`(?i)(prompt|response|user_input|ai_output|llm|generated|agent.*output|lm_response)`,
		),

		// Database patterns
		cursorExecutePattern: regexp.MustCompile(
			`(?i)(cursor|db|database|query)\.execute\s*\(|execute_query\s*\(`,
		),
		sqlConstructionPattern: regexp.MustCompile(
			`(?i)query\s*=\s*f?['"]+.*[%+].*['"]+.*(?:user_input|prompt|response|llm)`,
		),

		// File operations
		openFilePattern: regexp.MustCompile(
			`(?i)open\s*\(\s*[^,]+\s*,\s*['"](w|a|wb|ab)['"]\s*\)|\.write_text\s*\(|\.write\s*\(`,
		),
		deleteFilePattern: regexp.MustCompile(
			`(?i)(remove|unlink|delete|shutil\.rmtree|Path\.unlink|rm_f|os\.remove)\s*\(`,
		),

		// Agent initialization patterns
		initializeAgentPattern: regexp.MustCompile(
			`(?i)(initialize_agent|create_agent|AgentExecutor|Agent\s*\(|CrewAI|crew\s*=)`,
		),
		agentExecutorPattern: regexp.MustCompile(
			`(?i)AgentExecutor\s*\(|Agent\s*\(.*\)|agent\.run\s*\(`,
		),

		// Privileged operations
		deletePermissionPattern: regexp.MustCompile(
			`(?i)(DELETE|drop|truncate|destroy)\s+(from|table|database)|DELETE\s+\*`,
		),
		modifyPermissionPattern: regexp.MustCompile(
			`(?i)(ALTER|MODIFY|UPDATE|GRANT|chmod|chown)\s+(table|database|user|file|permission)`,
		),
	}
}

// Detect performs missing human oversight detection
func (d *MissingHumanOversightDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	sourceStr := string(src)
	lines := strings.Split(sourceStr, "\n")
	var findings []patterns.Finding

	for i, line := range lines {
		lineNum := i + 1
		trimmedLine := strings.TrimSpace(line)

		// Skip empty lines and comments
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "//") || strings.HasPrefix(trimmedLine, "#") {
			continue
		}

		// Check for nosec comment (developer acknowledged)
		if strings.Contains(line, "nosec") || strings.Contains(line, "# noqa") {
			continue
		}

		// Pattern 1: Direct execution of untrusted code
		if d.pythonEvalPattern.MatchString(line) || d.pythonExecPattern.MatchString(line) {
			hasUntrustedArg := d.looksLikeUntrustedInput(line)
			hasSafeguard := d.checkForSafeguards(sourceStr, i)

			if hasUntrustedArg && !hasSafeguard {
				finding := d.createFinding(
					filePath,
					lineNum,
					"Direct execution of potentially untrusted code",
					"eval() or exec() is used on data that appears to come from LLM/user input. This can lead to arbitrary code execution. Implement human approval, sandboxing, or use ast.literal_eval() for safe evaluation.",
					"CRITICAL",
					0.95,
				)
				findings = append(findings, finding)
			}
		}

		// Pattern 2: Subprocess/OS commands from untrusted input
		if d.subprocessRunPattern.MatchString(line) || d.osSystemPattern.MatchString(line) {
			if d.looksLikeUntrustedInput(line) {
				shellTrue := strings.Contains(line, "shell=True")
				hasSafeguard := d.checkForSafeguards(sourceStr, i)

				confidence := float32(0.85)
				if shellTrue {
					confidence = 0.95 // shell=True is extremely dangerous
				}

				if !hasSafeguard {
					finding := d.createFinding(
						filePath,
						lineNum,
						"Subprocess/system command with untrusted arguments",
						"Command is constructed from untrusted input (LLM/user). This can lead to command injection. Use static command lists, parameterized execution, or implement human approval.",
						"CRITICAL",
						confidence,
					)
					findings = append(findings, finding)
				}
			}
		}

		// Pattern 3: Dangerous tools without human oversight
		if d.pythonREPLToolPattern.MatchString(line) || d.shellToolPattern.MatchString(line) ||
			d.writeFileToolPattern.MatchString(line) {

			// Check if human oversight is present in agent setup
			if !d.hasHumanOversight(sourceStr) {
				toolName := "dangerous tool"
				if d.pythonREPLToolPattern.MatchString(line) {
					toolName = "PythonREPLTool"
				} else if d.shellToolPattern.MatchString(line) {
					toolName = "ShellTool"
				} else if d.writeFileToolPattern.MatchString(line) {
					toolName = "WriteFileTool"
				}

				finding := d.createFinding(
					filePath,
					lineNum,
					"Dangerous tool without human-in-the-loop oversight",
					toolName+" allows LLM to execute code or modify files. No HumanInputRun or approval mechanism detected. Add human approval step before dangerous operations.",
					"HIGH",
					0.80,
				)
				findings = append(findings, finding)
			}
		}

		// Pattern 4: GraphCypherQAChain without safe defaults
		if d.graphCypherQAChainPattern.MatchString(line) {
			if !d.allowDangerousFalsePattern.MatchString(sourceStr) {
				finding := d.createFinding(
					filePath,
					lineNum,
					"GraphCypherQAChain without explicit safety controls",
					"GraphCypherQAChain can execute arbitrary Cypher queries. Set allow_dangerous_requests=False or require human approval for query modification.",
					"HIGH",
					0.75,
				)
				findings = append(findings, finding)
			}
		}

		// Pattern 5: Insecure defaults
		if d.allowDangerousTruePattern.MatchString(line) {
			finding := d.createFinding(
				filePath,
				lineNum,
				"Dangerous options explicitly enabled",
				"allow_dangerous_requests=True enables potentially harmful actions. Ensure adequate oversight is in place (human approval, monitoring, sandboxing).",
				"MEDIUM",
				0.70,
			)
			findings = append(findings, finding)
		}

		if d.codeExecConfigTruePattern.MatchString(line) {
			finding := d.createFinding(
				filePath,
				lineNum,
				"Code execution enabled by default",
				"code_execution_config is enabled, allowing agents to run arbitrary code. Ensure this is intentional and properly controlled.",
				"MEDIUM",
				0.70,
			)
			findings = append(findings, finding)
		}

		// Pattern 6: Over-scoped tokens/permissions
		if d.fulAccessTokenPattern.MatchString(line) && !d.scopedTokenPattern.MatchString(line) {
			finding := d.createFinding(
				filePath,
				lineNum,
				"Agent given over-scoped permissions",
				"Token or permission appears to be unrestricted (full access detected). Scope permissions minimally (e.g., read-only if writes aren't needed).",
				"HIGH",
				0.80,
			)
			findings = append(findings, finding)
		}

		// Pattern 7: Direct database query execution from untrusted source
		if d.cursorExecutePattern.MatchString(line) {
			if d.looksLikeUntrustedInput(line) && !d.hasParameterizedQuery(line) {
				finding := d.createFinding(
					filePath,
					lineNum,
					"Direct database query execution with untrusted input",
					"Query appears to be constructed from user/LLM input without parameterization. Use parameterized queries or require human approval for schema-modifying operations.",
					"CRITICAL",
					0.90,
				)
				findings = append(findings, finding)
			}
		}

		// Pattern 8: File operations without path validation
		if d.openFilePattern.MatchString(line) && d.writeFileToolPattern.MatchString(sourceStr) {
			if d.looksLikeUntrustedInput(line) {
				finding := d.createFinding(
					filePath,
					lineNum,
					"File write with untrusted path",
					"File path comes from untrusted source (LLM/user). This can lead to path traversal and arbitrary file overwrite. Validate and restrict paths.",
					"HIGH",
					0.85,
				)
				findings = append(findings, finding)
			}
		}

		// Pattern 9: JavaScript/Node.js execution risks
		if (d.jsFunctionPattern.MatchString(line) || d.jsEvalPattern.MatchString(line)) &&
			d.looksLikeUntrustedInput(line) {
			finding := d.createFinding(
				filePath,
				lineNum,
				"JavaScript dynamic code execution on untrusted input",
				"Function() or eval() with untrusted input can lead to code execution (as seen in Flowise CVE-2025-59528). Use safer alternatives or sandboxing.",
				"CRITICAL",
				0.95,
			)
			findings = append(findings, finding)
		}

		// Pattern 10: Autonomous agent setup without restrictions
		if d.initializeAgentPattern.MatchString(line) {
			if !d.hasHumanOversight(sourceStr) && d.hasDestructiveTools(sourceStr) {
				finding := d.createFinding(
					filePath,
					lineNum,
					"Autonomous agent with destructive capabilities and no human oversight",
					"Agent is initialized with dangerous tools (delete, execute, modify) but no HumanInputRun or approval mechanism. Add oversight for high-impact actions.",
					"HIGH",
					0.85,
				)
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// Helper functions

func (d *MissingHumanOversightDetector) looksLikeUntrustedInput(line string) bool {
	return d.untrustedInputPattern.MatchString(line)
}

func (d *MissingHumanOversightDetector) checkForSafeguards(sourceStr string, lineIdx int) bool {
	// Check for validation, sanitization, or approval nearby
	safeguardPatterns := []string{
		"validate", "sanitize", "filter", "check", "if.*==.*:", "assert", "raise",
		"approved", "confirm", "allow_list", "whitelist", "restricted",
	}

	for _, pattern := range safeguardPatterns {
		if strings.Contains(sourceStr, pattern) {
			return true
		}
	}

	return false
}

func (d *MissingHumanOversightDetector) hasHumanOversight(sourceStr string) bool {
	// Check for human-in-the-loop mechanisms
	return d.humanInputToolPattern.MatchString(sourceStr) ||
		strings.Contains(sourceStr, "approve") ||
		strings.Contains(sourceStr, "confirm") ||
		strings.Contains(sourceStr, "review") ||
		d.allowDangerousFalsePattern.MatchString(sourceStr)
}

func (d *MissingHumanOversightDetector) hasDestructiveTools(sourceStr string) bool {
	// Check for tools that can cause harm
	destructive := []string{
		"delete", "remove", "drop", "truncate", "kill", "shutdown",
		"destroy", "format", "exec", "eval", "PythonREPL", "Shell",
	}

	for _, tool := range destructive {
		if strings.Contains(strings.ToLower(sourceStr), strings.ToLower(tool)) {
			return true
		}
	}

	return false
}

func (d *MissingHumanOversightDetector) hasParameterizedQuery(line string) bool {
	// Check for parameterized query indicators
	paramPatterns := []string{
		"%s", "%d", "?", "$1", ":param", "%(", "@", "::",
	}

	for _, pattern := range paramPatterns {
		if strings.Contains(line, pattern) {
			return true
		}
	}

	return false
}

func (d *MissingHumanOversightDetector) detectLanguage(filePath string, sourceStr string) string {
	if strings.HasSuffix(filePath, ".py") {
		return "python"
	}
	if strings.HasSuffix(filePath, ".js") || strings.HasSuffix(filePath, ".ts") {
		return "javascript"
	}
	if strings.HasSuffix(filePath, ".go") {
		return "go"
	}
	if strings.HasSuffix(filePath, ".java") {
		return "java"
	}

	// Content-based detection
	if strings.Contains(sourceStr, "def ") && strings.Contains(sourceStr, "import ") {
		return "python"
	}
	if strings.Contains(sourceStr, "function ") || strings.Contains(sourceStr, "const ") {
		return "javascript"
	}

	return "unknown"
}

func (d *MissingHumanOversightDetector) createFinding(
	filePath string,
	lineNum int,
	title string,
	message string,
	severity string,
	confidence float32,
) patterns.Finding {
	return patterns.Finding{
		File:       filePath,
		Line:       lineNum,
		Message:    title + ": " + message,
		Severity:   severity,
		Confidence: confidence,
		PatternID:  "missing_human_oversight",
	}
}

// Name returns the detector name
func (d *MissingHumanOversightDetector) Name() string {
	return "missing_human_oversight"
}

// GetPattern returns the pattern metadata
func (d *MissingHumanOversightDetector) GetPattern() patterns.Pattern {
	return patterns.Pattern{
		ID:          "missing_human_oversight",
		Name:        "Missing Human Oversight",
		Version:     "1.0",
		Category:    "governance",
		Severity:    "HIGH",
		CVSS:        8.5,
		CWEIDs:      []string{"CWE-862", "CWE-693"},
		OWASP:       "A05:2021 Resource Exhaustion",
		Description: "Detects autonomous agent actions without human approval mechanisms",
	}
}

// GetConfidence returns the confidence score for this detector
func (d *MissingHumanOversightDetector) GetConfidence() float32 {
	return 0.75
}
