package detectors

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
	"github.com/inkog-io/inkog/action/pkg/patterns/metadata"
)

// UnvalidatedExecEvalDetector detects unvalidated exec/eval calls that can lead to RCE
// Pattern covers Python eval/exec, JavaScript eval, and Go exec.Command with user input
type UnvalidatedExecEvalDetector struct {
	pattern patterns.Pattern
}

// NewUnvalidatedExecEvalDetector creates a new unvalidated exec/eval detector
func NewUnvalidatedExecEvalDetector() *UnvalidatedExecEvalDetector {
	pattern := patterns.Pattern{
		ID:       "unvalidated_exec_eval",
		Name:     "Unvalidated Code Execution (eval/exec)",
		Version:  "1.0",
		Category: "code_injection",
		Severity: "CRITICAL",
		CVSS:     9.8,
		CWEIDs:   []string{"CWE-94", "CWE-95"},
		OWASP:    "A03:2021 Injection",
		Description: "Unvalidated eval/exec calls with user input or LLM output allow arbitrary code execution. " +
			"This affects Python (eval, exec, compile), JavaScript (eval, new Function), and Go (exec.Command).",
		Remediation: "Never use eval/exec with user input. Use ast.literal_eval for safe evaluation or sandboxed environments.",
		FinancialImpact: struct {
			Severity    string
			Description string
			RiskPerYear float32
		}{
			Severity:    "CRITICAL",
			Description: "Full system compromise, data theft, lateral movement, malware installation",
			RiskPerYear: 10000000, // $10M+ for full system compromise
		},
	}

	return &UnvalidatedExecEvalDetector{
		pattern: pattern,
	}
}

// Name returns the detector name
func (d *UnvalidatedExecEvalDetector) Name() string {
	return "unvalidated_exec_eval"
}

// GetPatternID returns the canonical detector ID (implements Detector interface)
func (d *UnvalidatedExecEvalDetector) GetPatternID() string {
	return metadata.ID_UNVALIDATED_EXEC_EVAL
}


// GetPattern returns the pattern metadata
func (d *UnvalidatedExecEvalDetector) GetPattern() patterns.Pattern {
	return d.pattern
}

// Detect analyzes code for unvalidated eval/exec calls
func (d *UnvalidatedExecEvalDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	var findings []patterns.Finding

	// Skip unsupported files
	if !isSupportedFile(filePath) {
		return findings, nil
	}

	sourceStr := string(src)
	lines := strings.Split(sourceStr, "\n")

	// Python patterns for eval/exec
	d.detectPythonExecEval(lines, filePath, sourceStr, &findings)

	// JavaScript patterns for eval/Function
	d.detectJavaScriptEval(lines, filePath, sourceStr, &findings)

	// Go patterns for exec.Command
	d.detectGoExecCommand(lines, filePath, sourceStr, &findings)

	return findings, nil
}

// detectPythonExecEval detects Python eval, exec, compile patterns
func (d *UnvalidatedExecEvalDetector) detectPythonExecEval(
	lines []string,
	filePath string,
	sourceStr string,
	findings *[]patterns.Finding,
) {
	// Pattern 1: Direct eval(variable) - most dangerous
	evalPattern := regexp.MustCompile(`(?i)eval\s*\([^)]*\)`)
	// Pattern 2: Direct exec(variable)
	execPattern := regexp.MustCompile(`(?i)exec\s*\([^)]*\)`)
	// Pattern 3: compile() + exec() - also dangerous
	compilePattern := regexp.MustCompile(`(?i)compile\s*\([^)]*[,)]`)
	// Pattern 4: __builtins__ access patterns - obfuscation
	builtinsPattern := regexp.MustCompile(`(?i)(__builtins__|__import__|getattr.*__builtins__|globals.*eval|globals.*exec)`)
	// Pattern 5: Base64 decode + eval - obfuscation
	base64EvalPattern := regexp.MustCompile(`(?i)(base64|b64decode|codecs\.decode|binascii\.a2b).*(eval|exec)`)

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}

		// Skip safe patterns like ast.literal_eval
		if d.isSafeEvalPattern(line) {
			continue
		}

		// Check for eval() with non-constant argument
		if evalPattern.MatchString(line) && !d.isConstantEval(line) {
			severity := d.determinePythonSeverity(line, sourceStr, "eval")
			if severity != "" {
				finding := patterns.Finding{
					ID:        fmt.Sprintf("unvalidated_exec_eval_py_eval_%d_%s", i, filePath),
					PatternID: d.pattern.ID,
					Pattern:   d.pattern.Name,
					File:      filePath,
					Line:      i + 1,
					Column:    len(line) - len(trimmed) + 1,
					Message:   "Unvalidated eval() with user input or LLM output - RCE vulnerability",
					Code:      line,
					Severity:  severity,
					Confidence: d.calculateConfidence(line, "eval", sourceStr),
					CWE:       "CWE-95",
					CVSS:      9.8,
					OWASP:     "A03:2021",
					FinancialRisk: "Full system compromise, data theft, lateral movement",
				}
				*findings = append(*findings, finding)
			}
		}

		// Check for exec() with non-constant argument
		if execPattern.MatchString(line) && !d.isConstantEval(line) {
			severity := d.determinePythonSeverity(line, sourceStr, "exec")
			if severity != "" {
				finding := patterns.Finding{
					ID:        fmt.Sprintf("unvalidated_exec_eval_py_exec_%d_%s", i, filePath),
					PatternID: d.pattern.ID,
					Pattern:   d.pattern.Name,
					File:      filePath,
					Line:      i + 1,
					Column:    len(line) - len(trimmed) + 1,
					Message:   "Unvalidated exec() with user input or LLM output - RCE vulnerability",
					Code:      line,
					Severity:  severity,
					Confidence: d.calculateConfidence(line, "exec", sourceStr),
					CWE:       "CWE-94",
					CVSS:      9.8,
					OWASP:     "A03:2021",
					FinancialRisk: "Full system compromise, code injection",
				}
				*findings = append(*findings, finding)
			}
		}

		// Check for compile() + exec pattern
		if compilePattern.MatchString(line) && !d.isConstantEval(line) {
			finding := patterns.Finding{
				ID:        fmt.Sprintf("unvalidated_exec_eval_py_compile_%d_%s", i, filePath),
				PatternID: d.pattern.ID,
				Pattern:   d.pattern.Name,
				File:      filePath,
				Line:      i + 1,
				Column:    len(line) - len(trimmed) + 1,
				Message:   "compile() + exec() pattern with user input - RCE vulnerability",
				Code:      line,
				Severity:  "CRITICAL",
				Confidence: 0.92,
				CWE:       "CWE-95",
				CVSS:      9.8,
				OWASP:     "A03:2021",
				FinancialRisk: "Full system compromise",
			}
			*findings = append(*findings, finding)
		}

		// Check for __builtins__ obfuscation patterns
		if builtinsPattern.MatchString(line) {
			severity := "HIGH"
			if d.isObfuscationPattern(line) {
				severity = "CRITICAL"
			}
			finding := patterns.Finding{
				ID:        fmt.Sprintf("unvalidated_exec_eval_py_builtins_%d_%s", i, filePath),
				PatternID: d.pattern.ID,
				Pattern:   d.pattern.Name,
				File:      filePath,
				Line:      i + 1,
				Column:    len(line) - len(trimmed) + 1,
				Message:   "Obfuscated eval/exec access via __builtins__ or getattr - likely RCE",
				Code:      line,
				Severity:  severity,
				Confidence: 0.88,
				CWE:       "CWE-94",
				CVSS:      9.0,
				OWASP:     "A03:2021",
				FinancialRisk: "Code injection via obfuscation",
			}
			*findings = append(*findings, finding)
		}

		// Check for base64 + eval patterns (common obfuscation)
		if base64EvalPattern.MatchString(line) {
			finding := patterns.Finding{
				ID:        fmt.Sprintf("unvalidated_exec_eval_py_base64_%d_%s", i, filePath),
				PatternID: d.pattern.ID,
				Pattern:   d.pattern.Name,
				File:      filePath,
				Line:      i + 1,
				Column:    len(line) - len(trimmed) + 1,
				Message:   "Base64 decode followed by eval/exec - common obfuscation technique for RCE",
				Code:      line,
				Severity:  "CRITICAL",
				Confidence: 0.90,
				CWE:       "CWE-95",
				CVSS:      9.8,
				OWASP:     "A03:2021",
				FinancialRisk: "Hidden RCE payload",
			}
			*findings = append(*findings, finding)
		}
	}
}

// detectJavaScriptEval detects JavaScript eval, new Function, setTimeout/setInterval patterns
func (d *UnvalidatedExecEvalDetector) detectJavaScriptEval(
	lines []string,
	filePath string,
	sourceStr string,
	findings *[]patterns.Finding,
) {
	// Pattern 1: Direct eval()
	evalPattern := regexp.MustCompile(`(?i)\beval\s*\(\s*([a-zA-Z_$]\w*|[\w.]+\(.*?\))\s*\)`)
	// Pattern 2: new Function() - creates function from string
	functionPattern := regexp.MustCompile(`(?i)new\s+Function\s*\(\s*[^)]*\)`)
	// Pattern 3: setTimeout/setInterval with any argument (could be string or variable)
	timeoutPattern := regexp.MustCompile(`(?i)(setTimeout|setInterval)\s*\(.*?,`)

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
			continue
		}

		// Check for eval()
		if evalPattern.MatchString(line) && !d.isConstantEval(line) {
			finding := patterns.Finding{
				ID:        fmt.Sprintf("unvalidated_exec_eval_js_eval_%d_%s", i, filePath),
				PatternID: d.pattern.ID,
				Pattern:   d.pattern.Name,
				File:      filePath,
				Line:      i + 1,
				Column:    len(line) - len(trimmed) + 1,
				Message:   "JavaScript eval() with user input - XSS/RCE vulnerability",
				Code:      line,
				Severity:  "CRITICAL",
				Confidence: 0.95,
				CWE:       "CWE-95",
				CVSS:      9.0,
				OWASP:     "A03:2021",
				FinancialRisk: "Client-side code execution, data theft",
			}
			*findings = append(*findings, finding)
		}

		// Check for new Function()
		if functionPattern.MatchString(line) {
			finding := patterns.Finding{
				ID:        fmt.Sprintf("unvalidated_exec_eval_js_function_%d_%s", i, filePath),
				PatternID: d.pattern.ID,
				Pattern:   d.pattern.Name,
				File:      filePath,
				Line:      i + 1,
				Column:    len(line) - len(trimmed) + 1,
				Message:   "new Function() creates function from string - RCE vulnerability",
				Code:      line,
				Severity:  "CRITICAL",
				Confidence: 0.93,
				CWE:       "CWE-95",
				CVSS:      9.0,
				OWASP:     "A03:2021",
				FinancialRisk: "Remote code execution",
			}
			*findings = append(*findings, finding)
		}

		// Check for setTimeout/setInterval with string code
		if timeoutPattern.MatchString(line) {
			finding := patterns.Finding{
				ID:        fmt.Sprintf("unvalidated_exec_eval_js_timeout_%d_%s", i, filePath),
				PatternID: d.pattern.ID,
				Pattern:   d.pattern.Name,
				File:      filePath,
				Line:      i + 1,
				Column:    len(line) - len(trimmed) + 1,
				Message:   "setTimeout/setInterval with string code - code injection vulnerability",
				Code:      line,
				Severity:  "HIGH",
				Confidence: 0.85,
				CWE:       "CWE-95",
				CVSS:      8.0,
				OWASP:     "A03:2021",
				FinancialRisk: "Client-side code injection",
			}
			*findings = append(*findings, finding)
		}
	}
}

// detectGoExecCommand detects Go exec.Command with user input
func (d *UnvalidatedExecEvalDetector) detectGoExecCommand(
	lines []string,
	filePath string,
	sourceStr string,
	findings *[]patterns.Finding,
) {
	// Pattern 1: exec.Command with variable argument
	execCmdPattern := regexp.MustCompile(`(?i)exec\.Command\s*\(\s*([a-zA-Z_]\w*|[\w.]+\(.*?\))\s*[,)]`)
	// Pattern 2: os/exec with string concatenation
	concatPattern := regexp.MustCompile(`(?i)(exec|Command)\s*\(\s*[^)]*\s*\+\s*[^)]*\)`)

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}

		// Skip if it's clearly a constant command
		if strings.Contains(line, `"ls"`) || strings.Contains(line, `"cat"`) ||
			strings.Contains(line, `"echo"`) || strings.Contains(line, `"grep"`) {
			continue
		}

		// Check for exec.Command with variable
		if execCmdPattern.MatchString(line) {
			finding := patterns.Finding{
				ID:        fmt.Sprintf("unvalidated_exec_eval_go_exec_%d_%s", i, filePath),
				PatternID: d.pattern.ID,
				Pattern:   d.pattern.Name,
				File:      filePath,
				Line:      i + 1,
				Column:    len(line) - len(trimmed) + 1,
				Message:   "exec.Command with variable argument - command injection vulnerability",
				Code:      line,
				Severity:  "CRITICAL",
				Confidence: 0.90,
				CWE:       "CWE-94",
				CVSS:      9.0,
				OWASP:     "A03:2021",
				FinancialRisk: "Remote code execution",
			}
			*findings = append(*findings, finding)
		}

		// Check for string concatenation in exec
		if concatPattern.MatchString(line) {
			finding := patterns.Finding{
				ID:        fmt.Sprintf("unvalidated_exec_eval_go_concat_%d_%s", i, filePath),
				PatternID: d.pattern.ID,
				Pattern:   d.pattern.Name,
				File:      filePath,
				Line:      i + 1,
				Column:    len(line) - len(trimmed) + 1,
				Message:   "Command constructed via string concatenation - command injection vulnerability",
				Code:      line,
				Severity:  "CRITICAL",
				Confidence: 0.88,
				CWE:       "CWE-94",
				CVSS:      9.0,
				OWASP:     "A03:2021",
				FinancialRisk: "Remote code execution",
			}
			*findings = append(*findings, finding)
		}
	}
}

// isSafeEvalPattern checks if line uses safe evaluation patterns
func (d *UnvalidatedExecEvalDetector) isSafeEvalPattern(line string) bool {
	safePatterns := []string{
		"ast.literal_eval",
		"json.loads",
		"pickle.loads",
		"yaml.safe_load",
		"JSON.parse",
		"literal_eval",
	}

	lowerLine := strings.ToLower(line)
	for _, pattern := range safePatterns {
		if strings.Contains(lowerLine, strings.ToLower(pattern)) {
			return true
		}
	}

	return false
}

// isConstantEval checks if eval/exec is operating on constant strings
func (d *UnvalidatedExecEvalDetector) isConstantEval(line string) bool {
	// If the argument to eval/exec is a plain string literal, it's constant
	// e.g., eval("1+2") is constant, but eval(user_input) is not

	if strings.Contains(line, `eval("`) || strings.Contains(line, `eval('`) ||
		strings.Contains(line, `exec("`) || strings.Contains(line, `exec('`) {
		// Check if it looks like a simple constant
		if !strings.Contains(line, "+") && !strings.Contains(line, "f\"") &&
			!strings.Contains(line, "f'") {
			return true
		}
	}

	return false
}

// determinePythonSeverity determines severity based on context
func (d *UnvalidatedExecEvalDetector) determinePythonSeverity(
	line string,
	sourceStr string,
	pattern string,
) string {
	// Check for sandboxing indicators
	isSandboxed := strings.Contains(sourceStr, `{"__builtins__": None}`) ||
		strings.Contains(sourceStr, `{__builtins__: null}`) ||
		strings.Contains(sourceStr, `RestrictedPython`) ||
		strings.Contains(sourceStr, `sandboxed`)

	if isSandboxed {
		return "MEDIUM" // Still a vulnerability but mitigated
	}

	// Check for LLM output patterns (very dangerous)
	hasLLMOutput := strings.Contains(sourceStr, "llm.") ||
		strings.Contains(sourceStr, "openai.") ||
		strings.Contains(sourceStr, "anthropic.") ||
		strings.Contains(sourceStr, "gpt") ||
		strings.Contains(sourceStr, "claude")

	if hasLLMOutput && (strings.Contains(line, "response") || strings.Contains(line, "output")) {
		return "CRITICAL"
	}

	// Check for obfuscation
	if d.isObfuscationPattern(line) {
		return "CRITICAL"
	}

	return "CRITICAL" // Default to critical for unvalidated eval/exec
}

// isObfuscationPattern checks if line contains obfuscation techniques
func (d *UnvalidatedExecEvalDetector) isObfuscationPattern(line string) bool {
	obfuscationIndicators := []string{
		"replace(",
		"encode(",
		"decode(",
		"join(",
		"split(",
		"['",
		`["`,
		"getattr(",
		"__import__",
		"base64",
		"b64",
		"hex",
	}

	lowerLine := strings.ToLower(line)
	for _, indicator := range obfuscationIndicators {
		if strings.Contains(lowerLine, strings.ToLower(indicator)) {
			return true
		}
	}

	return false
}

// calculateConfidence calculates confidence score for the vulnerability
func (d *UnvalidatedExecEvalDetector) calculateConfidence(
	line string,
	pattern string,
	sourceStr string,
) float32 {
	confidence := float32(0.85)

	// Higher confidence for variable arguments
	if strings.Contains(line, "(") && !d.isConstantEval(line) {
		confidence = 0.92
	}

	// Lower confidence if there's some validation attempt
	validationPatterns := []string{
		"if ", "validate", "check", "sanitize", "escape",
	}
	lowerLine := strings.ToLower(line)
	for _, vp := range validationPatterns {
		if strings.Contains(lowerLine, vp) {
			confidence -= 0.05
		}
	}

	// Higher confidence for obfuscation patterns (they're hiding something)
	if d.isObfuscationPattern(line) {
		confidence = 0.94
	}

	return confidence
}

// GetConfidence returns the confidence score for this detector
func (d *UnvalidatedExecEvalDetector) GetConfidence() float32 {
	return 0.90
}
