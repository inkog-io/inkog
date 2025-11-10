package detectors

import (
	"regexp"
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// UnsafeEnvAccessDetectorV2 detects unsafe environment access and code execution patterns
// Covers dangerous function calls, environment variable access, and obfuscation techniques
// that can lead to RCE, path traversal, and information disclosure vulnerabilities
type UnsafeEnvAccessDetectorV2 struct {
	pattern patterns.Pattern

	// PRIORITY 1: Dangerous code execution patterns
	osSystemPattern         *regexp.Regexp // os.system()
	subprocessPattern       *regexp.Regexp // subprocess.run, subprocess.Popen
	evalPattern             *regexp.Regexp // eval(), exec()
	importPattern           *regexp.Regexp // __import__()
	phpSystemPattern        *regexp.Regexp // PHP: system(), shell_exec(), exec()
	nodeExecPattern         *regexp.Regexp // Node.js: child_process.exec()

	// PRIORITY 2: Environment variable access and file operations
	envVarPattern           *regexp.Regexp // os.environ, os.getenv()
	processEnvPattern       *regexp.Regexp // process.env[] (JavaScript)
	fileAccessPattern       *regexp.Regexp // open(), read/write with user input
	pathTraversalPattern    *regexp.Regexp // ../, ..\\, path concatenation

	// PRIORITY 3: Obfuscation and evasion techniques
	getAttrPattern          *regexp.Regexp // getattr(module, "function")
	importlibPattern        *regexp.Regexp // importlib.import_module()
	dynamicImportPattern    *regexp.Regexp // Dynamic imports and function calls
	stringConcatPattern     *regexp.Regexp // String concatenation for obfuscation

	// False positive reduction
	breakPattern            *regexp.Regexp // break, return statements
	commentPattern          *regexp.Regexp // Comments
	allowlistPattern        *regexp.Regexp // Safe patterns (logging, config, etc.)
	sandboxPattern          *regexp.Regexp // Sandbox environment indicators
}

// NewUnsafeEnvAccessDetectorV2 creates a new V2 unsafe environment access detector
func NewUnsafeEnvAccessDetectorV2() *UnsafeEnvAccessDetectorV2 {
	return &UnsafeEnvAccessDetectorV2{
		pattern: patterns.Pattern{
			ID:          "unsafe-env-access-v2",
			Name:        "Unsafe Environment Access V2",
			Version:     "2.0",
			Category:    "unsafe_env_access",
			Severity:    "CRITICAL",
			CVSS:        8.8, // High severity RCE vulnerability
			CWEIDs:      []string{"CWE-94", "CWE-78", "CWE-426", "CWE-427"},
			OWASP:       "A03:2021 - Injection",
			Description: "Detects unsafe environment variable access, dangerous function calls, and code execution patterns that can lead to remote code execution and information disclosure",
		},

		// PRIORITY 1: Code execution
		osSystemPattern:      regexp.MustCompile(`(?i)os\.system\s*\(|subprocess\.(run|Popen|call|check_call)\s*\(`),
		subprocessPattern:    regexp.MustCompile(`(?i)subprocess\.(run|Popen|call|check_call|spawn)\s*\(`),
		evalPattern:          regexp.MustCompile(`(?i)\b(?:eval|exec|compile|exec|Eval|Execute)\s*\(`),
		importPattern:        regexp.MustCompile(`(?i)__import__\s*\(`),
		phpSystemPattern:     regexp.MustCompile(`(?i)(?:system|shell_exec|exec|passthru|proc_open)\s*\(`),
		nodeExecPattern:      regexp.MustCompile(`(?i)(?:child_process\.(exec|spawn|spawnSync)|require\(['"]*child_process['"]*\))`),

		// PRIORITY 2: Environment and file access
		envVarPattern:        regexp.MustCompile(`(?i)os\.environ\[|os\.getenv\(|getenv\(`),
		processEnvPattern:    regexp.MustCompile(`(?i)process\.env\[|process\.env\.`),
		fileAccessPattern:    regexp.MustCompile(`(?i)open\s*\(|\.read\s*\(|\.write\s*\(|\.open\s*\(|fopen\s*\(`),
		pathTraversalPattern: regexp.MustCompile(`\.\./|\.\\\|path\.join|os\.path\.join|Path\(`),

		// PRIORITY 3: Obfuscation
		getAttrPattern:       regexp.MustCompile(`(?i)getattr\s*\(`),
		importlibPattern:     regexp.MustCompile(`(?i)importlib\.import_module\s*\(`),
		dynamicImportPattern: regexp.MustCompile(`(?i)__import__|importlib|__getattribute__|globals\(\)`),
		stringConcatPattern:  regexp.MustCompile(`\+\s*['"]\w+['"]|\+\s*str\(|\.format\(|f['"]`),

		// False positive reduction
		breakPattern:         regexp.MustCompile(`\b(?:break|return|continue)\b`),
		commentPattern:       regexp.MustCompile(`^#|^//`),
		allowlistPattern:     regexp.MustCompile(`(?i)(?:logging|logger|log\.|print|config|settings|test_|mock_|stub_)`),
		sandboxPattern:       regexp.MustCompile(`(?i)(?:test|sandbox|mock|fixture|example|sample|demo)`),
	}
}

// Name returns detector name
func (d *UnsafeEnvAccessDetectorV2) Name() string {
	return d.pattern.Name
}

// GetPattern returns the pattern metadata
func (d *UnsafeEnvAccessDetectorV2) GetPattern() patterns.Pattern {
	return d.pattern
}

// GetConfidence returns detector confidence
func (d *UnsafeEnvAccessDetectorV2) GetConfidence() float32 {
	return 0.85
}

// Detect scans for unsafe environment access patterns
func (d *UnsafeEnvAccessDetectorV2) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	if !isSupportedFile(filePath) {
		return []patterns.Finding{}, nil
	}

	// Skip test files and documentation
	if isTestFile(filePath) {
		return []patterns.Finding{}, nil
	}

	content := string(src)
	lines := strings.Split(content, "\n")
	var findings []patterns.Finding

	for i, line := range lines {
		// Skip empty lines and comments
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || d.commentPattern.MatchString(trimmed) {
			continue
		}

		// Check for unsafe access patterns
		lineFindings := d.scanLine(line, i+1, filePath, lines, i)
		findings = append(findings, lineFindings...)
	}

	return findings, nil
}

// scanLine checks a single line for unsafe environment access patterns
func (d *UnsafeEnvAccessDetectorV2) scanLine(line string, lineNum int, filePath string, allLines []string, lineIdx int) []patterns.Finding {
	var findings []patterns.Finding

	// PRIORITY 1: Code execution patterns
	if d.osSystemPattern.MatchString(line) {
		confidence := d.analyzeUnsafeConfidence(line, allLines, lineIdx, filePath, "code_execution")
		if confidence > 0.5 {
			findings = append(findings, d.createFinding(line, lineNum, filePath, "CRITICAL", confidence,
				"Dangerous code execution detected: os.system() allows command injection")...)
		}
	}

	if d.subprocessPattern.MatchString(line) && !d.allowlistPattern.MatchString(line) {
		confidence := d.analyzeUnsafeConfidence(line, allLines, lineIdx, filePath, "subprocess")
		if confidence > 0.5 {
			findings = append(findings, d.createFinding(line, lineNum, filePath, "CRITICAL", confidence,
				"Dangerous code execution detected: subprocess.run() with unsanitized input")...)
		}
	}

	if d.evalPattern.MatchString(line) {
		confidence := d.analyzeUnsafeConfidence(line, allLines, lineIdx, filePath, "eval")
		if confidence > 0.6 {
			findings = append(findings, d.createFinding(line, lineNum, filePath, "CRITICAL", confidence,
				"Dangerous code execution detected: eval() enables arbitrary code execution")...)
		}
	}

	if d.importPattern.MatchString(line) {
		confidence := d.analyzeUnsafeConfidence(line, allLines, lineIdx, filePath, "import")
		if confidence > 0.6 {
			findings = append(findings, d.createFinding(line, lineNum, filePath, "CRITICAL", confidence,
				"Dangerous dynamic import detected: __import__() bypasses import restrictions")...)
		}
	}

	if d.phpSystemPattern.MatchString(line) {
		confidence := d.analyzeUnsafeConfidence(line, allLines, lineIdx, filePath, "php_exec")
		if confidence > 0.5 {
			findings = append(findings, d.createFinding(line, lineNum, filePath, "CRITICAL", confidence,
				"Dangerous PHP code execution detected: shell_exec() allows command injection")...)
		}
	}

	if d.nodeExecPattern.MatchString(line) {
		confidence := d.analyzeUnsafeConfidence(line, allLines, lineIdx, filePath, "node_exec")
		if confidence > 0.5 {
			findings = append(findings, d.createFinding(line, lineNum, filePath, "CRITICAL", confidence,
				"Dangerous Node.js code execution detected: child_process.exec() allows command injection")...)
		}
	}

	// PRIORITY 2: Environment variable and file access
	if d.envVarPattern.MatchString(line) && !d.allowlistPattern.MatchString(line) {
		confidence := d.analyzeUnsafeConfidence(line, allLines, lineIdx, filePath, "env_access")
		if confidence > 0.55 {
			findings = append(findings, d.createFinding(line, lineNum, filePath, "HIGH", confidence,
				"Unsafe environment variable access detected: os.environ may contain sensitive data")...)
		}
	}

	if d.processEnvPattern.MatchString(line) && !d.allowlistPattern.MatchString(line) {
		confidence := d.analyzeUnsafeConfidence(line, allLines, lineIdx, filePath, "process_env")
		if confidence > 0.55 {
			findings = append(findings, d.createFinding(line, lineNum, filePath, "HIGH", confidence,
				"Unsafe environment variable access detected: process.env may contain sensitive data")...)
		}
	}

	if d.fileAccessPattern.MatchString(line) && d.pathTraversalPattern.MatchString(line) {
		confidence := d.analyzeUnsafeConfidence(line, allLines, lineIdx, filePath, "path_traversal")
		if confidence > 0.6 {
			findings = append(findings, d.createFinding(line, lineNum, filePath, "HIGH", confidence,
				"Path traversal vulnerability detected: file access with unsanitized paths")...)
		}
	}

	// PRIORITY 3: Obfuscation and evasion
	if d.getAttrPattern.MatchString(line) && d.dynamicImportPattern.MatchString(allLines[lineIdx]) {
		confidence := d.analyzeUnsafeConfidence(line, allLines, lineIdx, filePath, "obfuscation")
		if confidence > 0.65 {
			findings = append(findings, d.createFinding(line, lineNum, filePath, "HIGH", confidence,
				"Obfuscated code execution detected: getattr() with dynamic function names")...)
		}
	}

	if d.importlibPattern.MatchString(line) && !d.allowlistPattern.MatchString(line) {
		confidence := d.analyzeUnsafeConfidence(line, allLines, lineIdx, filePath, "importlib")
		if confidence > 0.6 {
			findings = append(findings, d.createFinding(line, lineNum, filePath, "HIGH", confidence,
				"Dynamic module import detected: importlib.import_module() may execute untrusted code")...)
		}
	}

	return findings
}

// analyzeUnsafeConfidence calculates confidence based on context
func (d *UnsafeEnvAccessDetectorV2) analyzeUnsafeConfidence(line string, allLines []string, lineIdx int, filePath string, patternType string) float32 {
	confidence := float32(0.85) // Base confidence for dangerous patterns

	// Check for user input indicators
	hasUserInput := d.hasUserInputIndicators(line, allLines, lineIdx)
	if !hasUserInput && patternType != "eval" && patternType != "import" {
		confidence -= 0.20 // Reduce if no obvious user input
	}

	// Check for sanitization/validation
	hasSanitization := d.hasSanitization(line, allLines, lineIdx)
	if hasSanitization {
		confidence -= 0.25 // Strong reduction if sanitized
	}

	// Check for safe patterns (test, mock, sandbox)
	if d.sandboxPattern.MatchString(filePath) || d.allowlistPattern.MatchString(line) {
		confidence -= 0.30 // Reduce for test/demo contexts
	}

	// Eval and import are always high risk
	if patternType == "eval" || patternType == "import" {
		confidence = 0.9 // Very high confidence for eval/import
	}

	// Check for allowlists or safe patterns
	if strings.Contains(line, "\"\"") || strings.Contains(line, "''") {
		confidence -= 0.10 // Slight reduction for empty/static strings
	}

	// Clamp confidence
	if confidence < 0.0 {
		confidence = 0.0
	}
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// hasUserInputIndicators checks if user input is involved
func (d *UnsafeEnvAccessDetectorV2) hasUserInputIndicators(line string, allLines []string, lineIdx int) bool {
	userInputPatterns := []string{
		"request", "input", "user", "arg", "param", "query", "form",
		"stdin", "argv", "sys.argv", "raw_input", "input(", "gets",
		"@request", "@param", "req.", "body", "data", "GET", "POST",
	}

	lowerLine := strings.ToLower(line)
	for _, pattern := range userInputPatterns {
		if strings.Contains(lowerLine, pattern) {
			return true
		}
	}

	// Check previous lines for assignments
	startIdx := lineIdx - 5
	if startIdx < 0 {
		startIdx = 0
	}
	for i := startIdx; i < lineIdx; i++ {
		if strings.Contains(strings.ToLower(allLines[i]), "request") ||
			strings.Contains(strings.ToLower(allLines[i]), "input") {
			return true
		}
	}

	return false
}

// hasSanitization checks for sanitization/validation
func (d *UnsafeEnvAccessDetectorV2) hasSanitization(line string, allLines []string, lineIdx int) bool {
	sanitizationPatterns := []string{
		"shlex.quote", "pipes.quote", "escape", "sanitize", "validate",
		"whitelist", "is_safe", "check_", "verify_", "allow_list",
		"strip_", "filter_", "replace(", "sub(", "match(",
	}

	lowerLine := strings.ToLower(line)
	for _, pattern := range sanitizationPatterns {
		if strings.Contains(lowerLine, pattern) {
			return true
		}
	}

	// Check nearby lines for validation
	startIdx := lineIdx - 3
	if startIdx < 0 {
		startIdx = 0
	}
	endIdx := lineIdx + 3
	if endIdx > len(allLines) {
		endIdx = len(allLines)
	}

	for i := startIdx; i < endIdx; i++ {
		lowerCheckLine := strings.ToLower(allLines[i])
		for _, pattern := range sanitizationPatterns {
			if strings.Contains(lowerCheckLine, pattern) {
				return true
			}
		}
	}

	return false
}

// createFinding creates a Finding with the given parameters
func (d *UnsafeEnvAccessDetectorV2) createFinding(line string, lineNum int, filePath string, severity string, confidence float32, message string) []patterns.Finding {
	return []patterns.Finding{
		{
			Pattern:    d.pattern.Name,
			PatternID:  d.pattern.ID,
			Severity:   severity,
			CVSS:       d.pattern.CVSS,
			Confidence: confidence,
			Line:       lineNum,
			Column:     1,
			Message:    message,
			Code:       strings.TrimSpace(line),
			File:       filePath,
			CWE:        strings.Join(d.pattern.CWEIDs, ", "),
			OWASP:      d.pattern.OWASP,
		},
	}
}
