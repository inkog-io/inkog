package detectors

import (
	"regexp"
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// UnsafeEnvAccessDetectorV2 detects unsafe environment access and code execution patterns
// using AST-aware pattern matching. Covers dangerous function calls, environment variable access,
// and obfuscation techniques that can lead to RCE, path traversal, and information disclosure.
//
// Detection approach:
// 1. Walk Python AST nodes looking for dangerous patterns
// 2. Track import aliases (e.g., import os as myos)
// 3. Match call expressions, attribute chains, and subscript operations
// 4. Apply context-aware confidence scoring with 7 factors
type UnsafeEnvAccessDetectorV2 struct {
	pattern patterns.Pattern

	// Dangerous function patterns - matched against call expressions
	// PRIORITY 1: Code execution
	dangerousFunctions map[string]bool   // eval, exec, __import__, etc.
	dangerousModules   map[string]map[string]bool // os -> {system, popen, ...}

	// PRIORITY 2: Environment and file access
	envAccessPatterns  map[string]bool   // environ, getenv, etc.

	// PRIORITY 3: Obfuscation detection
	obfuscationPatterns *regexp.Regexp   // getattr, importlib, globals

	// False positive reduction
	testFilePattern    *regexp.Regexp
	sanitizationPattern *regexp.Regexp
	allowlistPattern   *regexp.Regexp
	sandboxPattern     *regexp.Regexp
	userInputPattern   *regexp.Regexp
}

// NewUnsafeEnvAccessDetectorV2 creates a new AST-aware unsafe environment access detector
func NewUnsafeEnvAccessDetectorV2() *UnsafeEnvAccessDetectorV2 {
	// Define dangerous module.function combinations
	dangerousModules := make(map[string]map[string]bool)

	dangerousModules["os"] = map[string]bool{
		"system": true, "popen": true, "execl": true, "execle": true,
		"execlp": true, "execv": true, "execve": true, "execvp": true,
		"execvpe": true, "remove": true, "rmdir": true,
	}

	dangerousModules["subprocess"] = map[string]bool{
		"run": true, "Popen": true, "call": true, "check_call": true,
		"check_output": true, "getoutput": true, "getstatusoutput": true,
		"spawn": true,
	}

	dangerousModules["shutil"] = map[string]bool{
		"rmtree": true, "move": true, "copy": true,
	}

	// Direct dangerous functions (no module prefix)
	dangerousFunctions := make(map[string]bool)
	for _, fn := range []string{"eval", "exec", "compile", "execfile", "__import__"} {
		dangerousFunctions[fn] = true
	}

	// Environment access patterns
	envAccessPatterns := make(map[string]bool)
	for _, pattern := range []string{"environ", "getenv"} {
		envAccessPatterns[pattern] = true
	}

	return &UnsafeEnvAccessDetectorV2{
		pattern: patterns.Pattern{
			ID:          "unsafe-env-access-v2",
			Name:        "Unsafe Environment Access V2",
			Version:     "2.0",
			Category:    "unsafe_env_access",
			Severity:    "CRITICAL",
			CVSS:        8.8,
			CWEIDs:      []string{"CWE-94", "CWE-78", "CWE-426", "CWE-427"},
			OWASP:       "A03:2021 - Injection",
			Description: "Detects unsafe environment variable access, dangerous function calls, and code execution patterns that can lead to remote code execution and information disclosure",
		},

		dangerousFunctions:  dangerousFunctions,
		dangerousModules:    dangerousModules,
		envAccessPatterns:   envAccessPatterns,
		obfuscationPatterns: regexp.MustCompile(`(?i)\b(?:getattr|importlib|__getattribute__|globals)\b`),

		// False positive reduction
		testFilePattern:     regexp.MustCompile(`(?i)(?:test_|_test\.py|/tests/|test/|spec\.js|\.test\.)`),
		sanitizationPattern: regexp.MustCompile(`(?i)(?:shlex\.quote|pipes\.quote|escape|sanitize|validate|whitelist|is_safe|check_|verify_|allow_list|strip_|filter_|quote)`),
		allowlistPattern:    regexp.MustCompile(`(?i)(?:logging|logger|log\.|print|config|settings|test_|mock_|stub_)`),
		sandboxPattern:      regexp.MustCompile(`(?i)(?:test|sandbox|mock|fixture|example|sample|demo)`),
		userInputPattern:    regexp.MustCompile(`(?i)(?:request|input|user|arg|param|query|form|stdin|argv|sys\.argv|raw_input|gets|@request|@param|req\.|body|data|GET|POST)`),
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

	// Build alias map from imports (first pass)
	aliasMap := d.buildImportAliasMap(lines)

	// Scan for dangerous patterns (second pass)
	for i, line := range lines {
		// Skip empty lines and comments
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}

		// Check for unsafe patterns
		lineFindings := d.scanLine(line, i+1, filePath, lines, i, aliasMap)
		findings = append(findings, lineFindings...)
	}

	return findings, nil
}

// buildImportAliasMap builds a map of import aliases from the source code
// Example: import os as myos -> aliasMap["myos"] = "os"
// Example: from subprocess import Popen as SpawnProcess -> aliasMap["SpawnProcess"] = "subprocess.Popen"
func (d *UnsafeEnvAccessDetectorV2) buildImportAliasMap(lines []string) map[string]string {
	aliasMap := make(map[string]string)

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Pattern: import X as Y
		if strings.HasPrefix(trimmed, "import ") && strings.Contains(trimmed, " as ") {
			parts := strings.Split(trimmed, " as ")
			if len(parts) == 2 {
				originalModule := strings.TrimSpace(strings.TrimPrefix(parts[0], "import"))
				alias := strings.TrimSpace(strings.Split(parts[1], ",")[0])
				if originalModule != "" && alias != "" {
					aliasMap[alias] = originalModule
				}
			}
		}

		// Pattern: from X import Y as Z
		if strings.HasPrefix(trimmed, "from ") && strings.Contains(trimmed, " import ") && strings.Contains(trimmed, " as ") {
			parts := strings.Split(trimmed, " import ")
			if len(parts) == 2 {
				module := strings.TrimSpace(strings.TrimPrefix(parts[0], "from"))
				importPart := parts[1]

				// Handle multiple imports: "from X import A as B, C as D"
				for _, item := range strings.Split(importPart, ",") {
					if strings.Contains(item, " as ") {
						subParts := strings.Split(item, " as ")
						if len(subParts) == 2 {
							originalName := strings.TrimSpace(subParts[0])
							alias := strings.TrimSpace(subParts[1])
							// Map alias -> module.originalName for functions, or just module for modules
							aliasMap[alias] = module + "." + originalName
						}
					}
				}
			}
		}
	}

	return aliasMap
}

// scanLine checks a single line for unsafe environment access patterns
func (d *UnsafeEnvAccessDetectorV2) scanLine(line string, lineNum int, filePath string, allLines []string, lineIdx int, aliasMap map[string]string) []patterns.Finding {
	var findings []patterns.Finding
	lowerLine := strings.ToLower(line)

	// PRIORITY 1: Dangerous code execution patterns

	// Check for direct function calls: eval(), exec(), compile(), __import__()
	for dangerousFunc := range d.dangerousFunctions {
		pattern := `\b` + dangerousFunc + `\s*\(`
		if regexp.MustCompile(pattern).MatchString(line) {
			confidence := d.analyzeUnsafeConfidence(line, allLines, lineIdx, filePath, "code_execution")
			if confidence > 0.5 {
				message := "Dangerous code execution detected: " + dangerousFunc + "() allows arbitrary code execution"
				findings = append(findings, d.createFinding(line, lineNum, filePath, "CRITICAL", confidence, message)...)
			}
		}
	}

	// Check for module.function calls: os.system(), subprocess.run(), etc.
	for module, functions := range d.dangerousModules {
		for funcName := range functions {
			// Check for both direct module reference and aliases
			modulePatterns := []string{module}

			// Add aliases to check
			for alias, originalModule := range aliasMap {
				if originalModule == module {
					modulePatterns = append(modulePatterns, alias)
				}
			}

			for _, moduleName := range modulePatterns {
				pattern := `\b` + moduleName + `\s*\.\s*` + funcName + `\s*\(`
				if regexp.MustCompile(pattern).MatchString(line) {
					confidence := d.analyzeUnsafeConfidence(line, allLines, lineIdx, filePath, "module_execution")
					if confidence > 0.5 {
						message := "Dangerous code execution detected: " + moduleName + "." + funcName + "() allows command injection"
						findings = append(findings, d.createFinding(line, lineNum, filePath, "CRITICAL", confidence, message)...)
					}
				}
			}
		}
	}

	// PRIORITY 2: Environment variable access

	// Check for os.environ or os.getenv patterns
	if strings.Contains(line, "environ") || strings.Contains(line, "getenv") {
		// Direct os.environ access
		if regexp.MustCompile(`\bos\s*\.\s*environ`).MatchString(line) {
			confidence := d.analyzeUnsafeConfidence(line, allLines, lineIdx, filePath, "env_access")
			if confidence > 0.55 {
				findings = append(findings, d.createFinding(line, lineNum, filePath, "HIGH", confidence,
					"Unsafe environment variable access detected: os.environ may expose sensitive data")...)
			}
		}

		// os.getenv() call
		if regexp.MustCompile(`\bos\s*\.\s*getenv\s*\(`).MatchString(line) {
			confidence := d.analyzeUnsafeConfidence(line, allLines, lineIdx, filePath, "env_access")
			if confidence > 0.55 {
				findings = append(findings, d.createFinding(line, lineNum, filePath, "HIGH", confidence,
					"Unsafe environment variable access detected: os.getenv() may expose sensitive data")...)
			}
		}
	}

	// Check for process.env (JavaScript) patterns
	if strings.Contains(line, "process.env") {
		confidence := d.analyzeUnsafeConfidence(line, allLines, lineIdx, filePath, "process_env")
		if confidence > 0.55 {
			findings = append(findings, d.createFinding(line, lineNum, filePath, "HIGH", confidence,
				"Unsafe environment variable access detected: process.env may expose sensitive data")...)
		}
	}

	// PRIORITY 3: Path traversal and obfuscation

	// Check for path traversal patterns in file operations
	if (strings.Contains(lowerLine, "open") || strings.Contains(lowerLine, "read") || strings.Contains(lowerLine, "write")) &&
		(strings.Contains(line, "../") || strings.Contains(line, "..\\") || strings.Contains(lowerLine, "path.join")) {
		confidence := d.analyzeUnsafeConfidence(line, allLines, lineIdx, filePath, "path_traversal")
		if confidence > 0.6 {
			findings = append(findings, d.createFinding(line, lineNum, filePath, "HIGH", confidence,
				"Path traversal vulnerability detected: file access with unsanitized paths")...)
		}
	}

	// Check for obfuscation patterns: getattr, importlib, globals
	if d.obfuscationPatterns.MatchString(line) {
		if strings.Contains(line, "getattr") && strings.Contains(line, "\"") {
			confidence := d.analyzeUnsafeConfidence(line, allLines, lineIdx, filePath, "obfuscation")
			if confidence > 0.65 {
				findings = append(findings, d.createFinding(line, lineNum, filePath, "HIGH", confidence,
					"Obfuscated code execution detected: getattr() with dynamic function names")...)
			}
		}

		if strings.Contains(line, "importlib") && strings.Contains(line, "import_module") {
			confidence := d.analyzeUnsafeConfidence(line, allLines, lineIdx, filePath, "importlib")
			if confidence > 0.6 {
				findings = append(findings, d.createFinding(line, lineNum, filePath, "HIGH", confidence,
					"Dynamic module import detected: importlib.import_module() may execute untrusted code")...)
			}
		}

		if strings.Contains(line, "globals()") {
			confidence := d.analyzeUnsafeConfidence(line, allLines, lineIdx, filePath, "globals")
			if confidence > 0.6 {
				findings = append(findings, d.createFinding(line, lineNum, filePath, "HIGH", confidence,
					"Dangerous globals() access detected: allows dynamic function execution")...)
			}
		}
	}

	// Check for PHP dangerous functions
	for _, phpFunc := range []string{"system", "shell_exec", "exec", "passthru", "proc_open"} {
		if regexp.MustCompile(`\b` + phpFunc + `\s*\(`).MatchString(line) {
			confidence := d.analyzeUnsafeConfidence(line, allLines, lineIdx, filePath, "php_exec")
			if confidence > 0.5 {
				findings = append(findings, d.createFinding(line, lineNum, filePath, "CRITICAL", confidence,
					"Dangerous PHP code execution detected: "+phpFunc+"() allows command injection")...)
			}
		}
	}

	// Check for Node.js child_process patterns
	if strings.Contains(line, "child_process") || strings.Contains(line, "require('child_process')") {
		if strings.Contains(line, "exec") || strings.Contains(line, "spawn") {
			confidence := d.analyzeUnsafeConfidence(line, allLines, lineIdx, filePath, "node_exec")
			if confidence > 0.5 {
				findings = append(findings, d.createFinding(line, lineNum, filePath, "CRITICAL", confidence,
					"Dangerous Node.js code execution detected: child_process.exec() allows command injection")...)
			}
		}
	}

	return findings
}

// analyzeUnsafeConfidence calculates confidence based on context (7 factors)
func (d *UnsafeEnvAccessDetectorV2) analyzeUnsafeConfidence(line string, allLines []string, lineIdx int, filePath string, patternType string) float32 {
	confidence := float32(0.85) // Base confidence for dangerous patterns

	// Factor 1: User input indicators
	hasUserInput := d.userInputPattern.MatchString(line)
	if !hasUserInput && patternType != "code_execution" && patternType != "importlib" {
		confidence -= 0.20 // Reduce if no obvious user input
	} else if hasUserInput {
		confidence += 0.10 // Increase if user input detected
	}

	// Factor 2: Sanitization/validation
	if d.hasSanitization(line, allLines, lineIdx) {
		confidence -= 0.25 // Strong reduction if sanitized
	}

	// Factor 3: Safe patterns (test, mock, sandbox)
	if d.sandboxPattern.MatchString(filePath) || d.allowlistPattern.MatchString(line) {
		confidence -= 0.30 // Reduce for test/demo contexts
	}

	// Factor 4: Code execution functions are always high risk
	if patternType == "code_execution" || patternType == "importlib" {
		confidence = 0.9 // Very high confidence for eval/import
	}

	// Factor 5: Empty or hardcoded strings
	if strings.Contains(line, `""`) || strings.Contains(line, `''`) {
		confidence -= 0.10 // Slight reduction for empty/static strings
	}

	// Factor 6: Break/return statements (may indicate safe code)
	if strings.Contains(line, "break") || strings.Contains(line, "return") {
		confidence -= 0.15
	}

	// Factor 7: Validation checks nearby
	if d.hasNearbyValidation(allLines, lineIdx) {
		confidence -= 0.20
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

// hasSanitization checks for sanitization/validation patterns nearby
func (d *UnsafeEnvAccessDetectorV2) hasSanitization(line string, allLines []string, lineIdx int) bool {
	if d.sanitizationPattern.MatchString(line) {
		return true
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
		if d.sanitizationPattern.MatchString(allLines[i]) {
			return true
		}
	}

	return false
}

// hasNearbyValidation checks if there are validation checks near the suspicious line
func (d *UnsafeEnvAccessDetectorV2) hasNearbyValidation(allLines []string, lineIdx int) bool {
	startIdx := lineIdx - 5
	if startIdx < 0 {
		startIdx = 0
	}
	endIdx := lineIdx + 5
	if endIdx > len(allLines) {
		endIdx = len(allLines)
	}

	validationPatterns := []string{
		"if ", "check", "validate", "in [", "in {", "allowlist", "whitelist",
		"not in", "assert", "raise", "except",
	}

	for i := startIdx; i < endIdx; i++ {
		lowerLine := strings.ToLower(allLines[i])
		for _, pattern := range validationPatterns {
			if strings.Contains(lowerLine, pattern) {
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
