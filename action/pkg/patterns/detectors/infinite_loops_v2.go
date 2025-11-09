package detectors

import (
	"regexp"
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// InfiniteLoopDetectorV2 detects infinite loop patterns in code
// Covers constant conditions, empty for loops, recursion without base cases
// and other patterns that lead to uncontrolled resource consumption
type InfiniteLoopDetectorV2 struct {
	pattern patterns.Pattern

	// PRIORITY 1: Critical infinite loop patterns
	whileTruePattern         *regexp.Regexp // while True:, while true, while(true)
	whileConstantPattern     *regexp.Regexp // while 1, while 1==1, while not False, etc.
	forEmptyConditionPattern *regexp.Regexp // for(;;), for {}
	forTruePattern           *regexp.Regexp // for(true), for true

	// PRIORITY 2: Advanced loop detection
	whileVariablePattern     *regexp.Regexp // while <var>: (needs break analysis)
	recursionPattern         *regexp.Regexp // function calling itself
	mutualRecursionPattern   *regexp.Regexp // A calls B, B calls A (harder to detect)

	// PRIORITY 3: Multi-language support
	rubyLoopPattern          *regexp.Regexp // loop { }, while true
	goInfinitePattern        *regexp.Regexp // for {
	javaWhilePattern         *regexp.Regexp // while(true)
	cStylePattern            *regexp.Regexp // while(1), for(;;)

	// False positive reduction
	breakPattern             *regexp.Regexp // break statement
	returnPattern            *regexp.Regexp // return statement
	sleepPattern             *regexp.Regexp // sleep, wait, select, accept, etc.
	eventLoopPattern         *regexp.Regexp // common event loop keywords
	exceptionPattern         *regexp.Regexp // except, catch, try blocks
}

// NewInfiniteLoopDetectorV2 creates a new V2 infinite loop detector
func NewInfiniteLoopDetectorV2() *InfiniteLoopDetectorV2 {
	return &InfiniteLoopDetectorV2{
		pattern: patterns.Pattern{
			ID:       "infinite-loops-v2",
			Name:     "Infinite Loops V2",
			Version:  "2.0",
			Category: "infinite_loops",
			Severity: "HIGH",
			CVSS:     7.5, // DoS vulnerability
			CWEIDs:   []string{"CWE-835", "CWE-400", "CWE-674"},
			OWASP:    "A06:2021 - Vulnerable and Outdated Components",
			Description: "Detects infinite loops, uncontrolled recursion, and loops with unreachable exit conditions that can lead to denial-of-service",
		},

		// PRIORITY 1: Critical patterns
		whileTruePattern:     regexp.MustCompile(`(?i)\bwhile\s+(?:True|true|1\b)\s*[:\(]`),
		whileConstantPattern: regexp.MustCompile(`(?i)\bwhile\s+(?:1\s*==\s*1|True\s*and\s*True|not\s+False|False\s*==\s*False|True\s*or)\s*[:\(]`),
		forEmptyConditionPattern: regexp.MustCompile(`\bfor\s*\(\s*;\s*;\s*\)|\bfor\s*\{\s*`),
		forTruePattern:       regexp.MustCompile(`(?i)\bfor\s*\(\s*(?:true|1)\s*\)`),

		// PRIORITY 2: Variable-based patterns
		whileVariablePattern: regexp.MustCompile(`(?i)\bwhile\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*:`),
		recursionPattern:     regexp.MustCompile(`(?i)(?:def|function|func|method)\s+\w+\s*\([^)]*\)\s*[:\{]`),

		// PRIORITY 3: Multi-language
		rubyLoopPattern:      regexp.MustCompile(`(?i)\bloop\s*(?:\{|do)|\bwhile\s+true`),
		goInfinitePattern:    regexp.MustCompile(`\bfor\s*\{\s*`),
		javaWhilePattern:     regexp.MustCompile(`(?i)\bwhile\s*\(\s*true\s*\)`),
		cStylePattern:        regexp.MustCompile(`(?i)\bwhile\s*\(\s*(?:1|true)\s*\)|\bfor\s*\(\s*;\s*;\s*\)`),

		// False positive reduction patterns
		breakPattern:         regexp.MustCompile(`\b(?:break|return|exit|quit|sys\.exit)\b`),
		returnPattern:        regexp.MustCompile(`\breturn\b`),
		sleepPattern:         regexp.MustCompile(`(?i)(?:sleep|wait|select|accept|receive|listen|\.sleep\(|time\.sleep|Thread\.sleep|Thread\.wait|await|async|select\{)`),
		eventLoopPattern:     regexp.MustCompile(`(?i)(?:server|daemon|listener|handler|event_loop|main_loop|run_server|accept_connection|event|reactor|dispatch)`),
		exceptionPattern:     regexp.MustCompile(`(?i)(?:except|catch|try|raise|throw|error|exception)`),
	}
}

// Name returns detector name
func (d *InfiniteLoopDetectorV2) Name() string {
	return d.pattern.Name
}

// GetPattern returns the pattern metadata
func (d *InfiniteLoopDetectorV2) GetPattern() patterns.Pattern {
	return d.pattern
}

// GetConfidence returns detector confidence
func (d *InfiniteLoopDetectorV2) GetConfidence() float32 {
	return 0.85
}

// Detect scans for infinite loops
func (d *InfiniteLoopDetectorV2) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
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
		// Skip comments and empty lines
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}

		// Check for infinite loop patterns
		loopFindings := d.scanLine(line, i+1, filePath, lines, i)
		findings = append(findings, loopFindings...)
	}

	return findings, nil
}

// scanLine checks a single line for infinite loop patterns
func (d *InfiniteLoopDetectorV2) scanLine(line string, lineNum int, filePath string, allLines []string, lineIdx int) []patterns.Finding {
	var findings []patterns.Finding

	// PRIORITY 1: While True patterns
	if d.whileTruePattern.MatchString(line) {
		confidence := d.analyzeLoopConfidence(line, allLines, lineIdx, filePath, "while_true")
		if confidence > 0.5 {
			findings = append(findings, d.createFinding(line, lineNum, filePath, "HIGH", confidence, "Infinite loop detected: while True with no exit condition")...)
		}
	}

	// PRIORITY 1: While with constant conditions
	if d.whileConstantPattern.MatchString(line) && !strings.Contains(line, "while True") {
		confidence := d.analyzeLoopConfidence(line, allLines, lineIdx, filePath, "while_constant")
		if confidence > 0.5 {
			findings = append(findings, d.createFinding(line, lineNum, filePath, "HIGH", confidence, "Infinite loop detected: constant while condition")...)
		}
	}

	// PRIORITY 1: For loops with empty conditions
	if d.forEmptyConditionPattern.MatchString(line) {
		confidence := d.analyzeLoopConfidence(line, allLines, lineIdx, filePath, "for_empty")
		if confidence > 0.5 {
			findings = append(findings, d.createFinding(line, lineNum, filePath, "HIGH", confidence, "Infinite loop detected: for(;;) or for{}")...)
		}
	}

	// PRIORITY 1: For True patterns
	if d.forTruePattern.MatchString(line) {
		confidence := d.analyzeLoopConfidence(line, allLines, lineIdx, filePath, "for_true")
		if confidence > 0.5 {
			findings = append(findings, d.createFinding(line, lineNum, filePath, "HIGH", confidence, "Infinite loop detected: for(true)")...)
		}
	}

	// PRIORITY 2: While with variable (check if variable is modified)
	if d.whileVariablePattern.MatchString(line) && !d.whileTruePattern.MatchString(line) {
		confidence := d.analyzeLoopConfidence(line, allLines, lineIdx, filePath, "while_var")
		if confidence > 0.6 {
			findings = append(findings, d.createFinding(line, lineNum, filePath, "MEDIUM", confidence, "Potential infinite loop: variable condition not modified in loop")...)
		}
	}

	// PRIORITY 3: Ruby loop pattern
	if d.rubyLoopPattern.MatchString(line) {
		confidence := d.analyzeLoopConfidence(line, allLines, lineIdx, filePath, "ruby_loop")
		if confidence > 0.5 {
			findings = append(findings, d.createFinding(line, lineNum, filePath, "HIGH", confidence, "Infinite loop detected: Ruby loop construct")...)
		}
	}

	// PRIORITY 3: Go infinite pattern
	if d.goInfinitePattern.MatchString(line) && strings.Contains(filePath, ".go") {
		confidence := d.analyzeLoopConfidence(line, allLines, lineIdx, filePath, "go_infinite")
		if confidence > 0.5 {
			findings = append(findings, d.createFinding(line, lineNum, filePath, "HIGH", confidence, "Infinite loop detected: for{}")...)
		}
	}

	// PRIORITY 3: Java while(true)
	if d.javaWhilePattern.MatchString(line) {
		confidence := d.analyzeLoopConfidence(line, allLines, lineIdx, filePath, "java_while")
		if confidence > 0.5 {
			findings = append(findings, d.createFinding(line, lineNum, filePath, "HIGH", confidence, "Infinite loop detected: while(true)")...)
		}
	}

	// PRIORITY 3: C-style patterns (while(1), for(;;))
	if d.cStylePattern.MatchString(line) && !d.whileTruePattern.MatchString(line) && !d.forEmptyConditionPattern.MatchString(line) {
		confidence := d.analyzeLoopConfidence(line, allLines, lineIdx, filePath, "c_style")
		if confidence > 0.5 {
			findings = append(findings, d.createFinding(line, lineNum, filePath, "HIGH", confidence, "Infinite loop detected: C-style loop")...)
		}
	}

	return findings
}

// analyzeLoopConfidence calculates confidence based on loop context
func (d *InfiniteLoopDetectorV2) analyzeLoopConfidence(line string, allLines []string, lineIdx int, filePath string, loopType string) float32 {
	confidence := float32(0.8) // Base confidence for loop pattern

	// Check for break/return in next few lines (simple lookahead)
	hasBreakOrReturn := d.hasBreakOrReturnNearby(allLines, lineIdx)
	if hasBreakOrReturn {
		confidence -= 0.35 // Strong reduction if break/return found
	}

	// Check for sleep/wait patterns (intentional loops)
	hasSleepOrWait := d.sleepPattern.MatchString(line)
	if hasSleepOrWait {
		confidence -= 0.25 // Reduces for intentional delay loops
	}

	// Check context (filenames, function names suggesting intentional)
	if d.isIntentionalLoopContext(line, filePath) {
		confidence -= 0.25 // Server loops, event handlers, etc.
	}

	// Check for recursion
	if d.recursionPattern.MatchString(line) {
		if !d.hasBaseCase(allLines, lineIdx) {
			confidence = 0.9 // High confidence for recursion without base case
		}
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

// hasBreakOrReturnNearby checks if there's a break/return within next 10 lines
func (d *InfiniteLoopDetectorV2) hasBreakOrReturnNearby(allLines []string, loopStartIdx int) bool {
	endIdx := loopStartIdx + 10
	if endIdx > len(allLines) {
		endIdx = len(allLines)
	}

	for i := loopStartIdx + 1; i < endIdx; i++ {
		line := allLines[i]
		trimmed := strings.TrimSpace(line)

		// Skip empty lines and comments
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}

		if d.breakPattern.MatchString(trimmed) {
			return true
		}

		// Also check for exception handling
		if d.exceptionPattern.MatchString(trimmed) {
			return true
		}
	}

	return false
}

// isIntentionalLoopContext checks if loop is in a known benign context
func (d *InfiniteLoopDetectorV2) isIntentionalLoopContext(line string, filePath string) bool {
	// Check filename
	lowerPath := strings.ToLower(filePath)
	if strings.Contains(lowerPath, "server") ||
		strings.Contains(lowerPath, "daemon") ||
		strings.Contains(lowerPath, "listener") ||
		strings.Contains(lowerPath, "handler") ||
		strings.Contains(lowerPath, "main") {
		return true
	}

	// Check function name in line
	if d.eventLoopPattern.MatchString(line) {
		return true
	}

	// Check for common event loop keywords
	lowerLine := strings.ToLower(line)
	if strings.Contains(lowerLine, "accept") ||
		strings.Contains(lowerLine, "select") ||
		strings.Contains(lowerLine, "reactor") ||
		strings.Contains(lowerLine, "dispatch") {
		return true
	}

	return false
}

// hasBaseCase checks if a recursive function has a base case
func (d *InfiniteLoopDetectorV2) hasBaseCase(allLines []string, funcStartIdx int) bool {
	// Simple heuristic: look for if/return pattern in next 20 lines
	endIdx := funcStartIdx + 20
	if endIdx > len(allLines) {
		endIdx = len(allLines)
	}

	for i := funcStartIdx; i < endIdx; i++ {
		line := allLines[i]
		trimmed := strings.TrimSpace(line)

		// Look for base case indicators
		if (strings.Contains(trimmed, "if") && strings.Contains(trimmed, "return")) ||
			(strings.Contains(trimmed, "if") && strings.Contains(trimmed, "break")) ||
			(strings.Contains(trimmed, "if") && strings.Contains(trimmed, ">") && strings.Contains(trimmed, "return")) ||
			(strings.Contains(trimmed, "if") && strings.Contains(trimmed, "<") && strings.Contains(trimmed, "return")) {
			return true
		}
	}

	return false
}

// createFinding creates a Finding with the given parameters
func (d *InfiniteLoopDetectorV2) createFinding(line string, lineNum int, filePath string, severity string, confidence float32, message string) []patterns.Finding {
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
