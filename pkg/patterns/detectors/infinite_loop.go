package detectors

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// InfiniteLoopDetector detects while True loops that could cause unbounded resource consumption
type InfiniteLoopDetector struct {
	pattern    patterns.Pattern
	confidence float32
	regex      *regexp.Regexp
}

// NewInfiniteLoopDetector creates a new infinite loop detector
func NewInfiniteLoopDetector() *InfiniteLoopDetector {
	pattern := patterns.Pattern{
		ID:       "infinite_loop",
		Name:     "Infinite Loop in Agent Execution",
		Version:  "1.0",
		Category: "resource_exhaustion",
		Severity: "HIGH",
		CVSS:     7.5,
		CWEIDs:   []string{"CWE-835", "CWE-400"},
		OWASP:    "LLM10",
		Description: "Unbounded loops (while True) without proper termination conditions cause exponential token consumption, API cost explosion, and DoS",
		Remediation: "Add max_iterations, max_execution_time, break conditions, and timeout parameters to all loops",
		FinancialImpact: struct {
			Severity    string
			Description string
			RiskPerYear float32
		}{
			Severity:    "CRITICAL",
			Description: "Escalated from $5K to $50K monthly API costs (10x) in production incidents",
			RiskPerYear: 500000,
		},
	}

	// Match: while True:, while true:, while 1:
	regex := regexp.MustCompile(`while\s+(True|true|1)\s*:`)

	return &InfiniteLoopDetector{
		pattern:    pattern,
		confidence: 0.95,
		regex:      regex,
	}
}

// Name returns the detector name
func (d *InfiniteLoopDetector) Name() string {
	return "infinite_loop"
}

// GetPattern returns the pattern metadata
func (d *InfiniteLoopDetector) GetPattern() patterns.Pattern {
	return d.pattern
}

// GetConfidence returns confidence score
func (d *InfiniteLoopDetector) GetConfidence() float32 {
	return d.confidence
}

// Detect analyzes code for infinite loops
func (d *InfiniteLoopDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	var findings []patterns.Finding

	// Skip unsupported files
	if !isSupportedFile(filePath) {
		return findings, nil
	}

	// Skip test files
	if isTestFile(filePath) {
		return findings, nil
	}

	lines := strings.Split(string(src), "\n")

	for i, line := range lines {
		// Check for infinite loop pattern
		if d.regex.MatchString(line) {
			// Check if there's a break condition or max_iterations in the following lines
			hasBreakCondition := d.hasBreakCondition(lines, i)

			if !hasBreakCondition {
				finding := patterns.Finding{
					ID:            fmt.Sprintf("infinite_loop_%d_%s", i, filePath),
					PatternID:     d.pattern.ID,
					Pattern:       d.pattern.Name,
					File:          filePath,
					Line:          i + 1,
					Column:        strings.Index(line, "while") + 1,
					Message:       "Infinite loop detected: while True without break condition or iteration limit",
					Code:          line,
					Severity:      d.pattern.Severity,
					Confidence:    d.confidence,
					CWE:           "CWE-835",
					CVSS:          d.pattern.CVSS,
					OWASP:         d.pattern.OWASP,
					FinancialRisk: "$500/hour in API costs during uncontrolled loops",
				}

				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// hasBreakCondition checks if the loop body has a break, max_iterations, or timeout
func (d *InfiniteLoopDetector) hasBreakCondition(lines []string, loopStartIndex int) bool {
	// Check the next 20 lines for break conditions
	maxLinesAhead := 20
	if loopStartIndex+maxLinesAhead > len(lines) {
		maxLinesAhead = len(lines) - loopStartIndex
	}

	breakPatterns := []string{
		"break",
		"max_iterations",
		"max_execution_time",
		"early_stopping",
		"timeout",
		"return",
		"raise",
	}

	for j := loopStartIndex + 1; j < loopStartIndex+maxLinesAhead; j++ {
		line := strings.ToLower(lines[j])

		for _, pattern := range breakPatterns {
			if strings.Contains(line, pattern) {
				return true
			}
		}

		// Stop looking if we find another loop or function definition (different block)
		if strings.Contains(line, "for ") || strings.Contains(line, "while ") ||
			strings.Contains(line, "def ") || strings.Contains(line, "class ") {
			break
		}
	}

	return false
}
