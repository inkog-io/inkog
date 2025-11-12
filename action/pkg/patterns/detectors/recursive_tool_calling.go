package detectors

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// RecursiveToolCallingDetector detects recursive function calls and agent delegation loops
// This pattern identifies infinite recursion, mutual recursion, and unbounded agent loops
type RecursiveToolCallingDetector struct {
	pattern patterns.Pattern
}

func NewRecursiveToolCallingDetector() patterns.Detector {
	return &RecursiveToolCallingDetector{
		pattern: patterns.Pattern{
			ID:          "recursive_tool_calling",
			Name:        "Recursive Tool Calling",
			Version:     "1.0",
			Category:    "resource_exhaustion",
			Severity:    "CRITICAL",
			CVSS:        8.2,
			CWEIDs:      []string{"CWE-674", "CWE-835"},
			OWASP:       "A05:2021 Broken Access Control",
			Description: "Detects recursive function/agent calls leading to infinite loops and DoS",
		},
	}
}

func (d *RecursiveToolCallingDetector) Name() string {
	return "recursive_tool_calling"
}

// Detect finds recursive tool calling vulnerabilities
func (d *RecursiveToolCallingDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	findings := []patterns.Finding{}
	sourceStr := string(src)
	lines := strings.Split(sourceStr, "\n")

	// Pattern 1: Direct recursion detection
	findings = append(findings, d.detectDirectRecursion(lines, filePath)...)

	// Pattern 2: Unbounded agent loops
	findings = append(findings, d.detectUnboundedAgentLoops(lines, filePath)...)

	// Pattern 3: Agent delegation loops
	findings = append(findings, d.detectAgentDelegationLoops(lines, filePath)...)

	return findings, nil
}

// detectDirectRecursion looks for functions that call themselves without clear base cases
func (d *RecursiveToolCallingDetector) detectDirectRecursion(lines []string, filePath string) []patterns.Finding {
	findings := []patterns.Finding{}
	functionRegex := regexp.MustCompile(`(?i)^(def|func|function)\s+(\w+)`)

	// Map function names to their line numbers and their recursive calls
	functions := make(map[string][]int) // function name -> line numbers where it calls itself

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}

		// Find function definitions
		matches := functionRegex.FindStringSubmatch(line)
		if len(matches) > 2 {
			funcName := matches[2]

			// Look ahead to see if this function calls itself
			hasBaseCase := false
			hasRecursiveCall := false
			hasIfStatement := false

			for j := i + 1; j < len(lines) && j < i+30; j++ {
				checkLine := strings.TrimSpace(lines[j])

				// Stop at next function definition
				if (strings.HasPrefix(checkLine, "def ") || strings.HasPrefix(checkLine, "func ")) && j > i {
					break
				}

				// Track if statements (potential guard conditions for base case)
				if strings.HasPrefix(checkLine, "if ") || strings.Contains(checkLine, ": if ") {
					hasIfStatement = true
				}

				// Check for base case - must have:
				// 1. An if statement (guard condition)
				// 2. A return/break in that if block (not the recursive call)
				// A base case is like: if n <= 1: return 1
				// NOT: return func(n-1) which is the recursive call
				if hasIfStatement && (strings.Contains(checkLine, "return") || strings.Contains(checkLine, "break")) {
					// Make sure this return/break is NOT the recursive call itself
					if !strings.Contains(checkLine, funcName+"(") {
						hasBaseCase = true
						hasIfStatement = false // Reset for next potential base case
					}
				}

				// Check for recursive call (but skip if it's inside a return on first recursion line)
				if strings.Contains(checkLine, funcName+"(") {
					hasRecursiveCall = true
					functions[funcName] = append(functions[funcName], j)
				}
			}

			// Flag as vulnerable if recursion without clear base case
			if hasRecursiveCall && !hasBaseCase {
				for _, lineNum := range functions[funcName] {
					finding := patterns.Finding{
						ID:         fmt.Sprintf("recursive_tool_calling_%d_%s", lineNum+1, funcName),
						PatternID:  d.pattern.ID,
						Pattern:    d.pattern.Name,
						File:       filePath,
						Line:       lineNum + 1,
						Column:     1,
						Severity:   "CRITICAL",
						Confidence: 0.90,
						Message:    fmt.Sprintf("Function '%s' calls itself recursively without clear base case", funcName),
						Code:       strings.TrimSpace(lines[lineNum]),
						CWE:        "CWE-674",
						CVSS:       8.2,
						OWASP:      "A05:2021",
					}
					findings = append(findings, finding)
				}
			}
		}
	}

	return findings
}

// detectUnboundedAgentLoops finds while/for loops that call agent methods without limits
func (d *RecursiveToolCallingDetector) detectUnboundedAgentLoops(lines []string, filePath string) []patterns.Finding {
	findings := []patterns.Finding{}

	loopRegex := regexp.MustCompile(`(?i)while\s*\(\s*(true|True|1)\s*\)|while\s+(True|true):|for\s*\{|\bfor\s*\(\s*;\s*;\s*\)`)
	agentRegex := regexp.MustCompile(`(?i)(agent|tool|assistant|executor|worker)\s*\.\s*(run|execute|invoke|call|act|work|process)`)

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}

		// Look for loops
		if loopRegex.MatchString(line) {
			// Check inside loop for agent calls and exit conditions
			hasAgentCall := false
			hasExitCondition := false

			for j := i + 1; j < len(lines) && j < i+20; j++ {
				checkLine := strings.TrimSpace(lines[j])

				// Stop if we hit another loop or function
				if (loopRegex.MatchString(checkLine) || strings.Contains(checkLine, "def ") || strings.Contains(checkLine, "func ")) && j > i {
					break
				}

				// Check for agent call
				if agentRegex.MatchString(checkLine) {
					hasAgentCall = true
				}

				// Check for exit condition
				if strings.Contains(checkLine, "break") || strings.Contains(checkLine, "return") ||
					strings.Contains(checkLine, "if ") && (strings.Contains(checkLine, "break") || strings.Contains(checkLine, "return")) {
					hasExitCondition = true
					break
				}
			}

			// If we have agent call but no exit, flag it
			if hasAgentCall && !hasExitCondition {
				finding := patterns.Finding{
					ID:         fmt.Sprintf("recursive_tool_calling_%d_unbounded_loop", i+1),
					PatternID:  d.pattern.ID,
					Pattern:    d.pattern.Name,
					File:       filePath,
					Line:       i + 1,
					Column:     1,
					Severity:   "CRITICAL",
					Confidence: 0.92,
					Message:    "Unbounded loop calling agent/tool without exit condition - potential infinite loop",
					Code:       strings.TrimSpace(line),
					CWE:        "CWE-835",
					CVSS:       8.2,
					OWASP:      "A05:2021",
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// detectAgentDelegationLoops finds multiple agents with delegation enabled (CrewAI pattern)
func (d *RecursiveToolCallingDetector) detectAgentDelegationLoops(lines []string, filePath string) []patterns.Finding {
	findings := []patterns.Finding{}

	delegationRegex := regexp.MustCompile(`(?i)(allow_delegation\s*=\s*[Tt]rue|allow_delegation\s*=\s*true|delegate\s*=\s*[Tt]rue)`)
	agentRegex := regexp.MustCompile(`(?i)(agent|Agent|crew|Crew)\s*\(`)

	delegationCount := 0
	delegationLines := []int{}

	for i, line := range lines {
		// Count agents with delegation enabled
		if delegationRegex.MatchString(line) {
			delegationCount++
			delegationLines = append(delegationLines, i)
		}

		// Also look for agent definitions
		if agentRegex.MatchString(line) && i > 0 {
			// Check if this agent has delegation enabled in following lines
			for j := i; j < len(lines) && j < i+5; j++ {
				if delegationRegex.MatchString(lines[j]) {
					delegationCount++
					delegationLines = append(delegationLines, j)
				}
			}
		}
	}

	// If multiple agents with delegation, flag as potential delegation loop
	if delegationCount >= 2 {
		finding := patterns.Finding{
			ID:         fmt.Sprintf("recursive_tool_calling_%d_delegation", delegationLines[0]+1),
			PatternID:  d.pattern.ID,
			Pattern:    d.pattern.Name,
			File:       filePath,
			Line:       delegationLines[0] + 1,
			Column:     1,
			Severity:   "HIGH",
			Confidence: 0.85,
			Message:    fmt.Sprintf("Multiple agents with delegation enabled (%d agents) - potential agent delegation loop", delegationCount),
			Code:       strings.TrimSpace(lines[delegationLines[0]]),
			CWE:        "CWE-835",
			CVSS:       7.5,
			OWASP:      "A05:2021",
		}
		findings = append(findings, finding)
	}

	return findings
}

func (d *RecursiveToolCallingDetector) GetPattern() patterns.Pattern {
	return d.pattern
}

func (d *RecursiveToolCallingDetector) GetConfidence() float32 {
	return 0.88
}

func (d *RecursiveToolCallingDetector) Close() error {
	return nil
}
