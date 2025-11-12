package detectors

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

type RecursiveToolCallingDetectorV2Clean struct {
	pattern patterns.Pattern

	functionDefPattern   *regexp.Regexp
	recursiveCallPattern *regexp.Regexp
	selfCallPattern      *regexp.Regexp
	agentRunPattern      *regexp.Regexp
	agentDelegatePattern *regexp.Regexp
	whilePattern         *regexp.Regexp
	forPattern           *regexp.Regexp
}

func NewRecursiveToolCallingDetectorV2Clean() patterns.Detector {
	return &RecursiveToolCallingDetectorV2Clean{
		pattern: patterns.Pattern{
			ID:       "recursive_tool_calling_v2",
			Name:     "Recursive Tool Calling",
			Version:  "2.0",
			Category: "Resource Exhaustion",
			Severity: "CRITICAL",
			CVSS:     8.2,
			CWEIDs:   []string{"CWE-674", "CWE-835"},
			OWASP:    "A05:2021",
			Description: "Detects recursive function/agent calls leading to infinite loops and DoS",
		},
		functionDefPattern:   regexp.MustCompile(`(?i)^def\s+(\w+)|^func\s+(\w+)\s*\(|function\s+(\w+)\s*\(`),
		recursiveCallPattern: regexp.MustCompile(`(?i)self\.(\w+)\(|(\w+)\(.*?self`),
		selfCallPattern:      regexp.MustCompile(`(?i)this\.(\w+)\(|(\w+)\.invoke\(\s*\)`),
		agentRunPattern:      regexp.MustCompile(`(?i)(agent|tool|assistant)\.run\(|\.execute\(\)|\.invoke\(\)`),
		agentDelegatePattern: regexp.MustCompile(`(?i)allow_delegation\s*=\s*[Tt]rue|delegate\s*=\s*[Tt]rue`),
		whilePattern:         regexp.MustCompile(`while\s*\(\s*(true|True|1)\s*\)|while\s+\bTrue\b`),
		forPattern:           regexp.MustCompile(`for\s*\{|for\s*\(\s*;;\s*\)`),
	}
}

func (d *RecursiveToolCallingDetectorV2Clean) Name() string {
	return "recursive_tool_calling_v2"
}

func (d *RecursiveToolCallingDetectorV2Clean) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	findings := []patterns.Finding{}
	sourceStr := string(src)
	lines := strings.Split(sourceStr, "\n")

	// Check for direct recursion
	functionMap := d.buildFunctionCallMap(lines)
	for funcName, callLines := range functionMap {
		for _, callLineNum := range callLines {
			confidence := float32(0.80)

			if d.isDataProcessorName(funcName) {
				confidence -= 0.25
			}

			if d.hasTerminationCondition(lines, callLineNum) {
				confidence -= 0.20
			}

			if confidence >= 0.60 {
				finding := patterns.Finding{
					ID:         fmt.Sprintf("recursive_tool_calling_%d_%s", callLineNum+1, funcName),
					PatternID:  d.pattern.ID,
					Pattern:    d.pattern.Name,
					File:       filePath,
					Line:       callLineNum + 1,
					Column:     1,
					Severity:   "CRITICAL",
					Confidence: confidence,
					Message:    fmt.Sprintf("Function '%s' calls itself recursively", funcName),
					Code:       lines[callLineNum],
					CWE:        "CWE-674",
					CVSS:       8.2,
					OWASP:      "A05:2021",
				}
				findings = append(findings, finding)
			}
		}
	}

	// Check for agent delegation loops
	delegationCount := 0
	for _, line := range lines {
		if d.agentDelegatePattern.MatchString(line) {
			delegationCount++
		}
	}

	if delegationCount >= 2 {
		for lineNum, line := range lines {
			if d.agentDelegatePattern.MatchString(line) {
				finding := patterns.Finding{
					ID:         fmt.Sprintf("recursive_tool_calling_%d_%s", lineNum+1, "agent_delegation"),
					PatternID:  d.pattern.ID,
					Pattern:    d.pattern.Name,
					File:       filePath,
					Line:       lineNum + 1,
					Column:     1,
					Severity:   "HIGH",
					Confidence: 0.80,
					Message:    "Multiple agents with delegation enabled - potential delegation loop",
					Code:       line,
					CWE:        "CWE-835",
					CVSS:       7.5,
					OWASP:      "A05:2021",
				}
				findings = append(findings, finding)
				break
			}
		}
	}

	// Check for unbounded while loops calling agent/tool methods
	for lineNum, line := range lines {
		if d.whilePattern.MatchString(line) {
			hasAgentCall := false
			hasBreak := false

			for j := lineNum + 1; j < len(lines) && j < lineNum+15; j++ {
				if d.agentRunPattern.MatchString(lines[j]) {
					hasAgentCall = true
				}
				if strings.Contains(lines[j], "break") || strings.Contains(lines[j], "return") {
					hasBreak = true
					break
				}
				if d.whilePattern.MatchString(lines[j]) || d.forPattern.MatchString(lines[j]) {
					break
				}
			}

			if hasAgentCall && !hasBreak {
				finding := patterns.Finding{
					ID:         fmt.Sprintf("recursive_tool_calling_%d_%s", lineNum+1, "while_loop"),
					PatternID:  d.pattern.ID,
					Pattern:    d.pattern.Name,
					File:       filePath,
					Line:       lineNum + 1,
					Column:     1,
					Severity:   "CRITICAL",
					Confidence: 0.85,
					Message:    "Unbounded while loop calling agent/tool without break",
					Code:       line,
					CWE:        "CWE-835",
					CVSS:       8.2,
					OWASP:      "A05:2021",
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

func (d *RecursiveToolCallingDetectorV2Clean) buildFunctionCallMap(lines []string) map[string][]int {
	funcMap := make(map[string][]int)
	var currentFunc string

	for lineNum, line := range lines {
		if matches := d.functionDefPattern.FindStringSubmatch(line); matches != nil {
			for i := 1; i < len(matches); i++ {
				if matches[i] != "" {
					currentFunc = matches[i]
					break
				}
			}
		}

		if currentFunc != "" && d.selfCallPattern.MatchString(line) {
			if strings.Contains(line, currentFunc) {
				funcMap[currentFunc] = append(funcMap[currentFunc], lineNum)
			}
		}
	}

	return funcMap
}

func (d *RecursiveToolCallingDetectorV2Clean) hasTerminationCondition(lines []string, lineNum int) bool {
	for i := lineNum; i >= 0 && i > lineNum-5; i-- {
		if strings.Contains(lines[i], "if ") && (strings.Contains(lines[i], "return") || strings.Contains(lines[i], "break")) {
			return true
		}
	}
	return false
}

func (d *RecursiveToolCallingDetectorV2Clean) isDataProcessorName(name string) bool {
	dataProcessors := []string{"map", "filter", "reduce", "fold", "traverse", "walk", "visit", "process"}
	nameLower := strings.ToLower(name)
	for _, proc := range dataProcessors {
		if strings.Contains(nameLower, proc) {
			return true
		}
	}
	return false
}

func (d *RecursiveToolCallingDetectorV2Clean) GetPattern() patterns.Pattern {
	return d.pattern
}

func (d *RecursiveToolCallingDetectorV2Clean) GetConfidence() float32 {
	return 0.82
}

func (d *RecursiveToolCallingDetectorV2Clean) Close() error {
	return nil
}
