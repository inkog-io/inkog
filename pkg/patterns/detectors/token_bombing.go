package detectors

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
	"github.com/inkog-io/inkog/action/pkg/patterns/metadata"
)

// TokenBombingDetector detects unbounded token consumption in LLM API calls
// This pattern identifies calls to LLM APIs that lack token limits in loops or unbounded contexts
type TokenBombingDetector struct {
	pattern patterns.Pattern
}

func NewTokenBombingDetector() patterns.Detector {
	return &TokenBombingDetector{
		pattern: patterns.Pattern{
			ID:          "token_bombing",
			Name:        "Token Bombing Attack",
			Version:     "1.0",
			Category:    "resource_exhaustion",
			Severity:    "HIGH",
			CVSS:        7.5,
			CWEIDs:      []string{"CWE-770", "CWE-834"},
			OWASP:       "A01:2021 Broken Access Control",
			Description: "Detects unbounded token consumption in LLM API calls causing DoS or runaway costs",
		},
	}
}

func (d *TokenBombingDetector) Name() string {
	return "token_bombing"
}

// GetPatternID returns the canonical detector ID (implements Detector interface)
func (d *TokenBombingDetector) GetPatternID() string {
	return metadata.ID_TOKEN_BOMBING
}

// Detect finds token bombing vulnerabilities in source code
func (d *TokenBombingDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	findings := []patterns.Finding{}
	sourceStr := string(src)
	lines := strings.Split(sourceStr, "\n")

	// Common LLM API patterns and their libraries
	llmPatterns := map[string]*regexp.Regexp{
		"OpenAI":    regexp.MustCompile(`(?i)(openai|ChatGPT|GPT|gpt-[0-9]|text-davinci|gpt\.chat|gpt\.create|completion|chat\.completion)`),
		"Anthropic": regexp.MustCompile(`(?i)(anthropic|claude|claude-[0-9]|messages\.create|message\.create)`),
		"Google":    regexp.MustCompile(`(?i)(google|palm|bard|generativeai|generate|GenerateContent)`),
		"Ollama":    regexp.MustCompile(`(?i)(ollama|local.*model|localhost.*11434)`),
		"Cohere":    regexp.MustCompile(`(?i)(cohere|co\.generate|generate_text)`),
	}

	// Token limit patterns
	tokenLimitPatterns := []string{
		"max_tokens", "maxTokens", "max_length", "maxLength",
		"token_limit", "tokenLimit", "limit", "max_output_tokens",
	}

	// Identify loops and unbounded contexts
	loopPatterns := map[string]*regexp.Regexp{
		"while_true":    regexp.MustCompile(`(?i)while\s*\(\s*(true|True|1|1\.0)\s*\)`),
		"while_true_py": regexp.MustCompile(`(?i)while\s+(True|true):`),
		"for_empty":     regexp.MustCompile(`for\s*\{|\bfor\s*\(\s*;\s*;\s*\)`),
		"recursive":     regexp.MustCompile(`(?i)def\s+\w+|func\s+\w+|function\s+\w+`), // function definitions
	}

	// Patterns for BOUNDED loops (safe to use with LLM calls)
	boundedLoopPatterns := map[string]*regexp.Regexp{
		"for_range":     regexp.MustCompile(`(?i)for\s+\w+\s+in\s+range\s*\(`),      // Python: for i in range(n)
		"for_length":    regexp.MustCompile(`(?i)for\s+\w+\s+in\s+range\s*\(\s*len`), // Python: for i in range(len(...))
		"for_collection": regexp.MustCompile(`(?i)for\s+\w+\s+in\s+[a-zA-Z_]\w*`),    // Python: for item in collection
		"for_C_style":   regexp.MustCompile(`for\s*\(\s*\w+\s*=\s*0\s*;\s*\w+\s*<`),  // C-style: for(int i=0; i<n; i++)
	}

	// Track function contexts for recursion
	functionStack := map[string][]int{}
	var currentFunc string

	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}

		// Track function definitions
		if strings.Contains(line, "def ") || strings.Contains(line, "func ") {
			// Extract function name from "def func_name(...)" or "func funcname(...)"
			var funcName string
			if strings.Contains(line, "def ") {
				// Python: def func_name(...)
				parts := strings.Split(line, "def ")
				if len(parts) > 1 {
					rest := strings.TrimSpace(parts[1])
					// Split by '(' to get the function name
					nameParts := strings.Split(rest, "(")
					if len(nameParts) > 0 {
						funcName = strings.TrimSpace(nameParts[0])
					}
				}
			} else if strings.Contains(line, "func ") {
				// Go: func funcname(...) or func (receiver) funcname(...)
				parts := strings.Split(line, "func ")
				if len(parts) > 1 {
					rest := strings.TrimSpace(parts[1])
					// Handle receiver method: "func (receiver) funcname"
					if strings.HasPrefix(rest, "(") {
						// Find closing paren
						closeIdx := strings.Index(rest, ")")
						if closeIdx != -1 {
							rest = strings.TrimSpace(rest[closeIdx+1:])
						}
					}
					// Split by '(' to get the function name
					nameParts := strings.Split(rest, "(")
					if len(nameParts) > 0 {
						funcName = strings.TrimSpace(nameParts[0])
					}
				}
			}

			if funcName != "" {
				currentFunc = funcName
				functionStack[currentFunc] = append(functionStack[currentFunc], lineNum)
			}
		}

		// Check if line contains LLM API call
		hasLLMCall := false
		llmProvider := ""
		for provider, pattern := range llmPatterns {
			if pattern.MatchString(line) {
				hasLLMCall = true
				llmProvider = provider
				break
			}
		}

		if !hasLLMCall {
			continue
		}

		// Check if this LLM call has token limit protection (check surrounding lines too)
		hasTokenLimit := false
		// Check current line and nearby lines for token limits (multi-line function calls)
		// Start from a few lines before to catch function parameters, go several lines after
		startCheck := lineNum - 2
		if startCheck < 0 {
			startCheck = 0
		}
		endCheck := lineNum + 3
		if endCheck > len(lines) {
			endCheck = len(lines)
		}

		for i := startCheck; i < endCheck && i >= 0; i++ {
			for _, limitPattern := range tokenLimitPatterns {
				if strings.Contains(lines[i], limitPattern) {
					hasTokenLimit = true
					break
				}
			}
			if hasTokenLimit {
				break
			}
		}

		if hasTokenLimit {
			continue // Token limit specified, not vulnerable
		}

		// Check if we're in a BOUNDED loop first (these are safe)
		inBoundedLoop := d.isInBoundedLoop(lines, lineNum, boundedLoopPatterns)
		if inBoundedLoop {
			continue // Bounded loops are safe, skip this LLM call
		}

		// Check if we're in an unbounded context
		inUnboundedLoop := d.isInUnboundedLoop(lines, lineNum, loopPatterns)
		isRecursive := d.isRecursiveCall(lines, lineNum, currentFunc, llmPatterns)

		if inUnboundedLoop || isRecursive {
			confidence := float32(0.80)
			severity := "HIGH"

			// Unbounded loop alone should be CRITICAL with high confidence
			if inUnboundedLoop {
				confidence = 0.88
				severity = "CRITICAL"
			}

			// Recursive call alone should also have high confidence
			if isRecursive && !inUnboundedLoop {
				confidence = 0.88
				severity = "HIGH"
			}

			// Increase confidence if both conditions present
			if inUnboundedLoop && isRecursive {
				confidence = 0.95
				severity = "CRITICAL"
			}

			message := fmt.Sprintf("LLM API call (%s) without token limits in unbounded context", llmProvider)
			if isRecursive {
				message = fmt.Sprintf("LLM API call (%s) without token limits in recursive context", llmProvider)
			}

			finding := patterns.Finding{
				ID:         fmt.Sprintf("token_bombing_%d_%s", lineNum+1, llmProvider),
				PatternID:  d.pattern.ID,
				Pattern:    d.pattern.Name,
				File:       filePath,
				Line:       lineNum + 1,
				Column:     1,
				Severity:   severity,
				Confidence: confidence,
				Message:    message,
				Code:       strings.TrimSpace(line),
				CWE:        "CWE-770",
				CVSS:       7.5,
				OWASP:      "A01:2021",
			}
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// isInUnboundedLoop checks if a line is within an unbounded loop
func (d *TokenBombingDetector) isInUnboundedLoop(lines []string, currentLine int, loopPatterns map[string]*regexp.Regexp) bool {
	// Look backward from current line to find a loop start
	for i := currentLine; i >= 0 && i > currentLine-50; i-- {
		line := lines[i]

		// Check for loop patterns
		for _, pattern := range loopPatterns {
			if pattern.MatchString(line) {
				// Found a loop, now check if it has break/return anywhere in the loop
				// We'll look forward from the LLM call to find breaks/returns
				// Stop at either next function definition OR when indentation decreases significantly
				hasExit := false

				for j := currentLine + 1; j < len(lines) && j < currentLine+30; j++ {
					checkLine := strings.TrimSpace(lines[j])

					// Stop at next function definition
					if strings.HasPrefix(checkLine, "def ") || strings.HasPrefix(checkLine, "func ") {
						break
					}

					// Stop if indentation decreases below loop level (end of loop)
					if len(checkLine) > 0 {
						currentIndent := len(lines[j]) - len(strings.TrimLeft(lines[j], " \t"))
						loopIndent := len(lines[i]) - len(strings.TrimLeft(lines[i], " \t"))
						// If indentation is same or less than loop level and line is not empty, we've exited the loop
						if currentIndent <= loopIndent && !strings.HasPrefix(checkLine, "#") {
							break
						}
					}

					// Check for explicit exit conditions
					if strings.Contains(checkLine, "break") || strings.Contains(checkLine, "return") {
						hasExit = true
						break
					}
				}

				if !hasExit {
					return true // Unbounded loop found (no break/return found)
				}
				return false // Has exit condition, so not unbounded
			}
		}

		// Stop if we hit another function/class definition
		if strings.Contains(line, "def ") || strings.Contains(line, "func ") || strings.Contains(line, "class ") {
			break
		}
	}

	return false
}

// isInBoundedLoop checks if a line is within a bounded loop (which is safe)
func (d *TokenBombingDetector) isInBoundedLoop(lines []string, currentLine int, boundedLoopPatterns map[string]*regexp.Regexp) bool {
	// Look backward from current line to find a loop start
	for i := currentLine; i >= 0 && i > currentLine-50; i-- {
		line := lines[i]

		// Check for bounded loop patterns
		for _, pattern := range boundedLoopPatterns {
			if pattern.MatchString(line) {
				// Found a bounded loop
				// Now verify we're still inside it by checking indentation
				loopIndent := len(lines[i]) - len(strings.TrimLeft(lines[i], " \t"))

				// Check all lines between loop and current line
				allIndented := true
				for j := i + 1; j < currentLine; j++ {
					checkLine := strings.TrimSpace(lines[j])
					if checkLine == "" || strings.HasPrefix(checkLine, "#") {
						continue // Skip empty and comment lines
					}

					currentIndent := len(lines[j]) - len(strings.TrimLeft(lines[j], " \t"))
					if currentIndent <= loopIndent {
						// Exited the loop
						allIndented = false
						break
					}
				}

				if allIndented {
					return true // We're inside a bounded loop
				}
			}
		}

		// Stop if we hit another function/class definition
		if strings.Contains(line, "def ") || strings.Contains(line, "func ") || strings.Contains(line, "class ") {
			break
		}
	}

	return false
}

// isRecursiveCall checks if this LLM call is in a recursive function
func (d *TokenBombingDetector) isRecursiveCall(lines []string, currentLine int, functionName string, llmPatterns map[string]*regexp.Regexp) bool {
	if functionName == "" {
		return false
	}

	// Look forward from function definition to see if it calls itself
	for i := currentLine; i < len(lines) && i < currentLine+20; i++ {
		line := lines[i]

		// Stop at next function definition
		if i > currentLine && (strings.Contains(line, "def ") || strings.Contains(line, "func ")) {
			break
		}

		// Check if this function calls itself (recursion)
		if strings.Contains(line, functionName+"(") || strings.Contains(line, "self."+functionName) {
			return true
		}
	}

	return false
}

func (d *TokenBombingDetector) GetPattern() patterns.Pattern {
	return d.pattern
}

func (d *TokenBombingDetector) GetConfidence() float32 {
	return 0.85
}

func (d *TokenBombingDetector) Close() error {
	return nil
}
