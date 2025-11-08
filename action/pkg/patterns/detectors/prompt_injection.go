package detectors

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// PromptInjectionDetector detects unvalidated user input in LLM prompts
type PromptInjectionDetector struct {
	pattern    patterns.Pattern
	confidence float32
	regex      *regexp.Regexp
}

// NewPromptInjectionDetector creates a new prompt injection detector
func NewPromptInjectionDetector() *PromptInjectionDetector {
	pattern := patterns.Pattern{
		ID:       "prompt_injection",
		Name:     "Prompt Injection",
		Version:  "1.0",
		Category: "injection",
		Severity: "HIGH",
		CVSS:     8.8,
		CWEIDs:   []string{"CWE-74", "CWE-94", "CWE-95"},
		OWASP:    "LLM01",
		Description: "Unvalidated user input directly interpolated into LLM prompts enables attackers to inject arbitrary instructions and override system behavior",
		Remediation: "Use prompt templating, validate/sanitize user input, implement output filtering, use structured inputs",
		FinancialImpact: struct {
			Severity    string
			Description string
			RiskPerYear float32
		}{
			Severity:    "HIGH",
			Description: "Enables data exfiltration, jailbreaks, privilege escalation",
			RiskPerYear: 100000, // Estimated annual impact
		},
	}

	// Regex detects f-strings and template literals with user input variables
	// Pattern: f"... {user_input, prompt, query, request, message}" or similar
	regex := regexp.MustCompile(`(f["']|f"""|\$\{)[^"']*(?:prompt|query|user_input|request|message|input|cmd|command)[^"']*["']`)

	return &PromptInjectionDetector{
		pattern:    pattern,
		confidence: 0.90,
		regex:      regex,
	}
}

// Name returns the detector name
func (d *PromptInjectionDetector) Name() string {
	return "prompt_injection"
}

// GetPattern returns the pattern metadata
func (d *PromptInjectionDetector) GetPattern() patterns.Pattern {
	return d.pattern
}

// GetConfidence returns confidence score
func (d *PromptInjectionDetector) GetConfidence() float32 {
	return d.confidence
}

// Detect analyzes code for prompt injection vulnerabilities
func (d *PromptInjectionDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	var findings []patterns.Finding

	// Skip unsupported files
	if !isSupportedFile(filePath) {
		return findings, nil
	}

	// Skip test files (false positive reduction)
	if isTestFile(filePath) {
		return findings, nil
	}

	lines := strings.Split(string(src), "\n")

	for i, line := range lines {
		trimmedLine := strings.TrimSpace(line)

		// Skip comments and empty lines
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") || strings.HasPrefix(trimmedLine, "//") {
			continue
		}

		// Check if line contains prompt injection pattern
		if d.regex.MatchString(line) {
			// Additional context check: verify it's in an LLM context
			if d.isInLLMContext(line) {
				finding := patterns.Finding{
					ID:             fmt.Sprintf("prompt_injection_%d_%s", i, filePath),
					PatternID:      d.pattern.ID,
					Pattern:        d.pattern.Name,
					File:           filePath,
					Line:           i + 1,
					Column:         len(line) - len(trimmedLine) + 1,
					Message:        "Unvalidated user input directly interpolated into LLM prompt - enables prompt injection attacks",
					Code:           line,
					Severity:       d.pattern.Severity,
					Confidence:     d.confidence,
					CWE:            "CWE-74",
					CVSS:           d.pattern.CVSS,
					OWASP:          d.pattern.OWASP,
					FinancialRisk:  "Data exfiltration, system compromise",
				}

				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// isInLLMContext checks if the string interpolation is in an LLM function call context
func (d *PromptInjectionDetector) isInLLMContext(line string) bool {
	// Check for common LLM function names
	llmFunctions := []string{
		"chat(", "invoke(", "predict(", "complete(", "generate(",
		"apredict(", "ainvoke(", ".chat", ".invoke", ".predict",
		"llm.predict", "model.chat", "ChatOpenAI", "Anthropic",
	}

	for _, fn := range llmFunctions {
		if strings.Contains(line, fn) {
			return true
		}
	}

	// Check if it looks like a prompt variable (common naming)
	llmVarNames := []string{
		"prompt", "instruction", "messages", "system", "message",
	}

	for _, v := range llmVarNames {
		if strings.Contains(strings.ToLower(line), v) {
			return true
		}
	}

	return false
}

// isSupportedFile checks if file extension is supported
func isSupportedFile(path string) bool {
	supported := []string{".py", ".js", ".ts", ".jsx", ".tsx", ".go"}
	for _, ext := range supported {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// isTestFile checks if file is a test file (false positive reduction)
func isTestFile(path string) bool {
	testPatterns := []string{
		"test_", "_test.py", "/tests/", "test/",
		".test.js", ".test.ts", "spec.js", "spec.ts",
		"example", "sample", "demo",
	}

	lowerPath := strings.ToLower(path)
	for _, pattern := range testPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}

	return false
}

// Finding represents a single security finding
// (Re-exported here for convenience in detector packages)
type Finding = patterns.Finding
