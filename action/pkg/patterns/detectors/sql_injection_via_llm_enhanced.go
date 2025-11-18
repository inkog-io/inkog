package detectors

import (
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// EnhancedSQLInjectionViaLLMDetector detects SQL injection via LLM with simplified confidence scoring
// Uses: Core detection + FileClassifier + SimpleConfidenceFramework + SimpleEnterpriseConfig
// Note: This pattern uses context-aware analysis instead of pure regex
type EnhancedSQLInjectionViaLLMDetector struct {
	baseDetector        *SQLInjectionViaLLMDetector
	fileClassifier      *FileClassifier
	confidenceFramework *SimpleConfidenceFramework
	config              *SimpleEnterpriseConfig
}

// NewEnhancedSQLInjectionViaLLMDetector creates a new SQL injection via LLM detector
func NewEnhancedSQLInjectionViaLLMDetector(
	config *SimpleEnterpriseConfig,
) *EnhancedSQLInjectionViaLLMDetector {
	if config == nil {
		config = NewSimpleEnterpriseConfig()
	}

	return &EnhancedSQLInjectionViaLLMDetector{
		baseDetector:        NewSQLInjectionViaLLMDetector(),
		fileClassifier:      NewFileClassifier(),
		confidenceFramework: NewSimpleConfidenceFramework(0.70),
		config:              config,
	}
}

// Detect performs SQL injection via LLM detection with context-aware confidence
func (d *EnhancedSQLInjectionViaLLMDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	// Step 1: Check if pattern is enabled
	patternConfig := d.config.GetPatternConfig("sql_injection_via_llm")
	if !patternConfig.Enabled {
		return []patterns.Finding{}, nil
	}

	// Step 2: Get base findings from original detector
	baseFindings, err := d.baseDetector.Detect(filePath, src)
	if err != nil {
		return nil, err
	}

	if len(baseFindings) == 0 {
		return []patterns.Finding{}, nil
	}

	sourceStr := string(src)
	lines := strings.Split(sourceStr, "\n")

	// Step 3: Apply context-aware filtering and confidence scoring
	var enhancedFindings []patterns.Finding

	for _, finding := range baseFindings {
		lineIdx := finding.Line - 1
		var lineContent string
		if lineIdx >= 0 && lineIdx < len(lines) {
			lineContent = lines[lineIdx]
		}

		// Check if finding is in test file
		isInTestFile := d.fileClassifier.IsTestFile(filePath)
		if isInTestFile && patternConfig.FilterTestCode {
			// For SQL injection, still flag test code (test code with SQL injection is still dangerous)
			// But reduce confidence slightly
			finding.Confidence = finding.Confidence * 0.85
		}

		// Check if finding is in comment
		isInComment := strings.HasPrefix(strings.TrimSpace(lineContent), "//") ||
			strings.HasPrefix(strings.TrimSpace(lineContent), "#")
		if isInComment && patternConfig.FilterComments {
			continue // Skip findings in comments
		}

		// Check if finding is in string (example code in docstring)
		isInString := d.isDocstringExample(lineContent)
		if isInString && patternConfig.FilterStrings {
			continue // Skip findings in docstrings/examples
		}

		// Apply context-aware confidence adjustments
		// Check for mitigating factors (parameterization, safe flags, validation)
		hasMitigatingFactor := d.hasMitigatingFactor(sourceStr, lineContent)

		adjusted := d.confidenceFramework.AdjustConfidence(
			finding.Confidence,
			isInTestFile,
			isInComment,
			isInString,
			hasMitigatingFactor, // Presence of mitigating factors reduces confidence
		)

		// For SQL injection, we're more conservative (higher threshold)
		if !d.confidenceFramework.ShouldReport(adjusted) {
			continue
		}

		// Update finding with adjusted confidence
		finding.Confidence = adjusted

		enhancedFindings = append(enhancedFindings, finding)
	}

	return enhancedFindings, nil
}

// hasMitigatingFactor checks for safeguards that reduce risk
func (d *EnhancedSQLInjectionViaLLMDetector) hasMitigatingFactor(sourceStr string, lineContent string) bool {
	// Check for parameterized query indicators
	parameterizedIndicators := []string{
		"%s", "$1", "$2", "?", ":{", ":named",
		"prepared", "statement", "bind", "parameter",
	}

	for _, indicator := range parameterizedIndicators {
		if strings.Contains(sourceStr, indicator) || strings.Contains(lineContent, indicator) {
			return true
		}
	}

	// Check for safe flags/patterns
	safePatterns := []string{
		"allow_dangerous_requests=False",
		"allow_dangerous_requests = False",
		"SQLAlchemy",
		"ORM",
		"sanitize",
		"validate",
		"whitelist",
		"escape",
	}

	for _, safe := range safePatterns {
		if strings.Contains(sourceStr, safe) {
			return true
		}
	}

	return false
}

// isDocstringExample checks if a line is within a docstring or example
func (d *EnhancedSQLInjectionViaLLMDetector) isDocstringExample(line string) bool {
	trimmed := strings.TrimSpace(line)

	// Check for docstring markers
	if strings.HasPrefix(trimmed, "\"\"\"") || strings.HasPrefix(trimmed, "'''") {
		return true
	}

	// Check if line is within example/doc string context
	if strings.Contains(trimmed, ">>>") || strings.Contains(trimmed, "...") {
		return true
	}

	return false
}

// Name returns detector name
func (d *EnhancedSQLInjectionViaLLMDetector) Name() string {
	return "sql_injection_via_llm_enhanced"
}

// IsEnabled checks if pattern is enabled
func (d *EnhancedSQLInjectionViaLLMDetector) IsEnabled() bool {
	patternConfig := d.config.GetPatternConfig("sql_injection_via_llm")
	return patternConfig.Enabled
}
