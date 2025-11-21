package detectors

import (
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
	"github.com/inkog-io/inkog/action/pkg/patterns/metadata"
)

// EnhancedLoggingSensitiveDataDetector detects logging of sensitive data with confidence scoring
// Uses: Core detection + FileClassifier + SimpleConfidenceFramework + SimpleEnterpriseConfig
// Pattern: Logging of sensitive information (passwords, tokens, API keys, PII) leading to information disclosure
type EnhancedLoggingSensitiveDataDetector struct {
	baseDetector        *LoggingSensitiveDataDetector
	fileClassifier      *FileClassifier
	confidenceFramework *SimpleConfidenceFramework
	config              *SimpleEnterpriseConfig
}

// NewEnhancedLoggingSensitiveDataDetector creates a new enhanced logging sensitive data detector
func NewEnhancedLoggingSensitiveDataDetector(
	config *SimpleEnterpriseConfig,
) *EnhancedLoggingSensitiveDataDetector {
	if config == nil {
		config = NewSimpleEnterpriseConfig()
	}

	return &EnhancedLoggingSensitiveDataDetector{
		baseDetector:        NewLoggingSensitiveDataDetector(),
		fileClassifier:      NewFileClassifier(),
		confidenceFramework: NewSimpleConfidenceFramework(0.70), // 0.70 threshold for logging patterns (higher due to FP proneness)
		config:              config,
	}
}

// Detect performs logging sensitive data detection with context-aware confidence
func (d *EnhancedLoggingSensitiveDataDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	// Step 1: Check if pattern is enabled
	patternConfig := d.config.GetPatternConfig("logging_sensitive_data")
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
			// For logging, we may want to flag even in test code (tests should be clean too)
			// but reduce confidence slightly
			finding.Confidence = finding.Confidence * 0.85
		}

		// Check if finding is in comment
		isInComment := strings.HasPrefix(strings.TrimSpace(lineContent), "//") ||
			strings.HasPrefix(strings.TrimSpace(lineContent), "#")
		if isInComment && patternConfig.FilterComments {
			continue // Skip findings in comments
		}

		// Check if finding is in string or docstring
		isInString := d.isDocstringExample(lineContent)
		if isInString && patternConfig.FilterStrings {
			continue // Skip findings in docstrings/examples
		}

		// Apply context-aware confidence adjustments
		// Check for mitigating factors (masking, safe context, etc.)
		hasMitigatingFactor := d.hasMitigatingFactor(sourceStr, lineContent)

		adjusted := d.confidenceFramework.AdjustConfidence(
			finding.Confidence,
			isInTestFile,
			isInComment,
			isInString,
			hasMitigatingFactor, // Presence of mitigating factors reduces confidence
		)

		// For logging sensitive data, use 0.70 threshold (conservative)
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
func (d *EnhancedLoggingSensitiveDataDetector) hasMitigatingFactor(sourceStr string, lineContent string) bool {
	// Check for masking/redaction patterns
	maskingPatterns := []string{
		"*",
		"[FILTERED]",
		"[REDACTED]",
		"[MASKED]",
		"<redacted>",
		"<masked>",
		"mask(",
		"redact(",
		"filter_sensitive",
		"obfuscate(",
	}

	for _, pattern := range maskingPatterns {
		if strings.Contains(lineContent, pattern) || strings.Contains(sourceStr, pattern) {
			return true
		}
	}

	// Check for safe context patterns (password reset vs actual password logging)
	safeContexts := []string{
		"password reset",
		"password change",
		"password field",
		"password column",
		"password parameter",
		"password updated",
		"password changed",
		"password requirement",
		"password policy",
		"password strength",
		"secret in code",
		"secret key in config",
		"api_key parameter",
		"token field",
		"token parameter",
		"token updated",
	}

	for _, context := range safeContexts {
		if strings.Contains(strings.ToLower(lineContent), context) || strings.Contains(strings.ToLower(sourceStr), context) {
			return true
		}
	}

	// Check for frameworks/libraries that provide safe logging
	safeFrameworks := []string{
		"structlog",
		"python_logging_masked",
		"secure_logger",
		"sanitize",
		"sanitized_log",
		"logstash",
		"datadog",
		"sentry",
	}

	for _, framework := range safeFrameworks {
		if strings.Contains(strings.ToLower(sourceStr), framework) {
			return true
		}
	}

	// Check for parameterized/structured logging without values
	if d.isStructuredLoggingWithoutValues(lineContent) {
		return true
	}

	return false
}

// isStructuredLoggingWithoutValues checks if this is structured logging that doesn't leak values
func (d *EnhancedLoggingSensitiveDataDetector) isStructuredLoggingWithoutValues(line string) bool {
	// Structured logging with .With() or .WithField() but no string interpolation
	if strings.Contains(line, ".With") && !strings.Contains(line, "${") && !strings.Contains(line, "f\"") {
		return true
	}

	// Check if it's just logging a field name (e.g., logger.WithField("password_field"))
	// not the actual password value
	if strings.Count(line, "\"") >= 2 && !strings.Contains(line, "${") && !strings.Contains(line, "+") {
		// Likely just logging strings, not variables
		return true
	}

	return false
}

// isDocstringExample checks if a line is within a docstring or example
func (d *EnhancedLoggingSensitiveDataDetector) isDocstringExample(line string) bool {
	trimmed := strings.TrimSpace(line)

	// Check for docstring markers
	if strings.HasPrefix(trimmed, "\"\"\"") || strings.HasPrefix(trimmed, "'''") {
		return true
	}

	// Check if line is within example/doc string context
	if strings.Contains(trimmed, ">>>") || strings.Contains(trimmed, "...") {
		return true
	}

	// Check for code fence markers (markdown)
	if strings.HasPrefix(trimmed, "```") {
		return true
	}

	return false
}

// Name returns detector name
func (d *EnhancedLoggingSensitiveDataDetector) Name() string {
	return "logging_sensitive_data_enhanced"
}

// GetPatternID returns the canonical detector ID (implements Detector interface)
func (d *EnhancedLoggingSensitiveDataDetector) GetPatternID() string {
	return metadata.ID_LOGGING_SENSITIVE_DATA
}


// IsEnabled checks if pattern is enabled
func (d *EnhancedLoggingSensitiveDataDetector) IsEnabled() bool {
	patternConfig := d.config.GetPatternConfig("logging_sensitive_data")
	return patternConfig.Enabled
}
