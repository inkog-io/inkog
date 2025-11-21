package detectors

import (
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
	"github.com/inkog-io/inkog/action/pkg/patterns/metadata"
)

// EnhancedOutputValidationFailuresDetector detects improper output handling in LLM agent code
// Uses: Core detection + FileClassifier + SimpleConfidenceFramework + SimpleEnterpriseConfig
// Pattern: Unvalidated/unsanitized LLM output in dangerous sinks (eval, HTML, commands, SQL)
type EnhancedOutputValidationFailuresDetector struct {
	baseDetector        *OutputValidationFailuresDetector
	fileClassifier      *FileClassifier
	confidenceFramework *SimpleConfidenceFramework
	config              *SimpleEnterpriseConfig
}

// NewEnhancedOutputValidationFailuresDetector creates a new enhanced output validation detector
func NewEnhancedOutputValidationFailuresDetector(
	config *SimpleEnterpriseConfig,
) *EnhancedOutputValidationFailuresDetector {
	if config == nil {
		config = NewSimpleEnterpriseConfig()
	}

	return &EnhancedOutputValidationFailuresDetector{
		baseDetector:        NewOutputValidationFailuresDetector(),
		fileClassifier:      NewFileClassifier(),
		confidenceFramework: NewSimpleConfidenceFramework(0.65), // 0.65 threshold for output validation
		config:              config,
	}
}

// Detect performs output validation failure detection with context-aware confidence
func (d *EnhancedOutputValidationFailuresDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	// Step 1: Check if pattern is enabled
	patternConfig := d.config.GetPatternConfig("output_validation_failures")
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
			finding.Confidence = finding.Confidence * 0.80
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
		// Check for mitigating factors (sanitization, safe APIs, etc.)
		hasSafeguard := d.hasSafeguard(sourceStr, lineContent, lineIdx, lines)

		adjusted := d.confidenceFramework.AdjustConfidence(
			finding.Confidence,
			isInTestFile,
			isInComment,
			isInString,
			hasSafeguard, // Presence of safeguards reduces confidence
		)

		// For output validation, use 0.65 threshold
		if !d.confidenceFramework.ShouldReport(adjusted) {
			continue
		}

		// Update finding with adjusted confidence
		finding.Confidence = adjusted

		enhancedFindings = append(enhancedFindings, finding)
	}

	return enhancedFindings, nil
}

// hasSafeguard checks for sanitization, escaping, and safe API usage
func (d *EnhancedOutputValidationFailuresDetector) hasSafeguard(sourceStr string, lineContent string, lineIdx int, lines []string) bool {
	lowerContent := strings.ToLower(lineContent)
	lowerSource := strings.ToLower(sourceStr)

	// Sanitization function patterns
	sanitizationPatterns := []string{
		"bleach.clean",
		"bleach",
		"markupsafe.escape",
		"markupsafe",
		"html.escape",
		"html.EscapeString",
		"htmlsanitizer",
		"dompurify",
		"sanitize",
		"escape(",
		"escapehtml",
		"normalize",
		"strip_tags",
		"striptags",
		"safe_html",
	}

	for _, pattern := range sanitizationPatterns {
		if strings.Contains(lowerContent, pattern) || strings.Contains(lowerSource, pattern) {
			return true
		}
	}

	// Safe API patterns (alternatives to dangerous functions)
	safeAPIPatterns := []string{
		"textcontent",
		"innertext",
		"text(",
		"text_content",
		"parameterized",
		"prepared statement",
		"?",
		"$1",
		"%s",
		"exec.Command(",
		"subprocess.run([",
		"shlex.quote",
		"html/template",
		"html.Template",
		"render_template_string",
		"render_template",
		"jinja",
		"django",
		"autoescape",
	}

	for _, pattern := range safeAPIPatterns {
		if strings.Contains(lowerContent, pattern) {
			return true
		}
	}

	// Safe template patterns (auto-escaping)
	templateSafePatterns := []string{
		"jinja2",
		"jinja",
		"django",
		"html/template",
		"html.Template",
		"autoescape=True",
		"autoescape = True",
	}

	for _, pattern := range templateSafePatterns {
		if strings.Contains(lowerSource, pattern) {
			return true
		}
	}

	// Input validation patterns
	inputValidationPatterns := []string{
		"if not",
		"if !",
		"raise error",
		"throw error",
		"return error",
		"validate",
		"check",
		"verify",
		"assert",
		"whitelist",
		"allowlist",
		"startswith",
		"endswith",
		"match",
		"startswith('http",
		"startswith(\"http",
	}

	for _, pattern := range inputValidationPatterns {
		if strings.Contains(lowerContent, pattern) {
			return true
		}
	}

	// Check surrounding lines for validation/sanitization
	if lineIdx > 0 && lineIdx < len(lines) {
		// Look at previous lines for sanitization
		for j := lineIdx - 1; j >= 0 && j > lineIdx-5; j-- {
			prevLine := strings.ToLower(lines[j])
			if strings.Contains(prevLine, "bleach") ||
				strings.Contains(prevLine, "escape") ||
				strings.Contains(prevLine, "sanitize") ||
				strings.Contains(prevLine, "validate") ||
				strings.Contains(prevLine, "dompurify") {
				return true
			}
		}

		// Look at next lines for validation
		for j := lineIdx + 1; j < len(lines) && j < lineIdx+3; j++ {
			nextLine := strings.ToLower(lines[j])
			if strings.Contains(nextLine, "sanitize") ||
				strings.Contains(nextLine, "escape") ||
				strings.Contains(nextLine, "validate") {
				return true
			}
		}
	}

	// Check for parameterized queries (SQL safety)
	sqlSafetyPatterns := []string{
		"execute(",
		"execute_query(",
		"prepared",
		"parameterized",
		"?",
		"$1",
		"%s",
	}

	for _, pattern := range sqlSafetyPatterns {
		if strings.Contains(lowerContent, pattern) {
			return true
		}
	}

	// Check for quoting/escaping functions
	quotingPatterns := []string{
		"shlex.quote",
		"pipes.quote",
		"quote(",
		"escape",
		"shellquote",
	}

	for _, pattern := range quotingPatterns {
		if strings.Contains(lowerContent, pattern) {
			return true
		}
	}

	return false
}

// isDocstringExample checks if a line is within a docstring or example
func (d *EnhancedOutputValidationFailuresDetector) isDocstringExample(line string) bool {
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
func (d *EnhancedOutputValidationFailuresDetector) Name() string {
	return "output_validation_failures_enhanced"
}

// GetPatternID returns the canonical detector ID (implements Detector interface)
func (d *EnhancedOutputValidationFailuresDetector) GetPatternID() string {
	return metadata.ID_OUTPUT_VALIDATION
}


// IsEnabled checks if pattern is enabled
func (d *EnhancedOutputValidationFailuresDetector) IsEnabled() bool {
	patternConfig := d.config.GetPatternConfig("output_validation_failures")
	return patternConfig.Enabled
}
