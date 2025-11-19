package detectors

import (
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// EnhancedMissingRateLimitsDetector detects missing rate limits with simplified confidence scoring
// Uses: Core detection + FileClassifier + SimpleConfidenceFramework + SimpleEnterpriseConfig
// Removed: GuardFramework, AISemanticAnalyzer, LearningSystem (archived for future use)
type EnhancedMissingRateLimitsDetector struct {
	baseDetector        *MissingRateLimitsDetector
	fileClassifier      *FileClassifier
	confidenceFramework *SimpleConfidenceFramework
	config              *SimpleEnterpriseConfig
}

// NewEnhancedMissingRateLimitsDetector creates a new simplified missing rate limits detector
func NewEnhancedMissingRateLimitsDetector(
	config *SimpleEnterpriseConfig,
) *EnhancedMissingRateLimitsDetector {
	if config == nil {
		config = NewSimpleEnterpriseConfig()
	}

	return &EnhancedMissingRateLimitsDetector{
		baseDetector:        NewMissingRateLimitsDetector(),
		fileClassifier:      NewFileClassifier(),
		confidenceFramework: NewSimpleConfidenceFramework(0.70),
		config:              config,
	}
}

// Detect performs missing rate limits detection with simplified confidence
func (d *EnhancedMissingRateLimitsDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	// Step 1: Check if pattern is enabled
	patternConfig := d.config.GetPatternConfig("missing_rate_limits")
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

	// Step 3: Apply filters and confidence scoring to each finding
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
			continue // Skip findings in test files
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
			continue // Skip findings in strings/docstrings
		}

		// Apply simplified confidence scoring
		baseConfidence := finding.Confidence

		// Check for infrastructure protection indicators (positive factor)
		hasInfraProtection := strings.Contains(sourceStr, "WAF") ||
			strings.Contains(sourceStr, "API Gateway") ||
			strings.Contains(sourceStr, "CloudFlare") ||
			strings.Contains(sourceStr, "nginx") ||
			strings.Contains(sourceStr, "ratelimit")

		adjusted := d.confidenceFramework.AdjustConfidence(
			baseConfidence,
			isInTestFile,
			isInComment,
			isInString,
			hasInfraProtection, // Infrastructure protection reduces confidence in vulnerability
		)

		// Check if meets threshold
		if !d.confidenceFramework.ShouldReport(adjusted) {
			continue
		}

		// Update finding with adjusted confidence
		finding.Confidence = adjusted

		enhancedFindings = append(enhancedFindings, finding)
	}

	return enhancedFindings, nil
}

// isDocstringExample checks if a line is within a docstring or example
func (d *EnhancedMissingRateLimitsDetector) isDocstringExample(line string) bool {
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
func (d *EnhancedMissingRateLimitsDetector) Name() string {
	return "missing_rate_limits_enhanced"
}

// IsEnabled checks if pattern is enabled
func (d *EnhancedMissingRateLimitsDetector) IsEnabled() bool {
	patternConfig := d.config.GetPatternConfig("missing_rate_limits")
	return patternConfig.Enabled
}
