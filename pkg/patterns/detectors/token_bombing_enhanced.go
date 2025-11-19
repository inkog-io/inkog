package detectors

import (
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// EnhancedTokenBombingDetector detects token bombing attacks with simplified confidence scoring
// Uses: Core detection + FileClassifier + SimpleConfidenceFramework + SimpleEnterpriseConfig
// Removed: GuardFramework, AISemanticAnalyzer, LearningSystem (archived for future use)
type EnhancedTokenBombingDetector struct {
	baseDetector        *TokenBombingDetector
	fileClassifier      *FileClassifier
	confidenceFramework *SimpleConfidenceFramework
	config              *SimpleEnterpriseConfig
}

// NewEnhancedTokenBombingDetector creates a new simplified detector
func NewEnhancedTokenBombingDetector(config *SimpleEnterpriseConfig) *EnhancedTokenBombingDetector {
	if config == nil {
		config = NewSimpleEnterpriseConfig()
	}

	return &EnhancedTokenBombingDetector{
		baseDetector:        NewTokenBombingDetector().(*TokenBombingDetector),
		fileClassifier:      NewFileClassifier(),
		confidenceFramework: NewSimpleConfidenceFramework(0.7),
		config:              config,
	}
}

// Detect performs token bombing detection
func (d *EnhancedTokenBombingDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	patternConfig := d.config.GetPatternConfig("token_bombing")
	if !patternConfig.Enabled {
		return []patterns.Finding{}, nil
	}

	baseFindings, err := d.baseDetector.Detect(filePath, src)
	if err != nil {
		return nil, err
	}

	if len(baseFindings) == 0 {
		return []patterns.Finding{}, nil
	}

	sourceStr := string(src)
	lines := strings.Split(sourceStr, "\n")
	var enhancedFindings []patterns.Finding

	for _, finding := range baseFindings {
		lineIdx := finding.Line - 1
		var lineContent string
		if lineIdx >= 0 && lineIdx < len(lines) {
			lineContent = lines[lineIdx]
		}

		isInTestFile := d.fileClassifier.IsTestFile(filePath)
		if isInTestFile && patternConfig.FilterTestCode {
			continue
		}

		isInComment := strings.HasPrefix(strings.TrimSpace(lineContent), "//") ||
			strings.HasPrefix(strings.TrimSpace(lineContent), "#")
		if isInComment && patternConfig.FilterComments {
			continue
		}

		isInString := strings.Count(lineContent, `"`)%2 == 1 ||
			strings.Count(lineContent, `'`)%2 == 1
		if isInString && patternConfig.FilterStrings {
			continue
		}

		adjusted := d.confidenceFramework.AdjustConfidence(
			finding.Confidence,
			isInTestFile,
			isInComment,
			isInString,
			false,
		)

		if !d.confidenceFramework.ShouldReport(adjusted) {
			continue
		}

		finding.Confidence = adjusted
		enhancedFindings = append(enhancedFindings, finding)
	}

	return enhancedFindings, nil
}

// Name returns detector name
func (d *EnhancedTokenBombingDetector) Name() string {
	return "token_bombing_enhanced"
}

// IsEnabled checks if pattern is enabled
func (d *EnhancedTokenBombingDetector) IsEnabled() bool {
	patternConfig := d.config.GetPatternConfig("token_bombing")
	return patternConfig.Enabled
}
