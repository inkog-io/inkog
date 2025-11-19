package detectors

import (
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// EnhancedPromptInjectionDetector detects prompt injection with simplified confidence scoring
// Uses: Core detection + FileClassifier + SimpleConfidenceFramework + SimpleEnterpriseConfig
// Removed: GuardFramework, AISemanticAnalyzer, LearningSystem (archived)
type EnhancedPromptInjectionDetector struct {
	baseDetector        *PromptInjectionDetector
	fileClassifier      *FileClassifier
	confidenceFramework *SimpleConfidenceFramework
	config              *SimpleEnterpriseConfig
}

// NewEnhancedPromptInjectionDetector creates a new simplified detector
func NewEnhancedPromptInjectionDetector(config *SimpleEnterpriseConfig) *EnhancedPromptInjectionDetector {
	if config == nil {
		config = NewSimpleEnterpriseConfig()
	}

	return &EnhancedPromptInjectionDetector{
		baseDetector:        NewPromptInjectionDetector(),
		fileClassifier:      NewFileClassifier(),
		confidenceFramework: NewSimpleConfidenceFramework(0.7),
		config:              config,
	}
}

// Detect performs prompt injection detection
func (d *EnhancedPromptInjectionDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	patternConfig := d.config.GetPatternConfig("prompt_injection")
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
func (d *EnhancedPromptInjectionDetector) Name() string {
	return "prompt_injection_enhanced"
}

// IsEnabled checks if pattern is enabled
func (d *EnhancedPromptInjectionDetector) IsEnabled() bool {
	patternConfig := d.config.GetPatternConfig("prompt_injection")
	return patternConfig.Enabled
}
