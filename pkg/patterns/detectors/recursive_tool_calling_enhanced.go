package detectors

import (
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
	"github.com/inkog-io/inkog/action/pkg/patterns/metadata"
)

// EnhancedRecursiveToolCallingDetector detects recursive tool calling with simplified confidence scoring
// Uses: Core detection + FileClassifier + SimpleConfidenceFramework + SimpleEnterpriseConfig
// Removed: GuardFramework, AISemanticAnalyzer, LearningSystem (archived for future use)
type EnhancedRecursiveToolCallingDetector struct {
	baseDetector        *RecursiveToolCallingDetector
	fileClassifier      *FileClassifier
	confidenceFramework *SimpleConfidenceFramework
	config              *SimpleEnterpriseConfig
}

// NewEnhancedRecursiveToolCallingDetector creates a new simplified detector
func NewEnhancedRecursiveToolCallingDetector(config *SimpleEnterpriseConfig) *EnhancedRecursiveToolCallingDetector {
	if config == nil {
		config = NewSimpleEnterpriseConfig()
	}

	return &EnhancedRecursiveToolCallingDetector{
		baseDetector:        NewRecursiveToolCallingDetector().(*RecursiveToolCallingDetector),
		fileClassifier:      NewFileClassifier(),
		confidenceFramework: NewSimpleConfidenceFramework(0.7),
		config:              config,
	}
}

// Detect performs recursive tool calling detection
func (d *EnhancedRecursiveToolCallingDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	patternConfig := d.config.GetPatternConfig("recursive_tool_calling")
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
func (d *EnhancedRecursiveToolCallingDetector) Name() string {
	return "recursive_tool_calling_enhanced"
}

// GetPatternID returns the canonical detector ID (implements Detector interface)
func (d *EnhancedRecursiveToolCallingDetector) GetPatternID() string {
	return metadata.ID_RECURSIVE_TOOL_CALLING
}


// IsEnabled checks if pattern is enabled
func (d *EnhancedRecursiveToolCallingDetector) IsEnabled() bool {
	patternConfig := d.config.GetPatternConfig("recursive_tool_calling")
	return patternConfig.Enabled
}
