package detectors

import (
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
	"github.com/inkog-io/inkog/action/pkg/patterns/metadata"
)

// EnhancedUnsafeEnvAccessDetector detects unsafe environment variable access with simplified confidence scoring
// Uses: Core detection + FileClassifier + SimpleConfidenceFramework + SimpleEnterpriseConfig
// Removed: GuardFramework, AISemanticAnalyzer, LearningSystem (archived for future use)
type EnhancedUnsafeEnvAccessDetector struct {
	baseDetector        *UnsafeEnvAccessDetector
	fileClassifier      *FileClassifier
	confidenceFramework *SimpleConfidenceFramework
	config              *SimpleEnterpriseConfig
}

// NewEnhancedUnsafeEnvAccessDetector creates a new simplified detector
func NewEnhancedUnsafeEnvAccessDetector(config *SimpleEnterpriseConfig) *EnhancedUnsafeEnvAccessDetector {
	if config == nil {
		config = NewSimpleEnterpriseConfig()
	}

	return &EnhancedUnsafeEnvAccessDetector{
		baseDetector:        NewUnsafeEnvAccessDetector(),
		fileClassifier:      NewFileClassifier(),
		confidenceFramework: NewSimpleConfidenceFramework(0.7),
		config:              config,
	}
}

// Detect performs unsafe environment variable access detection
func (d *EnhancedUnsafeEnvAccessDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	patternConfig := d.config.GetPatternConfig("unsafe_env_access")
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

		adjusted := d.confidenceFramework.AdjustConfidence(
			finding.Confidence, isInTestFile, isInComment, false, false,
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
func (d *EnhancedUnsafeEnvAccessDetector) Name() string {
	return "unsafe_env_access_enhanced"
}

// GetPatternID returns the canonical detector ID (implements Detector interface)
func (d *EnhancedUnsafeEnvAccessDetector) GetPatternID() string {
	return metadata.ID_UNSAFE_ENV_ACCESS
}


// IsEnabled checks if pattern is enabled
func (d *EnhancedUnsafeEnvAccessDetector) IsEnabled() bool {
	patternConfig := d.config.GetPatternConfig("unsafe_env_access")
	return patternConfig.Enabled
}
