package detectors

import (
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// EnhancedHardcodedCredentialsDetector detects hardcoded credentials with simplified confidence scoring
// Uses: Core detection + FileClassifier + SimpleConfidenceFramework + SimpleEnterpriseConfig
// Removed: GuardFramework, AISemanticAnalyzer, LearningSystem (archived for future use)
type EnhancedHardcodedCredentialsDetector struct {
	baseDetector        *HardcodedCredentialsDetector
	fileClassifier      *FileClassifier
	confidenceFramework *SimpleConfidenceFramework
	config              *SimpleEnterpriseConfig
}

// NewEnhancedHardcodedCredentialsDetector creates a new simplified detector
func NewEnhancedHardcodedCredentialsDetector(
	config *SimpleEnterpriseConfig,
) *EnhancedHardcodedCredentialsDetector {
	if config == nil {
		config = NewSimpleEnterpriseConfig()
	}

	return &EnhancedHardcodedCredentialsDetector{
		baseDetector:        NewHardcodedCredentialsDetector(),
		fileClassifier:      NewFileClassifier(),
		confidenceFramework: NewSimpleConfidenceFramework(0.7),
		config:              config,
	}
}

// Detect performs hardcoded credentials detection with simplified confidence
func (d *EnhancedHardcodedCredentialsDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	// Step 1: Check if pattern is enabled
	patternConfig := d.config.GetPatternConfig("hardcoded_credentials")
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

		// For hardcoded credentials, we DO want to detect in strings (don't filter them by default)
		// This is different from other patterns

		// Apply simplified confidence scoring
		baseConfidence := finding.Confidence
		adjusted := d.confidenceFramework.AdjustConfidence(
			baseConfidence,
			isInTestFile,
			isInComment,
			false, // Don't filter strings for credentials
			false, // No validation check for credentials
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

// Name returns detector name
func (d *EnhancedHardcodedCredentialsDetector) Name() string {
	return "hardcoded_credentials_enhanced"
}

// IsEnabled checks if pattern is enabled
func (d *EnhancedHardcodedCredentialsDetector) IsEnabled() bool {
	patternConfig := d.config.GetPatternConfig("hardcoded_credentials")
	return patternConfig.Enabled
}
