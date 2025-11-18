package detectors

import (
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// EnhancedRAGOverFetchingDetector detects RAG over-fetching with simplified confidence scoring
// Uses: Core detection + FileClassifier + SimpleConfidenceFramework + SimpleEnterpriseConfig
// Removed: GuardFramework, AISemanticAnalyzer, LearningSystem (archived for future use)
type EnhancedRAGOverFetchingDetector struct {
	baseDetector        *RAGOverFetchingDetector
	fileClassifier      *FileClassifier
	confidenceFramework *SimpleConfidenceFramework
	config              *SimpleEnterpriseConfig
}

// NewEnhancedRAGOverFetchingDetector creates a new simplified RAG detector
func NewEnhancedRAGOverFetchingDetector(
	config *SimpleEnterpriseConfig,
) *EnhancedRAGOverFetchingDetector {
	if config == nil {
		config = NewSimpleEnterpriseConfig()
	}

	return &EnhancedRAGOverFetchingDetector{
		baseDetector:        NewRAGOverFetchingDetector(),
		fileClassifier:      NewFileClassifier(),
		confidenceFramework: NewSimpleConfidenceFramework(0.70),
		config:              config,
	}
}

// Detect performs RAG over-fetching detection with simplified confidence
func (d *EnhancedRAGOverFetchingDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	// Step 1: Check if pattern is enabled
	patternConfig := d.config.GetPatternConfig("rag_over_fetching")
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
		isInString := d.isStringLiteral(lineContent)
		if isInString && patternConfig.FilterStrings {
			continue // Skip findings in strings/docstrings
		}

		// Apply simplified confidence scoring
		baseConfidence := finding.Confidence

		// Check for caching indicators (positive factor)
		hasCaching := strings.Contains(lineContent, "cache") ||
			strings.Contains(lineContent, "Cache") ||
			strings.Contains(lineContent, "CACHE")

		adjusted := d.confidenceFramework.AdjustConfidence(
			baseConfidence,
			isInTestFile,
			isInComment,
			isInString,
			hasCaching, // Presence of caching increases confidence in safe code
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

// isStringLiteral checks if a line is within a string or docstring
func (d *EnhancedRAGOverFetchingDetector) isStringLiteral(line string) bool {
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
func (d *EnhancedRAGOverFetchingDetector) Name() string {
	return "rag_over_fetching_enhanced"
}

// IsEnabled checks if pattern is enabled
func (d *EnhancedRAGOverFetchingDetector) IsEnabled() bool {
	patternConfig := d.config.GetPatternConfig("rag_over_fetching")
	return patternConfig.Enabled
}
