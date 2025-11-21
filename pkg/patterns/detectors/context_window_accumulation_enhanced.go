package detectors

import (
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
	"github.com/inkog-io/inkog/action/pkg/patterns/metadata"
)

// EnhancedContextWindowAccumulationDetector detects context window accumulation with confidence scoring
// Uses: Core detection + FileClassifier + SimpleConfidenceFramework + SimpleEnterpriseConfig
// Pattern: Unbounded conversation history growth in AI agents leading to token exhaustion and memory leaks
type EnhancedContextWindowAccumulationDetector struct {
	baseDetector        *ContextWindowAccumulationDetector
	fileClassifier      *FileClassifier
	confidenceFramework *SimpleConfidenceFramework
	config              *SimpleEnterpriseConfig
}

// NewEnhancedContextWindowAccumulationDetector creates a new enhanced context window accumulation detector
func NewEnhancedContextWindowAccumulationDetector(
	config *SimpleEnterpriseConfig,
) *EnhancedContextWindowAccumulationDetector {
	if config == nil {
		config = NewSimpleEnterpriseConfig()
	}

	return &EnhancedContextWindowAccumulationDetector{
		baseDetector:        NewContextWindowAccumulationDetector(),
		fileClassifier:      NewFileClassifier(),
		confidenceFramework: NewSimpleConfidenceFramework(0.65),
		config:              config,
	}
}

// Detect performs context window accumulation detection with context-aware confidence
func (d *EnhancedContextWindowAccumulationDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	// Step 1: Check if pattern is enabled
	patternConfig := d.config.GetPatternConfig("context_window_accumulation")
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
			// For context window accumulation, reduce confidence for test code but still flag
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
		// Check for mitigating factors (bounding logic, summarization, windowing)
		hasMitigatingFactor := d.hasMitigatingFactor(sourceStr, lineContent)

		adjusted := d.confidenceFramework.AdjustConfidence(
			finding.Confidence,
			isInTestFile,
			isInComment,
			isInString,
			hasMitigatingFactor, // Presence of mitigating factors reduces confidence
		)

		// For context window accumulation, we use a lower threshold (0.65)
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
func (d *EnhancedContextWindowAccumulationDetector) hasMitigatingFactor(sourceStr string, lineContent string) bool {
	// Check for bounding logic indicators
	boundingIndicators := []string{
		"k=",
		"max_",
		"limit",
		"window",
		"truncate",
		"trim",
		"len(",
		"size(",
		"length",
	}

	for _, indicator := range boundingIndicators {
		if strings.Contains(sourceStr, indicator) || strings.Contains(lineContent, indicator) {
			return true
		}
	}

	// Check for safe patterns (summarization, windowing, population)
	safePatterns := []string{
		"summarize",
		"summary",
		"compress",
		"condense",
		"ConversationSummary",
		"ConversationBufferWindow",
		"pop(",
		"shift(",
		"remove(",
		"slice(",
	}

	for _, safe := range safePatterns {
		if strings.Contains(sourceStr, safe) {
			return true
		}
	}

	// Check for safe frameworks
	safeFrameworks := []string{
		"ConversationSummaryMemory",
		"context_manager",
		"LangSmith",
		"managed_memory",
	}

	for _, framework := range safeFrameworks {
		if strings.Contains(sourceStr, framework) {
			return true
		}
	}

	return false
}

// isDocstringExample checks if a line is within a docstring or example
func (d *EnhancedContextWindowAccumulationDetector) isDocstringExample(line string) bool {
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
func (d *EnhancedContextWindowAccumulationDetector) Name() string {
	return "context_window_accumulation_enhanced"
}

// GetPatternID returns the canonical detector ID (implements Detector interface)
func (d *EnhancedContextWindowAccumulationDetector) GetPatternID() string {
	return metadata.ID_CONTEXT_EXHAUSTION
}


// IsEnabled checks if pattern is enabled
func (d *EnhancedContextWindowAccumulationDetector) IsEnabled() bool {
	patternConfig := d.config.GetPatternConfig("context_window_accumulation")
	return patternConfig.Enabled
}
