package detectors

import (
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
	"github.com/inkog-io/inkog/action/pkg/patterns/metadata"
)

// EnhancedUnvalidatedExecEvalDetector detects unvalidated exec/eval with simplified confidence scoring
// Uses: Core detection + FileClassifier + SimpleConfidenceFramework + SimpleEnterpriseConfig
// Removed: GuardFramework, AISemanticAnalyzer, LearningSystem (archived for future use)
type EnhancedUnvalidatedExecEvalDetector struct {
	baseDetector        *UnvalidatedExecEvalDetector
	fileClassifier      *FileClassifier
	confidenceFramework *SimpleConfidenceFramework
	config              *SimpleEnterpriseConfig
}

// NewEnhancedUnvalidatedExecEvalDetector creates a new simplified unvalidated exec/eval detector
func NewEnhancedUnvalidatedExecEvalDetector(
	config *SimpleEnterpriseConfig,
) *EnhancedUnvalidatedExecEvalDetector {
	if config == nil {
		config = NewSimpleEnterpriseConfig()
	}

	return &EnhancedUnvalidatedExecEvalDetector{
		baseDetector:        NewUnvalidatedExecEvalDetector(),
		fileClassifier:      NewFileClassifier(),
		confidenceFramework: NewSimpleConfidenceFramework(0.75),
		config:              config,
	}
}

// GetPatternID returns the canonical detector ID (implements Detector interface)
func (d *EnhancedUnvalidatedExecEvalDetector) GetPatternID() string {
	return metadata.ID_UNVALIDATED_EXEC_EVAL
}

// GetPattern returns the pattern definition (implements Detector interface)
func (d *EnhancedUnvalidatedExecEvalDetector) GetPattern() patterns.Pattern {
	return d.baseDetector.GetPattern()
}

// Detect performs unvalidated exec/eval detection with simplified confidence (implements Detector interface)
func (d *EnhancedUnvalidatedExecEvalDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	return d.DetectEnhanced(filePath, src)
}

// DetectEnhanced is the original enhanced detection logic
func (d *EnhancedUnvalidatedExecEvalDetector) DetectEnhanced(filePath string, src []byte) ([]patterns.Finding, error) {
	// Step 1: Check if pattern is enabled
	patternConfig := d.config.GetPatternConfig("unvalidated_exec_eval")
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
			// Reduce confidence but don't skip - eval/exec in tests is still dangerous
			finding.Confidence = 0.60
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
			// Reduce confidence for docstring examples
			finding.Confidence = 0.50
		}

		// Check for LLM output indicators (increases severity)
		hasLLMContext := strings.Contains(sourceStr, "llm.") ||
			strings.Contains(sourceStr, "openai.") ||
			strings.Contains(sourceStr, "anthropic.") ||
			strings.Contains(sourceStr, "agent.") ||
			strings.Contains(sourceStr, "response") ||
			strings.Contains(sourceStr, "output")

		// Check for model names in context
		hasModelContext := strings.Contains(sourceStr, "gpt") ||
			strings.Contains(sourceStr, "claude") ||
			strings.Contains(sourceStr, "model") ||
			strings.Contains(sourceStr, "LLM")

		adjusted := d.confidenceFramework.AdjustConfidence(
			finding.Confidence,
			isInTestFile,
			isInComment,
			isInString,
			hasLLMContext && hasModelContext, // High risk when eval is used with LLM output
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
func (d *EnhancedUnvalidatedExecEvalDetector) isDocstringExample(line string) bool {
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
func (d *EnhancedUnvalidatedExecEvalDetector) Name() string {
	return "unvalidated_exec_eval_enhanced"
}

// IsEnabled checks if pattern is enabled
func (d *EnhancedUnvalidatedExecEvalDetector) IsEnabled() bool {
	patternConfig := d.config.GetPatternConfig("unvalidated_exec_eval")
	return patternConfig.Enabled
}
