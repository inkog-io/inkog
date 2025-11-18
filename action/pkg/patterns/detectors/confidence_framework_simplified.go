package detectors

import (
	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// SimpleConfidenceFramework provides basic confidence scoring for patterns
// Simplified from 7-factor framework to: match strength + context + validation
// This is enough for MVP and easier to validate against real code
type SimpleConfidenceFramework struct {
	minThreshold float32 // Minimum confidence to report (configurable)
	maxThreshold float32 // Maximum confidence possible (hard cap)
}

// NewSimpleConfidenceFramework creates a new simplified confidence framework
func NewSimpleConfidenceFramework(minThreshold float32) *SimpleConfidenceFramework {
	if minThreshold < 0 {
		minThreshold = 0
	}
	if minThreshold > 1 {
		minThreshold = 1
	}
	return &SimpleConfidenceFramework{
		minThreshold: minThreshold,
		maxThreshold: 1.0,
	}
}

// AdjustConfidence takes a base confidence and applies simple adjustments
// This replaces the complex 7-factor calculation with straightforward logic
func (scf *SimpleConfidenceFramework) AdjustConfidence(
	baseConfidence float32,
	isInTestFile bool,
	isInComment bool,
	isInString bool,
	hasValidation bool,
) float32 {
	// Start with base confidence
	adjusted := baseConfidence

	// Reduce confidence if in test file (false positive indicator)
	if isInTestFile {
		adjusted *= 0.7 // 30% confidence penalty
	}

	// Reduce confidence if in comment (usually not code)
	if isInComment {
		adjusted *= 0.5 // 50% confidence penalty
	}

	// Reduce confidence if in string (might be example/documentation)
	// EXCEPT for hardcoded_credentials pattern where strings are valid
	if isInString {
		adjusted *= 0.6 // 40% confidence penalty
	}

	// Increase confidence if validation is present
	if hasValidation {
		adjusted *= 1.2 // 20% confidence boost
	}

	// Clamp between 0 and 1
	if adjusted < 0 {
		adjusted = 0
	}
	if adjusted > scf.maxThreshold {
		adjusted = scf.maxThreshold
	}

	return adjusted
}

// ShouldReport determines if a finding should be reported based on confidence
func (scf *SimpleConfidenceFramework) ShouldReport(confidence float32) bool {
	return confidence >= scf.minThreshold
}

// SetMinimumThreshold allows configuration of minimum confidence to report
func (scf *SimpleConfidenceFramework) SetMinimumThreshold(threshold float32) {
	if threshold < 0 {
		threshold = 0
	}
	if threshold > 1 {
		threshold = 1
	}
	scf.minThreshold = threshold
}

// ApplyToFinding updates a finding's confidence based on context
func (scf *SimpleConfidenceFramework) ApplyToFinding(
	finding *patterns.Finding,
	isInTestFile bool,
	isInComment bool,
	isInString bool,
	hasValidation bool,
) {
	if finding == nil {
		return
	}

	// Adjust finding confidence based on context
	adjusted := scf.AdjustConfidence(
		finding.Confidence,
		isInTestFile,
		isInComment,
		isInString,
		hasValidation,
	)

	finding.Confidence = adjusted
}
