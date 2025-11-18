package detectors

import (
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// EnhancedInfiniteLoopDetector detects infinite loops with simplified confidence
type EnhancedInfiniteLoopDetector struct {
	baseDetector        *InfiniteLoopDetector
	loopDetector        *UnboundedLoopDetector
	fileClassifier      *FileClassifier
	confidenceFramework *SimpleConfidenceFramework
	config              *SimpleEnterpriseConfig
}

func NewEnhancedInfiniteLoopDetector(config *SimpleEnterpriseConfig) *EnhancedInfiniteLoopDetector {
	if config == nil {
		config = NewSimpleEnterpriseConfig()
	}
	return &EnhancedInfiniteLoopDetector{
		baseDetector:        NewInfiniteLoopDetector(),
		loopDetector:        NewUnboundedLoopDetector(),
		fileClassifier:      NewFileClassifier(),
		confidenceFramework: NewSimpleConfidenceFramework(0.8),
		config:              config,
	}
}

func (d *EnhancedInfiniteLoopDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	patternConfig := d.config.GetPatternConfig("infinite_loops")
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

		if !d.loopDetector.IsUnboundedLoop(lineContent) {
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

func (d *EnhancedInfiniteLoopDetector) Name() string {
	return "infinite_loops_enhanced"
}

func (d *EnhancedInfiniteLoopDetector) IsEnabled() bool {
	patternConfig := d.config.GetPatternConfig("infinite_loops")
	return patternConfig.Enabled
}
