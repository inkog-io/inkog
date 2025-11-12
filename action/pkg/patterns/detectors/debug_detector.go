package detectors

import (
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

type DebugDetector struct {
	pattern patterns.Pattern
}

func NewDebugDetector() patterns.Detector {
	return &DebugDetector{
		pattern: patterns.Pattern{
			ID:       "debug_test",
			Name:     "Debug Test Pattern",
			Version:  "1.0",
			Severity: "MEDIUM",
		},
	}
}

func (d *DebugDetector) Name() string {
	return "debug_test"
}

func (d *DebugDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	// This should ALWAYS find something to verify the pipeline works
	sourceStr := string(src)
	findings := []patterns.Finding{}

	// If file contains "api_key", report it
	if strings.Contains(sourceStr, "api_key") {
		finding := patterns.Finding{
			ID:         "debug_1",
			PatternID:  "debug_test",
			Pattern:    "Debug Test",
			File:       filePath,
			Line:       1,
			Column:     1,
			Severity:   "MEDIUM",
			Confidence: 1.0,
			Message:    "DEBUG: Found api_key string in file",
			Code:       "api_key",
		}
		findings = append(findings, finding)
	}

	return findings, nil
}

func (d *DebugDetector) GetPattern() patterns.Pattern {
	return d.pattern
}

func (d *DebugDetector) GetConfidence() float32 {
	return 0.5
}

func (d *DebugDetector) Close() error {
	return nil
}
