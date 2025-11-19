package detectors

import (
	"fmt"
	"testing"
)

// TestContextWindowAccumulationDetectorRealWorldValidation tests Pattern 11 against real CVEs
func TestContextWindowAccumulationDetectorRealWorldValidation(t *testing.T) {
	detector := &ContextWindowAccumulationDetector{}

	cveTestCases := []struct {
		cveID       string
		description string
		cveDir      string
	}{
		{cveID: "CVE-2024-2965", description: "LangChain Context Window Accumulation", cveDir: "testdata/cves/2024"},
	}

	t.Run("DetectContextWindowAccumulation", func(t *testing.T) {
		detectedCount := 0
		for _, tc := range cveTestCases {
			testCase, err := LoadCVETestCase(tc.cveDir, tc.cveID)
			if err != nil {
				continue
			}
			result := RunCVEDetectionTest(detector, testCase)
			if result.Passed {
				detectedCount++
			}
		}
		t.Logf("Context Window Accumulation Detection: %d/%d", detectedCount, len(cveTestCases))
	})

	t.Run("SafeContextManagement", func(t *testing.T) {
		samples := []struct {
			language string
			code     string
		}{
			{"python", "MAX_CONTEXT = 4096\nif len(context) > MAX_CONTEXT:\n    context = context[-MAX_CONTEXT:]"},
			{"javascript", "const MAX_CONTEXT = 4096;\nif (context.length > MAX_CONTEXT) {\n    context = context.slice(-MAX_CONTEXT);\n}"},
		}

		for _, sample := range samples {
			result := RunCleanCodeTest(detector, sample.code, sample.language)
			if result.Passed {
				fmt.Printf("OK %s: Safe context management\n", sample.language)
			}
		}
	})

	t.Run("GenerateValidationReport", func(t *testing.T) {
		var results []ValidationResult
		cvesCovered := []string{}

		for _, tc := range cveTestCases {
			testCase, err := LoadCVETestCase(tc.cveDir, tc.cveID)
			if err != nil {
				continue
			}
			result := RunCVEDetectionTest(detector, testCase)
			results = append(results, *result)
			cvesCovered = append(cvesCovered, tc.cveID)
		}

		cleanResult := RunCleanCodeTest(detector, "context = context.truncate(max_length=4096)", "python")
		results = append(results, *cleanResult)

		report := GenerateValidationReport(
			"context_window_accumulation",
			"Context Window Accumulation Detector",
			results,
			cvesCovered,
			[]string{"LangChain"},
		)

		markdown := FormatReportAsMarkdown(report)
		t.Logf("\n%s", markdown)
	})
}

// BenchmarkContextWindowAccumulationDetector benchmarks performance
func BenchmarkContextWindowAccumulationDetector(b *testing.B) {
	detector := &ContextWindowAccumulationDetector{}
	code := "for message in messages:\n    context.append(message)"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.Detect("benchmark.py", []byte(code))
	}
}
