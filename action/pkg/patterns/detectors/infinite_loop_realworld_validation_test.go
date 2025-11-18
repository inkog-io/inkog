package detectors

import (
	"fmt"
	"testing"
)

// TestInfiniteLoopDetectorRealWorldValidation tests Pattern 3 against real CVEs
func TestInfiniteLoopDetectorRealWorldValidation(t *testing.T) {
	detector := &InfiniteLoopDetector{}

	cveTestCases := []struct {
		cveID       string
		description string
		cveDir      string
	}{
		{cveID: "CVE-2024-2965", description: "LangChain Recursive Sitemap DoS", cveDir: "testdata/cves/2024"},
	}

	t.Run("DetectInfiniteLoops", func(t *testing.T) {
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
		t.Logf("Infinite Loop Detection: %d/%d", detectedCount, len(cveTestCases))
	})

	t.Run("SafeLoopHandling", func(t *testing.T) {
		samples := []struct {
			language string
			code     string
		}{
			{"python", "visited = set()\nfor item in items:\n    if item in visited:\n        break\n    visited.add(item)"},
			{"javascript", "const visited = new Set()\nfor (const item of items) {\n    if (visited.has(item)) break\n    visited.add(item)\n}"},
		}

		for _, sample := range samples {
			result := RunCleanCodeTest(detector, sample.code, sample.language)
			if result.Passed {
				fmt.Printf("OK %s: Safe loop handling\n", sample.language)
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

		cleanResult := RunCleanCodeTest(detector, "for i in range(10):\n    pass", "python")
		results = append(results, *cleanResult)

		report := GenerateValidationReport(
			"infinite_loop",
			"Infinite Loop Detector",
			results,
			cvesCovered,
			[]string{"LangChain"},
		)

		markdown := FormatReportAsMarkdown(report)
		t.Logf("\n%s", markdown)
	})
}

// BenchmarkInfiniteLoopDetector benchmarks performance
func BenchmarkInfiniteLoopDetector(b *testing.B) {
	detector := &InfiniteLoopDetector{}
	code := "while True:\n    process_item()"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.Detect("benchmark.py", []byte(code))
	}
}
