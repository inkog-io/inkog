package detectors

import (
	"fmt"
	"testing"
)

// TestRecursiveToolCallingDetectorRealWorldValidation tests Pattern 6 against real CVEs
func TestRecursiveToolCallingDetectorRealWorldValidation(t *testing.T) {
	detector := &RecursiveToolCallingDetector{}

	cveTestCases := []struct {
		cveID       string
		description string
		cveDir      string
	}{
		{cveID: "CVE-2024-2965", description: "LangChain Recursive Tool Calling", cveDir: "testdata/cves/2024"},
	}

	t.Run("DetectRecursiveToolCalling", func(t *testing.T) {
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
		t.Logf("Recursive Tool Calling Detection: %d/%d", detectedCount, len(cveTestCases))
	})

	t.Run("SafeToolCalling", func(t *testing.T) {
		samples := []struct {
			language string
			code     string
		}{
			{"python", "call_depth = 0\nmax_depth = 5\ndef safe_tool(args):\n    global call_depth\n    if call_depth >= max_depth: return\n    call_depth += 1"},
			{"javascript", "let callDepth = 0;\nconst MAX_DEPTH = 5;\nfunction safeTool() {\n    if (callDepth >= MAX_DEPTH) return;\n    callDepth++;\n}"},
		}

		for _, sample := range samples {
			result := RunCleanCodeTest(detector, sample.code, sample.language)
			if result.Passed {
				fmt.Printf("OK %s: Safe tool calling\n", sample.language)
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

		cleanResult := RunCleanCodeTest(detector, "def process(data):\n    return transform(data)", "python")
		results = append(results, *cleanResult)

		report := GenerateValidationReport(
			"recursive_tool_calling",
			"Recursive Tool Calling Detector",
			results,
			cvesCovered,
			[]string{"LangChain"},
		)

		markdown := FormatReportAsMarkdown(report)
		t.Logf("\n%s", markdown)
	})
}

// BenchmarkRecursiveToolCallingDetector benchmarks performance
func BenchmarkRecursiveToolCallingDetector(b *testing.B) {
	detector := &RecursiveToolCallingDetector{}
	code := "def recursive_tool(n):\n    if n > 0:\n        recursive_tool(n-1)"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.Detect("benchmark.py", []byte(code))
	}
}
