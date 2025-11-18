package detectors

import (
	"fmt"
	"testing"
)

// TestUnvalidatedExecEvalDetectorRealWorldValidation tests Pattern 9 against real CVEs
func TestUnvalidatedExecEvalDetectorRealWorldValidation(t *testing.T) {
	detector := &UnvalidatedExecEvalDetector{}

	cveTestCases := []struct {
		cveID       string
		description string
		cveDir      string
	}{
		{cveID: "CVE-2024-46946", description: "LangChain sympy eval injection", cveDir: "testdata/cves/2024"},
		{cveID: "CVE-2024-27444", description: "LangChain PALChain bypass", cveDir: "testdata/cves/2024"},
		{cveID: "CVE-2023-44467", description: "LangChain PALChain injection", cveDir: "testdata/cves/2023"},
		{cveID: "CVE-2023-29374", description: "LangChain LLMMathChain code injection", cveDir: "testdata/cves/2023"},
		{cveID: "CVE-2024-8309", description: "LangChain GraphCypher SQL injection", cveDir: "testdata/cves/2024"},
	}

	t.Run("DetectVulnerableCode", func(t *testing.T) {
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
		t.Logf("Exec/Eval Detection: %d/%d", detectedCount, len(cveTestCases))
	})

	t.Run("CleanCodeFalsePositiveTest", func(t *testing.T) {
		samples := []struct {
			language string
			code     string
		}{
			{"python", "import ast\nresult = ast.literal_eval(expression)"},
			{"javascript", "const result = JSON.parse(jsonString)"},
			{"python", "if not validate_input(user_input):\n    raise ValueError('Invalid')"},
		}

		for _, sample := range samples {
			result := RunCleanCodeTest(detector, sample.code, sample.language)
			if result.Passed {
				fmt.Printf("OK %s: No false positives\n", sample.language)
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

		cleanResult := RunCleanCodeTest(detector, "result = ast.literal_eval(expression)", "python")
		results = append(results, *cleanResult)

		report := GenerateValidationReport(
			"unvalidated_exec_eval",
			"Unvalidated Exec/Eval Detector",
			results,
			cvesCovered,
			[]string{"LangChain"},
		)

		markdown := FormatReportAsMarkdown(report)
		t.Logf("\n%s", markdown)
	})
}

// BenchmarkUnvalidatedExecEvalDetector benchmarks performance
func BenchmarkUnvalidatedExecEvalDetector(b *testing.B) {
	detector := &UnvalidatedExecEvalDetector{}
	code := "result = eval(user_input)\nexec(user_code)"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.Detect("benchmark.py", []byte(code))
	}
}
