package detectors

import (
	"fmt"
	"testing"
)

// TestOutputValidationFailuresDetectorRealWorldValidation tests Pattern 15 against real CVEs
func TestOutputValidationFailuresDetectorRealWorldValidation(t *testing.T) {
	detector := NewOutputValidationFailuresDetector()

	cveTestCases := []struct {
		cveID       string
		description string
		cveDir      string
	}{
		{cveID: "CVE-2023-29374", description: "LangChain LLMMathChain - eval injection", cveDir: "testdata/cves/2023"},
		{cveID: "CVE-2024-36422", description: "Flowise XSS - unescaped output", cveDir: "testdata/cves/2024"},
		{cveID: "CVE-2024-11824", description: "Dify stored XSS - unfiltered HTML", cveDir: "testdata/cves/2024"},
	}

	t.Run("DetectOutputValidationFailures", func(t *testing.T) {
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
		t.Logf("Output Validation Failures Detection: %d/%d", detectedCount, len(cveTestCases))
	})

	t.Run("SafeOutputHandling", func(t *testing.T) {
		samples := []struct {
			language string
			code     string
		}{
			{"python", "safe_html = bleach.clean(llm_output)\ndisplay(HTML(safe_html))"},
			{"javascript", "const safe = element.textContent = llmOutput;"},
			{"python", "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"},
		}

		for _, sample := range samples {
			result := RunCleanCodeTest(detector, sample.code, sample.language)
			if result.Passed {
				fmt.Printf("OK %s: Safe output handling\n", sample.language)
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

		cleanResult := RunCleanCodeTest(detector, "safe = bleach.clean(output)\nprint(safe)", "python")
		results = append(results, *cleanResult)

		report := GenerateValidationReport(
			"output_validation_failures",
			"Output Validation Failures Detector",
			results,
			cvesCovered,
			[]string{"LangChain", "Flowise", "Dify"},
		)

		markdown := FormatReportAsMarkdown(report)
		t.Logf("\n%s", markdown)
	})
}
