package detectors

import (
	"fmt"
	"testing"
)

// TestMissingHumanOversightDetectorRealWorldValidation tests Pattern 13 against real CVEs
func TestMissingHumanOversightDetectorRealWorldValidation(t *testing.T) {
	detector := &MissingHumanOversightDetector{}

	cveTestCases := []struct {
		cveID       string
		description string
		cveDir      string
	}{
		{cveID: "CVE-2025-61913", description: "Flowise WriteFileTool without approval", cveDir: "testdata/cves/2025"},
		{cveID: "CVE-2025-26319", description: "Flowise File Upload without oversight", cveDir: "testdata/cves/2025"},
		{cveID: "CVE-2024-31621", description: "Flowise Auth Bypass without oversight", cveDir: "testdata/cves/2024"},
	}

	t.Run("DetectMissingHumanOversight", func(t *testing.T) {
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
		t.Logf("Missing Human Oversight Detection: %d/%d", detectedCount, len(cveTestCases))
	})

	t.Run("SafeHumanOversight", func(t *testing.T) {
		samples := []struct {
			language string
			code     string
		}{
			{"python", "approval = get_human_approval(request)\nif not approval:\n    raise Exception('Approval required')\nexecute_operation(request)"},
			{"javascript", "const approval = await requestApproval(request);\nif (!approval) throw new Error('No approval');\nawaitExecute(request);"},
		}

		for _, sample := range samples {
			result := RunCleanCodeTest(detector, sample.code, sample.language)
			if result.Passed {
				fmt.Printf("OK %s: Safe human oversight\n", sample.language)
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

		cleanResult := RunCleanCodeTest(detector, "approval = request_approval()\nif approval: execute()", "python")
		results = append(results, *cleanResult)

		report := GenerateValidationReport(
			"missing_human_oversight",
			"Missing Human Oversight Detector",
			results,
			cvesCovered,
			[]string{"Flowise"},
		)

		markdown := FormatReportAsMarkdown(report)
		t.Logf("\n%s", markdown)
	})
}

// BenchmarkMissingHumanOversightDetector benchmarks performance
func BenchmarkMissingHumanOversightDetector(b *testing.B) {
	detector := &MissingHumanOversightDetector{}
	code := "def delete_data(dataset):\n    os.system(f'rm -rf {dataset}')"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.Detect("benchmark.py", []byte(code))
	}
}
