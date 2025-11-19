package detectors

import (
	"fmt"
	"testing"
)

// TestHardcodedCredentialsDetectorRealWorldValidation tests Pattern 1 against real CVEs
func TestHardcodedCredentialsDetectorRealWorldValidation(t *testing.T) {
	detector := &HardcodedCredentialsDetector{}

	cveTestCases := []struct {
		cveID       string
		description string
		cveDir      string
	}{
		{cveID: "CVE-2024-28088", description: "LangChain Directory Traversal API Key", cveDir: "testdata/cves/2024"},
		{cveID: "CVE-2024-31621", description: "Flowise Authentication Bypass", cveDir: "testdata/cves/2024"},
		{cveID: "CVE-2025-58434", description: "Flowise Password Reset Token", cveDir: "testdata/cves/2025"},
	}

	t.Run("DetectHardcodedCredentials", func(t *testing.T) {
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
		t.Logf("Hardcoded Credentials Detection: %d/%d", detectedCount, len(cveTestCases))
	})

	t.Run("SafeCredentialHandling", func(t *testing.T) {
		samples := []struct {
			language string
			code     string
		}{
			{"python", "api_key = os.getenv('API_KEY')\nif not api_key:\n    raise ValueError('API_KEY required')"},
			{"javascript", "const apiKey = process.env.API_KEY || ''"},
			{"python", "import config\ndb_password = config.get_password()"},
		}

		for _, sample := range samples {
			result := RunCleanCodeTest(detector, sample.code, sample.language)
			if result.Passed {
				fmt.Printf("OK %s: Safe credential handling\n", sample.language)
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

		cleanResult := RunCleanCodeTest(detector, "api_key = os.getenv('API_KEY')", "python")
		results = append(results, *cleanResult)

		report := GenerateValidationReport(
			"hardcoded_credentials",
			"Hardcoded Credentials Detector",
			results,
			cvesCovered,
			[]string{"LangChain", "Flowise"},
		)

		markdown := FormatReportAsMarkdown(report)
		t.Logf("\n%s", markdown)
	})
}

// BenchmarkHardcodedCredentialsDetector benchmarks performance
func BenchmarkHardcodedCredentialsDetector(b *testing.B) {
	detector := &HardcodedCredentialsDetector{}
	code := "api_key = 'sk-1234567890abcdef'\npassword = 'MySecurePass123!'"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.Detect("benchmark.py", []byte(code))
	}
}
