package detectors

import (
	"fmt"
	"testing"
)

// TestLoggingSensitiveDataDetectorRealWorldValidation tests Pattern 12 against real CVEs
func TestLoggingSensitiveDataDetectorRealWorldValidation(t *testing.T) {
	detector := &LoggingSensitiveDataDetector{}

	cveTestCases := []struct {
		cveID       string
		description string
		cveDir      string
	}{
		{cveID: "CVE-2025-58434", description: "Flowise Password Reset Token Logging", cveDir: "testdata/cves/2025"},
	}

	t.Run("DetectSensitiveDataLogging", func(t *testing.T) {
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
		t.Logf("Sensitive Data Logging Detection: %d/%d", detectedCount, len(cveTestCases))
	})

	t.Run("SafeLogging", func(t *testing.T) {
		samples := []struct {
			language string
			code     string
		}{
			{"python", "logger.info(f'User authenticated: {user_id}')\nlogger.info('API key: REDACTED')"},
			{"javascript", "logger.info(`User authenticated: ${userId}`);\nlogger.info('API key: REDACTED');"},
		}

		for _, sample := range samples {
			result := RunCleanCodeTest(detector, sample.code, sample.language)
			if result.Passed {
				fmt.Printf("OK %s: Safe logging\n", sample.language)
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

		cleanResult := RunCleanCodeTest(detector, "logger.info('Status: OK')", "python")
		results = append(results, *cleanResult)

		report := GenerateValidationReport(
			"logging_sensitive_data",
			"Logging Sensitive Data Detector",
			results,
			cvesCovered,
			[]string{"Flowise"},
		)

		markdown := FormatReportAsMarkdown(report)
		t.Logf("\n%s", markdown)
	})
}

// BenchmarkLoggingSensitiveDataDetector benchmarks performance
func BenchmarkLoggingSensitiveDataDetector(b *testing.B) {
	detector := &LoggingSensitiveDataDetector{}
	code := "logger.info(f'API Key: {api_key}')\nlogger.info(f'Password: {password}')"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.Detect("benchmark.py", []byte(code))
	}
}
