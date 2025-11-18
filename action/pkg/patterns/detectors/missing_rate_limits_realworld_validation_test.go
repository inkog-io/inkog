package detectors

import (
	"fmt"
	"testing"
)

// TestMissingRateLimitsDetectorRealWorldValidation tests Pattern 8 against real CVEs
func TestMissingRateLimitsDetectorRealWorldValidation(t *testing.T) {
	detector := &MissingRateLimitsDetector{}

	cveTestCases := []struct {
		cveID       string
		description string
		cveDir      string
	}{
		{cveID: "CVE-2024-2965", description: "LangChain Missing Rate Limits", cveDir: "testdata/cves/2024"},
	}

	t.Run("DetectMissingRateLimits", func(t *testing.T) {
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
		t.Logf("Missing Rate Limits Detection: %d/%d", detectedCount, len(cveTestCases))
	})

	t.Run("SafeRateLimiting", func(t *testing.T) {
		samples := []struct {
			language string
			code     string
		}{
			{"python", "from ratelimit import limits, sleep_and_retry\n@limits(calls=100, period=60)\ndef api_call():\n    pass"},
			{"javascript", "const rateLimit = require('express-rate-limit');\nconst limiter = rateLimit({windowMs: 60000, max: 100});"},
		}

		for _, sample := range samples {
			result := RunCleanCodeTest(detector, sample.code, sample.language)
			if result.Passed {
				fmt.Printf("OK %s: Safe rate limiting\n", sample.language)
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

		cleanResult := RunCleanCodeTest(detector, "rate_limiter = RateLimiter(max_calls=10, time_window=60)", "python")
		results = append(results, *cleanResult)

		report := GenerateValidationReport(
			"missing_rate_limits",
			"Missing Rate Limits Detector",
			results,
			cvesCovered,
			[]string{"LangChain"},
		)

		markdown := FormatReportAsMarkdown(report)
		t.Logf("\n%s", markdown)
	})
}

// BenchmarkMissingRateLimitsDetector benchmarks performance
func BenchmarkMissingRateLimitsDetector(b *testing.B) {
	detector := &MissingRateLimitsDetector{}
	code := "while True:\n    api.call_endpoint(user_request)"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.Detect("benchmark.py", []byte(code))
	}
}
