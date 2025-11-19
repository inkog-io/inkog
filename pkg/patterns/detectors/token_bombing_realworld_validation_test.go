package detectors

import (
	"fmt"
	"testing"
)

// TestTokenBombingDetectorRealWorldValidation tests Pattern 5 against real CVEs
func TestTokenBombingDetectorRealWorldValidation(t *testing.T) {
	detector := &TokenBombingDetector{}

	cveTestCases := []struct {
		cveID       string
		description string
		cveDir      string
	}{
		{cveID: "CVE-2024-2965", description: "LangChain Token Exhaustion", cveDir: "testdata/cves/2024"},
	}

	t.Run("DetectTokenBombing", func(t *testing.T) {
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
		t.Logf("Token Bombing Detection: %d/%d", detectedCount, len(cveTestCases))
	})

	t.Run("SafeTokenHandling", func(t *testing.T) {
		samples := []struct {
			language string
			code     string
		}{
			{"python", "MAX_TOKENS = 4096\nif len(tokens) > MAX_TOKENS:\n    tokens = tokens[:MAX_TOKENS]"},
			{"javascript", "const MAX_TOKENS = 4096;\nif (tokens.length > MAX_TOKENS) {\n    tokens = tokens.slice(0, MAX_TOKENS);\n}"},
		}

		for _, sample := range samples {
			result := RunCleanCodeTest(detector, sample.code, sample.language)
			if result.Passed {
				fmt.Printf("OK %s: Safe token handling\n", sample.language)
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

		cleanResult := RunCleanCodeTest(detector, "max_tokens = 4096\nif tokens > max_tokens: return error", "python")
		results = append(results, *cleanResult)

		report := GenerateValidationReport(
			"token_bombing",
			"Token Bombing Detector",
			results,
			cvesCovered,
			[]string{"LangChain"},
		)

		markdown := FormatReportAsMarkdown(report)
		t.Logf("\n%s", markdown)
	})
}

// BenchmarkTokenBombingDetector benchmarks performance
func BenchmarkTokenBombingDetector(b *testing.B) {
	detector := &TokenBombingDetector{}
	code := "for _ in range(1000000):\n    tokens.append(generate_token())"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.Detect("benchmark.py", []byte(code))
	}
}
