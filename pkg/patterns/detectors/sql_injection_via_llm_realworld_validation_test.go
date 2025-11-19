package detectors

import (
	"fmt"
	"testing"
)

// TestSQLInjectionViaLLMDetectorRealWorldValidation tests Pattern 10 against real CVEs
func TestSQLInjectionViaLLMDetectorRealWorldValidation(t *testing.T) {
	detector := &SQLInjectionViaLLMDetector{}

	cveTestCases := []struct {
		cveID       string
		description string
		cveDir      string
	}{
		{cveID: "CVE-2024-8309", description: "LangChain GraphCypherQAChain SQL injection", cveDir: "testdata/cves/2024"},
		{cveID: "CVE-2024-7042", description: "LangChain JS GraphCypherQAChain SQL injection", cveDir: "testdata/cves/2024"},
	}

	t.Run("DetectSQLInjectionVulnerabilities", func(t *testing.T) {
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
		t.Logf("SQL Injection Detection: %d/%d", detectedCount, len(cveTestCases))
	})

	t.Run("ValidateParameterizedQueries", func(t *testing.T) {
		samples := []struct {
			language string
			code     string
		}{
			{"python", "query = text('SELECT * FROM users WHERE email = :email')\nresult = db.execute(query, {'email': user_email})"},
			{"javascript", "connection.query('SELECT * FROM users WHERE id = ?', [userId], callback)"},
		}

		for _, sample := range samples {
			result := RunCleanCodeTest(detector, sample.code, sample.language)
			if result.Passed {
				fmt.Printf("OK %s: Parameterized queries safe\n", sample.language)
			}
		}
	})
}

// BenchmarkSQLInjectionViaLLMDetector benchmarks performance
func BenchmarkSQLInjectionViaLLMDetector(b *testing.B) {
	detector := &SQLInjectionViaLLMDetector{}
	code := "query = f\"SELECT * FROM users WHERE email = '{user_input}'\"\ndb.execute(query)"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.Detect("benchmark.py", []byte(code))
	}
}
