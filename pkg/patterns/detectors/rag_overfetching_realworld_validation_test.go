package detectors

import (
	"fmt"
	"testing"
)

// TestRAGOverFetchingDetectorRealWorldValidation tests Pattern 7 against real CVEs
func TestRAGOverFetchingDetectorRealWorldValidation(t *testing.T) {
	detector := &RAGOverFetchingDetector{}

	cveTestCases := []struct {
		cveID       string
		description string
		cveDir      string
	}{
		{cveID: "CVE-2024-2965", description: "LangChain RAG Over-Fetching", cveDir: "testdata/cves/2024"},
	}

	t.Run("DetectRAGOverFetching", func(t *testing.T) {
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
		t.Logf("RAG Over-Fetching Detection: %d/%d", detectedCount, len(cveTestCases))
	})

	t.Run("SafeRAGFetching", func(t *testing.T) {
		samples := []struct {
			language string
			code     string
		}{
			{"python", "max_results = 10\nresults = retriever.get_relevant_documents(query, k=max_results)"},
			{"javascript", "const MAX_RESULTS = 10;\nconst results = await retriever.getRelevant(query, {limit: MAX_RESULTS});"},
		}

		for _, sample := range samples {
			result := RunCleanCodeTest(detector, sample.code, sample.language)
			if result.Passed {
				fmt.Printf("OK %s: Safe RAG fetching\n", sample.language)
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

		cleanResult := RunCleanCodeTest(detector, "results = db.query(limit=10)", "python")
		results = append(results, *cleanResult)

		report := GenerateValidationReport(
			"rag_overfetching",
			"RAG Over-Fetching Detector",
			results,
			cvesCovered,
			[]string{"LangChain"},
		)

		markdown := FormatReportAsMarkdown(report)
		t.Logf("\n%s", markdown)
	})
}

// BenchmarkRAGOverFetchingDetector benchmarks performance
func BenchmarkRAGOverFetchingDetector(b *testing.B) {
	detector := &RAGOverFetchingDetector{}
	code := "results = retriever.get_relevant_documents(query)"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.Detect("benchmark.py", []byte(code))
	}
}
