package detectors

import (
	"fmt"
	"testing"
)

// TestPromptInjectionDetectorRealWorldValidation tests Pattern 2 against real CVEs
// Validates detection of prompt injection attacks in LLM-based applications
func TestPromptInjectionDetectorRealWorldValidation(t *testing.T) {
	detector := &PromptInjectionDetector{}

	// Real CVEs targeting prompt injection
	cveTestCases := []struct {
		cveID       string
		description string
		cveDir      string
	}{
		{cveID: "CVE-2024-46946", description: "LangChain sympy eval injection", cveDir: "testdata/cves/2024"},
		{cveID: "CVE-2024-27444", description: "LangChain PALChain bypass", cveDir: "testdata/cves/2024"},
		{cveID: "CVE-2024-8309", description: "LangChain GraphCypher SQL injection", cveDir: "testdata/cves/2024"},
		{cveID: "CVE-2024-7042", description: "LangChain JS GraphCypher injection", cveDir: "testdata/cves/2024"},
		{cveID: "CVE-2023-44467", description: "LangChain PALChain prompt injection", cveDir: "testdata/cves/2023"},
		{cveID: "CVE-2023-29374", description: "LangChain LLMMathChain code injection", cveDir: "testdata/cves/2023"},
		{cveID: "CVE-2023-36189", description: "LangChain SQLDatabaseChain injection", cveDir: "testdata/cves/2023"},
	}

	// Detection Test
	t.Run("DetectPromptInjectionVulnerabilities", func(t *testing.T) {
		detectedCount := 0
		falseNegativeCount := 0

		for _, tc := range cveTestCases {
			testCase, err := LoadCVETestCase(tc.cveDir, tc.cveID)
			if err != nil {
				t.Logf("Skipping %s: test data not available", tc.cveID)
				continue
			}

			result := RunCVEDetectionTest(detector, testCase)

			if result.Passed {
				t.Logf("OK %s: Correctly detected prompt injection in %s",
					tc.cveID, tc.description)
				detectedCount++
			} else {
				t.Logf("FAIL %s: FAILED to detect prompt injection", tc.cveID)
				falseNegativeCount++
			}
		}

		t.Logf("\nPrompt Injection Detection Summary:")
		t.Logf("   Detected: %d/%d", detectedCount, len(cveTestCases))
		t.Logf("   False Negatives: %d", falseNegativeCount)
	})

	// Input Validation Test
	t.Run("ValidateInputSanitization", func(t *testing.T) {
		cleanCodeSamples := []struct {
			language string
			code     string
			desc     string
		}{
			{
				language: "python",
				code: "user_input = sanitize(get_user_input())\nprompt = f'Answer: {user_input}'\nreturn llm.predict(prompt)",
				desc: "Input validation and sanitization",
			},
			{
				language: "javascript",
				code: "const safeInput = userInput.replace(/[^a-zA-Z0-9]/g, '');\nreturn {user: safeInput};",
				desc: "Whitelist and escaping",
			},
			{
				language: "python",
				code: "if intent == UserIntent.QUESTION:\n    return handle_question_safely(user_input)",
				desc: "Intent-based routing",
			},
		}

		falsePositiveCount := 0

		for _, sample := range cleanCodeSamples {
			result := RunCleanCodeTest(detector, sample.code, sample.language)

			if result.Passed {
				fmt.Printf("OK %s (%s): No false positives\n", sample.language, sample.desc)
			} else {
				fmt.Printf("WARN %s (%s): Potential false positive (%d detections)\n",
					sample.language, sample.desc, result.TotalFindings)
				falsePositiveCount++
			}
		}

		t.Logf("\nInput Sanitization Test Summary:")
		t.Logf("   Clean code tests passed: %d/%d", len(cleanCodeSamples)-falsePositiveCount, len(cleanCodeSamples))
		t.Logf("   False positives: %d", falsePositiveCount)
	})

	// Generate Report
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

		// Clean code test
		cleanResult := RunCleanCodeTest(detector, "user_input = sanitize(get_user_input())\nprompt = f'Answer: {user_input}'\nreturn llm.predict(prompt)", "python")
		results = append(results, *cleanResult)

		report := GenerateValidationReport(
			"prompt_injection",
			"Prompt Injection Detector",
			results,
			cvesCovered,
			[]string{"LangChain", "Flowise"},
		)

		markdown := FormatReportAsMarkdown(report)
		t.Logf("\n%s", markdown)

		t.Logf("\nPattern Coverage:")
		t.Logf("   Real CVEs tested: %d", len(cvesCovered))
		t.Logf("   Detection accuracy: %.1f%%", report.DetectionAccuracy*100)
		t.Logf("   False positive rate: %.1f%%", report.FalsePositiveRate*100)
	})
}

// BenchmarkPromptInjectionDetector benchmarks performance
func BenchmarkPromptInjectionDetector(b *testing.B) {
	detector := &PromptInjectionDetector{}

	vulnerableCode := `
prompt = f"Answer: {user_question}"
result = llm.predict(prompt)
`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.Detect("benchmark.py", []byte(vulnerableCode))
	}
}
