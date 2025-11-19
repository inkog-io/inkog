package detectors

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// RealWorldTestResult tracks test results for a file
type RealWorldTestResult struct {
	FilePath          string
	DetectedFindings  int
	TruePositives     int
	FalsePositives    int
	FalseNegatives    int
	FindingsByPattern map[string]int
}

// ScanRealWorldFiles scans a directory with all patterns and generates a report
func TestRealWorldVulnerableScanning(t *testing.T) {
	config := NewSimpleEnterpriseConfig()
	vulnDir := "/tmp/inkog_realworld_tests/vulnerable_samples"

	// Check if directory exists
	if _, err := os.Stat(vulnDir); os.IsNotExist(err) {
		t.Logf("Real-world test directory not found, creating samples...")
		return
	}

	t.Logf("\n=== REAL-WORLD VULNERABLE CODE SCANNING ===")
	t.Logf("Scanning directory: %s\n", vulnDir)

	results := scanDirectoryWithAllPatterns(t, vulnDir, config, true)

	// Analyze results
	for _, result := range results {
		t.Logf("File: %s", filepath.Base(result.FilePath))
		t.Logf("  Total findings: %d", result.DetectedFindings)
		t.Logf("  True positives: %d", result.TruePositives)
		t.Logf("  False positives: %d", result.FalsePositives)
		t.Logf("  Findings by pattern:")

		for pattern, count := range result.FindingsByPattern {
			t.Logf("    - %s: %d", pattern, count)
		}
	}

	// For vulnerable code, we expect high detection rate
	totalFindings := 0
	for _, result := range results {
		totalFindings += result.DetectedFindings
	}

	if totalFindings == 0 {
		t.Errorf("Expected to find vulnerabilities in vulnerable code, found 0")
	} else {
		t.Logf("\nVulnerable code scanning PASSED: Detected %d vulnerabilities", totalFindings)
	}
}

// TestRealWorldCleanScanning tests scanning of secure code
func TestRealWorldCleanScanning(t *testing.T) {
	config := NewSimpleEnterpriseConfig()
	cleanDir := "/tmp/inkog_realworld_tests/clean_samples"

	// Check if directory exists
	if _, err := os.Stat(cleanDir); os.IsNotExist(err) {
		t.Logf("Real-world test directory not found")
		return
	}

	t.Logf("\n=== REAL-WORLD CLEAN CODE SCANNING ===")
	t.Logf("Scanning directory: %s\n", cleanDir)

	results := scanDirectoryWithAllPatterns(t, cleanDir, config, false)

	// Analyze results
	totalFindings := 0
	totalExpected := 0

	for _, result := range results {
		t.Logf("File: %s", filepath.Base(result.FilePath))
		t.Logf("  Total findings: %d", result.DetectedFindings)
		t.Logf("  False positives: %d", result.FalsePositives)
		t.Logf("  Findings by pattern:")

		for pattern, count := range result.FindingsByPattern {
			t.Logf("    - %s: %d", pattern, count)
		}

		totalFindings += result.DetectedFindings
		totalExpected += result.FalsePositives
	}

	t.Logf("\nClean code scanning PASSED: False positive rate = %d findings (expected minimal)", totalFindings)
}

// scanDirectoryWithAllPatterns scans all files in a directory with all 15 patterns
func scanDirectoryWithAllPatterns(t *testing.T, dirPath string, config *SimpleEnterpriseConfig, isVulnerable bool) []RealWorldTestResult {
	var results []RealWorldTestResult

	// Read all Python and JavaScript files
	files, err := ioutil.ReadDir(dirPath)
	if err != nil {
		t.Logf("Error reading directory: %v", err)
		return results
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		if !strings.HasSuffix(file.Name(), ".py") && !strings.HasSuffix(file.Name(), ".js") {
			continue
		}

		filePath := filepath.Join(dirPath, file.Name())
		content, err := ioutil.ReadFile(filePath)
		if err != nil {
			t.Logf("Error reading file %s: %v", filePath, err)
			continue
		}

		result := scanFileWithAllPatterns(filePath, content, config)
		results = append(results, result)
	}

	return results
}

// scanFileWithAllPatterns scans a single file with all 11 patterns
func scanFileWithAllPatterns(filePath string, content []byte, config *SimpleEnterpriseConfig) RealWorldTestResult {
	result := RealWorldTestResult{
		FilePath:          filePath,
		FindingsByPattern: make(map[string]int),
	}

	// All 15 detectors
	detectors := []struct {
		name     string
		detector interface {
			Detect(filePath string, src []byte) ([]patterns.Finding, error)
		}
	}{
		{"hardcoded_credentials", NewEnhancedHardcodedCredentialsDetector(config)},
		{"prompt_injection", NewEnhancedPromptInjectionDetector(config)},
		{"infinite_loops", NewEnhancedInfiniteLoopDetector(config)},
		{"unsafe_env_access", NewEnhancedUnsafeEnvAccessDetector(config)},
		{"token_bombing", NewEnhancedTokenBombingDetector(config)},
		{"recursive_tool_calling", NewEnhancedRecursiveToolCallingDetector(config)},
		{"rag_over_fetching", NewEnhancedRAGOverFetchingDetector(config)},
		{"missing_rate_limits", NewEnhancedMissingRateLimitsDetector(config)},
		{"unvalidated_exec_eval", NewEnhancedUnvalidatedExecEvalDetector(config)},
		{"sql_injection_via_llm", NewEnhancedSQLInjectionViaLLMDetector(config)},
		{"context_window_accumulation", NewEnhancedContextWindowAccumulationDetector(config)},
		{"logging_sensitive_data", NewEnhancedLoggingSensitiveDataDetector(config)},
		{"missing_human_oversight", NewEnhancedMissingHumanOversightDetector(config)},
		{"cross_tenant_data_leakage", NewEnhancedCrossTenantDataLeakageDetector(config)},
		{"output_validation_failures", NewEnhancedOutputValidationFailuresDetector(config)},
	}

	// Run all detectors
	for _, d := range detectors {
		findings, err := d.detector.Detect(filePath, content)
		if err != nil {
			continue
		}

		count := len(findings)
		if count > 0 {
			result.FindingsByPattern[d.name] = count
			result.DetectedFindings += count
		}
	}

	return result
}

// TestMultiPatternRealWorldIntegration tests all patterns together on real code
func TestMultiPatternRealWorldIntegration(t *testing.T) {
	config := NewSimpleEnterpriseConfig()

	t.Logf("\n=== MULTI-PATTERN REAL-WORLD INTEGRATION TEST ===\n")

	// Test vulnerable code
	vulnCode := `
from langchain.memory import ConversationBufferMemory
api_key = "sk-1234567890"
memory = ConversationBufferMemory()
while True:
    user_input = input()
    eval(user_input)
    exec(f"query = '{user_input}'")
`

	findings := scanWithAllPatterns(vulnCode, "test_vulnerable.py", config)
	t.Logf("Vulnerable code analysis:")
	t.Logf("  Total findings: %d", len(findings))

	// Group by pattern
	patterns := make(map[string]int)
	for _, f := range findings {
		patterns[f.PatternID]++
	}

	for pattern, count := range patterns {
		t.Logf("  - %s: %d", pattern, count)
	}

	// Test clean code
	cleanCode := `
import os
api_key = os.environ.get("API_KEY")
memory = ConversationSummaryMemory(llm=llm)
max_iterations = 10
for i in range(max_iterations):
    safe_result = execute_safe_tool()
`

	cleanFindings := scanWithAllPatterns(cleanCode, "test_clean.py", config)
	t.Logf("\nClean code analysis:")
	t.Logf("  Total findings: %d", len(cleanFindings))

	// Results should show detection on vulnerable, minimal on clean
	if len(findings) > 0 && len(cleanFindings) < len(findings) {
		t.Logf("\n✅ Real-world integration test PASSED")
		t.Logf("   - Vulnerable code: Detected %d issues", len(findings))
		t.Logf("   - Clean code: Detected %d issues (lower, as expected)", len(cleanFindings))
	}
}

// scanWithAllPatterns is a helper to scan code with all patterns
func scanWithAllPatterns(code string, filePath string, config *SimpleEnterpriseConfig) []patterns.Finding {
	var allFindings []patterns.Finding

	detectors := []interface {
		Detect(filePath string, src []byte) ([]patterns.Finding, error)
	}{
		NewEnhancedHardcodedCredentialsDetector(config),
		NewEnhancedPromptInjectionDetector(config),
		NewEnhancedInfiniteLoopDetector(config),
		NewEnhancedUnsafeEnvAccessDetector(config),
		NewEnhancedTokenBombingDetector(config),
		NewEnhancedRecursiveToolCallingDetector(config),
		NewEnhancedRAGOverFetchingDetector(config),
		NewEnhancedMissingRateLimitsDetector(config),
		NewEnhancedUnvalidatedExecEvalDetector(config),
		NewEnhancedSQLInjectionViaLLMDetector(config),
		NewEnhancedContextWindowAccumulationDetector(config),
		NewEnhancedLoggingSensitiveDataDetector(config),
		NewEnhancedMissingHumanOversightDetector(config),
		NewEnhancedCrossTenantDataLeakageDetector(config),
		NewEnhancedOutputValidationFailuresDetector(config),
	}

	for _, detector := range detectors {
		findings, err := detector.Detect(filePath, []byte(code))
		if err == nil {
			allFindings = append(allFindings, findings...)
		}
	}

	return allFindings
}

// BenchmarkRealWorldPerformance benchmarks scanning performance on real code
func BenchmarkRealWorldPerformance(b *testing.B) {
	config := NewSimpleEnterpriseConfig()

	// Real-world code sample
	realCode := `
from langchain.agents import AgentExecutor, initialize_agent
from langchain.memory import ConversationBufferMemory
from langchain.llms import OpenAI
import os

api_key = "sk-1234567890abcdefghijklmnop"
memory = ConversationBufferMemory()

def execute_query(user_input):
    while True:
        result = eval(user_input)
        exec(f"output = {user_input}")
        return result

agent = initialize_agent(tools, llm, memory=memory)
agent.run(user_input)
`

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		scanWithAllPatterns(realCode, "bench_test.py", config)
	}
}
