package detectors

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"time"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// CVETestCase represents a single CVE test case with vulnerable and safe code
type CVETestCase struct {
	CVEID                string  `json:"cve_id"`
	Title                string  `json:"title"`
	CVSS                 float32 `json:"cvss"`
	Framework            string  `json:"framework"`
	Patterns             []string `json:"patterns"`
	VulnerableCode       string
	SafeCode             string
	ExpectedDetections   int
	MinConfidenceScore   float32
	Language             string
}

// RealWorldTestSuite configures testing for a pattern against real CVEs
type RealWorldTestSuite struct {
	PatternID              string
	PatternName            string
	CVEExamples            []CVETestCase
	CleanCodeSamples       []string
	ExpectedDetectionRate  float32  // e.g., 0.95 = 95%
	MaxFalsePositiveRate   float32  // e.g., 0.05 = 5%
	PerformanceTarget      time.Duration
	Description            string
}

// ValidationResult tracks the validation results for a single CVE or code sample
type ValidationResult struct {
	TestID          string
	TestType        string // "cve", "clean", "framework"
	Code            string
	Language        string
	TotalFindings   int
	FindingsByType  map[string]int
	ConfidenceScores []float32
	ExecutionTime   time.Duration
	Passed          bool
	FailureReason   string
}

// ValidationReport aggregates results for an entire pattern
type ValidationReport struct {
	PatternID            string
	PatternName          string
	TestDate             time.Time
	TotalTests           int
	PassedTests          int
	FailedTests          int
	DetectionAccuracy    float32
	FalsePositiveRate    float32
	AvgPerformance       time.Duration
	ProductionReady      bool
	DetailedResults      []ValidationResult
	CVEsCovered          []string
	FrameworksCovered    []string
}

// LoadCVEInventory loads the CVE inventory from JSON file
func LoadCVEInventory(inventoryPath string) (map[string]interface{}, error) {
	data, err := ioutil.ReadFile(inventoryPath)
	if err != nil {
		return nil, err
	}

	var inventory map[string]interface{}
	if err := json.Unmarshal(data, &inventory); err != nil {
		return nil, err
	}

	return inventory, nil
}

// LoadCVETestCase loads vulnerable and safe code for a specific CVE
func LoadCVETestCase(cveDir string, cveID string) (*CVETestCase, error) {
	// Load metadata
	metadataPath := filepath.Join(cveDir, fmt.Sprintf("%s-metadata.json", cveID))
	metadataData, err := ioutil.ReadFile(metadataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load metadata for %s: %w", cveID, err)
	}

	var metadata map[string]interface{}
	if err := json.Unmarshal(metadataData, &metadata); err != nil {
		return nil, err
	}

	testCase := &CVETestCase{
		CVEID:        cveID,
	}

	// Extract basic fields
	if title, ok := metadata["title"].(string); ok {
		testCase.Title = title
	}
	if cvss, ok := metadata["cvss"].(float64); ok {
		testCase.CVSS = float32(cvss)
	}
	if framework, ok := metadata["framework"].(string); ok {
		testCase.Framework = framework
	}

	// Extract patterns (vulnerable_patterns or pattern_types)
	var patterns []string
	if expectedDet, ok := metadata["expected_detections"].(map[string]interface{}); ok {
		for pattern := range expectedDet {
			patterns = append(patterns, pattern)
		}
	} else if patternTypes, ok := metadata["pattern_types"].([]interface{}); ok {
		for _, p := range patternTypes {
			if patStr, ok := p.(string); ok {
				patterns = append(patterns, patStr)
			}
		}
	}
	testCase.Patterns = patterns

	// Detect language from vulnerable_code_file
	if codeFile, ok := metadata["vulnerable_code_file"].(string); ok {
		if strings.HasSuffix(codeFile, ".py") {
			testCase.Language = "python"
		} else if strings.HasSuffix(codeFile, ".js") || strings.HasSuffix(codeFile, ".ts") {
			testCase.Language = "javascript"
		} else if strings.HasSuffix(codeFile, ".go") {
			testCase.Language = "go"
		} else if strings.HasSuffix(codeFile, ".java") {
			testCase.Language = "java"
		}

		// Load vulnerable code
		vulnCodePath := filepath.Join(cveDir, codeFile)
		if vulnCode, err := ioutil.ReadFile(vulnCodePath); err == nil {
			testCase.VulnerableCode = string(vulnCode)
		}
	}

	// Load safe code if available
	if safeFile, ok := metadata["safe_code_file"].(string); ok {
		safeCodePath := filepath.Join(cveDir, safeFile)
		if safeCode, err := ioutil.ReadFile(safeCodePath); err == nil {
			testCase.SafeCode = string(safeCode)
		}
	}

	return testCase, nil
}

// RunCVEDetectionTest runs detection against vulnerable code from a real CVE
func RunCVEDetectionTest(detector interface {
	Detect(filePath string, src []byte) ([]patterns.Finding, error)
}, testCase *CVETestCase) *ValidationResult {
	startTime := time.Now()

	result := &ValidationResult{
		TestID:         testCase.CVEID,
		TestType:       "cve",
		Code:           testCase.VulnerableCode,
		Language:       testCase.Language,
		FindingsByType: make(map[string]int),
	}

	// Run detection
	findings, err := detector.Detect(fmt.Sprintf("%s.%s", testCase.CVEID, testCase.Language), []byte(testCase.VulnerableCode))
	if err != nil {
		result.FailureReason = err.Error()
		result.Passed = false
		result.ExecutionTime = time.Since(startTime)
		return result
	}

	result.TotalFindings = len(findings)

	// Aggregate by pattern type
	for _, finding := range findings {
		result.FindingsByType[finding.PatternID]++
		result.ConfidenceScores = append(result.ConfidenceScores, finding.Confidence)
	}

	// Determine if test passed
	// Should detect at least one finding for a vulnerable CVE sample
	result.Passed = len(findings) > 0
	result.ExecutionTime = time.Since(startTime)

	if !result.Passed {
		result.FailureReason = fmt.Sprintf("No findings detected for vulnerable CVE: %s", testCase.CVEID)
	}

	return result
}

// RunCleanCodeTest runs detection against safe code to measure false positives
func RunCleanCodeTest(detector interface {
	Detect(filePath string, src []byte) ([]patterns.Finding, error)
}, code string, language string) *ValidationResult {
	startTime := time.Now()

	result := &ValidationResult{
		TestID:         fmt.Sprintf("clean_%s", language),
		TestType:       "clean",
		Code:           code,
		Language:       language,
		FindingsByType: make(map[string]int),
	}

	// Run detection
	findings, err := detector.Detect(fmt.Sprintf("clean.%s", language), []byte(code))
	if err != nil {
		result.FailureReason = err.Error()
		result.ExecutionTime = time.Since(startTime)
		return result
	}

	result.TotalFindings = len(findings)

	// Aggregate by pattern type
	for _, finding := range findings {
		result.FindingsByType[finding.PatternID]++
		result.ConfidenceScores = append(result.ConfidenceScores, finding.Confidence)
	}

	// For clean code, ideally should have 0 findings (no false positives)
	result.Passed = len(findings) == 0
	result.ExecutionTime = time.Since(startTime)

	if !result.Passed {
		result.FailureReason = fmt.Sprintf("False positives detected: %d findings", len(findings))
	}

	return result
}

// GenerateValidationReport creates a comprehensive validation report
func GenerateValidationReport(
	patternID string,
	patternName string,
	results []ValidationResult,
	cvesCovered []string,
	frameworksCovered []string,
) *ValidationReport {
	report := &ValidationReport{
		PatternID:         patternID,
		PatternName:       patternName,
		TestDate:          time.Now(),
		DetailedResults:   results,
		CVEsCovered:       cvesCovered,
		FrameworksCovered: frameworksCovered,
	}

	// Calculate metrics
	var totalTime time.Duration
	cveTests := 0
	cleanTests := 0
	cvesPassed := 0
	cleansPassed := 0

	for _, result := range results {
		report.TotalTests++

		if result.Passed {
			report.PassedTests++
			if result.TestType == "cve" {
				cvesPassed++
			} else if result.TestType == "clean" {
				cleansPassed++
			}
		} else {
			report.FailedTests++
		}

		totalTime += result.ExecutionTime

		if result.TestType == "cve" {
			cveTests++
		} else if result.TestType == "clean" {
			cleanTests++
		}
	}

	// Calculate accuracy metrics
	if cveTests > 0 {
		report.DetectionAccuracy = float32(cvesPassed) / float32(cveTests)
	}

	if cleanTests > 0 {
		report.FalsePositiveRate = 1.0 - (float32(cleansPassed) / float32(cleanTests))
	}

	if report.TotalTests > 0 {
		avgTime := totalTime / time.Duration(report.TotalTests)
		report.AvgPerformance = avgTime
	}

	// Determine production readiness
	// Criteria: ≥95% detection accuracy, ≤5% false positive rate, <10ms performance
	report.ProductionReady =
		report.DetectionAccuracy >= 0.95 &&
		report.FalsePositiveRate <= 0.05 &&
		report.AvgPerformance < 10*time.Millisecond

	return report
}

// FormatReportAsMarkdown converts validation report to Markdown format
func FormatReportAsMarkdown(report *ValidationReport) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# Pattern Validation Report: %s\n\n", report.PatternName))
	sb.WriteString(fmt.Sprintf("**Test Date**: %s\n", report.TestDate.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("**Pattern ID**: %s\n\n", report.PatternID))

	// Summary
	sb.WriteString("## Summary\n\n")
	sb.WriteString(fmt.Sprintf("- **Total Tests**: %d\n", report.TotalTests))
	sb.WriteString(fmt.Sprintf("- **Passed**: %d ✅\n", report.PassedTests))
	sb.WriteString(fmt.Sprintf("- **Failed**: %d ❌\n", report.FailedTests))
	sb.WriteString(fmt.Sprintf("- **Detection Accuracy**: %.1f%%\n", report.DetectionAccuracy*100))
	sb.WriteString(fmt.Sprintf("- **False Positive Rate**: %.1f%%\n", report.FalsePositiveRate*100))
	sb.WriteString(fmt.Sprintf("- **Avg Performance**: %v\n", report.AvgPerformance))
	sb.WriteString(fmt.Sprintf("- **Production Ready**: %v\n\n", report.ProductionReady))

	// Coverage
	sb.WriteString("## CVE Coverage\n\n")
	for _, cve := range report.CVEsCovered {
		sb.WriteString(fmt.Sprintf("- %s\n", cve))
	}

	sb.WriteString("\n## Framework Coverage\n\n")
	for _, framework := range report.FrameworksCovered {
		sb.WriteString(fmt.Sprintf("- %s\n", framework))
	}

	sb.WriteString("\n## Detailed Results\n\n")
	sb.WriteString("| Test ID | Type | Status | Findings | Time |\n")
	sb.WriteString("|---------|------|--------|----------|------|\n")

	for _, result := range report.DetailedResults {
		status := "✅ PASS"
		if !result.Passed {
			status = "❌ FAIL"
		}
		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %d | %v |\n",
			result.TestID, result.TestType, status, result.TotalFindings, result.ExecutionTime))
	}

	return sb.String()
}
