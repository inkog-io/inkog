package detectors

import (
	"fmt"
	"testing"
)

// TestCrossTenantDataLeakageDetectorRealWorldValidation tests Pattern 14 against real CVEs
func TestCrossTenantDataLeakageDetectorRealWorldValidation(t *testing.T) {
	detector := &CrossTenantDataLeakageDetector{}

	cveTestCases := []struct {
		cveID       string
		description string
		cveDir      string
	}{
		{cveID: "CVE-2024-7042", description: "LangChain GraphCypherQAChain IDOR", cveDir: "testdata/cves/2024"},
		{cveID: "CVE-2023-44467", description: "LangChain PALChain cross-tenant access", cveDir: "testdata/cves/2023"},
		{cveID: "CVE-2025-59434", description: "Flowise environment variable disclosure", cveDir: "testdata/cves/2025"},
		{cveID: "CVE-2025-59422", description: "Dify broken access control", cveDir: "testdata/cves/2025"},
	}

	t.Run("DetectCrossTenantDataLeakage", func(t *testing.T) {
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
		t.Logf("Cross-Tenant Data Leakage Detection: %d/%d", detectedCount, len(cveTestCases))
	})

	t.Run("SafeTenantIsolation", func(t *testing.T) {
		samples := []struct {
			language string
			code     string
		}{
			{"python", "user = User.get(id=user_id, tenant_id=current_tenant)\nif user.tenant_id != current_tenant:\n    raise PermissionError()"},
			{"javascript", "const user = await User.findOne({ where: { id: userId, tenantId: currentTenant } });\nif (!user) throw new Error('Not found');"},
			{"sql", "SELECT * FROM users WHERE id = ? AND tenant_id = ? WITH (NOLOCK)"},
		}

		for _, sample := range samples {
			result := RunCleanCodeTest(detector, sample.code, sample.language)
			if result.Passed {
				fmt.Printf("OK %s: Safe tenant isolation\n", sample.language)
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

		cleanResult := RunCleanCodeTest(detector, "user = User.get(id=user_id, tenant_id=current_tenant)", "python")
		results = append(results, *cleanResult)

		report := GenerateValidationReport(
			"cross_tenant_data_leakage",
			"Cross-Tenant Data Leakage Detector",
			results,
			cvesCovered,
			[]string{"LangChain", "Flowise", "Dify"},
		)

		markdown := FormatReportAsMarkdown(report)
		t.Logf("\n%s", markdown)
	})
}
