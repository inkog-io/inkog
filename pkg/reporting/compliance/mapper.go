package compliance

import (
	"fmt"
	"time"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// ComplianceMapper enriches findings with regulatory information
type ComplianceMapper struct {
	mappings map[string]*ComplianceMapping
}

// NewComplianceMapper creates a new compliance mapper
func NewComplianceMapper() *ComplianceMapper {
	return &ComplianceMapper{
		mappings: ComplianceMappings,
	}
}

// EnrichFinding adds compliance metadata to a finding
func (cm *ComplianceMapper) EnrichFinding(finding *patterns.Finding) map[string]interface{} {
	enriched := make(map[string]interface{})

	mapping, exists := cm.mappings[finding.PatternID]
	if !exists {
		// Default mapping if pattern not explicitly defined
		mapping = cm.getDefaultMapping(finding)
	}

	enriched["compliance"] = map[string]interface{}{
		"regulations":     mapping.Regulations,
		"eu_ai_act":       mapping.EUArticles,
		"nist_ai_rmf":     mapping.NISTCategories,
		"owasp_llm_top10": mapping.OWASPCategories,
		"risk_level":      mapping.RiskLevel,
		"description":     mapping.Description,
	}

	return enriched
}

// GenerateComplianceReport creates a comprehensive compliance report
func (cm *ComplianceMapper) GenerateComplianceReport(findings []patterns.Finding) *ComplianceReport {
	report := &ComplianceReport{
		ScanDate:        time.Now().Format("2006-01-02T15:04:05Z"),
		TotalFindings:   len(findings),
		CriticalFindings: 0,
		Recommendations: make([]string, 0),
		RegulatoryGaps:  make([]string, 0),
	}

	// Categorize findings by regulation
	euIssues := make([]*ComplianceIssue, 0)
	nistIssues := make([]*ComplianceIssue, 0)
	owaspIssues := make([]*ComplianceIssue, 0)

	criticalCount := 0

	for _, finding := range findings {
		mapping, exists := cm.mappings[finding.PatternID]
		if !exists {
			mapping = cm.getDefaultMapping(&finding)
		}

		if mapping.RiskLevel == "CRITICAL" {
			criticalCount++
		}

		// Create compliance issues for each applicable regulation
		for _, article := range mapping.EUArticles {
			euIssues = append(euIssues, &ComplianceIssue{
				PatternID:   finding.PatternID,
				Article:     article,
				RiskLevel:   mapping.RiskLevel,
				Description: mapping.Description,
				RemediationSteps: cm.getRemediationSteps(finding.PatternID),
			})
		}

		for _, category := range mapping.NISTCategories {
			nistIssues = append(nistIssues, &ComplianceIssue{
				PatternID:   finding.PatternID,
				Article:     category,
				RiskLevel:   mapping.RiskLevel,
				Description: mapping.Description,
				RemediationSteps: cm.getRemediationSteps(finding.PatternID),
			})
		}

		for _, category := range mapping.OWASPCategories {
			owaspIssues = append(owaspIssues, &ComplianceIssue{
				PatternID:   finding.PatternID,
				Article:     category,
				RiskLevel:   mapping.RiskLevel,
				Description: mapping.Description,
				RemediationSteps: cm.getRemediationSteps(finding.PatternID),
			})
		}
	}

	report.CriticalFindings = criticalCount

	// Create compliance checklists
	report.EUAIActStatus = &ComplianceChecklist{
		Regulation:      EU_AI_ACT,
		RequiredControls: []string{
			"Article 14: Human Oversight",
			"Article 15: Accuracy, Robustness and Cybersecurity",
		},
		Findings:        euIssues,
		PassStatus:      len(euIssues) == 0,
		ComplianceScore: cm.calculateComplianceScore(len(euIssues), criticalCount),
	}

	report.NISTAIRMFStatus = &ComplianceChecklist{
		Regulation:      NIST_AI_RMF,
		RequiredControls: []string{
			"MAP 1.1: Input/Output Validation",
			"MAP 1.3: System Reliability",
			"MEASURE 2.2: Security Risk Assessment",
			"MEASURE 2.4: AI System Risks",
		},
		Findings:        nistIssues,
		PassStatus:      len(nistIssues) == 0,
		ComplianceScore: cm.calculateComplianceScore(len(nistIssues), criticalCount),
	}

	report.OWASPLLMStatus = &ComplianceChecklist{
		Regulation:      OWASP_LLM_TOP10,
		RequiredControls: []string{
			OWASP_LLM01, OWASP_LLM02, OWASP_LLM04, OWASP_LLM06,
			OWASP_LLM08, OWASP_LLM09,
		},
		Findings:        owaspIssues,
		PassStatus:      len(owaspIssues) == 0,
		ComplianceScore: cm.calculateComplianceScore(len(owaspIssues), criticalCount),
	}

	// Calculate overall compliance
	report.OverallCompliance = (report.EUAIActStatus.ComplianceScore +
		report.NISTAIRMFStatus.ComplianceScore +
		report.OWASPLLMStatus.ComplianceScore) / 3.0

	// Generate recommendations
	report.Recommendations = cm.generateRecommendations(findings)

	// Identify gaps
	if !report.EUAIActStatus.PassStatus {
		report.RegulatoryGaps = append(report.RegulatoryGaps, "EU AI Act Compliance Gaps Detected")
	}
	if !report.NISTAIRMFStatus.PassStatus {
		report.RegulatoryGaps = append(report.RegulatoryGaps, "NIST AI RMF Compliance Gaps Detected")
	}
	if !report.OWASPLLMStatus.PassStatus {
		report.RegulatoryGaps = append(report.RegulatoryGaps, "OWASP LLM Top 10 Risks Identified")
	}

	return report
}

// calculateComplianceScore calculates a compliance score (0.0-1.0)
func (cm *ComplianceMapper) calculateComplianceScore(issueCount int, criticalCount int) float32 {
	if issueCount == 0 {
		return 1.0
	}

	// Heavily penalize critical issues
	score := 1.0 - (float32(criticalCount)*0.2 + float32(issueCount)*0.05)
	if score < 0.0 {
		score = 0.0
	}
	return score
}

// generateRecommendations creates actionable recommendations
func (cm *ComplianceMapper) generateRecommendations(findings []patterns.Finding) []string {
	recommendations := make([]string, 0)
	patternsSeen := make(map[string]bool)

	for _, finding := range findings {
		if patternsSeen[finding.PatternID] {
			continue
		}
		patternsSeen[finding.PatternID] = true

		switch finding.PatternID {
		case "infinite_loop_semantic":
			recommendations = append(recommendations, "Add hard break counters with max_iterations limits to all loops")
			recommendations = append(recommendations, "Implement timeout mechanisms for LLM-dependent operations")
		case "context_exhaustion_semantic":
			recommendations = append(recommendations, "Use bounded collections (deque with maxlen) for context/message history")
			recommendations = append(recommendations, "Implement context truncation strategies when size exceeds threshold")
		case "tainted_eval":
			recommendations = append(recommendations, "Remove dynamic code evaluation; use structured APIs instead")
			recommendations = append(recommendations, "Validate and sanitize all LLM outputs before use")
		case "hardcoded_credentials":
			recommendations = append(recommendations, "Move all credentials to environment variables or secure vaults")
			recommendations = append(recommendations, "Use credential rotation and least-privilege principles")
		case "sql_injection_via_llm":
			recommendations = append(recommendations, "Use parameterized queries for all database operations")
			recommendations = append(recommendations, "Implement input validation and output escaping for LLM responses")
		case "prompt_injection":
			recommendations = append(recommendations, "Implement strict input validation on all user-provided content")
			recommendations = append(recommendations, "Use prompt engineering best practices (role-based prompts, few-shot examples)")
		}
	}

	// Add general recommendations
	if len(recommendations) > 0 {
		recommendations = append(recommendations,
			"Conduct security review with human oversight before deployment",
			"Implement continuous monitoring for AI system behavior",
			"Establish incident response procedures for AI system failures",
		)
	}

	return recommendations
}

// getRemediationSteps returns specific remediation steps for a pattern
func (cm *ComplianceMapper) getRemediationSteps(patternID string) []string {
	steps := make([]string, 0)

	switch patternID {
	case "infinite_loop_semantic":
		steps = []string{
			"1. Add max_iterations counter to loop condition",
			"2. Implement timeout() mechanism using time.time() or asyncio.wait_for()",
			"3. Add break statement when counter reaches max",
			"4. Log all iterations for monitoring",
		}
	case "context_exhaustion_semantic":
		steps = []string{
			"1. Replace list with deque(maxlen=N) for bounded storage",
			"2. OR: Add truncation logic: if len(context) > max: context = context[-max:]",
			"3. OR: Implement ring buffer with explicit pop(0) operations",
			"4. Add metrics to monitor context size growth",
		}
	case "tainted_eval":
		steps = []string{
			"1. Remove eval(), exec(), compile() calls",
			"2. Replace with function dispatch table or switch statement",
			"3. Validate LLM output against strict whitelist",
			"4. Use AST parsing to analyze generated code safely",
		}
	case "hardcoded_credentials":
		steps = []string{
			"1. Extract credentials to .env file",
			"2. Load using python-dotenv or Go os.Getenv()",
			"3. Never commit .env to version control",
			"4. Rotate credentials in production immediately",
		}
	case "sql_injection_via_llm":
		steps = []string{
			"1. Use parameterized queries (?) or ORM prepared statements",
			"2. Never concatenate user/LLM input into SQL strings",
			"3. Validate LLM output against expected types/formats",
			"4. Use database role with minimal permissions",
		}
	case "prompt_injection":
		steps = []string{
			"1. Validate all user inputs for suspicious patterns",
			"2. Use system prompts that clarify role and constraints",
			"3. Implement output filtering for sensitive information",
			"4. Monitor for unusual behavior changes in responses",
		}
	default:
		steps = []string{
			"1. Review the OWASP LLM Top 10 guidance",
			"2. Implement input/output validation",
			"3. Add human oversight and review steps",
		}
	}

	return steps
}

// getDefaultMapping creates a default compliance mapping for unknown patterns
func (cm *ComplianceMapper) getDefaultMapping(finding *patterns.Finding) *ComplianceMapping {
	return &ComplianceMapping{
		PatternID:     finding.PatternID,
		Regulations:   []string{EU_AI_ACT, NIST_AI_RMF},
		EUArticles:    []string{EUArticle15_Accuracy},
		NISTCategories: []string{NISTMeasure24_Risks},
		OWASPCategories: []string{OWASP_LLM04},
		RiskLevel:     finding.Severity,
		Description:   fmt.Sprintf("Pattern %s detected: %s", finding.PatternID, finding.Message),
	}
}

// FormatComplianceReport creates a human-readable compliance report
func (cm *ComplianceMapper) FormatComplianceReport(report *ComplianceReport) string {
	output := fmt.Sprintf(`
╔════════════════════════════════════════════════════════════╗
║         AI SYSTEM COMPLIANCE REPORT                        ║
╚════════════════════════════════════════════════════════════╝

Scan Date: %s
Total Findings: %d
Critical Findings: %d

┌─ REGULATORY SUMMARY ─────────────────────────────────────┐
│ EU AI Act:        %s (Score: %.1f%%)
│ NIST AI RMF:      %s (Score: %.1f%%)
│ OWASP LLM Top 10: %s (Score: %.1f%%)
│ Overall:          %.1f%% Compliant
└──────────────────────────────────────────────────────────┘

`,
		report.ScanDate,
		report.TotalFindings,
		report.CriticalFindings,
		statusString(report.EUAIActStatus.PassStatus),
		report.EUAIActStatus.ComplianceScore*100,
		statusString(report.NISTAIRMFStatus.PassStatus),
		report.NISTAIRMFStatus.ComplianceScore*100,
		statusString(report.OWASPLLMStatus.PassStatus),
		report.OWASPLLMStatus.ComplianceScore*100,
		report.OverallCompliance*100,
	)

	if len(report.RegulatoryGaps) > 0 {
		output += "⚠ REGULATORY GAPS:\n"
		for _, gap := range report.RegulatoryGaps {
			output += fmt.Sprintf("  • %s\n", gap)
		}
		output += "\n"
	}

	if len(report.Recommendations) > 0 {
		output += "📋 RECOMMENDATIONS:\n"
		for i, rec := range report.Recommendations {
			if i < 5 { // Show top 5
				output += fmt.Sprintf("  %d. %s\n", i+1, rec)
			}
		}
		output += "\n"
	}

	return output
}

func statusString(pass bool) string {
	if pass {
		return "✓ PASS"
	}
	return "✗ FAIL"
}
