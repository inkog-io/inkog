package contract

import (
	"encoding/json"
	"testing"
)

func TestFilterByPolicy(t *testing.T) {
	findings := []Finding{
		{ID: "1", RiskTier: TierVulnerability, Severity: "CRITICAL"},
		{ID: "2", RiskTier: TierRiskPattern, Severity: "HIGH"},
		{ID: "3", RiskTier: TierHardening, Severity: "LOW"},
		{ID: "4", RiskTier: TierVulnerability, Severity: "HIGH"},
		{ID: "5", RiskTier: TierRiskPattern, Severity: "MEDIUM"},
	}

	tests := []struct {
		policy   string
		expected int
	}{
		{PolicyLowNoise, 2},       // Only vulnerabilities (2 items)
		{PolicyBalanced, 4},       // Vulnerabilities + risk patterns
		{PolicyComprehensive, 5},  // All
		{PolicyGovernance, 0},     // No governance markers in test data
		{PolicyEUAIAct, 4},        // EU AI Act policy (Tier 1 + 2 + governance)
		{"", 4},                   // Default to balanced
		{"unknown", 4},            // Unknown defaults to balanced
	}

	for _, tt := range tests {
		t.Run(tt.policy, func(t *testing.T) {
			filtered := FilterByPolicy(findings, tt.policy)
			if len(filtered) != tt.expected {
				t.Errorf("FilterByPolicy(%s) returned %d findings, want %d",
					tt.policy, len(filtered), tt.expected)
			}
		})
	}
}

func TestFilterByPolicy_WithGovernanceData(t *testing.T) {
	findings := []Finding{
		{
			ID:                 "1",
			RiskTier:           TierVulnerability,
			Severity:           "CRITICAL",
			GovernanceCategory: "oversight",
			ComplianceMapping: &ComplianceMapping{
				EUAIActArticles: []string{"Article 14.1", "Article 14.4"},
			},
		},
		{
			ID:                 "2",
			RiskTier:           TierRiskPattern,
			Severity:           "HIGH",
			GovernanceCategory: "authorization",
		},
		{
			ID:       "3",
			RiskTier: TierHardening,
			Severity: "LOW",
		},
		{
			ID:       "4",
			RiskTier: TierVulnerability,
			Severity: "HIGH",
		},
	}

	// Governance policy should only include findings with governance markers
	t.Run("governance_policy", func(t *testing.T) {
		filtered := FilterByPolicy(findings, PolicyGovernance)
		if len(filtered) != 2 {
			t.Errorf("PolicyGovernance returned %d findings, want 2 (only governance-marked)", len(filtered))
		}
	})

	// EU AI Act policy should include findings with EU AI Act mapping
	t.Run("eu_ai_act_policy", func(t *testing.T) {
		filtered := FilterByPolicy(findings, PolicyEUAIAct)
		if len(filtered) != 3 {
			t.Errorf("PolicyEUAIAct returned %d findings, want 3", len(filtered))
		}
	})
}

func TestHasGovernanceCompliance(t *testing.T) {
	tests := []struct {
		name     string
		finding  Finding
		expected bool
	}{
		{
			name:     "nil_compliance_mapping",
			finding:  Finding{ID: "1"},
			expected: false,
		},
		{
			name: "eu_ai_act_article_14",
			finding: Finding{
				ID: "2",
				ComplianceMapping: &ComplianceMapping{
					EUAIActArticles: []string{"Article 14.1"},
				},
			},
			expected: true,
		},
		{
			name: "eu_ai_act_article_12",
			finding: Finding{
				ID: "3",
				ComplianceMapping: &ComplianceMapping{
					EUAIActArticles: []string{"Article 12"},
				},
			},
			expected: true,
		},
		{
			name: "nist_govern_category",
			finding: Finding{
				ID: "4",
				ComplianceMapping: &ComplianceMapping{
					NISTCategories: []string{"GOVERN 4.1"},
				},
			},
			expected: true,
		},
		{
			name: "non_governance_article",
			finding: Finding{
				ID: "5",
				ComplianceMapping: &ComplianceMapping{
					EUAIActArticles: []string{"Article 5"},
				},
			},
			expected: false,
		},
		{
			name: "non_governance_nist",
			finding: Finding{
				ID: "6",
				ComplianceMapping: &ComplianceMapping{
					NISTCategories: []string{"MANAGE 2.1"},
				},
			},
			expected: false,
		},
		{
			name: "empty_compliance_mapping",
			finding: Finding{
				ID:                "7",
				ComplianceMapping: &ComplianceMapping{},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasGovernanceCompliance(tt.finding)
			if got != tt.expected {
				t.Errorf("hasGovernanceCompliance() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGetBySeverity(t *testing.T) {
	findings := []Finding{
		{ID: "1", Severity: "CRITICAL"},
		{ID: "2", Severity: "HIGH"},
		{ID: "3", Severity: "MEDIUM"},
		{ID: "4", Severity: "LOW"},
		{ID: "5", Severity: "CRITICAL"},
	}

	tests := []struct {
		minSeverity string
		expected    int
	}{
		{"CRITICAL", 2},
		{"HIGH", 3},
		{"MEDIUM", 4},
		{"LOW", 5},
	}

	for _, tt := range tests {
		t.Run(tt.minSeverity, func(t *testing.T) {
			filtered := GetBySeverity(findings, tt.minSeverity)
			if len(filtered) != tt.expected {
				t.Errorf("GetBySeverity(%s) returned %d findings, want %d",
					tt.minSeverity, len(filtered), tt.expected)
			}
		})
	}
}

func TestGroupByTier(t *testing.T) {
	findings := []Finding{
		{ID: "1", RiskTier: TierVulnerability},
		{ID: "2", RiskTier: TierVulnerability},
		{ID: "3", RiskTier: TierRiskPattern},
		{ID: "4", RiskTier: TierHardening},
		{ID: "5", RiskTier: ""}, // Empty tier should default to risk_pattern
	}

	groups := GroupByTier(findings)

	if len(groups[TierVulnerability]) != 2 {
		t.Errorf("expected 2 vulnerabilities, got %d", len(groups[TierVulnerability]))
	}
	if len(groups[TierRiskPattern]) != 2 {
		t.Errorf("expected 2 risk patterns (including default), got %d", len(groups[TierRiskPattern]))
	}
	if len(groups[TierHardening]) != 1 {
		t.Errorf("expected 1 hardening, got %d", len(groups[TierHardening]))
	}
}

func TestCountByTier(t *testing.T) {
	findings := []Finding{
		{ID: "1", RiskTier: TierVulnerability},
		{ID: "2", RiskTier: TierVulnerability},
		{ID: "3", RiskTier: TierRiskPattern},
		{ID: "4", RiskTier: TierHardening},
	}

	counts := CountByTier(findings)

	if counts[TierVulnerability] != 2 {
		t.Errorf("expected 2 vulnerabilities, got %d", counts[TierVulnerability])
	}
	if counts[TierRiskPattern] != 1 {
		t.Errorf("expected 1 risk pattern, got %d", counts[TierRiskPattern])
	}
	if counts[TierHardening] != 1 {
		t.Errorf("expected 1 hardening, got %d", counts[TierHardening])
	}
}

func TestCountBySeverity(t *testing.T) {
	findings := []Finding{
		{ID: "1", Severity: "CRITICAL"},
		{ID: "2", Severity: "CRITICAL"},
		{ID: "3", Severity: "HIGH"},
		{ID: "4", Severity: "MEDIUM"},
		{ID: "5", Severity: "MEDIUM"},
		{ID: "6", Severity: "LOW"},
	}

	counts := CountBySeverity(findings)

	if counts["CRITICAL"] != 2 {
		t.Errorf("expected 2 critical, got %d", counts["CRITICAL"])
	}
	if counts["HIGH"] != 1 {
		t.Errorf("expected 1 high, got %d", counts["HIGH"])
	}
	if counts["MEDIUM"] != 2 {
		t.Errorf("expected 2 medium, got %d", counts["MEDIUM"])
	}
	if counts["LOW"] != 1 {
		t.Errorf("expected 1 low, got %d", counts["LOW"])
	}
}

func TestCalculateRiskScore(t *testing.T) {
	tests := []struct {
		name     string
		findings []Finding
		expected int
	}{
		{
			name:     "empty",
			findings: []Finding{},
			expected: 0,
		},
		{
			name: "single_critical",
			findings: []Finding{
				{Severity: "CRITICAL"},
			},
			expected: 30,
		},
		{
			name: "mixed_severities",
			findings: []Finding{
				{Severity: "CRITICAL"}, // 30
				{Severity: "HIGH"},     // 20
				{Severity: "MEDIUM"},   // 10
				{Severity: "LOW"},      // 5
			},
			expected: 65,
		},
		{
			name: "multiple_high",
			findings: []Finding{
				{Severity: "HIGH"},
				{Severity: "HIGH"},
				{Severity: "HIGH"},
			},
			expected: 60,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculateRiskScore(tt.findings)
			if got != tt.expected {
				t.Errorf("CalculateRiskScore() = %d, want %d", got, tt.expected)
			}
		})
	}
}

func TestGetEffectiveTier(t *testing.T) {
	tests := []struct {
		name     string
		finding  Finding
		expected string
	}{
		{
			name:     "explicit_vulnerability",
			finding:  Finding{RiskTier: TierVulnerability},
			expected: TierVulnerability,
		},
		{
			name:     "explicit_risk_pattern",
			finding:  Finding{RiskTier: TierRiskPattern},
			expected: TierRiskPattern,
		},
		{
			name:     "explicit_hardening",
			finding:  Finding{RiskTier: TierHardening},
			expected: TierHardening,
		},
		{
			name:     "empty_defaults_to_risk_pattern",
			finding:  Finding{RiskTier: ""},
			expected: TierRiskPattern,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetEffectiveTier(tt.finding)
			if got != tt.expected {
				t.Errorf("GetEffectiveTier() = %s, want %s", got, tt.expected)
			}
		})
	}
}

func TestFilterByTier(t *testing.T) {
	findings := []Finding{
		{ID: "1", RiskTier: TierVulnerability},
		{ID: "2", RiskTier: TierRiskPattern},
		{ID: "3", RiskTier: TierVulnerability},
		{ID: "4", RiskTier: TierHardening},
	}

	tests := []struct {
		tier     string
		expected int
	}{
		{TierVulnerability, 2},
		{TierRiskPattern, 1},
		{TierHardening, 1},
	}

	for _, tt := range tests {
		t.Run(tt.tier, func(t *testing.T) {
			filtered := FilterByTier(findings, tt.tier)
			if len(filtered) != tt.expected {
				t.Errorf("FilterByTier(%s) returned %d findings, want %d",
					tt.tier, len(filtered), tt.expected)
			}
		})
	}
}

func TestScanResult_MergeFindings(t *testing.T) {
	serverResult := &ScanResult{
		Findings: []Finding{
			{ID: "server_1", Source: SourceServerLogic},
			{ID: "server_2", Source: SourceServerTaint},
		},
	}

	localSecrets := []Finding{
		{ID: "local_1", Source: SourceLocalCLI},
		{ID: "local_2", Source: SourceLocalCLI},
	}

	merged := serverResult.MergeFindings(localSecrets)

	if merged.TotalFindingsCount != 4 {
		t.Errorf("expected 4 total findings, got %d", merged.TotalFindingsCount)
	}

	if len(merged.LocalSecrets) != 2 {
		t.Errorf("expected 2 local secrets, got %d", len(merged.LocalSecrets))
	}

	if len(merged.ServerFindings) != 2 {
		t.Errorf("expected 2 server findings, got %d", len(merged.ServerFindings))
	}

	if len(merged.AllFindings) != 4 {
		t.Errorf("expected 4 all findings, got %d", len(merged.AllFindings))
	}
}

func TestScanResult_MergeFindings_NilLocal(t *testing.T) {
	serverResult := &ScanResult{
		Findings: []Finding{
			{ID: "server_1"},
		},
	}

	merged := serverResult.MergeFindings(nil)

	if merged.TotalFindingsCount != 1 {
		t.Errorf("expected 1 total finding, got %d", merged.TotalFindingsCount)
	}

	if merged.LocalSecrets == nil {
		t.Error("LocalSecrets should not be nil")
	}

	if len(merged.LocalSecrets) != 0 {
		t.Errorf("expected 0 local secrets, got %d", len(merged.LocalSecrets))
	}
}

func TestSeverityLevels(t *testing.T) {
	// Verify severity ordering is correct
	if SeverityLevels["CRITICAL"] <= SeverityLevels["HIGH"] {
		t.Error("CRITICAL should be higher than HIGH")
	}
	if SeverityLevels["HIGH"] <= SeverityLevels["MEDIUM"] {
		t.Error("HIGH should be higher than MEDIUM")
	}
	if SeverityLevels["MEDIUM"] <= SeverityLevels["LOW"] {
		t.Error("MEDIUM should be higher than LOW")
	}
}

func TestRiskScoreMap(t *testing.T) {
	// Verify risk scores are in correct order
	if RiskScoreMap["CRITICAL"] <= RiskScoreMap["HIGH"] {
		t.Error("CRITICAL score should be higher than HIGH")
	}
	if RiskScoreMap["HIGH"] <= RiskScoreMap["MEDIUM"] {
		t.Error("HIGH score should be higher than MEDIUM")
	}
	if RiskScoreMap["MEDIUM"] <= RiskScoreMap["LOW"] {
		t.Error("MEDIUM score should be higher than LOW")
	}
}

func TestPolicyConstants(t *testing.T) {
	// Verify policy constants are defined
	if PolicyLowNoise == "" {
		t.Error("PolicyLowNoise should not be empty")
	}
	if PolicyBalanced == "" {
		t.Error("PolicyBalanced should not be empty")
	}
	if PolicyComprehensive == "" {
		t.Error("PolicyComprehensive should not be empty")
	}
	if PolicyGovernance == "" {
		t.Error("PolicyGovernance should not be empty")
	}
	if PolicyEUAIAct == "" {
		t.Error("PolicyEUAIAct should not be empty")
	}

	// Verify policy values are correct
	if PolicyLowNoise != "low-noise" {
		t.Errorf("PolicyLowNoise = %s, want low-noise", PolicyLowNoise)
	}
	if PolicyBalanced != "balanced" {
		t.Errorf("PolicyBalanced = %s, want balanced", PolicyBalanced)
	}
	if PolicyComprehensive != "comprehensive" {
		t.Errorf("PolicyComprehensive = %s, want comprehensive", PolicyComprehensive)
	}
	if PolicyGovernance != "governance" {
		t.Errorf("PolicyGovernance = %s, want governance", PolicyGovernance)
	}
	if PolicyEUAIAct != "eu-ai-act" {
		t.Errorf("PolicyEUAIAct = %s, want eu-ai-act", PolicyEUAIAct)
	}
}

func TestComplianceMappingStruct(t *testing.T) {
	// Test that ComplianceMapping struct has all required fields
	mapping := ComplianceMapping{
		EUAIActArticles: []string{"Article 14.1", "Article 14.4"},
		NISTCategories:  []string{"GOVERN 4.1"},
		ISO42001Clauses: []string{"7.2"},
		OWASPItems:      []string{"LLM06"},
		GDPRArticles:    []string{"Article 5"},
		CWEIDs:          []string{"CWE-862"},
	}

	if len(mapping.EUAIActArticles) != 2 {
		t.Errorf("EUAIActArticles length = %d, want 2", len(mapping.EUAIActArticles))
	}
	if len(mapping.NISTCategories) != 1 {
		t.Errorf("NISTCategories length = %d, want 1", len(mapping.NISTCategories))
	}
	if len(mapping.ISO42001Clauses) != 1 {
		t.Errorf("ISO42001Clauses length = %d, want 1", len(mapping.ISO42001Clauses))
	}
	if len(mapping.OWASPItems) != 1 {
		t.Errorf("OWASPItems length = %d, want 1", len(mapping.OWASPItems))
	}
	if len(mapping.GDPRArticles) != 1 {
		t.Errorf("GDPRArticles length = %d, want 1", len(mapping.GDPRArticles))
	}
	if len(mapping.CWEIDs) != 1 {
		t.Errorf("CWEIDs length = %d, want 1", len(mapping.CWEIDs))
	}
}

func TestGovernanceFieldsInFinding(t *testing.T) {
	finding := Finding{
		ID:                 "test-1",
		GovernanceCategory: "oversight",
		ComplianceMapping: &ComplianceMapping{
			EUAIActArticles: []string{"Article 14.1"},
		},
	}

	if finding.GovernanceCategory != "oversight" {
		t.Errorf("GovernanceCategory = %s, want oversight", finding.GovernanceCategory)
	}
	if finding.ComplianceMapping == nil {
		t.Error("ComplianceMapping should not be nil")
	}
	if len(finding.ComplianceMapping.EUAIActArticles) != 1 {
		t.Errorf("EUAIActArticles length = %d, want 1", len(finding.ComplianceMapping.EUAIActArticles))
	}
}

func TestGovernanceFieldsInScanResult(t *testing.T) {
	result := ScanResult{
		GovernanceScore:  85,
		EUAIActReadiness: "PARTIAL",
		ArticleMapping: map[string]ArticleStatus{
			"Article 14": {
				Article:      "Article 14",
				Status:       "PARTIAL",
				FindingCount: 2,
				Description:  "Human Oversight",
			},
		},
		FrameworkMapping: map[string]FrameworkStatus{
			"OWASP_LLM06": {
				Framework:    "OWASP_LLM06",
				Status:       "FAIL",
				FindingCount: 3,
			},
		},
	}

	if result.GovernanceScore != 85 {
		t.Errorf("GovernanceScore = %d, want 85", result.GovernanceScore)
	}
	if result.EUAIActReadiness != "PARTIAL" {
		t.Errorf("EUAIActReadiness = %s, want PARTIAL", result.EUAIActReadiness)
	}
	if len(result.ArticleMapping) != 1 {
		t.Errorf("ArticleMapping length = %d, want 1", len(result.ArticleMapping))
	}
	if len(result.FrameworkMapping) != 1 {
		t.Errorf("FrameworkMapping length = %d, want 1", len(result.FrameworkMapping))
	}

	// Test ArticleStatus
	article14 := result.ArticleMapping["Article 14"]
	if article14.Status != "PARTIAL" {
		t.Errorf("Article 14 status = %s, want PARTIAL", article14.Status)
	}
	if article14.FindingCount != 2 {
		t.Errorf("Article 14 finding count = %d, want 2", article14.FindingCount)
	}

	// Test FrameworkStatus
	owasp := result.FrameworkMapping["OWASP_LLM06"]
	if owasp.Status != "FAIL" {
		t.Errorf("OWASP_LLM06 status = %s, want FAIL", owasp.Status)
	}
}

func TestTierConstants(t *testing.T) {
	// Verify tier constants are defined
	if TierVulnerability == "" {
		t.Error("TierVulnerability should not be empty")
	}
	if TierRiskPattern == "" {
		t.Error("TierRiskPattern should not be empty")
	}
	if TierHardening == "" {
		t.Error("TierHardening should not be empty")
	}
}

func TestFindingEnrichedFields_Serialize(t *testing.T) {
	finding := Finding{
		ID:               "test-enriched",
		PatternID:        "sql_injection",
		Pattern:          "SQL Injection",
		Severity:         "CRITICAL",
		DisplayTitle:     "SQL Injection Through LLM Output",
		ShortDescription: "Unsanitized LLM output used in SQL query",
		RemediationCode:  "cursor.execute(query, (sanitized_input,))",
		RemediationSteps: []string{"Use parameterized queries", "Validate LLM output"},
		ExplanationTrace: []string{
			"User input enters via request.body at line 12",
			"Flows through process_query() without sanitization",
			"LLM output concatenated into SQL at line 45",
		},
		FixDifficulty: "medium",
	}

	data, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded Finding
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.DisplayTitle != "SQL Injection Through LLM Output" {
		t.Errorf("DisplayTitle = %q, want %q", decoded.DisplayTitle, "SQL Injection Through LLM Output")
	}
	if decoded.ShortDescription != "Unsanitized LLM output used in SQL query" {
		t.Errorf("ShortDescription = %q, want %q", decoded.ShortDescription, "Unsanitized LLM output used in SQL query")
	}
	if decoded.RemediationCode != "cursor.execute(query, (sanitized_input,))" {
		t.Errorf("RemediationCode = %q", decoded.RemediationCode)
	}
	if len(decoded.RemediationSteps) != 2 {
		t.Errorf("RemediationSteps length = %d, want 2", len(decoded.RemediationSteps))
	}
	if len(decoded.ExplanationTrace) != 3 {
		t.Errorf("ExplanationTrace length = %d, want 3", len(decoded.ExplanationTrace))
	}
	if decoded.FixDifficulty != "medium" {
		t.Errorf("FixDifficulty = %q, want %q", decoded.FixDifficulty, "medium")
	}
}

func TestFindingEnrichedFields_BackwardCompatibility(t *testing.T) {
	// Simulate an old server response without enriched fields
	oldJSON := `{"id":"old-1","pattern_id":"sql_injection","pattern":"SQL Injection","severity":"HIGH","message":"SQL injection detected"}`

	var finding Finding
	if err := json.Unmarshal([]byte(oldJSON), &finding); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// All enriched fields should be zero values
	if finding.DisplayTitle != "" {
		t.Errorf("DisplayTitle should be empty, got %q", finding.DisplayTitle)
	}
	if finding.ShortDescription != "" {
		t.Errorf("ShortDescription should be empty, got %q", finding.ShortDescription)
	}
	if finding.RemediationCode != "" {
		t.Errorf("RemediationCode should be empty, got %q", finding.RemediationCode)
	}
	if finding.RemediationSteps != nil {
		t.Errorf("RemediationSteps should be nil, got %v", finding.RemediationSteps)
	}
	if finding.ExplanationTrace != nil {
		t.Errorf("ExplanationTrace should be nil, got %v", finding.ExplanationTrace)
	}
	if finding.FixDifficulty != "" {
		t.Errorf("FixDifficulty should be empty, got %q", finding.FixDifficulty)
	}

	// Original fields should be populated
	if finding.ID != "old-1" {
		t.Errorf("ID = %q, want %q", finding.ID, "old-1")
	}
	if finding.Message != "SQL injection detected" {
		t.Errorf("Message = %q, want %q", finding.Message, "SQL injection detected")
	}
}

func TestFindingEnrichedFields_OmitEmpty(t *testing.T) {
	// A finding without enriched fields should not include them in JSON
	finding := Finding{
		ID:       "minimal",
		Severity: "LOW",
	}

	data, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	jsonStr := string(data)
	for _, field := range []string{"display_title", "short_description", "remediation_code", "remediation_steps", "explanation_trace", "fix_difficulty"} {
		if contains := json.Valid(data); contains && len(jsonStr) > 0 {
			// Check the field is not present in the JSON
			var m map[string]interface{}
			json.Unmarshal(data, &m)
			if _, exists := m[field]; exists {
				t.Errorf("field %q should be omitted from JSON when empty", field)
			}
		}
	}
}

func TestScanResultStrengths_Serialize(t *testing.T) {
	result := ScanResult{
		RiskScore: 42,
		Strengths: []string{"Uses parameterized queries", "Has rate limiting"},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded ScanResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if len(decoded.Strengths) != 2 {
		t.Fatalf("Strengths length = %d, want 2", len(decoded.Strengths))
	}
	if decoded.Strengths[0] != "Uses parameterized queries" {
		t.Errorf("Strengths[0] = %q", decoded.Strengths[0])
	}
	if decoded.Strengths[1] != "Has rate limiting" {
		t.Errorf("Strengths[1] = %q", decoded.Strengths[1])
	}
}

func TestScanResultStrengths_Nil(t *testing.T) {
	// Strengths should be omitted from JSON when nil
	result := ScanResult{RiskScore: 10}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var m map[string]interface{}
	json.Unmarshal(data, &m)
	if _, exists := m["strengths"]; exists {
		t.Error("strengths should be omitted from JSON when nil")
	}

	// Should deserialize fine from old server response without strengths
	oldJSON := `{"risk_score":10,"findings_count":0}`
	var decoded ScanResult
	if err := json.Unmarshal([]byte(oldJSON), &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if decoded.Strengths != nil {
		t.Errorf("Strengths should be nil, got %v", decoded.Strengths)
	}
}
