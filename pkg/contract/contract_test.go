package contract

import "testing"

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
		{PolicyBalanced, 4},      // Vulnerabilities + risk patterns
		{PolicyComprehensive, 5}, // All
		{"", 4},                  // Default to balanced
		{"unknown", 4},          // Unknown defaults to balanced
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
