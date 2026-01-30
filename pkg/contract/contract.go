package contract

import "fmt"

// FindingSource indicates where a finding originated
type FindingSource string

const (
	SourceLocalCLI    FindingSource = "local_cli"    // CLI detected secrets locally
	SourceServerLogic FindingSource = "server_logic" // Server logic analysis (loops, data flow)
	SourceServerTaint FindingSource = "server_taint" // Server taint flow analysis
)

// FindingType distinguishes vulnerabilities from governance violations
type FindingType string

const (
	// TypeVulnerability - Security vulnerabilities (exploits, injections)
	TypeVulnerability FindingType = "vulnerability"
	// TypeGovernanceViolation - Governance gaps (missing oversight, audit)
	TypeGovernanceViolation FindingType = "governance_violation"
)

// RiskTier constants for three-tier classification (Socket.dev inspired)
const (
	// TierVulnerability - Tier 1: Exploitable vulnerabilities with proven taint flow
	TierVulnerability = "vulnerability"
	// TierRiskPattern - Tier 2: Structural issues that could become exploitable
	TierRiskPattern = "risk_pattern"
	// TierHardening - Tier 3: Best practices and recommendations
	TierHardening = "hardening"
)

// SecurityPolicy constants for user-selectable scan policies
const (
	// PolicyLowNoise shows only Tier 1 (Exploitable Vulnerabilities)
	PolicyLowNoise = "low-noise"
	// PolicyBalanced shows Tier 1 + Tier 2 (default)
	PolicyBalanced = "balanced"
	// PolicyComprehensive shows all tiers
	PolicyComprehensive = "comprehensive"
	// PolicyGovernance focuses on governance controls (Article 14 compliance)
	PolicyGovernance = "governance"
	// PolicyEUAIAct focuses on EU AI Act compliance (Articles 12, 14, 15)
	PolicyEUAIAct = "eu-ai-act"
)

// RedactionInfo tracks where content was redacted
type RedactionInfo struct {
	Line      int    `json:"line"`
	Column    int    `json:"column"`
	Type      string `json:"type"`       // api_key, password, token, etc.
	PatternID string `json:"pattern_id"` // Which pattern detected it
}

// Finding represents a single security vulnerability detection
type Finding struct {
	// Identification
	ID        string        `json:"id"`
	PatternID string        `json:"pattern_id"`
	Pattern   string        `json:"pattern"`
	Source    FindingSource `json:"source"` // Track source

	// Location
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column"`

	// Details
	Message    string  `json:"message"`
	Code       string  `json:"code_snippet"`
	Severity   string  `json:"severity"`   // CRITICAL, HIGH, MEDIUM, LOW
	Confidence float32 `json:"confidence"` // 0.0-1.0

	// Security Metadata
	CWE   string  `json:"cwe"`
	CVSS  float32 `json:"cvss"`
	OWASP string  `json:"owasp_category"`

	// Risk Classification (Three-Tier System)
	Category    string      `json:"category,omitempty"`     // injection, resource_exhaustion, governance, etc.
	RiskTier    string      `json:"risk_tier,omitempty"`    // vulnerability, risk_pattern, hardening
	FindingType FindingType `json:"finding_type,omitempty"` // vulnerability, governance_violation

	// Taint Tracking (for credible tier elevation)
	InputTainted bool   `json:"input_tainted,omitempty"` // True if user input flows to dangerous operation
	TaintSource  string `json:"taint_source,omitempty"`  // e.g., "user_data", "customer_input", "request_body"

	// Financial Impact
	FinancialRisk string `json:"financial_risk"`

	// Track redaction for audit
	RedactedAt *RedactionInfo `json:"redacted_at,omitempty"`

	// Governance fields (EU AI Act compliance)
	GovernanceCategory string             `json:"governance_category,omitempty"` // "oversight", "authorization", "audit", "privacy"
	ComplianceMapping  *ComplianceMapping `json:"compliance_mapping,omitempty"`
}

// ComplianceMapping maps a finding to compliance frameworks
type ComplianceMapping struct {
	EUAIActArticles []string `json:"eu_ai_act_articles,omitempty"` // e.g., ["Article 14.1", "Article 14.4"]
	NISTCategories  []string `json:"nist_categories,omitempty"`    // e.g., ["GOVERN 4.1"]
	ISO42001Clauses []string `json:"iso_42001_clauses,omitempty"`  // e.g., ["7.2"]
	OWASPItems      []string `json:"owasp_items,omitempty"`        // e.g., ["LLM06"]
	GDPRArticles    []string `json:"gdpr_articles,omitempty"`      // e.g., ["Article 5"]
	CWEIDs          []string `json:"cwe_ids,omitempty"`            // e.g., ["CWE-862"]
}

// ScanResult represents the complete scan results from server
type ScanResult struct {
	// Metadata
	ContractVersion string `json:"contract_version"`
	ServerVersion   string `json:"server_version"`

	// Statistics
	RiskScore     int `json:"risk_score"`
	FindingsCount int `json:"findings_count"`
	CriticalCount int `json:"critical_count"`
	HighCount     int `json:"high_count"`
	MediumCount   int `json:"medium_count"`
	LowCount      int `json:"low_count"`

	// Results (from server logic analysis only)
	Findings []Finding `json:"findings"`

	// Scan Details
	ScanDuration     string   `json:"scan_duration"`
	FilesScanned     int      `json:"files_scanned"`
	LinesOfCode      int      `json:"lines_of_code"`
	PatternsChecked  int      `json:"patterns_checked"`
	SkippedFiles     int      `json:"skipped_files"`
	FailedFilesCount int      `json:"failed_files_count"`
	FailedFiles      []string `json:"failed_files"`
	PanicedDetectors []string `json:"panicked_detectors"`

	// Compliance Report
	ComplianceReport *ComplianceReport `json:"compliance_report,omitempty"`

	// Governance fields (EU AI Act compliance)
	GovernanceScore  int                        `json:"governance_score"`             // 0-100 score
	EUAIActReadiness string                     `json:"eu_ai_act_readiness"`          // "READY", "PARTIAL", "NOT_READY"
	ArticleMapping   map[string]ArticleStatus   `json:"article_mapping,omitempty"`    // Per-article status
	FrameworkMapping map[string]FrameworkStatus `json:"framework_mapping,omitempty"`  // Per-framework status

	// Agent topology visualization
	TopologyMap *TopologyMap `json:"topology_map,omitempty"` // Visual topology of agent structure
}

// ArticleStatus represents compliance status for a specific EU AI Act article
type ArticleStatus struct {
	Article      string `json:"article"`       // e.g., "Article 14"
	Status       string `json:"status"`        // "PASS", "PARTIAL", "FAIL"
	FindingCount int    `json:"finding_count"` // Number of findings related to this article
	Description  string `json:"description"`   // e.g., "Human Oversight"
}

// FrameworkStatus represents compliance status for a specific framework
type FrameworkStatus struct {
	Framework    string `json:"framework"`     // e.g., "OWASP_LLM06", "ISO_42001"
	Status       string `json:"status"`        // "PASS", "PARTIAL", "FAIL"
	FindingCount int    `json:"finding_count"` // Number of findings related to this framework
}

// TopologyMetadata contains metadata about the topology map
type TopologyMetadata struct {
	Framework  string `json:"framework"`
	FilePath   string `json:"file_path"`
	InputType  string `json:"input_type"`
	NodeCount  int    `json:"node_count"`
	EdgeCount  int    `json:"edge_count"`
}

// TopologyNodeLocation represents a source code location
type TopologyNodeLocation struct {
	File   string `json:"file,omitempty"`
	Line   int    `json:"line,omitempty"`
	Column int    `json:"column,omitempty"`
}

// TopologyNode represents a node in the agent topology
type TopologyNode struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Label       string                 `json:"label"`
	Data        map[string]interface{} `json:"data"`
	Location    *TopologyNodeLocation  `json:"location,omitempty"`
	RiskLevel   string                 `json:"risk_level"` // SAFE, LOW, MEDIUM, HIGH, CRITICAL
	RiskReasons []string               `json:"risk_reasons,omitempty"`
}

// TopologyEdge represents a connection between nodes
type TopologyEdge struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Type  string `json:"type"`
	Label string `json:"label,omitempty"`
}

// GovernanceStatus tracks governance control status
type GovernanceStatus struct {
	HasHumanOversight bool     `json:"has_human_oversight"`
	HasAuthChecks     bool     `json:"has_auth_checks"`
	HasAuditLogging   bool     `json:"has_audit_logging"`
	HasRateLimiting   bool     `json:"has_rate_limiting"`
	MissingControls   []string `json:"missing_controls"`
}

// TopologyMap represents the agent topology visualization
type TopologyMap struct {
	Metadata   TopologyMetadata `json:"metadata"`
	Nodes      []TopologyNode   `json:"nodes"`
	Edges      []TopologyEdge   `json:"edges"`
	Governance GovernanceStatus `json:"governance"`
}

// LocalSecretResult represents secrets detected locally on the CLI
type LocalSecretResult struct {
	Findings      []Finding       `json:"findings"`      // Local secret findings
	RedactedFiles map[string]bool `json:"redacted_files"` // Which files were redacted
	RedactionCount int            `json:"redaction_count"`
}

// MergedResult combines local CLI findings with server findings
type MergedResult struct {
	LocalSecrets      []Finding `json:"local_secrets"`       // From CLI
	ServerFindings    []Finding `json:"server_findings"`     // From server
	AllFindings       []Finding `json:"all_findings"`        // Merged + deduplicated
	TotalFindingsCount int      `json:"total_findings_count"`
}

// ScanRequest is sent by CLI to the server
type ScanRequest struct {
	ContractVersion   string `json:"contract_version"`
	CLIVersion        string `json:"cli_version"`
	SecretsVersion    string `json:"secrets_version"`
	LocalSecrets      int    `json:"local_secrets_found"`   // Count of secrets detected
	RedactedFileCount int    `json:"redacted_file_count"`   // How many files were redacted
	ScanPolicy        string `json:"scan_policy,omitempty"` // Policy: low-noise, balanced, comprehensive, governance, eu-ai-act
	// File content is sent as multipart form (binary zip)
}

// ScanResponse is returned by server
type ScanResponse struct {
	ContractVersion  string             `json:"contract_version"`
	ServerVersion    string             `json:"server_version"`
	ScanResult       ScanResult         `json:"scan_result"`
	ComplianceReport *ComplianceReport  `json:"compliance_report,omitempty"`
	Success          bool               `json:"success"`
	Error            string             `json:"error,omitempty"`
}

// ErrorResponse represents a structured error from the server API
// Used for parsing error responses with detailed information
type ErrorResponse struct {
	Code       string `json:"code"`                  // Error code: WORKER_TIMEOUT, RATE_LIMIT, etc.
	RequestID  string `json:"request_id"`            // Unique request ID for support
	Message    string `json:"message"`               // Human-readable error message
	RetryAfter int    `json:"retry_after,omitempty"` // Seconds to wait before retry (for rate limits)
}

// ComplianceReport provides compliance-focused summary
type ComplianceReport struct {
	Title          string `json:"title"`
	Organization   string `json:"organization,omitempty"`
	ScanDate       string `json:"scan_date"`
	ScanDuration   string `json:"scan_duration"`
	ReportVersion  string `json:"report_version"`

	// Compliance Metrics
	CriticalIssues int `json:"critical_issues"`
	HighIssues     int `json:"high_issues"`
	MediumIssues   int `json:"medium_issues"`
	LowIssues      int `json:"low_issues"`
	TotalIssues    int `json:"total_issues"`

	// Compliance Status
	CompliancePass bool   `json:"compliance_pass"`
	RiskScore      int    `json:"risk_score"`
	RiskLevel      string `json:"risk_level"` // Low, Medium, High, Critical

	// Details
	AllFindings   []Finding `json:"all_findings"`
	LocalSecrets  []Finding `json:"local_secrets"`
	RemoteIssues  []Finding `json:"remote_issues"`
}

// SeverityLevel defines severity ordering
var SeverityLevels = map[string]int{
	"CRITICAL": 40,
	"HIGH":     30,
	"MEDIUM":   20,
	"LOW":      10,
}

// RiskScoreMap defines scoring for risk calculation
var RiskScoreMap = map[string]int{
	"CRITICAL": 30,
	"HIGH":     20,
	"MEDIUM":   10,
	"LOW":      5,
}

// MergeFindings combines local CLI findings with server findings
// Returns deduplicated results suitable for display
func (sr *ScanResult) MergeFindings(localSecrets []Finding) *MergedResult {
	if localSecrets == nil {
		localSecrets = []Finding{}
	}

	merged := &MergedResult{
		LocalSecrets:   localSecrets,
		ServerFindings: sr.Findings,
		AllFindings:    []Finding{},
	}

	// Add all local secrets first
	merged.AllFindings = append(merged.AllFindings, localSecrets...)

	// Add server findings (they don't overlap with secrets since content was redacted)
	merged.AllFindings = append(merged.AllFindings, sr.Findings...)

	// Update count
	merged.TotalFindingsCount = len(merged.AllFindings)

	return merged
}

// GetBySeverity returns findings filtered by severity level
func GetBySeverity(findings []Finding, minSeverity string) []Finding {
	minScore := SeverityLevels[minSeverity]
	var filtered []Finding

	for _, f := range findings {
		if SeverityLevels[f.Severity] >= minScore {
			filtered = append(filtered, f)
		}
	}

	return filtered
}

// CountBySeverity tallies findings by severity
func CountBySeverity(findings []Finding) map[string]int {
	counts := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
	}

	for _, f := range findings {
		counts[f.Severity]++
	}

	return counts
}

// CalculateRiskScore computes overall risk score
func CalculateRiskScore(findings []Finding) int {
	score := 0
	for _, f := range findings {
		score += RiskScoreMap[f.Severity]
	}
	return score
}

// GetEffectiveTier returns the effective tier for a finding, defaulting to risk_pattern if empty
func GetEffectiveTier(f Finding) string {
	if f.RiskTier == "" {
		return TierRiskPattern // Default to risk_pattern (Tier 2)
	}
	return f.RiskTier
}

// FilterByTier returns findings matching the specified tier
func FilterByTier(findings []Finding, tier string) []Finding {
	var filtered []Finding
	for _, f := range findings {
		if GetEffectiveTier(f) == tier {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// FilterByPolicy returns findings based on security policy
func FilterByPolicy(findings []Finding, policy string) []Finding {
	switch policy {
	case PolicyLowNoise:
		// Only Tier 1: Exploitable vulnerabilities
		return FilterByTier(findings, TierVulnerability)
	case PolicyBalanced:
		// Tier 1 + Tier 2: Vulnerabilities and risk patterns (default for empty)
		var filtered []Finding
		for _, f := range findings {
			tier := GetEffectiveTier(f)
			if tier == TierVulnerability || tier == TierRiskPattern {
				filtered = append(filtered, f)
			}
		}
		return filtered
	case PolicyComprehensive:
		// All tiers
		return findings
	case PolicyGovernance:
		// Governance-focused: only findings with governance category or governance compliance mapping
		var filtered []Finding
		for _, f := range findings {
			if f.GovernanceCategory != "" || hasGovernanceCompliance(f) || isGovernancePattern(f.PatternID) {
				filtered = append(filtered, f)
			}
		}
		return filtered
	case PolicyEUAIAct:
		// EU AI Act focused: findings with EU AI Act compliance mapping
		var filtered []Finding
		for _, f := range findings {
			// Include findings with EU AI Act compliance mapping
			if f.ComplianceMapping != nil && len(f.ComplianceMapping.EUAIActArticles) > 0 {
				filtered = append(filtered, f)
			} else if f.GovernanceCategory != "" {
				// Also include governance findings (related to Article 14)
				filtered = append(filtered, f)
			} else {
				// For other findings, include if they're high severity (risk_pattern or vulnerability)
				tier := GetEffectiveTier(f)
				if tier == TierVulnerability || tier == TierRiskPattern {
					filtered = append(filtered, f)
				}
			}
		}
		return filtered
	default:
		// Default to balanced
		return FilterByPolicy(findings, PolicyBalanced)
	}
}

// hasGovernanceCompliance checks if a finding has governance-related compliance mapping
func hasGovernanceCompliance(f Finding) bool {
	if f.ComplianceMapping == nil {
		return false
	}
	// Check for EU AI Act Articles 12, 14, 15 (governance articles)
	governanceArticles := map[string]bool{
		"Article 12":   true,
		"Article 12.1": true,
		"Article 14":   true,
		"Article 14.1": true,
		"Article 14.4": true,
		"Article 15":   true,
		"Article 15.3": true,
	}
	for _, article := range f.ComplianceMapping.EUAIActArticles {
		if governanceArticles[article] {
			return true
		}
	}
	// Check for NIST governance categories
	for _, cat := range f.ComplianceMapping.NISTCategories {
		if len(cat) > 6 && cat[:6] == "GOVERN" {
			return true
		}
	}
	return false
}

// GroupByTier groups findings by their risk tier
func GroupByTier(findings []Finding) map[string][]Finding {
	groups := map[string][]Finding{
		TierVulnerability: {},
		TierRiskPattern:   {},
		TierHardening:     {},
	}

	for _, f := range findings {
		tier := GetEffectiveTier(f)
		groups[tier] = append(groups[tier], f)
	}

	return groups
}

// CountByTier tallies findings by risk tier
func CountByTier(findings []Finding) map[string]int {
	counts := map[string]int{
		TierVulnerability: 0,
		TierRiskPattern:   0,
		TierHardening:     0,
	}

	for _, f := range findings {
		tier := GetEffectiveTier(f)
		counts[tier]++
	}

	return counts
}

// GetEffectiveFindingType returns the effective finding type, inferring from pattern if not set
func GetEffectiveFindingType(f Finding) FindingType {
	if f.FindingType != "" {
		return f.FindingType
	}
	// Infer from governance category or pattern
	if f.GovernanceCategory != "" {
		return TypeGovernanceViolation
	}
	// Check pattern_id for governance-related patterns
	if isGovernancePattern(f.PatternID) {
		return TypeGovernanceViolation
	}
	return TypeVulnerability
}

// isGovernancePattern checks if a pattern ID indicates a governance violation
func isGovernancePattern(patternID string) bool {
	governancePatterns := map[string]bool{
		"missing_human_oversight":  true,
		"missing_rate_limits":      true,
		"missing_authorization":    true,
		"missing_audit_logging":    true,
		"missing_output_validation": true,
	}
	return governancePatterns[patternID]
}

// FilterByFindingType returns findings matching the specified finding type
func FilterByFindingType(findings []Finding, findingType FindingType) []Finding {
	var filtered []Finding
	for _, f := range findings {
		if GetEffectiveFindingType(f) == findingType {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// CountByFindingType tallies findings by finding type
func CountByFindingType(findings []Finding) map[FindingType]int {
	counts := map[FindingType]int{
		TypeVulnerability:       0,
		TypeGovernanceViolation: 0,
	}

	for _, f := range findings {
		fType := GetEffectiveFindingType(f)
		counts[fType]++
	}

	return counts
}

// DiffStatus represents the status of a finding in a diff
type DiffStatus string

const (
	DiffStatusNew       DiffStatus = "new"
	DiffStatusFixed     DiffStatus = "fixed"
	DiffStatusUnchanged DiffStatus = "unchanged"
)

// DiffSummary contains summary statistics for a diff
type DiffSummary struct {
	TotalNew       int            `json:"total_new"`
	TotalFixed     int            `json:"total_fixed"`
	TotalUnchanged int            `json:"total_unchanged"`
	NewBySeverity  map[string]int `json:"new_by_severity"`
	FixedBySeverity map[string]int `json:"fixed_by_severity"`
	BaseRiskScore  int            `json:"base_risk_score"`
	HeadRiskScore  int            `json:"head_risk_score"`
	RiskDelta      int            `json:"risk_delta"`
}

// DiffResult contains the result of comparing two scans
type DiffResult struct {
	Summary           DiffSummary `json:"summary"`
	NewFindings       []Finding   `json:"new_findings"`
	FixedFindings     []Finding   `json:"fixed_findings"`
	UnchangedFindings []Finding   `json:"unchanged_findings"`
}

// Baseline represents a stored baseline for comparison
type Baseline struct {
	Path          string    `json:"path"`
	CreatedAt     string    `json:"created_at"`
	FindingsCount int       `json:"findings_count"`
	RiskScore     int       `json:"risk_score"`
	Findings      []Finding `json:"findings"`
}

// GenerateFindingKey creates a unique key for a finding based on location
func GenerateFindingKey(f Finding) string {
	return fmt.Sprintf("%s:%s:%d:%d", f.PatternID, f.File, f.Line, f.Column)
}

// ComputeDiff compares current findings against a baseline
func ComputeDiff(baseline []Finding, current []Finding) *DiffResult {
	baselineKeys := make(map[string]Finding)
	for _, f := range baseline {
		key := GenerateFindingKey(f)
		baselineKeys[key] = f
	}

	currentKeys := make(map[string]Finding)
	for _, f := range current {
		key := GenerateFindingKey(f)
		currentKeys[key] = f
	}

	result := &DiffResult{
		Summary: DiffSummary{
			NewBySeverity:   make(map[string]int),
			FixedBySeverity: make(map[string]int),
		},
		NewFindings:       []Finding{},
		FixedFindings:     []Finding{},
		UnchangedFindings: []Finding{},
	}

	// Find new findings (in current but not in baseline)
	for key, f := range currentKeys {
		if _, exists := baselineKeys[key]; !exists {
			result.NewFindings = append(result.NewFindings, f)
			result.Summary.NewBySeverity[f.Severity]++
		} else {
			result.UnchangedFindings = append(result.UnchangedFindings, f)
		}
	}

	// Find fixed findings (in baseline but not in current)
	for key, f := range baselineKeys {
		if _, exists := currentKeys[key]; !exists {
			result.FixedFindings = append(result.FixedFindings, f)
			result.Summary.FixedBySeverity[f.Severity]++
		}
	}

	result.Summary.TotalNew = len(result.NewFindings)
	result.Summary.TotalFixed = len(result.FixedFindings)
	result.Summary.TotalUnchanged = len(result.UnchangedFindings)
	result.Summary.BaseRiskScore = CalculateRiskScore(baseline)
	result.Summary.HeadRiskScore = CalculateRiskScore(current)
	result.Summary.RiskDelta = result.Summary.HeadRiskScore - result.Summary.BaseRiskScore

	return result
}

// IsRegression returns true if there are new critical or high severity findings
func (d *DiffResult) IsRegression() bool {
	return d.Summary.NewBySeverity["CRITICAL"] > 0 || d.Summary.NewBySeverity["HIGH"] > 0
}

// IsImprovement returns true if critical/high findings were fixed without new ones
func (d *DiffResult) IsImprovement() bool {
	if d.IsRegression() {
		return false
	}
	return d.Summary.FixedBySeverity["CRITICAL"] > 0 || d.Summary.FixedBySeverity["HIGH"] > 0
}
