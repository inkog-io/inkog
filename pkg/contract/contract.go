package contract

// FindingSource indicates where a finding originated
type FindingSource string

const (
	SourceLocalCLI     FindingSource = "local_cli"      // CLI detected secrets locally
	SourceServerLogic  FindingSource = "server_logic"   // Server logic analysis (loops, data flow)
	SourceServerTaint  FindingSource = "server_taint"   // Server taint flow analysis
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
	Source    FindingSource `json:"source"` // NEW: Track source

	// Location
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column"`

	// Details
	Message    string `json:"message"`
	Code       string `json:"code_snippet"`
	Severity   string `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	Confidence float32 `json:"confidence"` // 0.0-1.0

	// Security Metadata
	CWE   string  `json:"cwe"`
	CVSS  float32 `json:"cvss"`
	OWASP string  `json:"owasp_category"`

	// Financial Impact
	FinancialRisk string `json:"financial_risk"`

	// NEW: Track redaction for audit
	RedactedAt *RedactionInfo `json:"redacted_at,omitempty"`
}

// ScanResult represents the complete scan results from server
type ScanResult struct {
	// Metadata
	ContractVersion string `json:"contract_version"`
	ServerVersion   string `json:"server_version"`

	// Statistics
	RiskScore       int `json:"risk_score"`
	FindingsCount   int `json:"findings_count"`
	CriticalCount   int `json:"critical_count"`
	HighCount       int `json:"high_count"`
	MediumCount     int `json:"medium_count"`
	LowCount        int `json:"low_count"`

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
	ContractVersion string   `json:"contract_version"`
	CLIVersion      string   `json:"cli_version"`
	SecretsVersion  string   `json:"secrets_version"`
	LocalSecrets    int      `json:"local_secrets_found"` // Count of secrets detected
	RedactedFileCount int    `json:"redacted_file_count"` // How many files were redacted
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
