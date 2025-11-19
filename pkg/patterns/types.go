package patterns

// Finding represents a single security vulnerability detection
type Finding struct {
	// Identification
	ID       string `json:"id"`
	PatternID string `json:"pattern_id"`
	Pattern   string `json:"pattern"`

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
}

// Pattern represents a vulnerability pattern definition
type Pattern struct {
	ID       string
	Name     string
	Version  string
	Category string
	Severity string
	CVSS     float32
	CWEIDs   []string
	OWASP    string

	Description string
	Remediation string

	FinancialImpact struct {
		Severity    string
		Description string
		RiskPerYear float32
	}
}

// ScanResult represents the complete scan results
type ScanResult struct {
	RiskScore       int        `json:"risk_score"`
	FindingsCount   int        `json:"findings_count"`
	CriticalCount   int        `json:"critical_count"`
	HighCount       int        `json:"high_count"`
	MediumCount     int        `json:"medium_count"`
	LowCount        int        `json:"low_count"`
	Findings        []Finding  `json:"findings"`
	ScanDuration    string     `json:"scan_duration"`
	FilesScanned    int        `json:"files_scanned"`
	LinesOfCode     int        `json:"lines_of_code"`
	PatternsChecked int        `json:"patterns_checked"`
	SkippedFiles    int        `json:"skipped_files"`
	FailedFilesCount int       `json:"failed_files_count"`
	FailedFiles     []string   `json:"failed_files"`
	PanicedDetectors []string  `json:"panicked_detectors"`
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
