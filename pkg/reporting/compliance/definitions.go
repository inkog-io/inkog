package compliance

// Regulation types
const (
	EU_AI_ACT      = "EU AI Act"
	NIST_AI_RMF    = "NIST AI RMF"
	OWASP_LLM_TOP10 = "OWASP LLM Top 10"
)

// EU AI Act Articles
const (
	EUArticle15_Accuracy = "Article 15: Accuracy, Robustness and Cybersecurity"
	EUArticle15_Resilience = "Article 15: Resilience against errors"
	EUArticle14_Oversight = "Article 14: Human Oversight"
	EUArticle13_DataGovernance = "Article 13: Data Governance"
	EUArticle12_Monitoring = "Article 12: Post-market Monitoring"
)

// NIST AI RMF Functions/Categories
const (
	NISTMap13_Reliability = "MAP 1.3: System reliability"
	NISTMeasure24_Risks = "MEASURE 2.4: AI System Risks"
	NISTMap11_InputOutput = "MAP 1.1: Input/Output validation"
	NISTMeasure22_Security = "MEASURE 2.2: Security risk assessment"
)

// OWASP LLM Top 10
const (
	OWASP_LLM01 = "LLM01: Prompt Injection"
	OWASP_LLM02 = "LLM02: Insecure Output Handling"
	OWASP_LLM03 = "LLM03: Training Data Poisoning"
	OWASP_LLM04 = "LLM04: Model Denial of Service"
	OWASP_LLM05 = "LLM05: Supply Chain Vulnerability"
	OWASP_LLM06 = "LLM06: Sensitive Information Disclosure"
	OWASP_LLM07 = "LLM07: Insecure Plugin Integration"
	OWASP_LLM08 = "LLM08: Excessive Agency"
	OWASP_LLM09 = "LLM09: Overreliance on LLM-produced Content"
	OWASP_LLM10 = "LLM10: Model Theft"
)

// ComplianceMapping defines which regulations apply to a finding
type ComplianceMapping struct {
	PatternID         string   // e.g., "infinite_loop_semantic"
	Regulations       []string // List of applicable regulations
	EUArticles        []string // EU AI Act articles
	NISTCategories    []string // NIST AI RMF categories
	OWASPCategories   []string // OWASP LLM Top 10 items
	RiskLevel         string   // LOW, MEDIUM, HIGH, CRITICAL
	Description       string   // Why this pattern violates the regulation
}

// ComplianceMappings contains all pattern-to-regulation mappings
var ComplianceMappings = map[string]*ComplianceMapping{
	"infinite_loop_semantic": {
		PatternID: "infinite_loop_semantic",
		Regulations: []string{EU_AI_ACT, NIST_AI_RMF, OWASP_LLM_TOP10},
		EUArticles: []string{
			EUArticle15_Accuracy,
			EUArticle15_Resilience,
			EUArticle14_Oversight,
		},
		NISTCategories: []string{
			NISTMap13_Reliability,
			NISTMeasure24_Risks,
		},
		OWASPCategories: []string{OWASP_LLM04, OWASP_LLM08},
		RiskLevel:       "CRITICAL",
		Description:     "Infinite loops without hard break counters violate system reliability and human oversight requirements. Uncontrolled token consumption can lead to Denial of Service (LLM04) and excessive agency issues (LLM08).",
	},

	"context_exhaustion_semantic": {
		PatternID: "context_exhaustion_semantic",
		Regulations: []string{EU_AI_ACT, NIST_AI_RMF, OWASP_LLM_TOP10},
		EUArticles: []string{
			EUArticle15_Resilience,
			EUArticle15_Accuracy,
			EUArticle12_Monitoring,
		},
		NISTCategories: []string{
			NISTMeasure24_Risks,
			NISTMap13_Reliability,
		},
		OWASPCategories: []string{OWASP_LLM04, OWASP_LLM09},
		RiskLevel:       "HIGH",
		Description:     "Unbounded context growth exhausts token limits and violates resilience requirements. Causes model degradation (LLM04 - Denial of Service) and may lead to overreliance on inconsistent outputs (LLM09).",
	},

	"tainted_eval": {
		PatternID: "tainted_eval",
		Regulations: []string{EU_AI_ACT, NIST_AI_RMF, OWASP_LLM_TOP10},
		EUArticles: []string{
			EUArticle14_Oversight,
			EUArticle13_DataGovernance,
		},
		NISTCategories: []string{
			NISTMap11_InputOutput,
			NISTMeasure22_Security,
		},
		OWASPCategories: []string{OWASP_LLM01, OWASP_LLM02, OWASP_LLM06},
		RiskLevel:       "CRITICAL",
		Description:     "Using LLM-generated code without validation violates human oversight and input/output validation requirements. Enables prompt injection (LLM01), insecure output handling (LLM02), and sensitive information disclosure (LLM06).",
	},

	"hardcoded_credentials": {
		PatternID: "hardcoded_credentials",
		Regulations: []string{EU_AI_ACT, NIST_AI_RMF},
		EUArticles: []string{
			EUArticle15_Accuracy,
			EUArticle13_DataGovernance,
		},
		NISTCategories: []string{
			NISTMeasure22_Security,
		},
		OWASPCategories: []string{OWASP_LLM06},
		RiskLevel:       "CRITICAL",
		Description:     "Hardcoded credentials in source code violate data governance and security requirements. Leads to sensitive information disclosure (LLM06).",
	},

	"sql_injection_via_llm": {
		PatternID: "sql_injection_via_llm",
		Regulations: []string{EU_AI_ACT, NIST_AI_RMF, OWASP_LLM_TOP10},
		EUArticles: []string{
			EUArticle14_Oversight,
			EUArticle15_Accuracy,
		},
		NISTCategories: []string{
			NISTMap11_InputOutput,
		},
		OWASPCategories: []string{OWASP_LLM01},
		RiskLevel:       "CRITICAL",
		Description:     "Using LLM outputs in SQL queries without validation violates input validation and human oversight. Enables prompt injection attacks (LLM01).",
	},

	"prompt_injection": {
		PatternID: "prompt_injection",
		Regulations: []string{EU_AI_ACT, NIST_AI_RMF, OWASP_LLM_TOP10},
		EUArticles: []string{
			EUArticle14_Oversight,
			EUArticle13_DataGovernance,
		},
		NISTCategories: []string{
			NISTMap11_InputOutput,
		},
		OWASPCategories: []string{OWASP_LLM01},
		RiskLevel:       "HIGH",
		Description:     "Insufficient input validation enables prompt injection attacks (LLM01), violating human oversight and input validation requirements.",
	},
}

// ComplianceChecklist defines pass/fail criteria for each regulation
type ComplianceChecklist struct {
	Regulation       string
	RequiredControls []string
	Findings         []*ComplianceIssue
	PassStatus       bool
	ComplianceScore  float32 // 0.0 to 1.0
}

// ComplianceIssue represents a single compliance violation
type ComplianceIssue struct {
	PatternID       string
	Article         string
	RiskLevel       string
	Description     string
	RemediationSteps []string
}

// ComplianceReport aggregates all compliance findings
type ComplianceReport struct {
	ScanDate          string
	TotalFindings     int
	CriticalFindings  int
	EUAIActStatus     *ComplianceChecklist
	NISTAIRMFStatus   *ComplianceChecklist
	OWASPLLMStatus    *ComplianceChecklist
	OverallCompliance float32 // 0.0 to 1.0
	RegulatoryGaps    []string
	Recommendations   []string
}
