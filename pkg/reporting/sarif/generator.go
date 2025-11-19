package sarif

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/inkog-io/inkog/action/pkg/patterns"
	"github.com/inkog-io/inkog/action/pkg/reporting/compliance"
)

// RuleID defines stable rule identifiers for each pattern
var RuleIDs = map[string]string{
	"infinite_loop_semantic":      "INKOG-001",
	"context_exhaustion_semantic":  "INKOG-002",
	"tainted_eval":                 "INKOG-003",
	"hardcoded_credentials":        "INKOG-004",
	"sql_injection_via_llm":        "INKOG-005",
	"prompt_injection":             "INKOG-006",
	"unvalidated_eval":             "INKOG-003", // Same as tainted_eval
	"unsafe_env_access":            "INKOG-007",
	"token_bombing":                "INKOG-008",
	"recursive_tool_calling":       "INKOG-009",
	"rag_overfetching":             "INKOG-010",
	"missing_rate_limits":          "INKOG-011",
	"context_window_accumulation":  "INKOG-002", // Same as context exhaustion
	"logging_sensitive_data":       "INKOG-012",
	"missing_human_oversight":      "INKOG-013",
	"cross_tenant_data_leakage":    "INKOG-014",
	"output_validation_failures":   "INKOG-015",
}

// SARIFReport represents a SARIF v2.1.0 report
type SARIFReport struct {
	Version string      `json:"version"`
	Schema  string      `json:"$schema"`
	Runs    []SARIFRun  `json:"runs"`
}

// SARIFRun represents a single analysis run
type SARIFRun struct {
	Tool            SARIFTool        `json:"tool"`
	Invocations     []SARIFInvocation `json:"invocations,omitempty"`
	Results         []SARIFResult    `json:"results"`
	Rules           []SARIFRule      `json:"rules"`
	Properties      map[string]interface{} `json:"properties,omitempty"`
	OriginalUriBaseIds map[string]SARIFArtifactLocation `json:"originalUriBaseIds,omitempty"`
}

// SARIFTool describes the analysis tool
type SARIFTool struct {
	Driver SARIFToolComponent `json:"driver"`
}

// SARIFToolComponent describes the tool driver
type SARIFToolComponent struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	InformationUri  string `json:"informationUri"`
	SemanticVersion string `json:"semanticVersion"`
	DownloadUri     string `json:"downloadUri,omitempty"`
	Organization    string `json:"organization,omitempty"`
	ShortDescription SARIFMessage `json:"shortDescription"`
	FullDescription  SARIFMessage `json:"fullDescription,omitempty"`
	SupportedRules  []string `json:"supportedRules,omitempty"`
}

// SARIFMessage represents a message (can be plain text or markdown)
type SARIFMessage struct {
	Text     string `json:"text,omitempty"`
	Markdown string `json:"markdown,omitempty"`
}

// SARIFResult represents a single finding
type SARIFResult struct {
	RuleID             string                     `json:"ruleId"`
	RuleIndex          int                        `json:"ruleIndex"`
	Level              string                     `json:"level"`
	Message            SARIFMessage               `json:"message"`
	Kind               string                     `json:"kind"`
	Locations          []SARIFLocation            `json:"locations"`
	RelatedLocations   []SARIFLocation            `json:"relatedLocations,omitempty"`
	Properties         map[string]interface{}    `json:"properties,omitempty"`
	Help               *SARIFMessage              `json:"help,omitempty"`
	Fingerprints       map[string]string          `json:"fingerprints,omitempty"`
}

// SARIFLocation represents the location of a finding
type SARIFLocation struct {
	Id                  int                        `json:"id,omitempty"`
	PhysicalLocation    SARIFPhysicalLocation      `json:"physicalLocation"`
	LogicalLocations    []SARIFLogicalLocation     `json:"logicalLocations,omitempty"`
	RelationshipTargets []SARIFLocationRelationship `json:"relationshipTargets,omitempty"`
}

// SARIFPhysicalLocation describes a file location
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           *SARIFRegion          `json:"region,omitempty"`
}

// SARIFArtifactLocation describes where an artifact is located
type SARIFArtifactLocation struct {
	Uri       string `json:"uri"`
	UriBaseId string `json:"uriBaseId,omitempty"`
	Index     int    `json:"index,omitempty"`
}

// SARIFRegion describes a region within a file
type SARIFRegion struct {
	StartLine            int    `json:"startLine"`
	StartColumn          int    `json:"startColumn,omitempty"`
	EndLine              int    `json:"endLine,omitempty"`
	EndColumn            int    `json:"endColumn,omitempty"`
	CharOffset           int    `json:"charOffset,omitempty"`
	CharLength           int    `json:"charLength,omitempty"`
	Snippet              *SARIFArtifactContent `json:"snippet,omitempty"`
}

// SARIFArtifactContent represents artifact content
type SARIFArtifactContent struct {
	Text     string `json:"text,omitempty"`
	Markdown string `json:"markdown,omitempty"`
	Rendering string `json:"rendering,omitempty"`
}

// SARIFLogicalLocation represents logical location (function, class, etc)
type SARIFLogicalLocation struct {
	Name               string `json:"name,omitempty"`
	Kind               string `json:"kind,omitempty"`
	ParentIndex        int    `json:"parentIndex,omitempty"`
	DecoratedName      string `json:"decoratedName,omitempty"`
}

// SARIFLocationRelationship describes relationships between locations
type SARIFLocationRelationship struct {
	Target    int               `json:"target"`
	Kinds     []string          `json:"kinds,omitempty"`
	Targets   []SARIFLocation   `json:"targets,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// SARIFRule describes a rule/pattern
type SARIFRule struct {
	Id                        string                     `json:"id"`
	Guid                      string                     `json:"guid,omitempty"`
	DeprecatedIds             []string                   `json:"deprecatedIds,omitempty"`
	Guid2021May               string                     `json:"guid-2021-05,omitempty"`
	ShortDescription          SARIFMessage               `json:"shortDescription"`
	FullDescription           SARIFMessage               `json:"fullDescription,omitempty"`
	MessageStrings            map[string]SARIFMessage    `json:"messageStrings,omitempty"`
	DefaultConfiguration      *SARIFRuleConfiguration    `json:"defaultConfiguration,omitempty"`
	HelpUri                   string                     `json:"helpUri,omitempty"`
	Help                      *SARIFMessage              `json:"help,omitempty"`
	Relationships             []SARIFRuleRelationship    `json:"relationships,omitempty"`
	Properties                map[string]interface{}    `json:"properties,omitempty"`
	Tags                      []string                   `json:"tags,omitempty"`
	Kind                      string                     `json:"kind,omitempty"`
	SecuritySeverity          string                     `json:"securitySeverity,omitempty"`
	DefaultLevel              string                     `json:"defaultLevel,omitempty"`
}

// SARIFRuleConfiguration describes rule configuration
type SARIFRuleConfiguration struct {
	Level              string                 `json:"level,omitempty"`
	Parameters         map[string]interface{} `json:"parameters,omitempty"`
	Enabled            bool                   `json:"enabled,omitempty"`
}

// SARIFRuleRelationship describes relationships between rules
type SARIFRuleRelationship struct {
	Target     SARIFRuleReference `json:"target"`
	Kinds      []string           `json:"kinds,omitempty"`
	Description *SARIFMessage     `json:"description,omitempty"`
}

// SARIFRuleReference references a rule
type SARIFRuleReference struct {
	Id      string `json:"id"`
	Index   int    `json:"index,omitempty"`
	ToolId  string `json:"toolComponent.id,omitempty"`
}

// SARIFInvocation describes a tool invocation
type SARIFInvocation struct {
	ToolExecutionSuccessful bool        `json:"toolExecutionSuccessful"`
	ExecutionSuccessful     bool        `json:"executionSuccessful"`
	ToolVersion             string      `json:"toolVersion,omitempty"`
	ToolVersionObject       interface{} `json:"toolVersionObject,omitempty"`
	EndTimeUtc              string      `json:"endTimeUtc,omitempty"`
	StartTimeUtc            string      `json:"startTimeUtc,omitempty"`
	CommandLine             string      `json:"commandLine,omitempty"`
	ResponseFiles           []string    `json:"responseFiles,omitempty"`
	ToolArguments           []string    `json:"toolArguments,omitempty"`
	EnvironmentVariables    map[string]string `json:"environmentVariables,omitempty"`
	Stdin                   string      `json:"stdin,omitempty"`
	Stdout                  string      `json:"stdout,omitempty"`
	Stderr                  string      `json:"stderr,omitempty"`
	StdoutStderr            string      `json:"stdoutStderr,omitempty"`
	ExitCode                int         `json:"exitCode,omitempty"`
	ExitCodeDescription     string      `json:"exitCodeDescription,omitempty"`
	ExitSignalName          string      `json:"exitSignalName,omitempty"`
	ExitSignalNumber        int         `json:"exitSignalNumber,omitempty"`
	ExitSignalDescription   string      `json:"exitSignalDescription,omitempty"`
	ToolExecutionNotifications []interface{} `json:"toolExecutionNotifications,omitempty"`
	ToolConfigurationNotifications []interface{} `json:"toolConfigurationNotifications,omitempty"`
	NotificationConfigurationOverrides []interface{} `json:"notificationConfigurationOverrides,omitempty"`
	ToolRuntimeEnvironment  map[string]string `json:"toolRuntimeEnvironment,omitempty"`
	Executions              []interface{} `json:"executions,omitempty"`
	Properties              map[string]interface{} `json:"properties,omitempty"`
	WorkingDirectory        SARIFArtifactLocation `json:"workingDirectory,omitempty"`
	Account                 map[string]interface{} `json:"account,omitempty"`
	ProcessStartFailureMessage string `json:"processStartFailureMessage,omitempty"`
	ProcessExitFailureMessage string `json:"processExitFailureMessage,omitempty"`
	ExecutionSuccessfulExitCodeDescription string `json:"executionSuccessfulExitCodeDescription,omitempty"`
}

// Generator generates SARIF reports
type Generator struct {
	complianceMapper *compliance.ComplianceMapper
}

// NewGenerator creates a new SARIF generator
func NewGenerator() *Generator {
	return &Generator{
		complianceMapper: compliance.NewComplianceMapper(),
	}
}

// GenerateReport creates a SARIF report from findings
func (g *Generator) GenerateReport(findings []patterns.Finding) *SARIFReport {
	report := &SARIFReport{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs:    make([]SARIFRun, 1),
	}

	run := &SARIFRun{
		Tool: SARIFTool{
			Driver: SARIFToolComponent{
				Name:                "Inkog AI Security Scanner",
				Version:             "1.0.0",
				SemanticVersion:     "1.0.0",
				InformationUri:      "https://github.com/inkog-io/inkog",
				DownloadUri:         "https://github.com/inkog-io/inkog/releases",
				Organization:        "Inkog",
				ShortDescription: SARIFMessage{
					Text: "Static analysis tool for AI system security vulnerabilities including LLM-specific risks, resource exhaustion, and compliance violations",
				},
				FullDescription: SARIFMessage{
					Markdown: "Inkog detects security vulnerabilities in AI systems including:\n\n- **Infinite Loops (Doom Loops)**: LLM-dependent loops without hard break counters\n- **Context Exhaustion (Context Bombs)**: Unbounded growth of context/token usage\n- **Tainted Eval**: Execution of LLM-generated code without validation\n- **Compliance Violations**: EU AI Act, NIST AI RMF, OWASP LLM Top 10\n",
				},
			},
		},
		Results:         make([]SARIFResult, 0),
		Rules:           make([]SARIFRule, 0),
		Properties:      make(map[string]interface{}),
		OriginalUriBaseIds: make(map[string]SARIFArtifactLocation),
	}

	// Add compliance metadata
	complianceReport := g.complianceMapper.GenerateComplianceReport(findings)
	run.Properties["compliance"] = map[string]interface{}{
		"eu_ai_act":         complianceReport.EUAIActStatus.PassStatus,
		"nist_ai_rmf":       complianceReport.NISTAIRMFStatus.PassStatus,
		"owasp_llm_top10":   complianceReport.OWASPLLMStatus.PassStatus,
		"overall_compliance": complianceReport.OverallCompliance,
		"critical_findings": complianceReport.CriticalFindings,
		"scan_date":         complianceReport.ScanDate,
	}

	// Track rules to avoid duplicates
	rulesAdded := make(map[string]bool)

	// Process findings
	for idx, finding := range findings {
		ruleID := g.getRuleID(finding.PatternID)

		// Add rule if not already added
		if !rulesAdded[ruleID] {
			rule := g.createSARIFRule(&finding, ruleID)
			run.Rules = append(run.Rules, rule)
			rulesAdded[ruleID] = true
		}

		// Create result
		result := g.createSARIFResult(&finding, ruleID, len(run.Rules)-1)
		run.Results = append(run.Results, result)

		_ = idx // Use idx for rule index if needed
	}

	// Add invocation information
	run.Invocations = []SARIFInvocation{
		{
			ToolExecutionSuccessful: true,
			ExecutionSuccessful:     true,
			ToolVersion:             "1.0.0",
			EndTimeUtc:              time.Now().UTC().Format(time.RFC3339),
			StartTimeUtc:            time.Now().UTC().Format(time.RFC3339),
			CommandLine:             "inkog scan",
			ToolRuntimeEnvironment: map[string]string{
				"language":    "Go",
				"version":     "1.21+",
			},
		},
	}

	report.Runs[0] = *run
	return report
}

// getRuleID returns the stable rule ID for a pattern
func (g *Generator) getRuleID(patternID string) string {
	if id, exists := RuleIDs[patternID]; exists {
		return id
	}
	// Default to INKOG-999 for unknown patterns
	return "INKOG-999"
}

// createSARIFRule creates a SARIF rule definition
func (g *Generator) createSARIFRule(finding *patterns.Finding, ruleID string) SARIFRule {
	mapping, _ := compliance.ComplianceMappings[finding.PatternID]
	if mapping == nil {
		// Create default mapping
		mapping = &compliance.ComplianceMapping{
			PatternID:      finding.PatternID,
			Description:    finding.Message,
			RiskLevel:      finding.Severity,
			EUArticles:     []string{"Article 15"},
			NISTCategories: []string{"MEASURE 2.4"},
		}
	}

	tags := []string{
		"security",
		"ai-safety",
		fmt.Sprintf("cwe-%s", finding.CWE),
		fmt.Sprintf("cvss-%.1f", finding.CVSS),
	}

	if len(mapping.EUArticles) > 0 {
		tags = append(tags, "eu-ai-act")
	}
	if len(mapping.NISTCategories) > 0 {
		tags = append(tags, "nist-ai-rmf")
	}

	rule := SARIFRule{
		Id:     ruleID,
		Guid:   fmt.Sprintf("urn:inkog:%s", finding.PatternID),
		ShortDescription: SARIFMessage{
			Text: finding.Pattern,
		},
		FullDescription: SARIFMessage{
			Markdown: fmt.Sprintf("**Pattern:** %s\n\n**Severity:** %s\n\n**Description:** %s\n\n**CWE:** %s\n\n**CVSS:** %.1f",
				finding.Pattern,
				finding.Severity,
				mapping.Description,
				finding.CWE,
				finding.CVSS,
			),
		},
		HelpUri: fmt.Sprintf("https://inkog.io/docs/patterns/%s", finding.PatternID),
		Help: &SARIFMessage{
			Markdown: fmt.Sprintf(
				"### Compliance Impact\n\n**EU AI Act Violations:**\n%s\n\n**NIST AI RMF:**\n%s\n\n**OWASP LLM Top 10:**\n%s",
				formatList(mapping.EUArticles),
				formatList(mapping.NISTCategories),
				formatList(mapping.OWASPCategories),
			),
		},
		DefaultConfiguration: &SARIFRuleConfiguration{
			Level:   g.severityToLevel(finding.Severity),
			Enabled: true,
		},
		Properties: map[string]interface{}{
			"confidence":        finding.Confidence,
			"financial_risk":    finding.FinancialRisk,
			"cwe_id":            finding.CWE,
			"cvss_score":        finding.CVSS,
			"owasp_category":    finding.OWASP,
		},
		Tags:             tags,
		Kind:             "problem",
		SecuritySeverity: finding.Severity,
		DefaultLevel:     g.severityToLevel(finding.Severity),
	}

	return rule
}

// createSARIFResult creates a SARIF result for a finding
func (g *Generator) createSARIFResult(finding *patterns.Finding, ruleID string, ruleIndex int) SARIFResult {
	result := SARIFResult{
		RuleID:    ruleID,
		RuleIndex: ruleIndex,
		Level:     g.severityToLevel(finding.Severity),
		Kind:      "fail",
		Message: SARIFMessage{
			Text: finding.Message,
		},
		Locations: []SARIFLocation{
			{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{
						Uri: finding.File,
					},
					Region: &SARIFRegion{
						StartLine:   finding.Line,
						StartColumn: finding.Column,
					},
				},
			},
		},
		Properties: map[string]interface{}{
			"confidence":     finding.Confidence,
			"financial_risk": finding.FinancialRisk,
			"finding_id":     finding.ID,
		},
	}

	// Add fingerprint for deduplication
	result.Fingerprints = map[string]string{
		"primaryLocationLineHash": fmt.Sprintf("%s:%d:%d", finding.File, finding.Line, finding.Column),
	}

	return result
}

// severityToLevel converts severity to SARIF level
func (g *Generator) severityToLevel(severity string) string {
	switch severity {
	case "CRITICAL":
		return "error"
	case "HIGH":
		return "warning"
	case "MEDIUM":
		return "warning"
	case "LOW":
		return "note"
	default:
		return "note"
	}
}

// ToJSON serializes the report to JSON
func (r *SARIFReport) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// Helper function to format lists
func formatList(items []string) string {
	if len(items) == 0 {
		return "None"
	}
	result := ""
	for _, item := range items {
		result += fmt.Sprintf("- %s\n", item)
	}
	return result
}
