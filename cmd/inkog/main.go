package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/inkog-io/inkog/pkg/cli"
	"github.com/inkog-io/inkog/pkg/contract"
	"golang.org/x/term"
)

// ServerURL is the default server endpoint. Can be overridden via:
// 1. Environment variable INKOG_SERVER_URL (highest priority)
// 2. Command-line flag -server
// 3. Build-time via -ldflags "-X main.ServerURL=..."
var ServerURL = "https://api.inkog.io"

func init() {
	// Allow override via environment variable (highest priority)
	if envURL := os.Getenv("INKOG_SERVER_URL"); envURL != "" {
		ServerURL = envURL
	}
}

const AppName = "inkog"

// AppVersion can be set at build time via:
// go build -ldflags "-X main.AppVersion=1.2.3"
var AppVersion = "1.0.1"

const (
	// ANSI color codes for terminal output
	colorReset    = "\033[0m"
	colorCritical = "\033[91m" // bright red
	colorHigh     = "\033[93m" // bright yellow
	colorMedium   = "\033[33m" // yellow
	colorLow      = "\033[32m" // green
	colorGray     = "\033[90m" // gray for gutter
	colorCyan     = "\033[96m" // bright cyan for taint info

	// Tier colors for risk classification
	colorTierVuln      = "\033[91m" // red for exploitable vulnerabilities
	colorTierRisk      = "\033[93m" // yellow for risk patterns
	colorTierHardening = "\033[36m" // cyan for hardening recommendations
	colorGovernance    = "\033[95m" // magenta for governance
	colorCheck         = "\033[92m" // green for checkmark
	colorCross         = "\033[91m" // red for cross

	// Security grading point values (Snyk-style)
	PointsCritical = 30
	PointsHigh     = 10
	PointsMedium   = 5
	PointsLow      = 1

	HelpText = `Inkog - Ship Safe Agents

Scan. Ship. Comply.

Verify your AI agents have human oversight, authorization controls, and audit
trails before deployment. EU AI Act Article 14 deadline: August 2, 2026.

Usage:
  inkog [OPTIONS] [PATH]

Options:
  -path string        Source path to scan (default: .)
  -server string      Inkog server URL (default: https://api.inkog.io)
  -output string      Output format: json, text, html, sarif (default: text)
  -policy string      Security policy (see below, default: balanced)
  -severity string    Minimum severity level: critical, high, medium, low (default: low)
  -agent-name string  Explicit agent name (overrides auto-detection from path)
  -max-files int      Maximum files to upload (default: 500)
  -deep               Inkog Deep scan — advanced security analysis (requires Inkog Deep role)
  -diff               Show only new findings since baseline (for CI/CD)
  -baseline string    Path to baseline file (default: .inkog-baseline.json)
  -update-baseline    Update the baseline after scanning
  -verbose            Enable verbose output
  -version            Show version information
  -help               Show this help message

Security Policies:
  low-noise           Only exploitable vulnerabilities (proven tainted input flows)
  balanced            Vulnerabilities + risk patterns (default, recommended)
  comprehensive       All findings including hardening recommendations
  governance          Governance-focused: Article 14, authorization, audit trails
  eu-ai-act           EU AI Act compliance: Articles 12, 14, 15

Supported Platforms:
  Pro-Code:    LangChain | LangGraph | CrewAI | Phidata | AutoGen | LlamaIndex
  No-Code:     Microsoft Copilot Studio | Salesforce Agentforce | n8n | Flowise

Examples:
  # Scan current directory with default policy
  inkog .

  # EU AI Act compliance scan
  inkog -path ./agents --policy eu-ai-act

  # Governance-focused scan (Article 14 controls)
  inkog -path ./agents --policy governance

  # Low noise mode - only proven vulnerabilities
  inkog -path ./agents --policy low-noise

  # Comprehensive mode - all findings including best practices
  inkog -path ./agents --policy comprehensive

  # Scan and output as JSON
  inkog -path . -output json

  # SARIF output for GitHub Security tab
  inkog -path . -output sarif > results.sarif

  # CI/CD mode - show only new findings since baseline
  inkog -path . --diff

  # Update baseline after clean main branch scan
  inkog -path . --update-baseline

  # Use custom baseline file
  inkog -path . --diff --baseline ./ci/security-baseline.json

  # Inkog Deep scan — advanced security analysis (requires Inkog Deep role)
  inkog --deep ./my-agent

Environment Variables:
  INKOG_SERVER_URL     Override default server URL (highest priority)
  INKOG_API_KEY        API key for authentication (get yours at https://app.inkog.io)
  INKOG_OUTPUT_FORMAT  Default output format

Privacy Notice:
  Source code is redacted locally before any remote analysis. Secrets, API keys,
  and credentials never leave your machine.

Learn more: https://docs.inkog.io
`
)

// Finding type constants for categorizing findings in the HTML report
const (
	FindingTypeCode   = "code"   // Traditional code analysis (Python, JS, Go)
	FindingTypeConfig = "config" // Configuration/workflow files (JSON, YAML, n8n)
	FindingTypeSecret = "secret" // Redacted secrets (no code shown intentionally)
)

// getFindingType determines the finding category based on source and file type
func getFindingType(f contract.Finding) string {
	// Local secrets are always "secret" type
	if f.Source == contract.SourceLocalCLI || f.RedactedAt != nil {
		return FindingTypeSecret
	}

	// Check file extension for config types
	ext := strings.ToLower(filepath.Ext(f.File))
	configExts := map[string]bool{
		".json": true,
		".yaml": true,
		".yml":  true,
		".toml": true,
	}
	if configExts[ext] {
		return FindingTypeConfig
	}

	return FindingTypeCode
}

// getCodeSnippetDisplay returns the code snippet and an optional empty-state message
// For findings without code, it provides context-aware explanations
// Uses minimal emoji approach: only lock icon for secrets (security symbol)
func getCodeSnippetDisplay(f contract.Finding) (code string, emptyMessage string, icon string) {
	if f.Code != "" {
		return f.Code, "", ""
	}

	findingType := getFindingType(f)

	switch findingType {
	case FindingTypeSecret:
		// Keep lock icon for secrets - meaningful security symbol
		return "", "Credentials detected and redacted for security", "🔒"
	case FindingTypeConfig:
		// No emoji for config - enterprise minimalist style
		jsonPath := extractJSONPath(f.Message)
		if jsonPath != "" {
			return "", "Configuration finding at " + jsonPath, ""
		}
		return "", "Configuration-based finding - see file for context", ""
	default:
		// No emoji for code - enterprise minimalist style
		return "", "Code context not available", ""
	}
}

// extractJSONPath extracts JSON path from message like "(at $.nodes[?(@.id=='agent-1')])"
func extractJSONPath(message string) string {
	// Look for pattern: (at $...)
	re := regexp.MustCompile(`\(at (\$[^)]+)\)`)
	if match := re.FindStringSubmatch(message); len(match) > 1 {
		return match[1]
	}
	return ""
}

func main() {
	// Command-line flags
	pathFlag := flag.String("path", ".", "Source path to scan")
	serverFlag := flag.String("server", "", "Inkog server URL")
	outputFlag := flag.String("output", "text", "Output format: text, json, html, sarif")
	policyFlag := flag.String("policy", contract.PolicyBalanced, "Security policy: low-noise, balanced, comprehensive")
	severityFlag := flag.String("severity", "low", "Minimum severity level")
	diffFlag := flag.Bool("diff", false, "Show only new findings since baseline")
	baselineFlag := flag.String("baseline", ".inkog-baseline.json", "Path to baseline file")
	updateBaselineFlag := flag.Bool("update-baseline", false, "Update baseline after scanning")
	deepFlag := flag.Bool("deep", false, "Inkog Deep scan — advanced security analysis (requires Inkog Deep role)")
	agentNameFlag := flag.String("agent-name", "", "Explicit agent name (overrides auto-detection from path)")
	maxFilesFlag := flag.Int("max-files", cli.DefaultMaxFiles, "Maximum files to upload (default 500)")
	verboseFlag := flag.Bool("verbose", false, "Enable verbose output")
	versionFlag := flag.Bool("version", false, "Show version information")
	helpFlag := flag.Bool("help", false, "Show help message")

	flag.Parse()

	// Validate policy flag
	validPolicies := map[string]bool{
		contract.PolicyLowNoise:      true,
		contract.PolicyBalanced:      true,
		contract.PolicyComprehensive: true,
		contract.PolicyGovernance:    true,
		contract.PolicyEUAIAct:       true,
	}
	if !validPolicies[*policyFlag] {
		log.Fatalf("❌ Error: invalid policy '%s'. Valid options: low-noise, balanced, comprehensive, governance, eu-ai-act\n", *policyFlag)
	}

	// Handle version flag
	if *versionFlag {
		fmt.Printf("%s v%s\n", AppName, AppVersion)
		os.Exit(0)
	}

	// Handle help flag
	if *helpFlag {
		fmt.Print(HelpText)
		os.Exit(0)
	}

	// Override path from positional argument if provided.
	// Supports "inkog scan ." syntax (used by npm wrapper) and "inkog ." (legacy).
	args := flag.Args()
	if len(args) > 0 && args[0] == "scan" {
		if len(args) > 1 {
			*pathFlag = args[1]
		}
		// "inkog scan" without path defaults to "." (the flag default)
	} else if len(args) > 0 {
		*pathFlag = args[0]
	}

	// Validate path exists
	if _, err := os.Stat(*pathFlag); os.IsNotExist(err) {
		log.Fatalf("❌ Error: path '%s' does not exist\n", *pathFlag)
	}

	// Use ServerURL as default if no server flag provided
	// Priority: command-line flag > env var > ServerURL variable (can be set via init or -ldflags)
	serverURL := *serverFlag
	if serverURL == "" {
		serverURL = ServerURL
	}

	// Determine quiet mode (disable spinners/colors for JSON output or CI environments)
	isQuietMode := *outputFlag == "json" || os.Getenv("CI") != ""

	// Resolve API key: env var > saved config > interactive flow
	apiKey := os.Getenv("INKOG_API_KEY")
	if apiKey == "" {
		apiKey = cli.GetSavedAPIKey()
		if apiKey != "" {
			os.Setenv("INKOG_API_KEY", apiKey)
		}
	}

	// No API key: run anonymous preview (interactive) or show error (non-interactive)
	if apiKey == "" {
		if !isQuietMode && isInteractiveTerminal() {
			apiKey = runFirstRunExperience(serverURL, *pathFlag)
			if apiKey != "" {
				os.Setenv("INKOG_API_KEY", apiKey)
			}
		}

		// If still no key after interactive flow, exit
		if apiKey == "" {
			if isQuietMode {
				fmt.Fprintf(os.Stderr, "Error: INKOG_API_KEY not set. Get your free key at https://app.inkog.io\n")
			} else {
				showWelcomeMessage()
			}
			os.Exit(1)
		}
	}

	var result *cli.ScanResult
	var err error

	// Hybrid mode: local secrets detection + server analysis
	if *verboseFlag && !isQuietMode {
		fmt.Println("🔐 Inkog")
		fmt.Printf("📍 Scanning: %s\n", *pathFlag)
	}

	scanner := cli.NewHybridScanner(*pathFlag, serverURL, *policyFlag, *verboseFlag, isQuietMode)
	scanner.AgentName = *agentNameFlag
	scanner.MaxFiles = *maxFilesFlag

	if *deepFlag {
		deepResult, deepErr := scanner.DeepScan()
		if deepErr != nil {
			log.Fatalf("❌ Deep scan failed: %v\n", deepErr)
		}

		// Convert deep scan findings to contract.Finding for full flag support
		findings := convertDeepFindings(deepResult)
		deepReport := extractDeepReport(deepResult.Scan)
		if deepReport == nil {
			deepReport = &cli.DeepReport{} // Ensure non-nil so Deep HTML template is always used
		}

		// Map clean detections to strengths for text output
		var strengths []contract.SecurityStrength
		if len(deepReport.CleanDetections) > 0 {
			for _, cd := range deepReport.CleanDetections {
				strengths = append(strengths, contract.SecurityStrength{
					Title:   humanizeDetectionID(cd.DetectionID),
					Message: cd.Reason,
				})
			}
		}

		// Build ScanResult compatible with all output formats
		scanResult := &cli.ScanResult{
			AllFindings:     findings,
			ServerFindings:  findings,
			GovernanceScore: deepScanInt(deepResult.Scan, "governance_score"),
			Strengths:       strengths,
			DeepReport:      deepReport,
		}

		// Handle baseline update (same as normal scan)
		if *updateBaselineFlag {
			if err := saveBaseline(*baselineFlag, *pathFlag, scanResult.AllFindings); err != nil {
				log.Fatalf("❌ Failed to update baseline: %v\n", err)
			}
			if *verboseFlag && !isQuietMode {
				fmt.Printf("📝 Baseline updated: %s (%d findings)\n", *baselineFlag, len(scanResult.AllFindings))
			}
		}

		// Handle diff mode (same as normal scan)
		if *diffFlag {
			baseline, err := loadBaseline(*baselineFlag)
			if err != nil {
				if os.IsNotExist(err) {
					if !isQuietMode {
						fmt.Printf("⚠️  No baseline found at %s. Showing all findings as new.\n", *baselineFlag)
						fmt.Println("   Run with --update-baseline to create a baseline.")
					}
					diffResult := contract.ComputeDiff([]contract.Finding{}, scanResult.AllFindings)
					if outErr := outputDiffResults(diffResult, *outputFlag, *severityFlag, *policyFlag, *verboseFlag, isQuietMode); outErr != nil {
						log.Fatalf("❌ Output failed: %v\n", outErr)
					}
					if diffResult.IsRegression() {
						os.Exit(1)
					}
					os.Exit(0)
				}
				log.Fatalf("❌ Failed to load baseline: %v\n", err)
			}
			diffResult := contract.ComputeDiff(baseline.Findings, scanResult.AllFindings)
			if outErr := outputDiffResults(diffResult, *outputFlag, *severityFlag, *policyFlag, *verboseFlag, isQuietMode); outErr != nil {
				log.Fatalf("❌ Output failed: %v\n", outErr)
			}
			if diffResult.IsRegression() {
				os.Exit(1)
			}
			os.Exit(0)
		}

		// Output using existing formatters (text, json, html, sarif all work)
		if err := outputResults(scanResult, *outputFlag, *severityFlag, *policyFlag, *verboseFlag, isQuietMode); err != nil {
			log.Fatalf("❌ Output failed: %v\n", err)
		}

		if len(findings) > 0 {
			os.Exit(1)
		}
		os.Exit(0)
	}

	result, err = scanner.Scan()

	if err != nil {
		log.Fatalf("❌ Scan failed: %v\n", err)
	}

	// Show framework detection feedback (not in quiet mode)
	if !isQuietMode {
		showFrameworkFeedback(result)
	}

	// Handle baseline update
	if *updateBaselineFlag {
		if err := saveBaseline(*baselineFlag, *pathFlag, result.AllFindings); err != nil {
			log.Fatalf("❌ Failed to update baseline: %v\n", err)
		}
		if *verboseFlag && !isQuietMode {
			fmt.Printf("📝 Baseline updated: %s (%d findings)\n", *baselineFlag, len(result.AllFindings))
		}
	}

	// Handle diff mode
	var diffResult *contract.DiffResult
	if *diffFlag {
		baseline, err := loadBaseline(*baselineFlag)
		if err != nil {
			if os.IsNotExist(err) {
				if !isQuietMode {
					fmt.Printf("⚠️  No baseline found at %s. Showing all findings as new.\n", *baselineFlag)
					fmt.Println("   Run with --update-baseline to create a baseline.")
				}
				// Treat all current findings as new
				diffResult = contract.ComputeDiff([]contract.Finding{}, result.AllFindings)
			} else {
				log.Fatalf("❌ Failed to load baseline: %v\n", err)
			}
		} else {
			diffResult = contract.ComputeDiff(baseline.Findings, result.AllFindings)
		}

		// Output diff results
		if err := outputDiffResults(diffResult, *outputFlag, *severityFlag, *policyFlag, *verboseFlag, isQuietMode); err != nil {
			log.Fatalf("❌ Output failed: %v\n", err)
		}

		// Exit based on new findings only
		if diffResult.Summary.TotalNew > 0 {
			if !isQuietMode {
				fmt.Printf("\n⚠️  Diff complete: %d new findings, %d fixed\n", diffResult.Summary.TotalNew, diffResult.Summary.TotalFixed)
			}
			// Exit with error only if there are new critical/high findings
			if diffResult.IsRegression() {
				os.Exit(1)
			}
		} else if !isQuietMode {
			if diffResult.Summary.TotalFixed > 0 {
				fmt.Printf("\n✅ Diff complete: %d fixed, no new findings\n", diffResult.Summary.TotalFixed)
			} else {
				fmt.Println("\n✅ Diff complete: No changes")
			}
		}
		os.Exit(0)
	}

	// Output results (non-diff mode)
	if err := outputResults(result, *outputFlag, *severityFlag, *policyFlag, *verboseFlag, isQuietMode); err != nil {
		log.Fatalf("❌ Output failed: %v\n", err)
	}

	// Determine exit code based on findings
	totalFindings := len(result.AllFindings)
	if totalFindings > 0 {
		if !isQuietMode {
			fmt.Printf("\n⚠️  Scan complete: %d security issues found\n", totalFindings)
		}
		os.Exit(1)
	}

	// Clean scan - show celebratory success message
	if !isQuietMode {
		showSuccessMessage(result, *policyFlag)
	}
	os.Exit(0)
}

// convertDeepFindings converts raw deep scan findings into contract.Finding structs,
// enabling full flag compatibility (--policy, --severity, --diff, --output html/sarif).
func convertDeepFindings(aiResult *cli.DeepScanResult) []contract.Finding {
	if aiResult.Scan == nil {
		return nil
	}
	raw := extractDeepFindings(aiResult.Scan)
	var findings []contract.Finding
	for _, f := range raw {
		severity := strings.ToUpper(deepStr(f, "severity"))
		category := deepStr(f, "category")
		title := deepStr(f, "title")

		// Extract file/line from orchestrator's affected_files array
		// Format: [{"file_path": "main.py", "line_numbers": "61-65, 117-118"}]
		filePath, lineNum, lineDisplay := extractAffectedFile(f)

		// Map orchestrator confidence string ("HIGH", "MEDIUM", "LOW") to numeric
		confidence := confidenceToFloat(deepStr(f, "confidence"))

		patternID := deepStr(f, "detection_id")
		if patternID == "" {
			patternID = slugify(title)
		}

		// Build explanation trace from proof array
		// Format: [{"code_snippet": "...", ...}]
		explanationTrace := extractProofTrace(f)

		finding := contract.Finding{
			PatternID:        patternID,
			Pattern:          title,
			DisplayTitle:     title,
			Message:          deepStr(f, "explanation"),
			ShortDescription: deepStr(f, "explanation"),
			Severity:         severity,
			File:             filePath,
			Line:             lineNum,
			Category:         category,
			Confidence:       confidence,
			Source:           contract.SourceServerLogic,
			RiskTier:         severityToRiskTier(severity),
			RemediationSteps: splitRemediation(deepStr(f, "recommended_action")),
			ExplanationTrace: explanationTrace,
		}

		// Store full line display (e.g. "61-65, 117-118") in Code field for rendering
		if lineDisplay != "" && filePath != "" {
			finding.Code = fmt.Sprintf("%s:%s", filePath, lineDisplay)
		}

		if isGovernanceCategory(category) {
			finding.GovernanceCategory = category
		}

		if cm := extractComplianceMapping(f); cm != nil {
			finding.ComplianceMapping = cm
		}

		// False positive assessment from orchestrator
		if fpRisk := deepStr(f, "false_positive_risk"); fpRisk != "" {
			finding.FPRisk = fpRisk
		}
		if fpRationale := deepStr(f, "false_positive_rationale"); fpRationale != "" {
			finding.FPRationale = fpRationale
		}

		findings = append(findings, finding)
	}
	return findings
}

// extractAffectedFile extracts file path and line info from the orchestrator's affected_files array.
func extractAffectedFile(f map[string]interface{}) (filePath string, lineNum int, lineDisplay string) {
	arr, ok := f["affected_files"].([]interface{})
	if !ok || len(arr) == 0 {
		return "", 0, ""
	}
	first, ok := arr[0].(map[string]interface{})
	if !ok {
		return "", 0, ""
	}
	filePath = deepStr(first, "file_path")
	lineDisplay = deepStr(first, "line_numbers")

	// Parse first line number from display string (e.g., "61-65, 117-118" → 61)
	if lineDisplay != "" {
		numStr := ""
		for _, c := range lineDisplay {
			if c >= '0' && c <= '9' {
				numStr += string(c)
			} else {
				break
			}
		}
		if numStr != "" {
			_, _ = fmt.Sscanf(numStr, "%d", &lineNum)
		}
	}
	return
}

// extractProofTrace builds explanation trace strings from the orchestrator's proof array.
func extractProofTrace(f map[string]interface{}) []string {
	arr, ok := f["proof"].([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	var traces []string
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		snippet := deepStr(m, "code_snippet")
		if snippet != "" {
			// Truncate long snippets for trace display
			if len(snippet) > 150 {
				snippet = snippet[:147] + "..."
			}
			traces = append(traces, snippet)
		}
	}
	return traces
}

// confidenceToFloat converts orchestrator confidence string to numeric value.
func confidenceToFloat(s string) float32 {
	switch strings.ToUpper(s) {
	case "HIGH":
		return 0.9
	case "MEDIUM":
		return 0.7
	case "LOW":
		return 0.5
	default:
		return 0.85
	}
}

func severityToRiskTier(severity string) string {
	switch severity {
	case "CRITICAL", "HIGH":
		return contract.TierVulnerability
	case "MEDIUM":
		return contract.TierRiskPattern
	default:
		return contract.TierHardening
	}
}

func slugify(title string) string {
	s := strings.ToLower(title)
	s = regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(s, "_")
	s = strings.Trim(s, "_")
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

func isGovernanceCategory(cat string) bool {
	switch strings.ToLower(cat) {
	case "governance", "oversight", "authorization", "audit", "privacy", "transparency", "accountability":
		return true
	}
	return false
}

func extractComplianceMapping(f map[string]interface{}) *contract.ComplianceMapping {
	mappingsRaw, ok := f["compliance_mappings"]
	if !ok || mappingsRaw == nil {
		return nil
	}
	arr, ok := mappingsRaw.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}

	var euArticles, nistCats []string
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		framework := deepStr(m, "framework")
		reference := deepStr(m, "reference")
		if reference == "" {
			continue
		}
		if strings.Contains(framework, "EU AI Act") {
			euArticles = append(euArticles, reference)
		} else if strings.Contains(framework, "NIST") {
			nistCats = append(nistCats, reference)
		}
	}

	if len(euArticles) == 0 && len(nistCats) == 0 {
		return nil
	}
	return &contract.ComplianceMapping{
		EUAIActArticles: euArticles,
		NISTCategories:  nistCats,
	}
}

func splitRemediation(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

func extractDeepFindings(scan map[string]interface{}) []map[string]interface{} {
	findingsRaw, ok := scan["findings"]
	if !ok || findingsRaw == nil {
		return nil
	}

	var reportData interface{}
	if s, ok := findingsRaw.(string); ok {
		if err := json.Unmarshal([]byte(s), &reportData); err != nil {
			return nil
		}
	} else {
		reportData = findingsRaw
	}

	if report, ok := reportData.(map[string]interface{}); ok {
		if arr, ok := report["findings"].([]interface{}); ok {
			return toFindingMaps(arr)
		}
		return nil
	}

	if arr, ok := reportData.([]interface{}); ok {
		return toFindingMaps(arr)
	}

	return nil
}

func toFindingMaps(arr []interface{}) []map[string]interface{} {
	var result []map[string]interface{}
	for _, item := range arr {
		if m, ok := item.(map[string]interface{}); ok {
			result = append(result, m)
		}
	}
	return result
}

func deepScanInt(m map[string]interface{}, key string) int {
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	default:
		return 0
	}
}

func deepStr(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

func deepFloat(m map[string]interface{}, key string, fallback float32) float32 {
	v, ok := m[key]
	if !ok || v == nil {
		return fallback
	}
	switch n := v.(type) {
	case float64:
		return float32(n)
	case float32:
		return n
	default:
		return fallback
	}
}

func deepStrSlice(m map[string]interface{}, key string) []string {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	var result []string
	for _, item := range arr {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func deepBool(m map[string]interface{}, key string) bool {
	v, ok := m[key]
	if !ok || v == nil {
		return false
	}
	b, _ := v.(bool)
	return b
}

// humanizeDetectionID converts "prompt_injection_via_tool_args" → "Prompt Injection Via Tool Args".
func humanizeDetectionID(id string) string {
	words := strings.Split(id, "_")
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}

// extractDeepReport parses orchestrator metadata from a deep scan result into typed structs.
// The orchestrator bundles all metadata (agent_profile, clean_detections, etc.) inside
// scan["findings"] alongside the findings array. This function resolves that wrapper
// first, then extracts each metadata key from the resolved report map.
func extractDeepReport(scan map[string]interface{}) *cli.DeepReport {
	if scan == nil {
		return nil
	}

	// The orchestrator nests everything under scan["findings"] which may be a JSON
	// string or a map like {"findings": [...], "agent_profile": {...}, ...}.
	// Resolve this wrapper to get the report map containing all metadata.
	reportMap := scan // fallback: look at top level
	if findingsRaw, ok := scan["findings"]; ok && findingsRaw != nil {
		var parsed interface{}
		if s, ok := findingsRaw.(string); ok {
			if err := json.Unmarshal([]byte(s), &parsed); err == nil {
				if m, ok := parsed.(map[string]interface{}); ok {
					reportMap = m
				}
			}
		} else if m, ok := findingsRaw.(map[string]interface{}); ok {
			reportMap = m
		}
	}

	// Helper: resolve a key as map (handles JSON string or map)
	resolve := func(key string) map[string]interface{} {
		v, ok := reportMap[key]
		if !ok || v == nil {
			return nil
		}
		if m, ok := v.(map[string]interface{}); ok {
			return m
		}
		if s, ok := v.(string); ok {
			var m map[string]interface{}
			if err := json.Unmarshal([]byte(s), &m); err == nil {
				return m
			}
		}
		return nil
	}

	// Helper: resolve a key as slice (handles JSON string or slice)
	resolveSlice := func(key string) []interface{} {
		v, ok := reportMap[key]
		if !ok || v == nil {
			return nil
		}
		if arr, ok := v.([]interface{}); ok {
			return arr
		}
		if s, ok := v.(string); ok {
			var arr []interface{}
			if err := json.Unmarshal([]byte(s), &arr); err == nil {
				return arr
			}
		}
		return nil
	}

	report := &cli.DeepReport{}
	hasData := false

	// agent_profile
	if m := resolve("agent_profile"); m != nil {
		hasData = true
		report.AgentProfile = &cli.DeepAgentProfile{
			ArchitectureSummary: deepStr(m, "architecture_summary"),
			Framework:           deepStr(m, "framework"),
			Language:            deepStr(m, "language"),
			Purpose:             deepStr(m, "purpose"),
			HighRiskOperations:  deepStrSlice(m, "high_risk_operations"),
			DataSources:         deepStrSlice(m, "data_sources"),
			DataSinks:           deepStrSlice(m, "data_sinks"),
			Integrations:        deepStrSlice(m, "integrations"),
			TrustBoundaries:     deepStrSlice(m, "trust_boundaries"),
		}
	}

	// clean_detections
	if arr := resolveSlice("clean_detections"); len(arr) > 0 {
		hasData = true
		for _, item := range arr {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			report.CleanDetections = append(report.CleanDetections, cli.DeepCleanDetection{
				DetectionID: deepStr(m, "detection_id"),
				Reason:      deepStr(m, "reason"),
			})
		}
	}

	// compliance_summary
	if arr := resolveSlice("compliance_summary"); len(arr) > 0 {
		hasData = true
		for _, item := range arr {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			entry := cli.DeepComplianceEntry{
				Framework: deepStr(m, "framework"),
			}
			// relevant_findings are integers
			if rf, ok := m["relevant_findings"].([]interface{}); ok {
				for _, v := range rf {
					switch n := v.(type) {
					case float64:
						entry.RelevantFindings = append(entry.RelevantFindings, int(n))
					case int:
						entry.RelevantFindings = append(entry.RelevantFindings, n)
					}
				}
			}
			report.ComplianceSummary = append(report.ComplianceSummary, entry)
		}
	}

	// methodology
	if m := resolve("methodology"); m != nil {
		hasData = true
		report.Methodology = &cli.DeepMethodology{
			Approach:              deepStr(m, "approach"),
			ConfidenceCalibration: deepStr(m, "confidence_calibration"),
		}
	}

	// report (meta)
	if m := resolve("report"); m != nil {
		hasData = true
		report.ReportMeta = &cli.DeepReportMeta{
			AgentName:             deepStr(m, "agent_name"),
			Date:                  deepStr(m, "date"),
			DetectionRulesApplied: deepScanInt(m, "detection_rules_applied"),
			DetectionRulesNA:      deepScanInt(m, "detection_rules_na"),
			DetectionRulesTotal:   deepScanInt(m, "detection_rules_total"),
			FilesAudited:          deepScanInt(m, "files_audited"),
			TotalClean:            deepScanInt(m, "total_clean"),
			TotalFindings:         deepScanInt(m, "total_findings"),
		}
	}

	// severity_summary
	if m := resolve("severity_summary"); m != nil {
		hasData = true
		report.SeveritySummary = &cli.DeepSeveritySummary{
			Clean:    deepScanInt(m, "clean"),
			Critical: deepScanInt(m, "critical"),
			High:     deepScanInt(m, "high"),
			Medium:   deepScanInt(m, "medium"),
			Low:      deepScanInt(m, "low"),
			NA:       deepScanInt(m, "na"),
		}
	}

	if !hasData {
		return nil
	}
	return report
}

// outputResults formats and displays scan results
func outputResults(result *cli.ScanResult, format, minSeverity, policy string, verbose, quiet bool) error {
	switch format {
	case "json":
		return outputJSON(result)
	case "text":
		return outputText(result, minSeverity, policy, verbose)
	case "html":
		return outputHTML(result, minSeverity)
	case "sarif":
		return outputSARIF(result)
	default:
		return fmt.Errorf("unknown output format: %s", format)
	}
}

// outputText provides human-readable text output with tiered risk classification
func outputText(result *cli.ScanResult, minSeverity, policy string, verbose bool) error {
	// First filter by severity
	filtered := contract.GetBySeverity(result.AllFindings, strings.ToUpper(minSeverity))

	// Then filter by policy (tier-based)
	filtered = contract.FilterByPolicy(filtered, policy)

	if len(filtered) == 0 {
		if len(result.AllFindings) > 0 {
			fmt.Printf("✓ No issues match policy '%s' (%d findings filtered)\n",
				policy, len(result.AllFindings))
		} else {
			fmt.Println("✓ No security issues found")
		}
		return nil
	}

	// Group findings by tier
	tierGroups := contract.GroupByTier(filtered)

	// Display header
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════╗")
	fmt.Println("║           🔍 AI Agent Risk Assessment                ║")
	fmt.Println("╚══════════════════════════════════════════════════════╝")
	fmt.Println()

	// Display each tier section
	displayTierSection(tierGroups[contract.TierVulnerability], "🔴 EXPLOITABLE VULNERABILITIES", colorTierVuln)
	displayTierSection(tierGroups[contract.TierRiskPattern], "🟠 RISK PATTERNS", colorTierRisk)
	displayTierSection(tierGroups[contract.TierHardening], "🟡 HARDENING RECOMMENDATIONS", colorTierHardening)

	// Display tiered summary
	displayTieredSummary(filtered, policy)

	// Display governance status (if available)
	displayGovernanceStatus(result)

	// Display strengths (if available)
	displayStrengths(result)

	return nil
}

// displayTierSection displays a section of findings for a specific tier
func displayTierSection(findings []contract.Finding, header string, color string) {
	if len(findings) == 0 {
		return
	}

	// Sort findings within tier
	sortFindingsByLocation(findings)

	// Display header
	fmt.Printf("%s%s (%d)%s\n", color, header, len(findings), colorReset)

	// Display each finding
	for _, f := range findings {
		displayTieredCodeFrame(f)
	}
	fmt.Println()
}

// displayTieredCodeFrame renders a finding with tier-aware formatting
func displayTieredCodeFrame(f contract.Finding) {
	// 1. Location line with tier-aware severity
	severityColor := getSeverityColor(f.Severity)
	col := f.Column
	if col == 0 {
		col = 1
	}

	// Show tier indicator
	tierIndicator := ""
	if f.RiskTier == contract.TierVulnerability {
		tierIndicator = "[VULN] "
	}

	// Use DisplayTitle with fallback to Pattern
	title := f.Pattern
	if f.DisplayTitle != "" {
		title = f.DisplayTitle
	}

	// Show fix difficulty inline if available
	fixTag := ""
	if f.FixDifficulty != "" {
		fixTag = fmt.Sprintf(" [%s fix]", f.FixDifficulty)
	}

	// Build location string, suppressing meaningless ".:0" values
	location := ""
	baseFile := filepath.Base(f.File)
	if f.File != "" && f.File != "." && baseFile != "." {
		if f.Line > 0 {
			location = fmt.Sprintf(" [%s:%d]", baseFile, f.Line)
		} else {
			location = fmt.Sprintf(" [%s]", baseFile)
		}
	}

	fmt.Printf("  └─ %s%s%s%s - %s%s%s%s\n",
		severityColor, tierIndicator, title,
		location,
		severityColor, f.Severity, colorReset, fixTag)

	// 2. Show description (truncated for terminal — full details in json/html/sarif)
	desc := f.Message
	if f.ShortDescription != "" {
		desc = f.ShortDescription
	}
	if desc != "" {
		if len(desc) > 120 {
			desc = desc[:117] + "..."
		}
		fmt.Printf("     %s%s%s\n", colorGray, desc, colorReset)
	}

	// 3. Show CWE/OWASP references if present
	if f.CWE != "" || f.OWASP != "" {
		refs := []string{}
		if f.CWE != "" {
			refs = append(refs, f.CWE)
		}
		if f.OWASP != "" {
			refs = append(refs, f.OWASP)
		}
		fmt.Printf("     %sRef: %s%s\n", colorGray, strings.Join(refs, " | "), colorReset)
	}

	// 4. Show compliance mappings if present
	if f.ComplianceMapping != nil {
		if len(f.ComplianceMapping.EUAIActArticles) > 0 {
			fmt.Printf("     %sEU AI Act: %s%s\n", colorGray, strings.Join(f.ComplianceMapping.EUAIActArticles, ", "), colorReset)
		}
		if len(f.ComplianceMapping.NISTCategories) > 0 {
			fmt.Printf("     %sNIST: %s%s\n", colorGray, strings.Join(f.ComplianceMapping.NISTCategories, ", "), colorReset)
		}
	}

	// 5. Show taint source if present (key differentiator for Tier 1)
	if f.InputTainted && f.TaintSource != "" {
		fmt.Printf("     %sTaint source: %s (user input)%s\n", colorCyan, f.TaintSource, colorReset)
	}
}

// displayTieredSummary shows a tier-based summary
func displayTieredSummary(findings []contract.Finding, policy string) {
	counts := contract.CountByTier(findings)

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("AI Agent Risk Assessment: %d findings (policy: %s)\n", len(findings), policy)

	if counts[contract.TierVulnerability] > 0 {
		fmt.Printf("  %s● %d Exploitable Vulnerabilities%s (require immediate fix)\n",
			colorTierVuln, counts[contract.TierVulnerability], colorReset)
	}
	if counts[contract.TierRiskPattern] > 0 {
		fmt.Printf("  %s● %d Risk Patterns%s (structural issues)\n",
			colorTierRisk, counts[contract.TierRiskPattern], colorReset)
	}
	if counts[contract.TierHardening] > 0 {
		fmt.Printf("  %s● %d Hardening Recommendations%s (best practices)\n",
			colorTierHardening, counts[contract.TierHardening], colorReset)
	}

	// Show finding type breakdown (vulnerability vs governance)
	typeCounts := contract.CountByFindingType(findings)
	if typeCounts[contract.TypeGovernanceViolation] > 0 {
		fmt.Printf("  %s● %d Governance Gaps%s (compliance issues)\n",
			colorGovernance, typeCounts[contract.TypeGovernanceViolation], colorReset)
	}
}

// displayGovernanceStatus shows governance control status
func displayGovernanceStatus(result *cli.ScanResult) {
	// Only show if we have governance data
	if result.TopologyMap == nil && result.GovernanceScore == 0 {
		return
	}

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════╗")
	fmt.Println("║           🛡️  Governance Status                      ║")
	fmt.Println("╚══════════════════════════════════════════════════════╝")
	fmt.Println()

	// Show governance controls if we have topology data
	if result.TopologyMap != nil {
		gov := result.TopologyMap.Governance
		fmt.Println("Control Status:")

		// Human Oversight
		if gov.HasHumanOversight {
			fmt.Printf("  %s✓%s Human Oversight: %sPRESENT%s\n", colorCheck, colorReset, colorCheck, colorReset)
		} else {
			fmt.Printf("  %s✗%s Human Oversight: %sMISSING%s (Article 14.1)\n", colorCross, colorReset, colorCross, colorReset)
		}

		// Authorization
		if gov.HasAuthChecks {
			fmt.Printf("  %s✓%s Authorization:   %sPRESENT%s\n", colorCheck, colorReset, colorCheck, colorReset)
		} else {
			fmt.Printf("  %s✗%s Authorization:   %sMISSING%s\n", colorCross, colorReset, colorCross, colorReset)
		}

		// Rate Limiting
		if gov.HasRateLimiting {
			fmt.Printf("  %s✓%s Rate Limiting:   %sPRESENT%s\n", colorCheck, colorReset, colorCheck, colorReset)
		} else {
			fmt.Printf("  %s✗%s Rate Limiting:   %sMISSING%s (OWASP LLM04)\n", colorCross, colorReset, colorCross, colorReset)
		}

		// Audit Logging
		if gov.HasAuditLogging {
			fmt.Printf("  %s✓%s Audit Logging:   %sPRESENT%s\n", colorCheck, colorReset, colorCheck, colorReset)
		} else {
			fmt.Printf("  %s✗%s Audit Logging:   %sMISSING%s\n", colorCross, colorReset, colorCross, colorReset)
		}
		fmt.Println()
	}

	// Show governance score
	if result.GovernanceScore > 0 {
		scoreColor := colorCross
		if result.GovernanceScore >= 80 {
			scoreColor = colorCheck
		} else if result.GovernanceScore >= 50 {
			scoreColor = colorMedium
		}
		fmt.Printf("Governance Score: %s%d/100%s\n", scoreColor, result.GovernanceScore, colorReset)
	}

	// Show readiness status
	if result.EUAIActReadiness != "" {
		statusColor := colorCross
		statusIcon := "✗"
		if result.EUAIActReadiness == "READY" {
			statusColor = colorCheck
			statusIcon = "✓"
		} else if result.EUAIActReadiness == "PARTIAL" {
			statusColor = colorMedium
			statusIcon = "~"
		}
		fmt.Printf("Compliance Status: %s%s %s%s\n", statusColor, statusIcon, result.EUAIActReadiness, colorReset)
	}
}

// displayStrengths shows detected strengths in the codebase
func displayStrengths(result *cli.ScanResult) {
	if len(result.Strengths) == 0 {
		return
	}
	fmt.Println()
	fmt.Println("Strengths:")
	for _, s := range result.Strengths {
		fmt.Printf("  %s✓%s %s — %s\n", colorCheck, colorReset, s.Title, s.Message)
	}
}

// getSeverityColor returns the ANSI color code for a severity level
func getSeverityColor(severity string) string {
	switch severity {
	case "CRITICAL":
		return colorCritical
	case "HIGH":
		return colorHigh
	case "MEDIUM":
		return colorMedium
	case "LOW":
		return colorLow
	default:
		return colorReset
	}
}

// displayCodeFrame renders a single finding in diagnostic format (Ruff/Semgrep style)
func displayCodeFrame(f contract.Finding) {
	// 1. Location line (clickable in VS Code: file:line:col)
	severityColor := getSeverityColor(f.Severity)
	col := f.Column
	if col == 0 {
		col = 1 // Default to column 1 if not specified
	}
	fmt.Printf("%s:%d:%d %s[%s]%s %s\n",
		f.File, f.Line, col,
		severityColor, f.Severity, colorReset,
		f.Pattern)

	// 2. Code frame with gutter
	if f.Code != "" {
		fmt.Printf("%s│%s\n", colorGray, colorReset)
		lines := strings.Split(f.Code, "\n")
		for i, line := range lines {
			lineNum := f.Line + i
			// Truncate long lines for readability
			if len(line) > 80 {
				line = line[:77] + "..."
			}
			fmt.Printf("%s%3d│%s  %s\n", colorGray, lineNum, colorReset, line)
		}
		// Underline highlight with message
		if col > 0 && f.Message != "" {
			underlineLen := 30
			if len(f.Message) < underlineLen {
				underlineLen = len(f.Message)
			}
			padding := strings.Repeat(" ", col-1)
			underline := strings.Repeat("^", underlineLen)
			fmt.Printf("%s   │%s  %s%s%s%s %s%s\n",
				colorGray, colorReset,
				padding, severityColor, underline, colorReset,
				f.Message, colorReset)
		}
		fmt.Printf("%s│%s\n", colorGray, colorReset)
	}

	// 3. Compliance footer
	compliance := []string{}
	if f.CWE != "" {
		compliance = append(compliance, f.CWE)
	}
	if f.OWASP != "" {
		compliance = append(compliance, f.OWASP)
	}
	if len(compliance) > 0 {
		fmt.Printf("%s= Compliance: %s%s\n", colorGray, strings.Join(compliance, " | "), colorReset)
	}
	fmt.Println()
}

// sortFindingsByLocation sorts findings by file path, then by line number
func sortFindingsByLocation(findings []contract.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		// Sort by severity first (CRITICAL > HIGH > MEDIUM > LOW), then by file/line
		si := contract.SeverityLevels[findings[i].Severity]
		sj := contract.SeverityLevels[findings[j].Severity]
		if si != sj {
			return si > sj
		}
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Line < findings[j].Line
	})
}

// displayCompactSummary shows a single-line summary of findings
func displayCompactSummary(findings []contract.Finding) {
	counts := countBySeverity(findings)
	fmt.Printf("\nFound %d issues: %s%d critical%s, %s%d high%s, %s%d medium%s, %s%d low%s\n",
		len(findings),
		colorCritical, counts["CRITICAL"], colorReset,
		colorHigh, counts["HIGH"], colorReset,
		colorMedium, counts["MEDIUM"], colorReset,
		colorLow, counts["LOW"], colorReset)
}

// countBySeverity returns a map of severity levels to counts
func countBySeverity(findings []contract.Finding) map[string]int {
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

// filterFindingsBySeverity returns findings matching the given severity level
func filterFindingsBySeverity(findings []contract.Finding, severity string) []contract.Finding {
	var filtered []contract.Finding
	for _, f := range findings {
		if f.Severity == severity {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// calculateSecurityScore computes total points based on findings
func calculateSecurityScore(findings []contract.Finding) int {
	score := 0
	for _, f := range findings {
		switch f.Severity {
		case "CRITICAL":
			score += PointsCritical
		case "HIGH":
			score += PointsHigh
		case "MEDIUM":
			score += PointsMedium
		case "LOW":
			score += PointsLow
		}
	}
	return score
}

// getSecurityGrade returns letter grade, description, and CSS class
func getSecurityGrade(score int) (string, string, string) {
	switch {
	case score == 0:
		return "A", "Excellent", "grade-a"
	case score <= 20:
		return "B", "Good", "grade-b"
	case score <= 50:
		return "C", "Moderate", "grade-c"
	case score <= 100:
		return "D", "Needs Work", "grade-d"
	default:
		return "F", "Critical", "grade-f"
	}
}

// gateStatusClass returns CSS class for security gate
func gateStatusClass(critical, high int) string {
	if critical == 0 && high == 0 {
		return "passed"
	}
	return "blocked"
}

// gateStatusText returns text for security gate
func gateStatusText(critical, high int) string {
	if critical == 0 && high == 0 {
		return "PASSED"
	}
	return "BLOCKED"
}

// gateStatusIcon returns icon for security gate
func gateStatusIcon(critical, high int) string {
	if critical == 0 && high == 0 {
		return "✅"
	}
	return "🚫"
}

// extractAgentName extracts the DEEPEST directory as the agent name
// For: /tmp/inkog-scan-xxx/examples/crewai-python/crew.py → "crewai-python"
// For: /tmp/inkog_e2e_demo/examples/langgraph-python/agent.py → "langgraph-python"
func extractAgentName(filePath string) string {
	parts := strings.Split(filePath, string(os.PathSeparator))

	// Find scan directory markers (inkog-scan-* or inkog_e2e_*)
	scanDirIndex := -1
	for i, part := range parts {
		if strings.HasPrefix(part, "inkog-scan-") || strings.HasPrefix(part, "inkog_e2e_") {
			scanDirIndex = i
			break
		}
	}

	if scanDirIndex != -1 && scanDirIndex+1 < len(parts) {
		// Get all parts after the scan directory
		afterScan := parts[scanDirIndex+1:]

		// Remove the file name (last element if it contains a dot)
		if len(afterScan) > 0 && strings.Contains(afterScan[len(afterScan)-1], ".") {
			afterScan = afterScan[:len(afterScan)-1]
		}

		// Return the DEEPEST directory (the actual agent name)
		if len(afterScan) > 0 {
			return afterScan[len(afterScan)-1]
		}
	}

	// Fallback: find the deepest non-file directory
	var lastDir string
	for _, part := range parts {
		if part != "" && !strings.Contains(part, ".") &&
			part != "tmp" && !strings.HasPrefix(part, "inkog-") {
			lastDir = part
		}
	}
	if lastDir != "" {
		return lastDir
	}
	return "default"
}

// groupFindingsByAgent groups findings by their agent directory
func groupFindingsByAgent(findings []contract.Finding) map[string][]contract.Finding {
	groups := make(map[string][]contract.Finding)
	for _, f := range findings {
		agent := extractAgentName(f.File)
		groups[agent] = append(groups[agent], f)
	}
	return groups
}

// getAgentNames returns sorted list of agent names
func getAgentNames(groups map[string][]contract.Finding) []string {
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// AgentReport contains per-agent security analysis
type AgentReport struct {
	Name          string
	Directory     string
	Framework     string
	Findings      []contract.Finding
	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int
	TotalCount    int
	Score         int
	Grade         string
	GradeClass    string
	TopIssues     []string
}

// detectFramework infers the AI framework from file patterns and code
func detectFramework(findings []contract.Finding) string {
	// Directory name patterns (most reliable - check file path)
	dirPatterns := map[string]string{
		"crewai":         "CrewAI",
		"langchain":      "LangChain",
		"langgraph":      "LangGraph",
		"autogen":        "AutoGen",
		"smolagents":     "Smolagents",
		"phidata":        "Phidata",
		"haystack":       "Haystack",
		"dspy":           "DSPy",
		"semantickernel": "Semantic Kernel",
		"openai-sdk":     "OpenAI SDK",
		"llamaindex":     "LlamaIndex",
		"agentops":       "AgentOps",
		"langflow":       "Langflow",
		"flowise":        "Flowise",
		"copilotstudio":  "Copilot Studio",
		"copilot-studio": "Copilot Studio",
		"agentforce":     "Agentforce",
		"einsteinbot":    "Einstein Bots",
	}

	// Code import patterns
	codePatterns := map[string]string{
		"from crewai":          "CrewAI",
		"import crewai":        "CrewAI",
		"from langchain":       "LangChain",
		"from langgraph":       "LangGraph",
		"from autogen":         "AutoGen",
		"from smolagents":      "Smolagents",
		"from phidata":         "Phidata",
		"from haystack":        "Haystack",
		"import dspy":          "DSPy",
		"from semantic_kernel": "Semantic Kernel",
		"from openai":          "OpenAI SDK",
		"import openai":        "OpenAI SDK",
		"from llama_index":     "LlamaIndex",
		"from llamaindex":      "LlamaIndex",
	}

	for _, f := range findings {
		file := strings.ToLower(f.File)
		code := strings.ToLower(f.Code)

		// Check directory name patterns first (most reliable)
		for pattern, name := range dirPatterns {
			if strings.Contains(file, pattern) {
				return name
			}
		}

		// Check code import patterns
		for pattern, name := range codePatterns {
			if strings.Contains(code, pattern) {
				return name
			}
		}

		// Check for n8n JSON patterns
		if strings.HasSuffix(file, ".n8n.json") || strings.Contains(code, "n8n-nodes") {
			return "n8n"
		}

		// Check for Flowise/Langflow JSON patterns
		if strings.HasSuffix(file, ".flowise.json") || strings.Contains(code, "flowise") {
			return "Flowise"
		}
		if strings.HasSuffix(file, ".langflow.json") || strings.Contains(code, "langflow") {
			return "Langflow"
		}

		// Check for Dify patterns
		if strings.HasSuffix(file, ".dify.json") || strings.Contains(code, "\"mode\":\"workflow\"") {
			return "Dify"
		}

		// Check for Copilot Studio patterns (YAML/JSON)
		if strings.Contains(code, "kind: copilotstudio") ||
			strings.Contains(code, "kind: copilot") ||
			strings.Contains(code, "\"schemaversion\":") && strings.Contains(code, "\"topics\":") ||
			strings.HasSuffix(file, ".copilot.yaml") ||
			strings.HasSuffix(file, ".copilot.json") {
			return "Copilot Studio"
		}

		// Check for Agentforce/Einstein patterns (XML/JSON/YAML)
		if strings.Contains(code, "genaiplanner") ||
			strings.Contains(code, "genaiplugin") ||
			strings.Contains(code, "einstein") && (strings.Contains(code, "bot") || strings.Contains(code, "gpt")) ||
			strings.HasSuffix(file, "-meta.xml") && strings.Contains(code, "agent") ||
			strings.Contains(code, "\"agentconfig\":") ||
			strings.Contains(code, "agentconfig:") {
			return "Agentforce"
		}
	}

	// Provide language-aware fallback based on file extensions
	for _, f := range findings {
		file := strings.ToLower(f.File)
		if strings.HasSuffix(file, ".py") {
			return "Python Agent"
		}
		if strings.HasSuffix(file, ".js") || strings.HasSuffix(file, ".ts") {
			return "JavaScript Agent"
		}
		if strings.HasSuffix(file, ".json") {
			return "JSON Workflow"
		}
	}

	return "AI Agent"
}

// extractTopIssues returns the top N most severe issue titles
func extractTopIssues(findings []contract.Finding, n int) []string {
	if len(findings) == 0 {
		return nil
	}

	// Sort by severity (Critical > High > Medium > Low)
	sorted := make([]contract.Finding, len(findings))
	copy(sorted, findings)
	sort.Slice(sorted, func(i, j int) bool {
		return contract.SeverityLevels[sorted[i].Severity] > contract.SeverityLevels[sorted[j].Severity]
	})

	// Extract top N titles
	var issues []string
	for i := 0; i < n && i < len(sorted); i++ {
		// Truncate long pattern names
		title := sorted[i].Pattern
		if len(title) > 40 {
			title = title[:37] + "..."
		}
		issues = append(issues, title)
	}
	return issues
}

// buildAgentReports creates AgentReport structs for each agent group
func buildAgentReports(groups map[string][]contract.Finding) []AgentReport {
	var reports []AgentReport

	// Find base scan path from any absolute path in findings
	scanBasePath := findScanBasePath(groups)

	for name, findings := range groups {
		report := AgentReport{
			Name:      extractAgentUseCaseName(findings, name, scanBasePath),
			Directory: name,
			Findings:  findings,
			Framework: detectFramework(findings),
		}

		// Count by severity
		for _, f := range findings {
			switch f.Severity {
			case "CRITICAL":
				report.CriticalCount++
			case "HIGH":
				report.HighCount++
			case "MEDIUM":
				report.MediumCount++
			case "LOW":
				report.LowCount++
			}
		}
		report.TotalCount = len(findings)

		// Calculate per-agent score and grade
		report.Score = calculateSecurityScore(findings)
		report.Grade, _, report.GradeClass = getSecurityGrade(report.Score)

		// Extract top 3 issues
		report.TopIssues = extractTopIssues(findings, 3)

		reports = append(reports, report)
	}

	// Sort by score (worst first - highest score)
	sort.Slice(reports, func(i, j int) bool {
		return reports[i].Score > reports[j].Score
	})

	return reports
}

// formatAgentDisplayName formats directory name for display
func formatAgentDisplayName(name string) string {
	// Replace dashes/underscores with spaces, capitalize words
	name = strings.ReplaceAll(name, "-", " ")
	name = strings.ReplaceAll(name, "_", " ")
	words := strings.Fields(name)
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + strings.ToLower(w[1:])
		}
	}
	return strings.Join(words, " ")
}

// ============================================================================
// Enterprise Agent Naming System
// Extracts meaningful use case names from agent code files
// ============================================================================

// Regex patterns for extracting agent names from code
var (
	// Python: class EnterpriseDevelopmentAgent: or class MyAgent(Base):
	pythonClassPattern = regexp.MustCompile(`class\s+(\w+(?:Agent|Crew|Assistant|Bot|Worker|Pipeline|Flow))\s*[\(:]`)

	// Python module docstring: """Finance Agent for processing..."""
	pythonDocstringPattern = regexp.MustCompile(`(?s)^(?:#!/.*?\n)?(?:#.*?\n)*\s*"""([\s\S]*?)"""`)

	// CrewAI role field: role="Senior Research Analyst"
	crewaiRolePattern = regexp.MustCompile(`role\s*=\s*["']([^"']+)["']`)

	// CrewAI crew name: @crew decorator or Crew() call
	crewaiCrewPattern = regexp.MustCompile(`(?:@crew|Crew\s*\(.*?name\s*=\s*["'])(\w+)`)

	// n8n workflow name: "name": "AI Agent"
	n8nNamePattern = regexp.MustCompile(`"name"\s*:\s*"([^"]+)"`)

	// Langchain/LangGraph agent name from variable assignment
	langchainAgentPattern = regexp.MustCompile(`(\w+)_agent\s*=|agent\s*=\s*(?:Agent|create_\w+_agent)\s*\(`)

	// Generic agent_name= or assistant_name= patterns (avoid generic name= which catches model names)
	genericNamePattern = regexp.MustCompile(`(?:agent_name|assistant_name|workflow_name)\s*=\s*["']([^"']+)["']`)

	// Phidata agent: Agent(name="Finance Agent")
	phidataAgentPattern = regexp.MustCompile(`Agent\s*\([^)]*name\s*=\s*["']([^"']+)["']`)

	// AutoGen agent: AssistantAgent(name="analyst")
	autogenAgentPattern = regexp.MustCompile(`(?:Assistant|User)Agent\s*\([^)]*name\s*=\s*["']([^"']+)["']`)

	// CamelCase word boundary pattern
	camelCaseSplit = regexp.MustCompile(`([a-z])([A-Z])|([A-Z]+)([A-Z][a-z])`)
)

// findScanBasePath extracts the base scan path from any absolute path in findings
func findScanBasePath(groups map[string][]contract.Finding) string {
	for _, findings := range groups {
		for _, f := range findings {
			if filepath.IsAbs(f.File) {
				// Find the "examples" or similar common parent directory
				dir := filepath.Dir(f.File)
				for dir != "/" && dir != "." {
					parent := filepath.Dir(dir)
					// Check if parent contains "examples" or common scan markers
					if _, err := os.Stat(filepath.Join(parent, "examples")); err == nil {
						return parent
					}
					// Check for inkog scan temp dir markers
					base := filepath.Base(parent)
					if strings.HasPrefix(base, "inkog-scan-") || strings.HasPrefix(base, "inkog_e2e_") {
						return parent
					}
					dir = parent
				}
				// Fallback: return grandparent of file (assumes examples/agent/file.py)
				dir = filepath.Dir(f.File)
				return filepath.Dir(filepath.Dir(dir))
			}
		}
	}
	return ""
}

// extractAgentUseCaseName extracts a meaningful use case name from agent files
// Priority: 1) Class name 2) Docstring 3) Role field 4) Name field 5) n8n JSON 6) Directory fallback
func extractAgentUseCaseName(findings []contract.Finding, directory string, scanBasePath string) string {
	// Collect unique file paths in this agent's directory
	fileSet := make(map[string]bool)

	// If we have a scan base path, construct absolute path for this directory
	var agentDirPath string
	if scanBasePath != "" {
		// Try common structures: basePath/examples/directory or basePath/directory
		possiblePaths := []string{
			filepath.Join(scanBasePath, "examples", directory),
			filepath.Join(scanBasePath, directory),
		}
		for _, p := range possiblePaths {
			if info, err := os.Stat(p); err == nil && info.IsDir() {
				agentDirPath = p
				break
			}
		}

		// For "default" directory (root-level files), use scan base path directly
		if directory == "default" && agentDirPath == "" {
			agentDirPath = scanBasePath
		}
	}

	// Collect files from findings (may have absolute or relative paths)
	for _, f := range findings {
		// For "default" directory, include all root-level files
		matchesDir := strings.Contains(f.File, directory)
		if directory == "default" && !matchesDir {
			// Root-level file if no path separator or not under examples/
			matchesDir = !strings.Contains(f.File, "/") ||
				(!strings.HasPrefix(f.File, "examples/") && filepath.Dir(f.File) == ".")
		}

		if matchesDir {
			if filepath.IsAbs(f.File) {
				fileSet[f.File] = true
			} else if scanBasePath != "" {
				// Try to make relative path absolute
				absPath := filepath.Join(scanBasePath, f.File)
				if _, err := os.Stat(absPath); err == nil {
					fileSet[absPath] = true
				}
			}
		}
	}

	// Glob for additional files in the agent directory
	if agentDirPath != "" {
		patterns := []string{"*.py", "*.json", "*.ts", "*.js"}
		for _, pattern := range patterns {
			matches, err := filepath.Glob(filepath.Join(agentDirPath, pattern))
			if err == nil {
				for _, m := range matches {
					fileSet[m] = true
				}
			}
		}
	}

	// Try each file to extract a meaningful name
	var bestName string
	var bestPriority int = 999

	for filePath := range fileSet {
		content, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}
		contentStr := string(content)

		// Priority 1: Python class names with Agent/Crew suffix
		if strings.HasSuffix(filePath, ".py") {
			if matches := pythonClassPattern.FindStringSubmatch(contentStr); len(matches) > 1 {
				name := formatClassName(matches[1])
				if name != "" && bestPriority > 1 {
					bestName = name
					bestPriority = 1
				}
			}

			// Priority 2: Module docstring (first line)
			if bestPriority > 2 {
				if matches := pythonDocstringPattern.FindStringSubmatch(contentStr); len(matches) > 1 {
					docLine := strings.Split(strings.TrimSpace(matches[1]), "\n")[0]
					docLine = strings.TrimSpace(docLine)
					if len(docLine) > 5 && len(docLine) < 60 {
						bestName = docLine
						bestPriority = 2
					}
				}
			}

			// Priority 3: Phidata Agent(name=...) pattern
			if bestPriority > 3 {
				if matches := phidataAgentPattern.FindStringSubmatch(contentStr); len(matches) > 1 {
					bestName = matches[1]
					bestPriority = 3
				}
			}

			// Priority 4: AutoGen agent pattern
			if bestPriority > 4 {
				if matches := autogenAgentPattern.FindStringSubmatch(contentStr); len(matches) > 1 {
					bestName = formatClassName(matches[1])
					bestPriority = 4
				}
			}

			// Priority 5: CrewAI role field
			if bestPriority > 5 {
				if matches := crewaiRolePattern.FindStringSubmatch(contentStr); len(matches) > 1 {
					bestName = matches[1]
					bestPriority = 5
				}
			}

			// Priority 6: Generic name= pattern
			if bestPriority > 6 {
				if matches := genericNamePattern.FindStringSubmatch(contentStr); len(matches) > 1 {
					bestName = matches[1]
					bestPriority = 6
				}
			}
		}

		// Priority 7: n8n JSON workflow name - prefer "agent" in name
		if strings.HasSuffix(filePath, ".json") && bestPriority > 7 {
			if matches := n8nNamePattern.FindAllStringSubmatch(contentStr, -1); len(matches) > 0 {
				// First pass: find names containing "agent"
				for _, m := range matches {
					if len(m) > 1 {
						name := m[1]
						lowerName := strings.ToLower(name)
						if strings.Contains(lowerName, "agent") {
							bestName = name
							bestPriority = 7
							break
						}
					}
				}
				// Second pass: find any meaningful non-generic name
				if bestPriority > 7 {
					for _, m := range matches {
						if len(m) > 1 {
							name := m[1]
							lowerName := strings.ToLower(name)
							// Skip generic/infrastructure names
							if lowerName != "default" && lowerName != "start" &&
								lowerName != "end" && lowerName != "main" &&
								!strings.Contains(lowerName, "loop") &&
								!strings.Contains(lowerName, "trigger") &&
								len(name) > 2 {
								bestName = name
								bestPriority = 7
								break
							}
						}
					}
				}
			}
		}
	}

	// Truncate long names (max ~40 chars for display)
	if len(bestName) > 40 {
		words := strings.Fields(bestName)
		truncated := ""
		for _, w := range words {
			if len(truncated)+len(w)+1 <= 40 {
				if truncated != "" {
					truncated += " "
				}
				truncated += w
			} else {
				break
			}
		}
		if truncated != "" {
			bestName = truncated
		}
	}

	// Fallback to formatted directory name
	if bestName == "" {
		return formatAgentDisplayName(directory)
	}

	return bestName
}

// formatClassName converts CamelCase class names to readable format
// EnterpriseDevelopmentAgent → Development Agent
// ContentResearchCrew → Content Research Crew
// FinanceAgent → Finance Agent
func formatClassName(className string) string {
	// Remove common prefixes
	name := className
	prefixes := []string{"Enterprise", "Custom", "My", "The"}
	for _, prefix := range prefixes {
		if strings.HasPrefix(name, prefix) && len(name) > len(prefix) {
			name = name[len(prefix):]
		}
	}

	// Remove common suffixes but keep them in mind
	suffixes := []string{"Agent", "Crew", "Assistant", "Bot", "Worker", "Pipeline", "Flow"}
	var suffix string
	for _, s := range suffixes {
		if strings.HasSuffix(name, s) && len(name) > len(s) {
			suffix = s
			name = name[:len(name)-len(s)]
			break
		}
	}

	// Split CamelCase into words
	// First pass: insert spaces before capitals
	name = camelCaseSplit.ReplaceAllString(name, "${1}${3} ${2}${4}")
	name = strings.TrimSpace(name)

	// If we have a meaningful name, optionally append the suffix type
	if name != "" {
		// Only append suffix if name is very short (like "Finance" → "Finance Agent")
		if suffix != "" && len(strings.Fields(name)) <= 1 {
			return name + " " + suffix
		}
		return name
	}

	// Fallback: return original with spaces
	return className
}

// getGlobalStatus returns the global system status based on findings
func getGlobalStatus(criticalCount, highCount int) (string, string, string) {
	if criticalCount > 0 {
		return "System Critical", "critical", "var(--critical)"
	}
	if highCount > 0 {
		return "Needs Attention", "warning", "var(--high)"
	}
	return "System Healthy", "healthy", "var(--low)"
}

// outputJSON provides JSON output for integration with CI/CD
func outputJSON(result *cli.ScanResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

// outputSARIF provides SARIF v2.1.0 output for GitHub Security integration
func outputSARIF(result *cli.ScanResult) error {
	sarif := buildSARIFReport(result)
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(sarif)
}

// SARIF v2.1.0 Schema Types
// Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	InformationURI  string            `json:"informationUri"`
	SemanticVersion string            `json:"semanticVersion"`
	Rules           []sarifRule       `json:"rules"`
}

type sarifRule struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	ShortDescription sarifMessage           `json:"shortDescription"`
	FullDescription  sarifMessage           `json:"fullDescription,omitempty"`
	HelpURI          string                 `json:"helpUri,omitempty"`
	DefaultConfiguration sarifConfiguration `json:"defaultConfiguration"`
	Properties       sarifRuleProperties    `json:"properties,omitempty"`
}

type sarifConfiguration struct {
	Level string `json:"level"`
}

type sarifRuleProperties struct {
	Tags         []string `json:"tags,omitempty"`
	SecuritySeverity string `json:"security-severity,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string            `json:"ruleId"`
	Level     string            `json:"level"`
	Message   sarifMessage      `json:"message"`
	Locations []sarifLocation   `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

func buildSARIFReport(result *cli.ScanResult) *sarifReport {
	// Build unique rules from findings
	rulesMap := make(map[string]sarifRule)
	var results []sarifResult

	for _, f := range result.AllFindings {
		// Generate rule ID from pattern
		ruleID := f.PatternID
		if ruleID == "" {
			ruleID = strings.ReplaceAll(strings.ToLower(f.Pattern), " ", "-")
		}
		if ruleID == "" {
			ruleID = "inkog-unknown"
		}

		// Add rule if not already present
		if _, exists := rulesMap[ruleID]; !exists {
			rulesMap[ruleID] = sarifRule{
				ID:   ruleID,
				Name: f.Pattern,
				ShortDescription: sarifMessage{
					Text: f.Pattern,
				},
				FullDescription: sarifMessage{
					Text: f.Message,
				},
				HelpURI: buildHelpURI(f.CWE),
				DefaultConfiguration: sarifConfiguration{
					Level: severityToSARIFLevel(f.Severity),
				},
				Properties: sarifRuleProperties{
					Tags:             buildTags(f),
					SecuritySeverity: severityToScore(f.Severity),
				},
			}
		}

		// Create result
		results = append(results, sarifResult{
			RuleID: ruleID,
			Level:  severityToSARIFLevel(f.Severity),
			Message: sarifMessage{
				Text: f.Message,
			},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifact{
							URI: f.File,
						},
						Region: sarifRegion{
							StartLine:   f.Line,
							StartColumn: f.Column,
						},
					},
				},
			},
		})
	}

	// Convert rules map to slice
	rules := make([]sarifRule, 0, len(rulesMap))
	for _, rule := range rulesMap {
		rules = append(rules, rule)
	}

	return &sarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:            "Inkog",
						Version:         AppVersion,
						InformationURI:  "https://inkog.io",
						SemanticVersion: AppVersion,
						Rules:           rules,
					},
				},
				Results: results,
			},
		},
	}
}

func severityToSARIFLevel(severity string) string {
	switch severity {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	case "LOW":
		return "note"
	default:
		return "warning"
	}
}

func severityToScore(severity string) string {
	switch severity {
	case "CRITICAL":
		return "9.0"
	case "HIGH":
		return "7.0"
	case "MEDIUM":
		return "5.0"
	case "LOW":
		return "3.0"
	default:
		return "5.0"
	}
}

func buildHelpURI(cwe string) string {
	if cwe == "" {
		return "https://inkog.io/docs/patterns"
	}
	// Extract CWE number for MITRE link
	cweNum := strings.TrimPrefix(cwe, "CWE-")
	return fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", cweNum)
}

func buildTags(f contract.Finding) []string {
	tags := []string{"security"}
	if f.CWE != "" {
		tags = append(tags, f.CWE)
	}
	if f.OWASP != "" {
		tags = append(tags, "OWASP:"+f.OWASP)
	}
	return tags
}

// Enterprise HTML Report - Inkog Design System
const htmlReportCSS = `
:root {
    /* Backgrounds - Inkog Dark Mode */
    --bg-primary: #0A0A0A;
    --bg-secondary: #121212;
    --bg-card: rgba(24, 24, 27, 0.5);
    --bg-elevated: #18181b;

    /* Text - Zinc Scale */
    --text-primary: #e4e4e7;
    --text-heading: #f4f4f5;
    --text-secondary: #a1a1aa;
    --text-muted: #71717a;

    /* Borders - Semi-transparent */
    --border: rgba(255, 255, 255, 0.1);
    --border-subtle: #27272a;

    /* Severity Colors */
    --critical: #ef4444;
    --critical-bg: rgba(239, 68, 68, 0.1);
    --high: #f97316;
    --high-bg: rgba(249, 115, 22, 0.1);
    --medium: #eab308;
    --medium-bg: rgba(234, 179, 8, 0.1);
    --low: #22c55e;
    --low-bg: rgba(34, 197, 94, 0.1);

    /* Primary Accent - Inkog Violet */
    --primary: #8b5cf6;
    --primary-hover: #7c3aed;
    --primary-light: #a78bfa;
    --primary-bg: rgba(139, 92, 246, 0.1);
    --primary-glow: rgba(139, 92, 246, 0.5);

    /* Layout */
    --radius-sm: 6px;
    --radius-md: 10px;
    --radius-lg: 14px;
    --radius-xl: 20px;

    /* Shadows - Violet Glow (Inkog Signature) */
    --shadow-sm: 0 0 20px -5px rgba(139, 92, 246, 0.2);
    --shadow-md: 0 0 30px -8px rgba(139, 92, 246, 0.3);
    --shadow-lg: 0 0 40px -10px rgba(139, 92, 246, 0.4);

    /* Transitions */
    --transition-fast: 150ms cubic-bezier(0.4, 0, 0.2, 1);
    --transition-normal: 250ms cubic-bezier(0.4, 0, 0.2, 1);
}

/* Light Mode Support */
@media (prefers-color-scheme: light) {
    :root {
        /* Backgrounds - Light Mode */
        --bg-primary: #fafafa;
        --bg-secondary: #f4f4f5;
        --bg-card: rgba(255, 255, 255, 0.9);
        --bg-elevated: #ffffff;

        /* Text - Dark for Light Mode */
        --text-primary: #18181b;
        --text-heading: #09090b;
        --text-secondary: #52525b;
        --text-muted: #71717a;

        /* Borders - Darker for Light Mode */
        --border: rgba(0, 0, 0, 0.1);
        --border-subtle: #e4e4e7;

        /* Severity Colors - Slightly darker for light mode contrast */
        --critical: #dc2626;
        --critical-bg: rgba(220, 38, 38, 0.1);
        --high: #ea580c;
        --high-bg: rgba(234, 88, 12, 0.1);
        --medium: #ca8a04;
        --medium-bg: rgba(202, 138, 4, 0.1);
        --low: #16a34a;
        --low-bg: rgba(22, 163, 74, 0.1);

        /* Primary Accent - Inkog Violet (darker for light mode) */
        --primary: #7c3aed;
        --primary-hover: #6d28d9;
        --primary-light: #8b5cf6;
        --primary-bg: rgba(124, 58, 237, 0.1);
        --primary-glow: rgba(124, 58, 237, 0.3);

        /* Shadows - Softer for Light Mode */
        --shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.1);
        --shadow-md: 0 4px 6px rgba(0, 0, 0, 0.1);
        --shadow-lg: 0 10px 15px rgba(0, 0, 0, 0.1);
    }

    /* Code blocks need inverted styling in light mode */
    .code-frame pre {
        background: #1e1e1e !important;
        color: #d4d4d4 !important;
    }
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', Roboto, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
    padding: 2rem;
    max-width: 1400px;
    margin: 0 auto;
    -webkit-font-smoothing: antialiased;
}

/* Header */
header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 2rem;
    padding-bottom: 1.5rem;
    border-bottom: 1px solid var(--border);
}

.logo {
    display: flex;
    align-items: center;
    gap: 0.75rem;
}

.logo svg {
    width: 32px;
    height: 32px;
}

.logo span {
    font-size: 1.25rem;
    font-weight: 600;
    letter-spacing: -0.025em;
    color: var(--text-heading);
}

.timestamp {
    color: var(--text-muted);
    font-size: 0.8125rem;
}

/* Global Status Bar */
.global-status {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 1rem 1.5rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 2rem;
    position: relative;
    overflow: hidden;
}

.global-status::before {
    content: '';
    position: absolute;
    left: 0;
    top: 0;
    bottom: 0;
    width: 4px;
}

.global-status.critical::before { background: var(--critical); }
.global-status.warning::before { background: var(--high); }
.global-status.healthy::before { background: var(--low); }

.status-indicator {
    display: flex;
    align-items: center;
    gap: 0.75rem;
}

.pulse {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    animation: pulse 2s ease-in-out infinite;
}

.global-status.critical .pulse { background: var(--critical); }
.global-status.warning .pulse { background: var(--high); }
.global-status.healthy .pulse { background: var(--low); }

@keyframes pulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.5; transform: scale(1.3); }
}

.status-text {
    font-size: 1rem;
    font-weight: 600;
}

.global-status.critical .status-text { color: var(--critical); }
.global-status.warning .status-text { color: var(--high); }
.global-status.healthy .status-text { color: var(--low); }

.status-meta {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    color: var(--text-secondary);
    font-size: 0.875rem;
}

.status-meta .divider {
    color: var(--text-muted);
}

/* Section Headers */
section {
    margin-bottom: 2.5rem;
}

section h2 {
    font-size: 0.8125rem;
    font-weight: 600;
    margin-bottom: 1rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.1em;
}

/* Agent Cards Grid */
.agent-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
    gap: 1.25rem;
}

.agent-card {
    background: var(--bg-card);
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 1.5rem;
    position: relative;
    overflow: hidden;
    cursor: pointer;
    transition: transform var(--transition-fast), box-shadow var(--transition-fast), border-color var(--transition-fast);
}

.agent-card:hover {
    transform: translateY(-2px);
    box-shadow: var(--shadow-lg);
    border-color: rgba(139, 92, 246, 0.3);
}

.agent-card.selected {
    border-color: var(--primary);
    box-shadow: 0 0 0 2px var(--primary-bg), var(--shadow-lg);
    transform: translateY(-2px);
}

.global-status {
    cursor: pointer;
    transition: background var(--transition-fast);
}

.global-status:hover {
    background: var(--bg-elevated);
}

.agent-card::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 3px;
}

.agent-card.grade-f::before { background: linear-gradient(90deg, var(--critical), #b91c1c); }
.agent-card.grade-d::before { background: linear-gradient(90deg, var(--high), #c2410c); }
.agent-card.grade-c::before { background: linear-gradient(90deg, var(--medium), #a16207); }
.agent-card.grade-b::before { background: linear-gradient(90deg, var(--primary), #6d28d9); }
.agent-card.grade-a::before { background: linear-gradient(90deg, var(--low), #15803d); }

.agent-card-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 1rem;
}

.agent-info {
    flex: 1;
}

.agent-name {
    font-size: 1.125rem;
    font-weight: 600;
    margin-bottom: 0.25rem;
    letter-spacing: -0.01em;
}

.agent-meta {
    display: flex;
    align-items: center;
    gap: 0.75rem;
}

.framework-tag {
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
    padding: 0.1875rem 0.5rem;
    background: var(--bg-elevated);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    font-size: 0.6875rem;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-weight: 500;
}

.issue-count {
    font-size: 0.8125rem;
    color: var(--text-muted);
}

.agent-grade {
    width: 52px;
    height: 52px;
    border-radius: var(--radius-md);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.75rem;
    font-weight: 800;
    flex-shrink: 0;
    letter-spacing: -0.025em;
}

.agent-grade.grade-f { background: var(--critical-bg); color: var(--critical); }
.agent-grade.grade-d { background: var(--high-bg); color: var(--high); }
.agent-grade.grade-c { background: var(--medium-bg); color: var(--medium); }
.agent-grade.grade-b { background: var(--primary-bg); color: var(--primary); }
.agent-grade.grade-a { background: var(--low-bg); color: var(--low); }

.severity-pills {
    display: flex;
    gap: 0.5rem;
    margin-bottom: 1rem;
}

.mini-pill {
    padding: 0.25rem 0.5rem;
    border-radius: 9999px;
    font-size: 0.6875rem;
    font-weight: 600;
}

.mini-pill.critical { background: var(--critical-bg); color: var(--critical); }
.mini-pill.high { background: var(--high-bg); color: var(--high); }
.mini-pill.medium { background: var(--medium-bg); color: var(--medium); }
.mini-pill.low { background: var(--low-bg); color: var(--low); }

.top-issues {
    padding-top: 1rem;
    border-top: 1px solid var(--border);
}

.top-issue {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.375rem 0;
    font-size: 0.8125rem;
    color: var(--text-secondary);
}

.top-issue::before {
    content: '';
    width: 4px;
    height: 4px;
    border-radius: 50%;
    background: var(--text-muted);
    flex-shrink: 0;
}

/* Accordion */
.accordion {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    margin-bottom: 0.75rem;
    overflow: hidden;
}

.accordion-header {
    display: flex;
    align-items: center;
    padding: 1rem 1.25rem;
    cursor: pointer;
    transition: background var(--transition-fast);
    gap: 1rem;
}

.accordion-header:hover {
    background: var(--bg-elevated);
}

.accordion-icon {
    color: var(--text-muted);
    font-size: 0.75rem;
    transition: transform var(--transition-fast);
    flex-shrink: 0;
}

.accordion.open .accordion-icon {
    transform: rotate(90deg);
}

.accordion-title {
    flex: 1;
    font-weight: 500;
    font-size: 0.9375rem;
}

.accordion-count {
    color: var(--text-muted);
    font-size: 0.8125rem;
}

.accordion-badges {
    display: flex;
    gap: 0.375rem;
}

.accordion-body {
    display: none;
    padding: 0 1.25rem 1.25rem;
    background: var(--bg-secondary);
    border-top: 1px solid var(--border);
}

.accordion.open .accordion-body {
    display: block;
}

/* Findings */
.finding {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    margin-top: 0.75rem;
    overflow: hidden;
}

.finding-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.875rem 1rem;
    cursor: pointer;
    transition: background var(--transition-fast);
    gap: 1rem;
}

.finding-header:hover {
    background: var(--bg-elevated);
}

.finding-title {
    flex: 1;
    font-weight: 500;
    font-size: 0.875rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.finding-title .icon {
    color: var(--text-muted);
    font-size: 0.625rem;
    transition: transform var(--transition-fast);
}

.finding.open .finding-title .icon {
    transform: rotate(90deg);
}

.finding-meta {
    display: flex;
    align-items: center;
    gap: 0.625rem;
    color: var(--text-muted);
    font-size: 0.8125rem;
}

.finding-body {
    display: none;
    padding: 1rem;
    border-top: 1px solid var(--border);
    background: var(--bg-secondary);
}

.finding.open .finding-body {
    display: block;
}

.finding-details {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 1rem;
    margin-bottom: 1rem;
}

.finding-details p {
    margin: 0;
}

.finding-details strong {
    color: var(--text-muted);
    font-weight: 500;
    display: block;
    font-size: 0.6875rem;
    text-transform: uppercase;
    letter-spacing: 0.075em;
    margin-bottom: 0.25rem;
}

.finding-message {
    margin-bottom: 1rem;
    color: var(--text-secondary);
    font-size: 0.875rem;
    line-height: 1.5;
}

.code-snippet {
    background: #000;
    padding: 1rem;
    border-radius: var(--radius-md);
    font-family: 'SF Mono', 'Fira Code', 'Monaco', monospace;
    font-size: 0.8125rem;
    overflow-x: auto;
    white-space: pre;
    color: #e4e4e7;
    border: 1px solid var(--border);
    line-height: 1.5;
}

.severity-badge {
    padding: 0.25rem 0.625rem;
    border-radius: 9999px;
    font-size: 0.6875rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.025em;
}

.severity-critical { background: var(--critical); color: white; }
.severity-high { background: var(--high); color: white; }
.severity-medium { background: var(--medium); color: #171717; }
.severity-low { background: var(--low); color: white; }

/* Finding Type Badges */
.finding-type-badge {
    padding: 0.125rem 0.5rem;
    border-radius: 4px;
    font-size: 0.625rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-right: 0.5rem;
}
.finding-type-badge.code {
    background: var(--primary-bg);
    color: var(--primary-light);
    border: 1px solid rgba(139, 92, 246, 0.3);
}
.finding-type-badge.config {
    background: var(--medium-bg);
    color: var(--medium);
    border: 1px solid rgba(234, 179, 8, 0.3);
}
.finding-type-badge.secret {
    background: var(--critical-bg);
    color: var(--critical);
    border: 1px solid rgba(239, 68, 68, 0.3);
}

/* Empty Code Snippet State */
.code-snippet.empty {
    background: var(--bg-elevated);
    border: 1px dashed var(--border);
    padding: 1.25rem;
    text-align: center;
    color: var(--text-muted);
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    font-family: var(--font-sans);
    font-size: 0.875rem;
}
.code-snippet.empty .empty-icon {
    font-size: 1rem;
}

/* Filter Pills */
.filter-bar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.5rem;
}

.filter-pills {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
}

.pill {
    padding: 0.375rem 0.875rem;
    border-radius: 9999px;
    border: 1px solid var(--border);
    background: transparent;
    color: var(--text-secondary);
    font-size: 0.8125rem;
    cursor: pointer;
    transition: all var(--transition-fast);
    font-weight: 500;
}

.pill:hover {
    border-color: var(--text-muted);
    background: var(--bg-elevated);
}

.pill.active {
    background: var(--text-primary);
    color: var(--bg-primary);
    border-color: var(--text-primary);
}

.pill.critical.active { background: var(--critical); border-color: var(--critical); color: white; }
.pill.high.active { background: var(--high); border-color: var(--high); color: white; }
.pill.medium.active { background: var(--medium); border-color: var(--medium); color: #171717; }
.pill.low.active { background: var(--low); border-color: var(--low); color: white; }

/* Empty State */
.empty-state {
    text-align: center;
    padding: 4rem 2rem;
    color: var(--text-secondary);
}

.empty-state .icon {
    font-size: 3.5rem;
    margin-bottom: 1rem;
}

.empty-state p {
    font-size: 1rem;
}

/* Footer */
footer {
    margin-top: 3rem;
    padding-top: 1.5rem;
    border-top: 1px solid var(--border);
    text-align: center;
    color: var(--text-muted);
    font-size: 0.8125rem;
}

footer a {
    color: var(--primary);
    text-decoration: none;
    font-weight: 500;
}

footer a:hover {
    text-decoration: underline;
}

/* Print styles */
@media print {
    :root {
        --bg-primary: #ffffff;
        --bg-secondary: #f9fafb;
        --bg-card: #ffffff;
        --bg-elevated: #f3f4f6;
        --text-primary: #111827;
        --text-secondary: #4b5563;
        --text-muted: #6b7280;
        --border: #e5e7eb;
    }

    body {
        background: white;
        padding: 0;
        max-width: none;
    }

    .global-status { page-break-inside: avoid; }
    .agent-card { page-break-inside: avoid; }
    .accordion-body { display: block !important; }
    .finding-body { display: block !important; }

    .code-snippet {
        background: #f3f4f6;
        color: #111827;
        white-space: pre-wrap;
    }

    @page { margin: 1.5cm; }
}
`

const htmlReportJS = `
// State for agent filtering
let activeAgent = null;

// Finding toggle
document.querySelectorAll('.finding-header').forEach(header => {
    header.addEventListener('click', (e) => {
        e.stopPropagation();
        header.parentElement.classList.toggle('open');
    });
});

// Accordion toggle
document.querySelectorAll('.accordion-header').forEach(header => {
    header.addEventListener('click', () => {
        header.parentElement.classList.toggle('open');
    });
});

// Agent card click - filter findings by agent
document.querySelectorAll('.agent-card').forEach(card => {
    card.addEventListener('click', () => {
        const agent = card.dataset.agent;

        // Toggle selection
        if (activeAgent === agent) {
            // Deselect - show all
            activeAgent = null;
            card.classList.remove('selected');
        } else {
            // Select this agent
            document.querySelectorAll('.agent-card').forEach(c => c.classList.remove('selected'));
            activeAgent = agent;
            card.classList.add('selected');
        }

        filterByAgent();
    });
});

// Global status click - reset filter (show all)
const globalStatus = document.querySelector('.global-status');
if (globalStatus) {
    globalStatus.addEventListener('click', () => {
        activeAgent = null;
        document.querySelectorAll('.agent-card').forEach(c => c.classList.remove('selected'));
        filterByAgent();
    });
}

// Filter findings by active agent
function filterByAgent() {
    document.querySelectorAll('.accordion').forEach(accordion => {
        const agent = accordion.dataset.agent;
        if (activeAgent === null || agent === activeAgent) {
            accordion.style.display = '';
            // Auto-open the selected agent's accordion
            if (activeAgent !== null) {
                accordion.classList.add('open');
                setTimeout(() => {
                    accordion.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }, 100);
            }
        } else {
            accordion.style.display = 'none';
            accordion.classList.remove('open');
        }
    });
}

// Severity filter pills - respects active agent selection
document.querySelectorAll('.pill').forEach(pill => {
    pill.addEventListener('click', () => {
        document.querySelectorAll('.pill').forEach(p => p.classList.remove('active'));
        pill.classList.add('active');

        const severity = pill.dataset.severity;

        // Filter accordions and findings together, respecting agent filter
        document.querySelectorAll('.accordion').forEach(accordion => {
            const agentMatch = activeAgent === null || accordion.dataset.agent === activeAgent;

            if (!agentMatch) {
                // Hide accordion and all its findings if agent doesn't match
                accordion.style.display = 'none';
                accordion.querySelectorAll('.finding').forEach(f => f.style.display = 'none');
                return;
            }

            // Agent matches - now filter findings by severity
            let visibleCount = 0;
            accordion.querySelectorAll('.finding').forEach(finding => {
                const severityMatch = severity === 'all' || finding.dataset.severity === severity;
                if (severityMatch) {
                    finding.style.display = '';
                    visibleCount++;
                } else {
                    finding.style.display = 'none';
                }
            });

            // Show accordion if it has visible findings
            accordion.style.display = visibleCount > 0 ? '' : 'none';
        });
    });
});
`

// outputHTML provides enterprise HTML dashboard report
func outputHTML(result *cli.ScanResult, minSeverity string) error {
	// Deep scan-specific HTML report
	if result.DeepReport != nil {
		return outputDeepHTML(result, minSeverity)
	}

	// Filter findings by minimum severity level
	filtered := contract.GetBySeverity(result.AllFindings, strings.ToUpper(minSeverity))

	// Calculate metrics from filtered findings
	criticalCount := len(filterFindingsBySeverity(filtered, "CRITICAL"))
	highCount := len(filterFindingsBySeverity(filtered, "HIGH"))
	mediumCount := len(filterFindingsBySeverity(filtered, "MEDIUM"))
	lowCount := len(filterFindingsBySeverity(filtered, "LOW"))
	totalCount := len(filtered)

	// Group findings by agent and build reports
	agentGroups := groupFindingsByAgent(filtered)
	agentReports := buildAgentReports(agentGroups)

	// Get global status
	statusText, statusClass, _ := getGlobalStatus(criticalCount, highCount)

	// Generate HTML components
	agentCardsHTML := generateAgentCardsHTML(agentReports)
	accordionsHTML := generateAccordionsHTML(agentReports)

	// Build the full HTML
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Inkog Security Report</title>
    <style>%s</style>
</head>
<body>
    <header>
        <div class="logo">
            <svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
                <!-- Inkog Shield Logo - Violet gradient with scanner motif -->
                <defs>
                    <linearGradient id="inkogGradient" x1="0%%" y1="0%%" x2="100%%" y2="100%%">
                        <stop offset="0%%" style="stop-color:#a78bfa"/>
                        <stop offset="100%%" style="stop-color:#7c3aed"/>
                    </linearGradient>
                </defs>
                <!-- Shield base -->
                <path d="M16 2L4 7v9c0 7.18 5.12 13.88 12 16 6.88-2.12 12-8.82 12-16V7L16 2z" fill="url(#inkogGradient)"/>
                <!-- Scanner lines -->
                <path d="M10 12h12M10 16h12M10 20h8" stroke="white" stroke-width="1.5" stroke-linecap="round" opacity="0.9"/>
                <!-- Checkmark overlay -->
                <path d="M12 16l3 3 5-6" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
            <span>Inkog Security Report</span>
        </div>
        <span class="timestamp">%s</span>
    </header>

    <!-- Global Status Bar -->
    <div class="global-status %s">
        <div class="status-indicator">
            <span class="pulse"></span>
            <span class="status-text">%s</span>
        </div>
        <div class="status-meta">
            <span>%d Agents Scanned</span>
            <span class="divider">•</span>
            <span>%d Total Issues</span>
        </div>
    </div>

    <!-- Agent Overview Cards -->
    <section>
        <h2>Agent Overview</h2>
        <div class="agent-grid">
            %s
        </div>
    </section>

    <!-- Detailed Findings -->
    <section>
        <h2>Detailed Findings</h2>
        <div class="filter-bar">
            <div class="filter-pills">
                <button class="pill active" data-severity="all">All (%d)</button>
                <button class="pill critical" data-severity="CRITICAL">Critical (%d)</button>
                <button class="pill high" data-severity="HIGH">High (%d)</button>
                <button class="pill medium" data-severity="MEDIUM">Medium (%d)</button>
                <button class="pill low" data-severity="LOW">Low (%d)</button>
            </div>
        </div>
        %s
    </section>

    <footer>
        <p>Powered by <a href="https://inkog.io" target="_blank">Inkog</a> • AI Agent Security Platform v%s</p>
    </footer>

    <script>%s</script>
</body>
</html>`,
		htmlReportCSS,
		currentTimestamp(),
		statusClass, statusText,
		len(agentReports), totalCount,
		agentCardsHTML,
		totalCount, criticalCount, highCount, mediumCount, lowCount,
		accordionsHTML,
		AppVersion,
		htmlReportJS,
	)

	fmt.Println(html)
	return nil
}

// generateAgentCardsHTML creates the agent cards grid
func generateAgentCardsHTML(reports []AgentReport) string {
	if len(reports) == 0 {
		return `<div class="empty-state"><div class="icon">✅</div><p>No agents scanned</p></div>`
	}

	var sb strings.Builder
	for _, r := range reports {
		// Build severity pills
		var pillsHTML string
		if r.CriticalCount > 0 {
			pillsHTML += fmt.Sprintf(`<span class="mini-pill critical">%d Critical</span>`, r.CriticalCount)
		}
		if r.HighCount > 0 {
			pillsHTML += fmt.Sprintf(`<span class="mini-pill high">%d High</span>`, r.HighCount)
		}
		if r.MediumCount > 0 {
			pillsHTML += fmt.Sprintf(`<span class="mini-pill medium">%d Medium</span>`, r.MediumCount)
		}
		if r.LowCount > 0 {
			pillsHTML += fmt.Sprintf(`<span class="mini-pill low">%d Low</span>`, r.LowCount)
		}

		// Build top issues
		var issuesHTML string
		for _, issue := range r.TopIssues {
			issuesHTML += fmt.Sprintf(`<div class="top-issue">%s</div>`, escapeHTML(issue))
		}

		// Issue count text
		issueText := "issues"
		if r.TotalCount == 1 {
			issueText = "issue"
		}

		sb.WriteString(fmt.Sprintf(`
        <div class="agent-card %s" data-agent="%s">
            <div class="agent-card-header">
                <div class="agent-info">
                    <div class="agent-name">%s</div>
                    <div class="agent-meta">
                        <span class="framework-tag">%s</span>
                        <span class="issue-count">%d %s</span>
                    </div>
                </div>
                <div class="agent-grade %s">%s</div>
            </div>
            <div class="severity-pills">%s</div>
            <div class="top-issues">%s</div>
        </div>`,
			r.GradeClass,
			escapeHTML(r.Directory),
			escapeHTML(r.Name),
			escapeHTML(r.Framework),
			r.TotalCount, issueText,
			r.GradeClass, r.Grade,
			pillsHTML,
			issuesHTML,
		))
	}
	return sb.String()
}

// generateAccordionsHTML creates the accordion sections for each agent
func generateAccordionsHTML(reports []AgentReport) string {
	if len(reports) == 0 {
		return `<div class="empty-state"><div class="icon">✅</div><p>No security issues found</p></div>`
	}

	var sb strings.Builder
	for i, r := range reports {
		// Build severity badges for accordion header
		var badgesHTML string
		if r.CriticalCount > 0 {
			badgesHTML += fmt.Sprintf(`<span class="mini-pill critical">%d</span>`, r.CriticalCount)
		}
		if r.HighCount > 0 {
			badgesHTML += fmt.Sprintf(`<span class="mini-pill high">%d</span>`, r.HighCount)
		}
		if r.MediumCount > 0 {
			badgesHTML += fmt.Sprintf(`<span class="mini-pill medium">%d</span>`, r.MediumCount)
		}

		// Issue count text
		issueText := "issues"
		if r.TotalCount == 1 {
			issueText = "issue"
		}

		// Open first accordion by default
		openClass := ""
		if i == 0 {
			openClass = " open"
		}

		// Generate findings for this agent
		findingsHTML := generateAgentFindingsHTML(r.Findings)

		sb.WriteString(fmt.Sprintf(`
        <div class="accordion%s" data-agent="%s">
            <div class="accordion-header">
                <span class="accordion-icon">▶</span>
                <span class="accordion-title">%s</span>
                <span class="accordion-count">%d %s</span>
                <div class="accordion-badges">%s</div>
            </div>
            <div class="accordion-body">
                %s
            </div>
        </div>`,
			openClass,
			escapeHTML(r.Directory),
			escapeHTML(r.Name),
			r.TotalCount, issueText,
			badgesHTML,
			findingsHTML,
		))
	}
	return sb.String()
}

// generateAgentFindingsHTML creates the findings HTML for a specific agent
func generateAgentFindingsHTML(findings []contract.Finding) string {
	if len(findings) == 0 {
		return `<div class="empty-state"><p>No findings for this agent</p></div>`
	}

	// Sort by severity (CRITICAL first)
	sortFindingsByLocation(findings)

	var sb strings.Builder
	for _, f := range findings {
		pattern := escapeHTML(f.Pattern)
		file := escapeHTML(f.File)
		message := escapeHTML(f.Message)

		// Get finding type for badge display
		findingType := getFindingType(f)

		// Get code snippet or context-aware empty message
		code, emptyMessage, icon := getCodeSnippetDisplay(f)
		code = escapeHTML(code)

		// Generate code snippet HTML based on whether code exists
		var codeSnippetHTML string
		if code != "" {
			codeSnippetHTML = fmt.Sprintf(`<div class="code-snippet">%s</div>`, code)
		} else {
			// Only show icon span if icon is not empty (minimal emoji style)
			if icon != "" {
				codeSnippetHTML = fmt.Sprintf(`<div class="code-snippet empty"><span class="empty-icon">%s</span><span>%s</span></div>`,
					icon, escapeHTML(emptyMessage))
			} else {
				codeSnippetHTML = fmt.Sprintf(`<div class="code-snippet empty"><span>%s</span></div>`,
					escapeHTML(emptyMessage))
			}
		}

		// Shorten file path for display
		shortFile := file
		if len(file) > 50 {
			shortFile = "..." + file[len(file)-47:]
		}

		sb.WriteString(fmt.Sprintf(`
            <div class="finding" data-severity="%s">
                <div class="finding-header">
                    <div class="finding-title">
                        <span class="icon">▶</span>
                        <span>%s</span>
                    </div>
                    <div class="finding-meta">
                        <span>%s:%d</span>
                        <span class="finding-type-badge %s">%s</span>
                        <span class="severity-badge severity-%s">%s</span>
                    </div>
                </div>
                <div class="finding-body">
                    <div class="finding-details">
                        <p><strong>File</strong>%s:%d:%d</p>
                        <p><strong>CWE</strong>%s</p>
                        <p><strong>OWASP</strong>%s</p>
                        <p><strong>Confidence</strong>%.0f%%</p>
                    </div>
                    <p class="finding-message">%s</p>
                    %s
                </div>
            </div>`,
			f.Severity,
			pattern,
			shortFile, f.Line,
			findingType, strings.Title(findingType),
			strings.ToLower(f.Severity), f.Severity,
			file, f.Line, f.Column,
			f.CWE,
			f.OWASP,
			f.Confidence*100,
			message,
			codeSnippetHTML,
		))
	}
	return sb.String()
}

// generateAgentTabsHTML creates the agent tabs navigation
func generateAgentTabsHTML(groups map[string][]contract.Finding, names []string, total int) string {
	if len(names) <= 1 {
		return "" // No tabs needed for single agent
	}

	var sb strings.Builder
	sb.WriteString(`<div class="agent-tabs">`)
	sb.WriteString(fmt.Sprintf(`<button class="agent-tab active" data-agent="all">All Agents (%d)</button>`, total))
	for _, name := range names {
		count := len(groups[name])
		sb.WriteString(fmt.Sprintf(`<button class="agent-tab" data-agent="%s">%s (%d)</button>`,
			escapeHTML(name), escapeHTML(name), count))
	}
	sb.WriteString(`</div>`)
	return sb.String()
}

// Gate item helper functions
func gateItemClass(count int) string {
	if count > 0 {
		return "fail"
	}
	return "pass"
}

func gateItemStatus(count int) string {
	if count > 0 {
		return "❌ Found"
	}
	return "✓ Clear"
}

func gateItemClassWarn(count int) string {
	if count > 0 {
		return "warn"
	}
	return "pass"
}

func gateItemStatusWarn(count int) string {
	if count > 0 {
		return "⚠️ Found"
	}
	return "✓ Clear"
}

func gateItemClassPass(count int) string {
	return "pass"
}

func gateItemStatusPass(count int) string {
	if count > 0 {
		return fmt.Sprintf("%d found", count)
	}
	return "✓ Clear"
}

// generateFindingsHTML creates the HTML for all findings with data attributes for filtering
func generateFindingsHTML(findings []contract.Finding) string {
	if len(findings) == 0 {
		return `<div class="empty-state">
            <div class="icon">✅</div>
            <p>No security issues found</p>
        </div>`
	}

	var sb strings.Builder
	for _, f := range findings {
		// Escape HTML in user content
		pattern := escapeHTML(f.Pattern)
		file := escapeHTML(f.File)
		message := escapeHTML(f.Message)

		// Get finding type for badge display
		findingType := getFindingType(f)

		// Get code snippet or context-aware empty message
		code, emptyMessage, icon := getCodeSnippetDisplay(f)
		code = escapeHTML(code)

		// Generate code snippet HTML based on whether code exists
		var codeSnippetHTML string
		if code != "" {
			codeSnippetHTML = fmt.Sprintf(`<div class="code-snippet">%s</div>`, code)
		} else {
			// Only show icon span if icon is not empty (minimal emoji style)
			if icon != "" {
				codeSnippetHTML = fmt.Sprintf(`<div class="code-snippet empty"><span class="empty-icon">%s</span><span>%s</span></div>`,
					icon, escapeHTML(emptyMessage))
			} else {
				codeSnippetHTML = fmt.Sprintf(`<div class="code-snippet empty"><span>%s</span></div>`,
					escapeHTML(emptyMessage))
			}
		}

		// Extract agent name for filtering
		agent := extractAgentName(f.File)

		// Add data attributes for filtering
		sb.WriteString(fmt.Sprintf(`
        <div class="finding" data-agent="%s" data-severity="%s">
            <div class="finding-header">
                <div class="finding-title">
                    <span class="icon">▶</span>
                    <span>%s</span>
                </div>
                <div class="finding-meta">
                    <span>%s:%d</span>
                    <span class="finding-type-badge %s">%s</span>
                    <span class="severity-badge severity-%s">%s</span>
                </div>
            </div>
            <div class="finding-body">
                <div class="finding-details">
                    <p>
                        <strong>File</strong>
                        %s:%d:%d
                    </p>
                    <p>
                        <strong>CWE</strong>
                        %s
                    </p>
                    <p>
                        <strong>OWASP</strong>
                        %s
                    </p>
                    <p>
                        <strong>Confidence</strong>
                        %.0f%%
                    </p>
                </div>
                <p style="margin-bottom: 1rem; color: var(--text-secondary);">%s</p>
                %s
            </div>
        </div>`,
			escapeHTML(agent), f.Severity,
			pattern,
			file, f.Line,
			findingType, strings.Title(findingType),
			strings.ToLower(f.Severity), f.Severity,
			file, f.Line, f.Column,
			f.CWE,
			f.OWASP,
			f.Confidence*100,
			message,
			codeSnippetHTML,
		))
	}
	return sb.String()
}

// Helper functions for HTML report
func currentTimestamp() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

func statusClass(pass bool) string {
	if pass {
		return "pass"
	}
	return "fail"
}

func statusText(pass bool) string {
	if pass {
		return "PASS"
	}
	return "FAIL"
}

func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}

// ============================================================================
// Baseline and Diff Functions
// ============================================================================

// saveBaseline saves the current findings as a baseline file
func saveBaseline(path, sourcePath string, findings []contract.Finding) error {
	baseline := contract.Baseline{
		Path:          sourcePath,
		CreatedAt:     time.Now().Format(time.RFC3339),
		FindingsCount: len(findings),
		RiskScore:     contract.CalculateRiskScore(findings),
		Findings:      findings,
	}

	data, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal baseline: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write baseline: %w", err)
	}

	return nil
}

// loadBaseline loads a baseline file for comparison
func loadBaseline(path string) (*contract.Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var baseline contract.Baseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		return nil, fmt.Errorf("failed to parse baseline: %w", err)
	}

	return &baseline, nil
}

// outputDiffResults formats and displays diff results
func outputDiffResults(diff *contract.DiffResult, format, minSeverity, policy string, verbose, quiet bool) error {
	switch format {
	case "json":
		return outputDiffJSON(diff)
	case "text":
		return outputDiffText(diff, minSeverity, policy, verbose)
	case "sarif":
		// SARIF shows only new findings
		return outputDiffSARIF(diff)
	default:
		return fmt.Errorf("diff output not supported for format: %s", format)
	}
}

// outputDiffJSON outputs diff results as JSON
func outputDiffJSON(diff *contract.DiffResult) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(diff)
}

// outputDiffText outputs diff results as formatted text
func outputDiffText(diff *contract.DiffResult, minSeverity, policy string, verbose bool) error {
	// Header
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════╗")
	fmt.Println("║           🔄 Security Diff Report                     ║")
	fmt.Println("╚══════════════════════════════════════════════════════╝")
	fmt.Println()

	// Summary
	if diff.IsRegression() {
		fmt.Printf("%s🔴 REGRESSION: %d new critical/high findings%s\n", colorCritical, diff.Summary.NewBySeverity["CRITICAL"]+diff.Summary.NewBySeverity["HIGH"], colorReset)
	} else if diff.IsImprovement() {
		fmt.Printf("%s🟢 IMPROVEMENT: %d critical/high findings fixed%s\n", colorCheck, diff.Summary.FixedBySeverity["CRITICAL"]+diff.Summary.FixedBySeverity["HIGH"], colorReset)
	} else if diff.Summary.TotalNew == 0 && diff.Summary.TotalFixed == 0 {
		fmt.Printf("%s✓ No changes%s\n", colorCheck, colorReset)
	}

	fmt.Println()
	fmt.Printf("  New:       %s+%d%s", colorCritical, diff.Summary.TotalNew, colorReset)
	if diff.Summary.NewBySeverity["CRITICAL"] > 0 {
		fmt.Printf(" (%d critical)", diff.Summary.NewBySeverity["CRITICAL"])
	}
	if diff.Summary.NewBySeverity["HIGH"] > 0 {
		fmt.Printf(" (%d high)", diff.Summary.NewBySeverity["HIGH"])
	}
	fmt.Println()

	fmt.Printf("  Fixed:     %s-%d%s", colorCheck, diff.Summary.TotalFixed, colorReset)
	if diff.Summary.FixedBySeverity["CRITICAL"] > 0 {
		fmt.Printf(" (%d critical)", diff.Summary.FixedBySeverity["CRITICAL"])
	}
	if diff.Summary.FixedBySeverity["HIGH"] > 0 {
		fmt.Printf(" (%d high)", diff.Summary.FixedBySeverity["HIGH"])
	}
	fmt.Println()

	fmt.Printf("  Unchanged: %d\n", diff.Summary.TotalUnchanged)
	fmt.Printf("  Risk:      %d → %d (%s%+d%s)\n", diff.Summary.BaseRiskScore, diff.Summary.HeadRiskScore,
		riskDeltaColor(diff.Summary.RiskDelta), diff.Summary.RiskDelta, colorReset)
	fmt.Println()

	// New findings
	if len(diff.NewFindings) > 0 {
		sortFindingsByLocation(diff.NewFindings)
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Printf("%s🔴 NEW FINDINGS (%d)%s\n", colorCritical, len(diff.NewFindings), colorReset)
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Println()

		for _, f := range diff.NewFindings {
			printFindingCompact(f, "+", colorCritical)
		}
	}

	// Fixed findings
	if len(diff.FixedFindings) > 0 && verbose {
		sortFindingsByLocation(diff.FixedFindings)
		fmt.Println()
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Printf("%s🟢 FIXED FINDINGS (%d)%s\n", colorCheck, len(diff.FixedFindings), colorReset)
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Println()

		for _, f := range diff.FixedFindings {
			printFindingCompact(f, "-", colorCheck)
		}
	}

	return nil
}

// printFindingCompact prints a compact finding summary for diff output
func printFindingCompact(f contract.Finding, prefix, color string) {
	severityColor := getSeverityColor(f.Severity)
	fmt.Printf("  %s%s%s [%s%s%s] %s:%d\n",
		color, prefix, colorReset,
		severityColor, f.Severity, colorReset,
		f.File, f.Line)
	fmt.Printf("    %s%s%s\n", colorGray, f.Message, colorReset)
}

// riskDeltaColor returns the color for risk delta
func riskDeltaColor(delta int) string {
	if delta > 0 {
		return colorCritical
	} else if delta < 0 {
		return colorCheck
	}
	return colorGray
}

// outputDiffSARIF outputs new findings in SARIF format
func outputDiffSARIF(diff *contract.DiffResult) error {
	// Create a minimal scan result with only new findings
	sarifResult := &cli.ScanResult{
		AllFindings: diff.NewFindings,
	}

	return outputSARIF(sarifResult)
}

// =============================================================================
// FIRST-RUN EXPERIENCE: Interactive API Key Prompt
// =============================================================================

// isInteractiveTerminal checks if stdin is a terminal (not piped)
func isInteractiveTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// showWelcomeMessage displays a friendly welcome message for first-time users (non-interactive fallback)
func showWelcomeMessage() {
	fmt.Println()
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("  Welcome to Inkog - The Pre-Flight Check for AI Agents")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
	fmt.Println("  Get your free API key (takes 30 seconds):")
	fmt.Println()
	fmt.Println("  1. Sign up at https://app.inkog.io")
	fmt.Println("  2. Go to Settings > API Keys")
	fmt.Println("  3. Create a new key")
	fmt.Println()
	fmt.Println("  Then run:")
	fmt.Println()
	fmt.Println("    export INKOG_API_KEY=sk_live_your_key_here")
	fmt.Println("    inkog scan .")
	fmt.Println()
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
}

// runFirstRunExperience handles the interactive no-key experience:
// 1. Runs an anonymous preview scan on the best agent file
// 2. Shows results with clear limitations
// 3. Offers to open browser for signup or accept key input
// Returns the API key if the user provides one, or "" to exit.
func runFirstRunExperience(serverURL, sourcePath string) string {
	fmt.Println()
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("  Inkog - The Pre-Flight Check for AI Agents")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
	fmt.Println("  No API key found. Running a free preview scan...")
	fmt.Println()

	// Try to find the best agent file and run anonymous scan
	previewShown := runAnonymousPreview(serverURL, sourcePath)

	if previewShown {
		fmt.Println()
		fmt.Println("  ┌──────────────────────────────────────────────────┐")
		fmt.Println("  │  Preview: 1 file scanned, up to 2 findings shown │")
		fmt.Println("  │                                                    │")
		fmt.Println("  │  With a free API key you get:                      │")
		fmt.Println("  │    - Full directory scans (all files)              │")
		fmt.Println("  │    - All findings with remediation guidance        │")
		fmt.Println("  │    - Compliance reports (EU AI Act, OWASP)         │")
		fmt.Println("  │    - Unlimited scans                               │")
		fmt.Println("  └──────────────────────────────────────────────────┘")
	} else {
		fmt.Println("  Could not run preview scan. A free API key unlocks")
		fmt.Println("  full directory scans, all findings, and compliance reports.")
	}

	fmt.Println()

	// Conversion menu
	return showConversionMenu()
}

// runAnonymousPreview picks the best file, hits the anonymous endpoint, and displays results.
// Returns true if a preview was successfully displayed.
func runAnonymousPreview(serverURL, sourcePath string) bool {
	filePath, content, err := cli.PickBestAgentFile(sourcePath)
	if err != nil || filePath == "" {
		return false
	}

	// Create a minimal client for the anonymous scan
	client := cli.NewInkogClient(serverURL, true, nil)

	relPath := filePath
	if rel, err := filepath.Rel(sourcePath, filePath); err == nil {
		relPath = rel
	}

	fmt.Printf("  Scanning: %s\n", relPath)
	fmt.Println()

	resp, err := client.SendAnonymousScan(filepath.Base(filePath), string(content))
	if err != nil {
		// Silently fail — the preview is best-effort
		return false
	}

	displayAnonymousPreview(resp)
	return true
}

// displayAnonymousPreview renders the anonymous scan results in the terminal
func displayAnonymousPreview(resp *cli.AnonymousPreviewResponse) {
	// Show severity counts
	critical := resp.Counts["critical"]
	high := resp.Counts["high"]
	medium := resp.Counts["medium"]
	low := resp.Counts["low"]

	if resp.TotalFindings == 0 {
		fmt.Printf("  %s✓ No issues found in %s%s\n", colorCheck, resp.FileName, colorReset)
		return
	}

	fmt.Printf("  Found %d issue(s) in %s:\n", resp.TotalFindings, resp.FileName)

	if critical > 0 {
		fmt.Printf("    %s● %d Critical%s", colorCritical, critical, colorReset)
	}
	if high > 0 {
		fmt.Printf("    %s● %d High%s", colorHigh, high, colorReset)
	}
	if medium > 0 {
		fmt.Printf("    %s● %d Medium%s", colorMedium, medium, colorReset)
	}
	if low > 0 {
		fmt.Printf("    %s● %d Low%s", colorLow, low, colorReset)
	}
	fmt.Println()

	// Show preview findings
	if len(resp.Preview) > 0 {
		fmt.Println()
		for _, f := range resp.Preview {
			sevColor := colorGray
			switch strings.ToUpper(f.Severity) {
			case "CRITICAL":
				sevColor = colorCritical
			case "HIGH":
				sevColor = colorHigh
			case "MEDIUM":
				sevColor = colorMedium
			case "LOW":
				sevColor = colorLow
			}
			fmt.Printf("    %s[%s]%s %s (line %d)\n", sevColor, strings.ToUpper(f.Severity), colorReset, f.Title, f.Line)
			if f.Message != "" {
				fmt.Printf("           %s\n", f.Message)
			}
		}
		if resp.TotalFindings > len(resp.Preview) {
			fmt.Printf("\n    ... and %d more finding(s)\n", resp.TotalFindings-len(resp.Preview))
		}
	}
}

// showConversionMenu displays options and returns an API key or empty string
func showConversionMenu() string {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("  What would you like to do?")
	fmt.Println()
	fmt.Println("    [1] Get free API key (opens browser, takes 30 seconds)")
	fmt.Println("    [2] Enter existing API key")
	fmt.Println("    [3] Exit")
	fmt.Println()
	fmt.Print("  Choice [1/2/3]: ")

	input, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	choice := strings.TrimSpace(input)

	switch choice {
	case "1":
		// Open browser to sign up
		fmt.Println()
		fmt.Println("  Opening browser...")
		if err := cli.OpenBrowser("https://app.inkog.io/sign-up?source=cli"); err != nil {
			fmt.Println("  Could not open browser. Visit: https://app.inkog.io/sign-up")
		}
		fmt.Println()
		fmt.Println("  After signing up, go to Settings > API Keys and create a key.")
		fmt.Println()
		fmt.Print("  Paste your API key here: ")
		return readAndValidateKey(reader)

	case "2":
		fmt.Println()
		fmt.Print("  Enter API key: ")
		return readAndValidateKey(reader)

	default:
		return ""
	}
}

// readAndValidateKey reads a key from the reader, validates it, and saves to config
func readAndValidateKey(reader *bufio.Reader) string {
	input, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}

	apiKey := strings.TrimSpace(input)
	if apiKey == "" {
		return ""
	}

	if !strings.HasPrefix(apiKey, "sk_") {
		fmt.Println()
		fmt.Println("  That doesn't look like an Inkog API key.")
		fmt.Println("  Keys start with 'sk_live_' or 'sk_test_'.")
		return ""
	}

	// Save to config for future sessions
	if err := cli.SaveAPIKey(apiKey); err != nil {
		// Non-fatal: config save failed, but key still works for this session
		fmt.Fprintf(os.Stderr, "  Note: Could not save key to config (%v)\n", err)
	} else {
		fmt.Println()
		fmt.Println("  ✓ API key saved to ~/.inkog/config.json")
		fmt.Println("    You won't need to enter it again.")
	}
	fmt.Println()

	return apiKey
}

// showSuccessMessage displays a celebratory message for clean scans
func showSuccessMessage(result *cli.ScanResult, policy string) {
	fmt.Println()
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("%s✅ All Clear! No security issues found%s\n", colorCheck, colorReset)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	// Show governance status if available
	if result.GovernanceScore > 0 {
		fmt.Printf("  Governance Score: %d/100\n", result.GovernanceScore)
	}
	if result.EUAIActReadiness != "" {
		fmt.Printf("  EU AI Act Status: %s\n", result.EUAIActReadiness)
	}

	// Show strengths if available
	if len(result.Strengths) > 0 {
		fmt.Println()
		fmt.Println("  Strengths:")
		for _, s := range result.Strengths {
			fmt.Printf("    %s✓%s %s — %s\n", colorCheck, colorReset, s.Title, s.Message)
		}
	}

	// Show policy used
	fmt.Printf("  Policy: %s\n", policy)
	fmt.Println()

	// Friendly sign-off
	fmt.Println("  Your AI agents are looking good! 🚀")
	fmt.Println()
}

// showFrameworkFeedback displays detected frameworks at the start of output
func showFrameworkFeedback(result *cli.ScanResult) {
	framework := detectFramework(result.AllFindings)
	if framework != "" {
		fmt.Printf("🔍 Detected: %s framework\n", framework)
	}
}

// ─── Deep HTML Report ───────────────────────────────────────────────────────

const htmlDeepReportCSS = `
/* Deep Report — Additional Classes */

.deep-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.375rem;
    background: linear-gradient(135deg, rgba(139, 92, 246, 0.2), rgba(59, 130, 246, 0.2));
    border: 1px solid rgba(139, 92, 246, 0.3);
    border-radius: 999px;
    padding: 0.25rem 0.75rem;
    font-size: 0.75rem;
    font-weight: 600;
    color: var(--primary-light);
    letter-spacing: 0.05em;
}

.deep-badge::before {
    content: '✦';
    font-size: 0.625rem;
}

/* Profile Hero Card */
.profile-hero {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    overflow: hidden;
    margin-bottom: 1.5rem;
    position: relative;
}

.profile-hero::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    background: linear-gradient(90deg, var(--primary), #3b82f6, var(--primary-light));
}

.profile-hero-header {
    padding: 1.5rem 1.5rem 1rem;
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 1rem;
}

.profile-hero-info {
    flex: 1;
}

.profile-hero-name {
    font-size: 1.5rem;
    font-weight: 700;
    color: var(--text-heading);
    letter-spacing: -0.025em;
    margin-bottom: 0.375rem;
}

.profile-hero-date {
    font-size: 0.8125rem;
    color: var(--text-muted);
}

.profile-hero-stats {
    display: flex;
    gap: 1.25rem;
    flex-shrink: 0;
}

.profile-hero-stat {
    text-align: center;
}

.profile-hero-stat .stat-value {
    font-size: 1.5rem;
    font-weight: 700;
    color: var(--text-heading);
    line-height: 1;
}

.profile-hero-stat .stat-label {
    font-size: 0.6875rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.06em;
    margin-top: 0.25rem;
}

.profile-hero-body {
    padding: 0 1.5rem 1.5rem;
}

.profile-tags {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
    margin-bottom: 1rem;
}

.profile-tag {
    background: var(--primary-bg);
    border: 1px solid rgba(139, 92, 246, 0.2);
    border-radius: var(--radius-sm);
    padding: 0.25rem 0.625rem;
    font-size: 0.8125rem;
    color: var(--primary-light);
    font-weight: 500;
}

.profile-tag.lang {
    background: rgba(59, 130, 246, 0.1);
    border-color: rgba(59, 130, 246, 0.2);
    color: #60a5fa;
}

.profile-section-label {
    font-size: 0.6875rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-muted);
    margin-bottom: 0.375rem;
    margin-top: 1rem;
}

.profile-section-label:first-child {
    margin-top: 0;
}

.profile-text {
    color: var(--text-secondary);
    font-size: 0.875rem;
    line-height: 1.7;
    margin-bottom: 0.5rem;
}

/* Profile Sub-cards Grid */
.profile-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 1rem;
    margin-top: 1rem;
}

.profile-subcard {
    background: var(--bg-elevated);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    padding: 1rem;
    position: relative;
    overflow: hidden;
}

.profile-subcard::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
}

.profile-subcard.risk::before    { background: var(--critical); }
.profile-subcard.sources::before { background: #3b82f6; }
.profile-subcard.sinks::before   { background: #3b82f6; }
.profile-subcard.integrations::before { background: var(--primary); }
.profile-subcard.boundaries::before   { background: #eab308; }

.profile-subcard h4 {
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-muted);
    margin-bottom: 0.5rem;
}

.profile-subcard ul {
    list-style: none;
    padding: 0;
}

.profile-subcard ul li {
    font-size: 0.875rem;
    color: var(--text-secondary);
    padding: 0.25rem 0;
    border-bottom: 1px solid var(--border-subtle);
}

.profile-subcard ul li:last-child {
    border-bottom: none;
}

/* Severity Metric Cards */
.severity-metrics {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
    gap: 0.75rem;
    margin-bottom: 1.5rem;
}

.severity-metric {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    padding: 1rem;
    text-align: center;
}

.severity-metric .metric-value {
    font-size: 2rem;
    font-weight: 700;
    line-height: 1;
    margin-bottom: 0.25rem;
}

.severity-metric .metric-label {
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-muted);
}

.severity-metric.clean .metric-value    { color: var(--low); }
.severity-metric.critical .metric-value { color: var(--critical); }
.severity-metric.high .metric-value     { color: var(--high); }
.severity-metric.medium .metric-value   { color: var(--medium); }
.severity-metric.low .metric-value      { color: #60a5fa; }
.severity-metric.na .metric-value       { color: var(--text-muted); }

/* Stacked Severity Bar */
.stacked-bar {
    display: flex;
    height: 8px;
    border-radius: 4px;
    overflow: hidden;
    background: var(--bg-elevated);
    margin-bottom: 1rem;
}

.stacked-bar .bar-segment {
    transition: width var(--transition-normal);
}

.stacked-bar .bar-critical { background: var(--critical); }
.stacked-bar .bar-high     { background: var(--high); }
.stacked-bar .bar-medium   { background: var(--medium); }
.stacked-bar .bar-low      { background: #60a5fa; }
.stacked-bar .bar-clean    { background: var(--low); }

/* Detection Rules Stats */
.detection-stats {
    display: flex;
    gap: 1.5rem;
    color: var(--text-secondary);
    font-size: 0.875rem;
    margin-bottom: 0.5rem;
}

.detection-stats strong {
    color: var(--text-primary);
}

/* Clean Detection Cards */
.clean-cards {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
    gap: 1rem;
}

.clean-card {
    background: rgba(34, 197, 94, 0.05);
    border: 1px solid rgba(34, 197, 94, 0.2);
    border-radius: var(--radius-md);
    padding: 1rem 1.25rem;
}

.clean-card .clean-title {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-weight: 600;
    color: var(--low);
    margin-bottom: 0.375rem;
    font-size: 0.9375rem;
}

.clean-card .clean-title::before {
    content: '✓';
    font-weight: 700;
}

.clean-card .clean-reason {
    color: var(--text-secondary);
    font-size: 0.875rem;
    line-height: 1.6;
}

/* Compliance Cards */
.compliance-cards {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 1rem;
}

.compliance-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    padding: 1rem 1.25rem;
}

.compliance-card h4 {
    font-size: 0.9375rem;
    font-weight: 600;
    color: var(--text-heading);
    margin-bottom: 0.5rem;
}

.compliance-card .finding-indices {
    font-size: 0.8125rem;
    color: var(--text-secondary);
}

.compliance-card .finding-indices span {
    display: inline-block;
    background: var(--primary-bg);
    border-radius: var(--radius-sm);
    padding: 0.125rem 0.5rem;
    margin: 0.125rem 0.25rem 0.125rem 0;
    font-weight: 500;
    color: var(--primary-light);
}

/* Methodology Card */
.methodology-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 1.5rem;
}

.methodology-card h4 {
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-muted);
    margin-bottom: 0.5rem;
}

.methodology-card p {
    color: var(--text-secondary);
    font-size: 0.875rem;
    line-height: 1.7;
    margin-bottom: 0.75rem;
}

.methodology-card p:last-child {
    margin-bottom: 0;
}

/* Deep Finding Enhanced Body */
.deep-finding-body {
    display: none;
    padding: 1.25rem;
    border-top: 1px solid var(--border);
    background: var(--bg-secondary);
}

.finding.open .deep-finding-body {
    display: block;
}

.deep-finding-meta-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 0.75rem;
    margin-bottom: 1.25rem;
    padding: 1rem;
    background: var(--bg-elevated);
    border-radius: var(--radius-md);
    border: 1px solid var(--border);
}

.deep-finding-meta-grid .meta-item {
    font-size: 0.8125rem;
}

.deep-finding-meta-grid .meta-label {
    color: var(--text-muted);
    font-weight: 500;
    display: block;
    font-size: 0.6875rem;
    text-transform: uppercase;
    letter-spacing: 0.075em;
    margin-bottom: 0.25rem;
}

.deep-finding-meta-grid .meta-value {
    color: var(--text-primary);
}

/* Category + Risk Tier Tags */
.deep-finding-tags {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
    margin-bottom: 1rem;
}

.deep-tag {
    display: inline-flex;
    align-items: center;
    padding: 0.1875rem 0.5rem;
    border-radius: var(--radius-sm);
    font-size: 0.6875rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.deep-tag.category {
    background: var(--primary-bg);
    color: var(--primary-light);
    border: 1px solid rgba(139, 92, 246, 0.3);
}

.deep-tag.tier-vulnerability {
    background: var(--critical-bg);
    color: var(--critical);
    border: 1px solid rgba(239, 68, 68, 0.3);
}

.deep-tag.tier-risk_pattern {
    background: var(--high-bg);
    color: var(--high);
    border: 1px solid rgba(249, 115, 22, 0.3);
}

.deep-tag.tier-hardening {
    background: var(--medium-bg);
    color: var(--medium);
    border: 1px solid rgba(234, 179, 8, 0.3);
}

.deep-tag.governance {
    background: rgba(168, 85, 247, 0.1);
    color: #c084fc;
    border: 1px solid rgba(168, 85, 247, 0.3);
}

/* Compliance Mapping in Finding */
.deep-compliance-tags {
    display: flex;
    gap: 0.375rem;
    flex-wrap: wrap;
    margin-bottom: 1.25rem;
}

.deep-compliance-tag {
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
    padding: 0.25rem 0.625rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 500;
}

.deep-compliance-tag.eu {
    background: rgba(59, 130, 246, 0.1);
    color: #60a5fa;
    border: 1px solid rgba(59, 130, 246, 0.2);
}

.deep-compliance-tag.nist {
    background: rgba(34, 197, 94, 0.1);
    color: #4ade80;
    border: 1px solid rgba(34, 197, 94, 0.2);
}

/* Description */
.deep-finding-description {
    color: var(--text-secondary);
    font-size: 0.875rem;
    line-height: 1.7;
    margin-bottom: 1.25rem;
}

/* Risk Assessment (per-finding) */
.deep-risk-assessment {
    background: rgba(168, 85, 247, 0.05);
    border: 1px solid rgba(168, 85, 247, 0.15);
    border-radius: var(--radius-md);
    padding: 1rem 1.25rem;
    margin-bottom: 1.25rem;
}

.deep-risk-assessment h5 {
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: #c084fc;
    margin-bottom: 0.75rem;
}

.deep-risk-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.5rem;
    font-size: 0.8125rem;
}

.deep-risk-row:last-child { margin-bottom: 0; }

.deep-risk-label {
    color: var(--text-muted);
    min-width: 5.5rem;
}

.deep-risk-badge {
    display: inline-flex;
    padding: 0.125rem 0.5rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 600;
}

.deep-risk-badge.high { background: rgba(239, 68, 68, 0.15); color: #f87171; }
.deep-risk-badge.medium { background: rgba(245, 158, 11, 0.15); color: #fbbf24; }
.deep-risk-badge.low { background: rgba(34, 197, 94, 0.15); color: #4ade80; }

.deep-risk-rationale {
    color: var(--text-secondary);
    font-size: 0.8125rem;
    line-height: 1.6;
    margin-top: 0.5rem;
}

/* Remediation Section */
.deep-remediation {
    background: rgba(34, 197, 94, 0.05);
    border: 1px solid rgba(34, 197, 94, 0.15);
    border-radius: var(--radius-md);
    padding: 1rem 1.25rem;
    margin-bottom: 1.25rem;
}

.deep-remediation h5 {
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--low);
    margin-bottom: 0.5rem;
}

.deep-remediation p, .deep-remediation li {
    color: var(--text-secondary);
    font-size: 0.8125rem;
    line-height: 1.7;
}

.deep-remediation ul {
    padding-left: 1.25rem;
    margin: 0;
}

.deep-remediation ul li {
    margin-bottom: 0.375rem;
}

/* Explanation Trace / Proof */
.deep-proof {
    margin-bottom: 1.25rem;
}

.deep-proof h5 {
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-muted);
    margin-bottom: 0.5rem;
}

.deep-proof-snippet {
    background: #000;
    padding: 0.75rem 1rem;
    border-radius: var(--radius-sm);
    font-family: 'SF Mono', 'Fira Code', 'Monaco', monospace;
    font-size: 0.8125rem;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-all;
    color: #e4e4e7;
    border: 1px solid var(--border);
    line-height: 1.5;
    margin-bottom: 0.5rem;
}

/* Code location reference */
.deep-code-ref {
    display: inline-flex;
    align-items: center;
    gap: 0.375rem;
    background: var(--bg-elevated);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 0.25rem 0.625rem;
    font-family: 'SF Mono', 'Fira Code', 'Monaco', monospace;
    font-size: 0.8125rem;
    color: var(--text-secondary);
    margin-bottom: 1.25rem;
}

/* Risk Assessment Section */
.risk-assessment-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 1rem;
    margin-bottom: 1.5rem;
}

.risk-tier-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    padding: 1.25rem;
    position: relative;
    overflow: hidden;
}

.risk-tier-card::before {
    content: '';
    position: absolute;
    left: 0; top: 0; bottom: 0;
    width: 4px;
}

.risk-tier-card.tier-vuln::before    { background: var(--critical); }
.risk-tier-card.tier-risk::before    { background: var(--high); }
.risk-tier-card.tier-harden::before  { background: var(--medium); }
.risk-tier-card.tier-gov::before     { background: #c084fc; }

.risk-tier-card .tier-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.5rem;
}

.risk-tier-card .tier-label {
    font-size: 0.875rem;
    font-weight: 600;
    color: var(--text-heading);
}

.risk-tier-card .tier-count {
    font-size: 1.5rem;
    font-weight: 700;
    line-height: 1;
}

.risk-tier-card.tier-vuln .tier-count   { color: var(--critical); }
.risk-tier-card.tier-risk .tier-count   { color: var(--high); }
.risk-tier-card.tier-harden .tier-count { color: var(--medium); }
.risk-tier-card.tier-gov .tier-count    { color: #c084fc; }

.risk-tier-card .tier-desc {
    font-size: 0.8125rem;
    color: var(--text-muted);
}

/* Governance Status Section */
.governance-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 1.5rem;
}

.governance-score {
    display: flex;
    align-items: center;
    gap: 1.25rem;
    margin-bottom: 1.25rem;
    padding-bottom: 1.25rem;
    border-bottom: 1px solid var(--border);
}

.governance-score-value {
    font-size: 2.5rem;
    font-weight: 800;
    line-height: 1;
}

.governance-score-value.score-good   { color: var(--low); }
.governance-score-value.score-mid    { color: var(--medium); }
.governance-score-value.score-bad    { color: var(--critical); }

.governance-score-label {
    font-size: 0.8125rem;
    color: var(--text-muted);
}

.governance-score-label strong {
    display: block;
    color: var(--text-heading);
    font-size: 1rem;
    margin-bottom: 0.125rem;
}

.governance-controls {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
    gap: 0.75rem;
}

.gov-control {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.75rem;
    border-radius: var(--radius-md);
    background: var(--bg-elevated);
    border: 1px solid var(--border);
}

.gov-control-icon {
    width: 28px;
    height: 28px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.8125rem;
    font-weight: 700;
    flex-shrink: 0;
}

.gov-control.present .gov-control-icon {
    background: rgba(34, 197, 94, 0.15);
    color: var(--low);
}

.gov-control.missing .gov-control-icon {
    background: rgba(239, 68, 68, 0.15);
    color: var(--critical);
}

.gov-control-info {
    flex: 1;
    display: flex;
    flex-direction: column;
}

.gov-control-name {
    font-size: 0.875rem;
    font-weight: 600;
    color: var(--text-heading);
}

.gov-control-status {
    font-size: 0.75rem;
    font-weight: 500;
}

.gov-control.present .gov-control-status { color: var(--low); }
.gov-control.missing .gov-control-status { color: var(--critical); }

.gov-control-ref {
    font-size: 0.6875rem;
    color: var(--text-muted);
}
`

// generateAgentProfileHTML builds the Agent Profile section.
func generateAgentProfileHTML(report *cli.DeepReport) string {
	// Need at least agent profile or report meta to render this section
	if report.AgentProfile == nil && report.ReportMeta == nil {
		return ""
	}

	var sb strings.Builder
	sb.WriteString(`<section><h2>Agent Profile</h2><div class="profile-hero">`)

	// ── Hero Header: agent name + stats ──
	sb.WriteString(`<div class="profile-hero-header">`)
	sb.WriteString(`<div class="profile-hero-info">`)

	// Agent name (from report meta, or profile framework as fallback)
	agentName := ""
	if report.ReportMeta != nil && report.ReportMeta.AgentName != "" {
		agentName = report.ReportMeta.AgentName
	} else if report.AgentProfile != nil && report.AgentProfile.Framework != "" {
		agentName = report.AgentProfile.Framework + " Agent"
	}
	if agentName != "" {
		sb.WriteString(fmt.Sprintf(`<div class="profile-hero-name">%s</div>`, escapeHTML(agentName)))
	}

	// Scan date
	if report.ReportMeta != nil && report.ReportMeta.Date != "" {
		sb.WriteString(fmt.Sprintf(`<div class="profile-hero-date">Scanned %s</div>`, escapeHTML(report.ReportMeta.Date)))
	}
	sb.WriteString(`</div>`) // close profile-hero-info

	// Stats badges (from report meta)
	if report.ReportMeta != nil {
		rm := report.ReportMeta
		sb.WriteString(`<div class="profile-hero-stats">`)
		if rm.FilesAudited > 0 {
			sb.WriteString(fmt.Sprintf(`<div class="profile-hero-stat"><div class="stat-value">%d</div><div class="stat-label">Files</div></div>`, rm.FilesAudited))
		}
		if rm.DetectionRulesApplied > 0 {
			sb.WriteString(fmt.Sprintf(`<div class="profile-hero-stat"><div class="stat-value">%d</div><div class="stat-label">Rules Applied</div></div>`, rm.DetectionRulesApplied))
		}
		if rm.TotalFindings > 0 {
			sb.WriteString(fmt.Sprintf(`<div class="profile-hero-stat"><div class="stat-value">%d</div><div class="stat-label">Findings</div></div>`, rm.TotalFindings))
		}
		if rm.TotalClean > 0 {
			sb.WriteString(fmt.Sprintf(`<div class="profile-hero-stat"><div class="stat-value">%d</div><div class="stat-label">Clean</div></div>`, rm.TotalClean))
		}
		sb.WriteString(`</div>`)
	}
	sb.WriteString(`</div>`) // close profile-hero-header

	// ── Hero Body: tags, purpose, architecture, sub-cards ──
	if report.AgentProfile != nil {
		ap := report.AgentProfile
		sb.WriteString(`<div class="profile-hero-body">`)

		// Framework + language tags
		if ap.Framework != "" || ap.Language != "" {
			sb.WriteString(`<div class="profile-tags">`)
			if ap.Framework != "" {
				sb.WriteString(fmt.Sprintf(`<span class="profile-tag">%s</span>`, escapeHTML(ap.Framework)))
			}
			if ap.Language != "" {
				sb.WriteString(fmt.Sprintf(`<span class="profile-tag lang">%s</span>`, escapeHTML(ap.Language)))
			}
			sb.WriteString(`</div>`)
		}

		// Purpose
		if ap.Purpose != "" {
			sb.WriteString(`<div class="profile-section-label">Purpose</div>`)
			sb.WriteString(fmt.Sprintf(`<p class="profile-text">%s</p>`, escapeHTML(ap.Purpose)))
		}

		// Architecture summary
		if ap.ArchitectureSummary != "" {
			sb.WriteString(`<div class="profile-section-label">Architecture</div>`)
			sb.WriteString(fmt.Sprintf(`<p class="profile-text">%s</p>`, escapeHTML(ap.ArchitectureSummary)))
		}

		// Sub-cards grid: high-risk ops, data sources/sinks, integrations, trust boundaries
		type subcard struct {
			class string
			title string
			items []string
		}
		cards := []subcard{
			{"risk", "High-Risk Operations", ap.HighRiskOperations},
			{"sources", "Data Sources", ap.DataSources},
			{"sinks", "Data Sinks", ap.DataSinks},
			{"integrations", "Integrations", ap.Integrations},
			{"boundaries", "Trust Boundaries", ap.TrustBoundaries},
		}

		hasAny := false
		for _, c := range cards {
			if len(c.items) > 0 {
				hasAny = true
				break
			}
		}
		if hasAny {
			sb.WriteString(`<div class="profile-grid">`)
			for _, c := range cards {
				if len(c.items) == 0 {
					continue
				}
				sb.WriteString(fmt.Sprintf(`<div class="profile-subcard %s"><h4>%s</h4><ul>`, c.class, c.title))
				for _, item := range c.items {
					sb.WriteString(fmt.Sprintf(`<li>%s</li>`, escapeHTML(item)))
				}
				sb.WriteString(`</ul></div>`)
			}
			sb.WriteString(`</div>`)
		}

		sb.WriteString(`</div>`) // close profile-hero-body
	}

	sb.WriteString(`</div></section>`) // close profile-hero + section
	return sb.String()
}

// generateSeverityOverviewHTML builds the Scan Overview section with metric cards and stacked bar.
// Falls back to counting from actual findings when orchestrator SeveritySummary is absent.
func generateSeverityOverviewHTML(report *cli.DeepReport, findings []contract.Finding) string {
	var sb strings.Builder
	sb.WriteString(`<section><h2>Scan Overview</h2>`)

	// Use orchestrator severity summary if available, otherwise compute from findings
	var clean, critical, high, medium, low, na int
	if report.SeveritySummary != nil {
		ss := report.SeveritySummary
		clean = ss.Clean
		critical = ss.Critical
		high = ss.High
		medium = ss.Medium
		low = ss.Low
		na = ss.NA
	} else {
		critical = len(filterFindingsBySeverity(findings, "CRITICAL"))
		high = len(filterFindingsBySeverity(findings, "HIGH"))
		medium = len(filterFindingsBySeverity(findings, "MEDIUM"))
		low = len(filterFindingsBySeverity(findings, "LOW"))
	}

	total := clean + critical + high + medium + low + na

	// Metric cards
	sb.WriteString(`<div class="severity-metrics">`)
	metrics := []struct {
		class string
		value int
		label string
	}{
		{"clean", clean, "Clean"},
		{"critical", critical, "Critical"},
		{"high", high, "High"},
		{"medium", medium, "Medium"},
		{"low", low, "Low"},
		{"na", na, "N/A"},
	}
	for _, m := range metrics {
		sb.WriteString(fmt.Sprintf(
			`<div class="severity-metric %s"><div class="metric-value">%d</div><div class="metric-label">%s</div></div>`,
			m.class, m.value, m.label))
	}
	sb.WriteString(`</div>`)

	// Stacked bar
	if total > 0 {
		pct := func(v int) float64 { return float64(v) / float64(total) * 100 }
		sb.WriteString(`<div class="stacked-bar">`)
		if critical > 0 {
			sb.WriteString(fmt.Sprintf(`<div class="bar-segment bar-critical" style="width:%.1f%%"></div>`, pct(critical)))
		}
		if high > 0 {
			sb.WriteString(fmt.Sprintf(`<div class="bar-segment bar-high" style="width:%.1f%%"></div>`, pct(high)))
		}
		if medium > 0 {
			sb.WriteString(fmt.Sprintf(`<div class="bar-segment bar-medium" style="width:%.1f%%"></div>`, pct(medium)))
		}
		if low > 0 {
			sb.WriteString(fmt.Sprintf(`<div class="bar-segment bar-low" style="width:%.1f%%"></div>`, pct(low)))
		}
		if clean > 0 {
			sb.WriteString(fmt.Sprintf(`<div class="bar-segment bar-clean" style="width:%.1f%%"></div>`, pct(clean)))
		}
		sb.WriteString(`</div>`)
	}

	// Detection rules stats (only if orchestrator returned them)
	if report.ReportMeta != nil && report.ReportMeta.DetectionRulesTotal > 0 {
		rm := report.ReportMeta
		sb.WriteString(`<div class="detection-stats">`)
		sb.WriteString(fmt.Sprintf(`<span>Rules applied: <strong>%d</strong></span>`, rm.DetectionRulesApplied))
		sb.WriteString(fmt.Sprintf(`<span>N/A: <strong>%d</strong></span>`, rm.DetectionRulesNA))
		sb.WriteString(fmt.Sprintf(`<span>Total: <strong>%d</strong></span>`, rm.DetectionRulesTotal))
		sb.WriteString(`</div>`)
	}

	sb.WriteString(`</section>`)
	return sb.String()
}

// generateCleanDetectionsHTML builds the Clean Detections section.
func generateCleanDetectionsHTML(report *cli.DeepReport) string {
	if len(report.CleanDetections) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(`<section><h2>Clean Detections</h2><div class="clean-cards">`)
	for _, cd := range report.CleanDetections {
		sb.WriteString(fmt.Sprintf(
			`<div class="clean-card"><div class="clean-title">%s</div><div class="clean-reason">%s</div></div>`,
			escapeHTML(humanizeDetectionID(cd.DetectionID)),
			escapeHTML(cd.Reason)))
	}
	sb.WriteString(`</div></section>`)
	return sb.String()
}

// generateComplianceSummaryHTML builds the Compliance Coverage section.
func generateComplianceSummaryHTML(report *cli.DeepReport) string {
	if len(report.ComplianceSummary) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(`<section><h2>Compliance Coverage</h2><div class="compliance-cards">`)
	for _, ce := range report.ComplianceSummary {
		sb.WriteString(fmt.Sprintf(`<div class="compliance-card"><h4>%s</h4>`, escapeHTML(ce.Framework)))
		if len(ce.RelevantFindings) > 0 {
			sb.WriteString(`<div class="finding-indices">Relevant findings: `)
			for _, idx := range ce.RelevantFindings {
				sb.WriteString(fmt.Sprintf(`<span>#%d</span>`, idx))
			}
			sb.WriteString(`</div>`)
		} else {
			sb.WriteString(`<div class="finding-indices">No findings mapped</div>`)
		}
		sb.WriteString(`</div>`)
	}
	sb.WriteString(`</div></section>`)
	return sb.String()
}

// generateMethodologyHTML builds the Methodology section.
func generateMethodologyHTML(report *cli.DeepReport) string {
	if report.Methodology == nil {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(`<section><h2>Methodology</h2><div class="methodology-card">`)
	if report.Methodology.Approach != "" {
		sb.WriteString(fmt.Sprintf(`<h4>Approach</h4><p>%s</p>`, escapeHTML(report.Methodology.Approach)))
	}
	if report.Methodology.ConfidenceCalibration != "" {
		sb.WriteString(fmt.Sprintf(`<h4>Confidence Calibration</h4><p>%s</p>`, escapeHTML(report.Methodology.ConfidenceCalibration)))
	}
	sb.WriteString(`</div></section>`)
	return sb.String()
}

// htmlDeepReportJS provides interactivity for the Deep HTML report.
const htmlDeepReportJS = `
// Finding toggle
document.querySelectorAll('.finding-header').forEach(header => {
    header.addEventListener('click', (e) => {
        e.stopPropagation();
        header.parentElement.classList.toggle('open');
    });
});

// Accordion toggle
document.querySelectorAll('.accordion-header').forEach(header => {
    header.addEventListener('click', () => {
        header.parentElement.classList.toggle('open');
    });
});

// Severity filter pills
document.querySelectorAll('.pill').forEach(pill => {
    pill.addEventListener('click', () => {
        document.querySelectorAll('.pill').forEach(p => p.classList.remove('active'));
        pill.classList.add('active');
        const severity = pill.dataset.severity;
        document.querySelectorAll('.finding').forEach(finding => {
            if (severity === 'all' || finding.dataset.severity === severity) {
                finding.style.display = '';
            } else {
                finding.style.display = 'none';
            }
        });
    });
});
`

// generateRiskAssessmentHTML builds the Risk Assessment section with tier breakdown.
func generateRiskAssessmentHTML(findings []contract.Finding) string {
	if len(findings) == 0 {
		return ""
	}

	tierCounts := contract.CountByTier(findings)
	typeCounts := contract.CountByFindingType(findings)
	govCount := typeCounts[contract.TypeGovernanceViolation]

	var sb strings.Builder
	sb.WriteString(`<section><h2>Risk Assessment</h2><div class="risk-assessment-grid">`)

	type tierCard struct {
		class string
		label string
		desc  string
		count int
	}
	cards := []tierCard{
		{"tier-vuln", "Exploitable Vulnerabilities", "Require immediate fix", tierCounts[contract.TierVulnerability]},
		{"tier-risk", "Risk Patterns", "Structural issues", tierCounts[contract.TierRiskPattern]},
		{"tier-harden", "Hardening Recommendations", "Best practices", tierCounts[contract.TierHardening]},
		{"tier-gov", "Governance Gaps", "Compliance issues", govCount},
	}

	for _, c := range cards {
		sb.WriteString(fmt.Sprintf(
			`<div class="risk-tier-card %s"><div class="tier-header"><span class="tier-label">%s</span><span class="tier-count">%d</span></div><span class="tier-desc">%s</span></div>`,
			c.class, c.label, c.count, c.desc))
	}

	sb.WriteString(`</div></section>`)
	return sb.String()
}

// generateGovernanceStatusHTML builds the Governance Status section.
// It infers governance control presence from findings: if a "missing_oversight",
// "missing_audit_logging", etc. finding exists, the control is missing.
func generateGovernanceStatusHTML(result *cli.ScanResult) string {
	// Only show if we have governance data (score or topology) or governance findings
	hasTopology := result.TopologyMap != nil
	hasScore := result.GovernanceScore > 0

	// Infer control status from findings when topology is not available
	hasOversight := true
	hasAuth := true
	hasRateLimit := true
	hasAudit := true

	if hasTopology {
		gov := result.TopologyMap.Governance
		hasOversight = gov.HasHumanOversight
		hasAuth = gov.HasAuthChecks
		hasRateLimit = gov.HasRateLimiting
		hasAudit = gov.HasAuditLogging
	} else {
		// Infer from finding pattern IDs
		for _, f := range result.AllFindings {
			switch f.PatternID {
			case "missing_oversight":
				hasOversight = false
			case "missing_authorization", "missing_auth_checks":
				hasAuth = false
			case "missing_rate_limiting":
				hasRateLimit = false
			case "missing_audit_logging":
				hasAudit = false
			}
		}
	}

	// Also check governance categories
	for _, f := range result.AllFindings {
		cat := strings.ToLower(f.GovernanceCategory)
		pid := strings.ToLower(f.PatternID)
		if cat == "governance" || cat == "oversight" {
			if strings.Contains(pid, "oversight") || strings.Contains(pid, "human") {
				hasOversight = false
			}
			if strings.Contains(pid, "auth") {
				hasAuth = false
			}
			if strings.Contains(pid, "audit") || strings.Contains(pid, "logging") {
				hasAudit = false
			}
			if strings.Contains(pid, "rate") || strings.Contains(pid, "limit") {
				hasRateLimit = false
			}
		}
	}

	// Skip section if all controls are present and no score
	if hasOversight && hasAuth && hasRateLimit && hasAudit && !hasScore {
		return ""
	}

	var sb strings.Builder
	sb.WriteString(`<section><h2>Governance Status</h2><div class="governance-card">`)

	// Governance score
	if hasScore {
		scoreClass := "score-bad"
		if result.GovernanceScore >= 80 {
			scoreClass = "score-good"
		} else if result.GovernanceScore >= 50 {
			scoreClass = "score-mid"
		}
		sb.WriteString(fmt.Sprintf(
			`<div class="governance-score"><span class="governance-score-value %s">%d</span><div class="governance-score-label"><strong>Governance Score</strong>out of 100</div></div>`,
			scoreClass, result.GovernanceScore))
	}

	// Control grid
	type control struct {
		name    string
		present bool
		ref     string
	}
	controls := []control{
		{"Human Oversight", hasOversight, "Article 14.1"},
		{"Authorization", hasAuth, ""},
		{"Rate Limiting", hasRateLimit, "OWASP LLM04"},
		{"Audit Logging", hasAudit, "Article 12.1"},
	}

	sb.WriteString(`<div class="governance-controls">`)
	for _, c := range controls {
		cls := "present"
		icon := "✓"
		status := "PRESENT"
		if !c.present {
			cls = "missing"
			icon = "✗"
			status = "MISSING"
		}
		refHTML := ""
		if c.ref != "" && !c.present {
			refHTML = fmt.Sprintf(`<span class="gov-control-ref">%s</span>`, escapeHTML(c.ref))
		}
		sb.WriteString(fmt.Sprintf(
			`<div class="gov-control %s"><span class="gov-control-icon">%s</span><div class="gov-control-info"><span class="gov-control-name">%s</span><span class="gov-control-status">%s</span>%s</div></div>`,
			cls, icon, c.name, status, refHTML))
	}
	sb.WriteString(`</div>`)

	sb.WriteString(`</div></section>`)
	return sb.String()
}

// generateDeepFindingHTML renders a single finding with all rich deep scan metadata.
func generateDeepFindingHTML(f contract.Finding) string {
	var sb strings.Builder

	pattern := escapeHTML(f.Pattern)
	if f.DisplayTitle != "" {
		pattern = escapeHTML(f.DisplayTitle)
	}
	file := escapeHTML(f.File)
	shortFile := file
	if len(file) > 50 {
		shortFile = "..." + file[len(file)-47:]
	}

	sb.WriteString(fmt.Sprintf(`
            <div class="finding" data-severity="%s">
                <div class="finding-header">
                    <div class="finding-title">
                        <span class="icon">▶</span>
                        <span>%s</span>
                    </div>
                    <div class="finding-meta">
                        <span>%s:%d</span>
                        <span class="severity-badge severity-%s">%s</span>
                    </div>
                </div>
                <div class="deep-finding-body">`,
		f.Severity,
		pattern,
		shortFile, f.Line,
		strings.ToLower(f.Severity), f.Severity,
	))

	// Tags: category, risk tier, governance
	hasTags := f.Category != "" || f.RiskTier != "" || f.GovernanceCategory != ""
	if hasTags {
		sb.WriteString(`<div class="deep-finding-tags">`)
		if f.Category != "" {
			sb.WriteString(fmt.Sprintf(`<span class="deep-tag category">%s</span>`, escapeHTML(f.Category)))
		}
		if f.RiskTier != "" {
			tierLabel := strings.ReplaceAll(f.RiskTier, "_", " ")
			sb.WriteString(fmt.Sprintf(`<span class="deep-tag tier-%s">%s</span>`, escapeHTML(f.RiskTier), escapeHTML(tierLabel)))
		}
		if f.GovernanceCategory != "" {
			sb.WriteString(fmt.Sprintf(`<span class="deep-tag governance">%s</span>`, escapeHTML(f.GovernanceCategory)))
		}
		sb.WriteString(`</div>`)
	}

	// Compliance mapping tags
	if f.ComplianceMapping != nil {
		hasCompliance := len(f.ComplianceMapping.EUAIActArticles) > 0 || len(f.ComplianceMapping.NISTCategories) > 0
		if hasCompliance {
			sb.WriteString(`<div class="deep-compliance-tags">`)
			for _, art := range f.ComplianceMapping.EUAIActArticles {
				sb.WriteString(fmt.Sprintf(`<span class="deep-compliance-tag eu">EU AI Act: %s</span>`, escapeHTML(art)))
			}
			for _, cat := range f.ComplianceMapping.NISTCategories {
				sb.WriteString(fmt.Sprintf(`<span class="deep-compliance-tag nist">NIST: %s</span>`, escapeHTML(cat)))
			}
			sb.WriteString(`</div>`)
		}
	}

	// Meta grid: file, confidence, CWE, OWASP
	sb.WriteString(`<div class="deep-finding-meta-grid">`)
	sb.WriteString(fmt.Sprintf(`<div class="meta-item"><span class="meta-label">File</span><span class="meta-value">%s:%d</span></div>`, file, f.Line))
	sb.WriteString(fmt.Sprintf(`<div class="meta-item"><span class="meta-label">Confidence</span><span class="meta-value">%.0f%%</span></div>`, f.Confidence*100))
	if f.CWE != "" {
		sb.WriteString(fmt.Sprintf(`<div class="meta-item"><span class="meta-label">CWE</span><span class="meta-value">%s</span></div>`, escapeHTML(f.CWE)))
	}
	if f.OWASP != "" {
		sb.WriteString(fmt.Sprintf(`<div class="meta-item"><span class="meta-label">OWASP</span><span class="meta-value">%s</span></div>`, escapeHTML(f.OWASP)))
	}
	sb.WriteString(`</div>`)

	// Code reference
	if f.Code != "" {
		sb.WriteString(fmt.Sprintf(`<div class="deep-code-ref">%s</div>`, escapeHTML(f.Code)))
	}

	// Description
	desc := f.Message
	if f.ShortDescription != "" {
		desc = f.ShortDescription
	}
	if desc != "" {
		sb.WriteString(fmt.Sprintf(`<p class="deep-finding-description">%s</p>`, escapeHTML(desc)))
	}

	// Explanation trace / proof
	if len(f.ExplanationTrace) > 0 {
		sb.WriteString(`<div class="deep-proof"><h5>Evidence</h5>`)
		for _, trace := range f.ExplanationTrace {
			sb.WriteString(fmt.Sprintf(`<div class="deep-proof-snippet">%s</div>`, escapeHTML(trace)))
		}
		sb.WriteString(`</div>`)
	}

	// Remediation
	if len(f.RemediationSteps) > 0 {
		sb.WriteString(`<div class="deep-remediation"><h5>Recommended Action</h5>`)
		if len(f.RemediationSteps) == 1 {
			sb.WriteString(fmt.Sprintf(`<p>%s</p>`, escapeHTML(f.RemediationSteps[0])))
		} else {
			sb.WriteString(`<ul>`)
			for _, step := range f.RemediationSteps {
				sb.WriteString(fmt.Sprintf(`<li>%s</li>`, escapeHTML(step)))
			}
			sb.WriteString(`</ul>`)
		}
		sb.WriteString(`</div>`)
	}

	// Risk Assessment (confidence + FP risk + rationale) — after remediation
	if f.FPRisk != "" || f.Confidence > 0 {
		sb.WriteString(`<div class="deep-risk-assessment"><h5>Risk Assessment</h5>`)
		if f.Confidence > 0 {
			confLabel := "HIGH"
			if f.Confidence < 0.5 {
				confLabel = "LOW"
			} else if f.Confidence < 0.8 {
				confLabel = "MEDIUM"
			}
			badgeClass := strings.ToLower(confLabel)
			sb.WriteString(fmt.Sprintf(`<div class="deep-risk-row"><span class="deep-risk-label">Confidence</span><span class="deep-risk-badge %s">%s</span></div>`, badgeClass, confLabel))
		}
		if f.FPRisk != "" {
			badgeClass := strings.ToLower(f.FPRisk)
			sb.WriteString(fmt.Sprintf(`<div class="deep-risk-row"><span class="deep-risk-label">FP Risk</span><span class="deep-risk-badge %s">%s</span></div>`, badgeClass, escapeHTML(strings.ToUpper(f.FPRisk))))
		}
		if f.FPRationale != "" {
			sb.WriteString(fmt.Sprintf(`<div class="deep-risk-rationale">%s</div>`, escapeHTML(f.FPRationale)))
		}
		sb.WriteString(`</div>`)
	}

	sb.WriteString(`</div></div>`)
	return sb.String()
}

// generateDeepAccordionsHTML creates accordion sections using the enriched deep finding renderer.
func generateDeepAccordionsHTML(findings []contract.Finding) string {
	if len(findings) == 0 {
		return `<div class="empty-state"><div class="icon">✅</div><p>No security issues found</p></div>`
	}

	// Sort findings
	sortFindingsByLocation(findings)

	// Single accordion for deep scans (no agent grouping needed)
	var badgesHTML string
	critCount := len(filterFindingsBySeverity(findings, "CRITICAL"))
	highCount := len(filterFindingsBySeverity(findings, "HIGH"))
	medCount := len(filterFindingsBySeverity(findings, "MEDIUM"))
	if critCount > 0 {
		badgesHTML += fmt.Sprintf(`<span class="mini-pill critical">%d</span>`, critCount)
	}
	if highCount > 0 {
		badgesHTML += fmt.Sprintf(`<span class="mini-pill high">%d</span>`, highCount)
	}
	if medCount > 0 {
		badgesHTML += fmt.Sprintf(`<span class="mini-pill medium">%d</span>`, medCount)
	}

	issueText := "issues"
	if len(findings) == 1 {
		issueText = "issue"
	}

	var findingsHTML strings.Builder
	for _, f := range findings {
		findingsHTML.WriteString(generateDeepFindingHTML(f))
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`
        <div class="accordion open">
            <div class="accordion-header">
                <span class="accordion-icon">▶</span>
                <span class="accordion-title">All Findings</span>
                <span class="accordion-count">%d %s</span>
                <div class="accordion-badges">%s</div>
            </div>
            <div class="accordion-body">
                %s
            </div>
        </div>`,
		len(findings), issueText,
		badgesHTML,
		findingsHTML.String(),
	))
	return sb.String()
}

// outputDeepHTML renders a premium HTML report for Inkog Deep scans.
func outputDeepHTML(result *cli.ScanResult, minSeverity string) error {
	report := result.DeepReport
	filtered := contract.GetBySeverity(result.AllFindings, strings.ToUpper(minSeverity))

	criticalCount := len(filterFindingsBySeverity(filtered, "CRITICAL"))
	highCount := len(filterFindingsBySeverity(filtered, "HIGH"))
	mediumCount := len(filterFindingsBySeverity(filtered, "MEDIUM"))
	lowCount := len(filterFindingsBySeverity(filtered, "LOW"))
	totalCount := len(filtered)

	statusText, statusClass, _ := getGlobalStatus(criticalCount, highCount)

	// Build accordion-style findings using enriched deep scan renderer
	accordionsHTML := generateDeepAccordionsHTML(filtered)

	// Section generators
	agentProfileHTML := generateAgentProfileHTML(report)
	severityOverviewHTML := generateSeverityOverviewHTML(report, filtered)
	riskAssessmentHTML := generateRiskAssessmentHTML(filtered)
	governanceStatusHTML := generateGovernanceStatusHTML(result)
	cleanDetectionsHTML := generateCleanDetectionsHTML(report)
	complianceSummaryHTML := generateComplianceSummaryHTML(report)
	methodologyHTML := generateMethodologyHTML(report)

	// Report title from metadata
	reportTitle := "Inkog Deep Scan"
	if report.ReportMeta != nil && report.ReportMeta.AgentName != "" {
		reportTitle = escapeHTML(report.ReportMeta.AgentName) + " — Inkog Deep Scan"
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Inkog Deep Scan Report</title>
    <style>%s%s</style>
</head>
<body>
    <header>
        <div class="logo">
            <svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
                <defs>
                    <linearGradient id="inkogGradient" x1="0%%" y1="0%%" x2="100%%" y2="100%%">
                        <stop offset="0%%" style="stop-color:#a78bfa"/>
                        <stop offset="100%%" style="stop-color:#7c3aed"/>
                    </linearGradient>
                </defs>
                <path d="M16 2L4 7v9c0 7.18 5.12 13.88 12 16 6.88-2.12 12-8.82 12-16V7L16 2z" fill="url(#inkogGradient)"/>
                <path d="M10 12h12M10 16h12M10 20h8" stroke="white" stroke-width="1.5" stroke-linecap="round" opacity="0.9"/>
                <path d="M12 16l3 3 5-6" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
            <span>%s</span>
            <span class="deep-badge">Deep Scan</span>
        </div>
        <span class="timestamp">%s</span>
    </header>

    <!-- Global Status Bar -->
    <div class="global-status %s">
        <div class="status-indicator">
            <span class="pulse"></span>
            <span class="status-text">%s</span>
        </div>
        <div class="status-meta">
            <span>%d Total Issues</span>
        </div>
    </div>

    %s
    %s
    %s
    %s

    <!-- Detailed Findings -->
    <section>
        <h2>Detailed Findings</h2>
        <div class="filter-bar">
            <div class="filter-pills">
                <button class="pill active" data-severity="all">All (%d)</button>
                <button class="pill critical" data-severity="CRITICAL">Critical (%d)</button>
                <button class="pill high" data-severity="HIGH">High (%d)</button>
                <button class="pill medium" data-severity="MEDIUM">Medium (%d)</button>
                <button class="pill low" data-severity="LOW">Low (%d)</button>
            </div>
        </div>
        %s
    </section>

    %s
    %s
    %s

    <footer>
        <p>Powered by <a href="https://inkog.io" target="_blank">Inkog Deep Scan</a> v%s</p>
    </footer>

    <script>%s</script>
</body>
</html>`,
		htmlReportCSS, htmlDeepReportCSS,
		reportTitle,
		currentTimestamp(),
		statusClass, statusText,
		totalCount,
		agentProfileHTML,
		severityOverviewHTML,
		riskAssessmentHTML,
		governanceStatusHTML,
		totalCount, criticalCount, highCount, mediumCount, lowCount,
		accordionsHTML,
		cleanDetectionsHTML,
		complianceSummaryHTML,
		methodologyHTML,
		AppVersion,
		htmlDeepReportJS,
	)

	fmt.Println(html)
	return nil
}
