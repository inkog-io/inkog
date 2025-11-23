package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/inkog-io/inkog/pkg/cli"
	"github.com/inkog-io/inkog/pkg/contract"
)

// ServerURL is the default server endpoint. Can be overridden via:
// 1. Environment variable INKOG_SERVER_URL (highest priority)
// 2. Command-line flag -server
// 3. Build-time via -ldflags "-X main.ServerURL=..."
var ServerURL = "https://inkog-api.fly.dev"

func init() {
	// Allow override via environment variable (highest priority)
	if envURL := os.Getenv("INKOG_SERVER_URL"); envURL != "" {
		ServerURL = envURL
	}
}

const (
	AppName    = "inkog"
	AppVersion = "1.0.0"
	HelpText   = `Inkog - Security Scanner with Hybrid Privacy

Usage:
  inkog [OPTIONS] [PATH]

Options:
  -path string        Source path to scan (default: .)
  -server string      Inkog server URL (default: https://inkog-api.fly.dev)
  -output string      Output format: json, text, html (default: text)
  -severity string    Minimum severity level: critical, high, medium, low (default: low)
  -verbose            Enable verbose output
  -version            Show version information
  -help               Show this help message

Examples:
  # Scan current directory
  inkog .

  # Scan with verbose output
  inkog -path ./src -verbose

  # Scan and output as JSON
  inkog -path . -output json

  # Scan using custom server
  inkog -path . -server https://your-inkog-server.com

Environment Variables:
  INKOG_SERVER_URL     Override default server URL (highest priority)
  INKOG_API_KEY        API key for authentication (optional)
  INKOG_OUTPUT_FORMAT  Default output format

Privacy Notice:
  Inkog uses a hybrid privacy model:
  1. Secrets are detected and redacted on your local machine
  2. Redacted code is sent to Inkog server for logic analysis
  3. Your actual secrets never leave your machine
  4. Server analysis is used for detecting loops, data flows, and logic issues
`
)

func main() {
	// Command-line flags
	pathFlag := flag.String("path", ".", "Source path to scan")
	serverFlag := flag.String("server", "", "Inkog server URL")
	outputFlag := flag.String("output", "text", "Output format: json, text, html")
	severityFlag := flag.String("severity", "low", "Minimum severity level")
	verboseFlag := flag.Bool("verbose", false, "Enable verbose output")
	versionFlag := flag.Bool("version", false, "Show version information")
	helpFlag := flag.Bool("help", false, "Show help message")

	flag.Parse()

	// Handle version flag
	if *versionFlag {
		fmt.Printf("%s v%s\n", AppName, AppVersion)
		os.Exit(0)
	}

	// Handle help flag
	if *helpFlag {
		fmt.Println(HelpText)
		os.Exit(0)
	}

	// Override path from positional argument if provided
	args := flag.Args()
	if len(args) > 0 {
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

	// Create scanner
	scanner := cli.NewHybridScanner(*pathFlag, serverURL, *verboseFlag)

	if *verboseFlag {
		fmt.Println("🔐 Inkog Hybrid Privacy Scanner")
		fmt.Printf("📍 Scanning: %s\n", *pathFlag)
	}

	// Run scan
	result, err := scanner.Scan()
	if err != nil {
		log.Fatalf("❌ Scan failed: %v\n", err)
	}

	// Output results
	if err := outputResults(result, *outputFlag, *severityFlag, *verboseFlag); err != nil {
		log.Fatalf("❌ Output failed: %v\n", err)
	}

	// Determine exit code based on findings
	totalFindings := len(result.AllFindings)
	if totalFindings > 0 {
		fmt.Printf("\n⚠️  Scan complete: %d security issues found\n", totalFindings)
		os.Exit(1)
	}

	fmt.Println("\n✅ Scan complete: No security issues found")
	os.Exit(0)
}

// outputResults formats and displays scan results
func outputResults(result *cli.ScanResult, format, minSeverity string, verbose bool) error {
	switch format {
	case "json":
		return outputJSON(result)
	case "text":
		return outputText(result, minSeverity, verbose)
	case "html":
		return outputHTML(result, minSeverity)
	default:
		return fmt.Errorf("unknown output format: %s", format)
	}
}

// outputText provides human-readable text output with rich formatting
func outputText(result *cli.ScanResult, minSeverity string, verbose bool) error {
	if verbose {
		fmt.Println("\n" + strings.Repeat("=", 80))
		fmt.Println("INKOG SECURITY SCAN REPORT")
		fmt.Println(strings.Repeat("=", 80))
	}

	if len(result.AllFindings) == 0 {
		fmt.Println("\n✅ No security issues found")
		return nil
	}

	// Group findings by severity
	criticalFindings := filterFindingsBySeverity(result.AllFindings, "CRITICAL")
	highFindings := filterFindingsBySeverity(result.AllFindings, "HIGH")
	mediumFindings := filterFindingsBySeverity(result.AllFindings, "MEDIUM")
	lowFindings := filterFindingsBySeverity(result.AllFindings, "LOW")

	// Display critical findings
	if len(criticalFindings) > 0 {
		displayFindingsByCategory("🔴 CRITICAL ISSUES", criticalFindings)
	}

	// Display high findings
	if len(highFindings) > 0 {
		displayFindingsByCategory("🟠 HIGH SEVERITY ISSUES", highFindings)
	}

	// Display medium findings
	if len(mediumFindings) > 0 {
		displayFindingsByCategory("🟡 MEDIUM SEVERITY ISSUES", mediumFindings)
	}

	// Display low findings
	if len(lowFindings) > 0 {
		displayFindingsByCategory("🟢 LOW SEVERITY ISSUES", lowFindings)
	}

	// Display compliance summary
	displayComplianceSummary(result.AllFindings)

	return nil
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

// displayFindingsByCategory displays findings grouped by category with rich formatting
func displayFindingsByCategory(category string, findings []contract.Finding) {
	fmt.Printf("\n%s (%d findings)\n", category, len(findings))
	fmt.Println(strings.Repeat("─", 80))

	for i, finding := range findings {
		fmt.Printf("[%d] %s", i+1, finding.Pattern)

		// Add security metadata
		securityTags := []string{}
		if finding.CWE != "" {
			securityTags = append(securityTags, finding.CWE)
		}
		if finding.CVSS > 0 {
			securityTags = append(securityTags, fmt.Sprintf("CVSS %.1f", finding.CVSS))
		}
		if len(securityTags) > 0 {
			fmt.Printf(" [%s]", strings.Join(securityTags, " | "))
		}
		fmt.Printf("\n")

		// Location with column number
		if finding.File != "" {
			fmt.Printf("    File:       %s:%d", finding.File, finding.Line)
			if finding.Column > 0 {
				fmt.Printf(":%d", finding.Column)
			}
			fmt.Printf("\n")
		}

		// Severity and confidence
		fmt.Printf("    Severity:   %s | Confidence: %.0f%%\n", finding.Severity, finding.Confidence*100)

		// OWASP compliance
		if finding.OWASP != "" {
			fmt.Printf("    OWASP:      %s\n", finding.OWASP)
		}

		// Message/Details
		if finding.Message != "" {
			fmt.Printf("    Details:    %s\n", finding.Message)
		}

		// Code snippet if available
		if finding.Code != "" {
			fmt.Printf("\n    Code Context:\n")
			fmt.Println("    " + strings.Repeat("─", 76))
			codeLines := strings.Split(finding.Code, "\n")
			for _, line := range codeLines {
				// Limit code line length for readability
				if len(line) > 70 {
					line = line[:70] + "..."
				}
				fmt.Printf("    │ %s\n", line)
			}
			fmt.Println("    " + strings.Repeat("─", 76))
		}

		fmt.Printf("\n")
	}
}

// displayComplianceSummary displays the compliance table and risk assessment
func displayComplianceSummary(findings []contract.Finding) {
	criticalCount := len(filterFindingsBySeverity(findings, "CRITICAL"))
	highCount := len(filterFindingsBySeverity(findings, "HIGH"))
	mediumCount := len(filterFindingsBySeverity(findings, "MEDIUM"))
	lowCount := len(filterFindingsBySeverity(findings, "LOW"))
	totalCount := len(findings)

	// Determine compliance status
	compliancePass := criticalCount == 0 && highCount == 0
	complianceStatus := "✅ COMPLIANT"
	if !compliancePass {
		complianceStatus = "❌ NON-COMPLIANT"
	}

	// Calculate risk score (0-10 scale)
	riskScore := float64(criticalCount)*2.5 + float64(highCount)*1.5 + float64(mediumCount)*0.5 + float64(lowCount)*0.1
	if riskScore > 10 {
		riskScore = 10
	}

	// Determine risk level
	riskLevel := "LOW"
	if riskScore >= 8 {
		riskLevel = "CRITICAL"
	} else if riskScore >= 6 {
		riskLevel = "HIGH"
	} else if riskScore >= 3 {
		riskLevel = "MEDIUM"
	}

	// Print compliance table
	fmt.Println("\n" + strings.Repeat("━", 80))
	fmt.Println("AI SYSTEM COMPLIANCE REPORT")
	fmt.Println(strings.Repeat("━", 80))

	fmt.Println("")
	fmt.Printf("  Severity Breakdown:\n")
	fmt.Printf("    Critical:  %2d  │  Status:     %s\n", criticalCount, complianceStatus)
	fmt.Printf("    High:      %2d  │  Risk Score: %.1f/10\n", highCount, riskScore)
	fmt.Printf("    Medium:    %2d  │  Risk Level: %s\n", mediumCount, riskLevel)
	fmt.Printf("    Low:       %2d  │\n", lowCount)
	fmt.Println("  " + strings.Repeat("─", 76))
	fmt.Printf("    Total:     %2d  │\n", totalCount)
	fmt.Println("")
	fmt.Println(strings.Repeat("━", 80))
}

// outputJSON provides JSON output for integration with CI/CD
func outputJSON(result *cli.ScanResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

// outputHTML provides HTML report (simplified version)
func outputHTML(result *cli.ScanResult, minSeverity string) error {
	// In production, generate comprehensive HTML report
	// For v1, we'll output a minimal HTML structure
	html := `<!DOCTYPE html>
<html>
<head>
  <title>Inkog Security Scan Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    h1 { color: #333; }
    .critical { color: #d32f2f; }
    .high { color: #f57c00; }
    .medium { color: #fbc02d; }
    .low { color: #388e3c; }
    table { width: 100%; border-collapse: collapse; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
    th { background-color: #f5f5f5; }
  </style>
</head>
<body>
  <h1>Inkog Security Scan Report</h1>
  <p>Total Findings: <strong>%d</strong></p>
  <p>Local Secrets: <strong>%d</strong></p>
  <p>Server Issues: <strong>%d</strong></p>
</body>
</html>`

	html = fmt.Sprintf(html, len(result.AllFindings), len(result.LocalSecrets), len(result.ServerFindings))
	fmt.Println(html)
	return nil
}
