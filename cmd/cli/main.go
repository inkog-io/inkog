package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/inkog-io/inkog-cli/pkg/cli"
)

// ServerURL is the default server endpoint. Can be overridden via:
// 1. Environment variable INKOG_SERVER_URL (highest priority)
// 2. Command-line flag -server
// 3. Build-time via -ldflags "-X main.ServerURL=..."
var ServerURL = "http://localhost:8080"

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
  -server string      Inkog server URL (default: https://api.inkog.io)
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
  inkog -path . -server https://inkog-enterprise.example.com

Environment Variables:
  INKOG_SERVER         Override default server URL
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

// outputText provides human-readable text output
func outputText(result *cli.ScanResult, minSeverity string, verbose bool) error {
	if verbose {
		fmt.Println("\n" + strings.Repeat("=", 80))
		fmt.Println("INKOG SECURITY SCAN REPORT")
		fmt.Println(strings.Repeat("=", 80))
	}

	// Display local secrets
	if len(result.LocalSecrets) > 0 {
		fmt.Printf("\n🔴 LOCAL SECRETS (found on your machine, redacted before upload)\n")
		fmt.Println(strings.Repeat("-", 80))
		for i, finding := range result.LocalSecrets {
			fmt.Printf("[%d] %s\n", i+1, finding.Pattern)
			fmt.Printf("    Location: %s:%d\n", finding.File, finding.Line)
			fmt.Printf("    Severity: %s | Confidence: %.0f%%\n", finding.Severity, finding.Confidence*100)
			if finding.Message != "" {
				fmt.Printf("    Details: %s\n", finding.Message)
			}
		}
	}

	// Display server findings
	if len(result.ServerFindings) > 0 {
		fmt.Printf("\n🟠 LOGIC ISSUES (detected by server analysis of sanitized code)\n")
		fmt.Println(strings.Repeat("-", 80))
		for i, finding := range result.ServerFindings {
			fmt.Printf("[%d] %s\n", i+1, finding.Pattern)
			fmt.Printf("    Severity: %s | Confidence: %.0f%%\n", finding.Severity, finding.Confidence*100)
			if finding.Message != "" {
				fmt.Printf("    Details: %s\n", finding.Message)
			}
		}
	}

	// Summary
	if len(result.AllFindings) == 0 {
		fmt.Println("\n✅ No security issues found")
	} else {
		fmt.Printf("\n" + strings.Repeat("-", 80))
		fmt.Printf("SUMMARY: %d total issues found\n", len(result.AllFindings))
		fmt.Printf("  Local Secrets: %d\n", len(result.LocalSecrets))
		fmt.Printf("  Server Issues: %d\n", len(result.ServerFindings))
	}

	return nil
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
