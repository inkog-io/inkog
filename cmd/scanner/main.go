package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/inkog-io/inkog/action/pkg/patterns"
	"github.com/inkog-io/inkog/action/pkg/reporting/compliance"
	"github.com/inkog-io/inkog/action/pkg/reporting/sarif"
)

func main() {
	// Parse command line flags
	scanPath := flag.String("path", ".", "Path to scan")
	riskThreshold := flag.String("risk-threshold", "high", "Minimum risk level (critical, high, medium, low)")
	jsonReport := flag.String("json-report", "", "Output JSON report file path")
	format := flag.String("format", "text", "Output format: text, json, or sarif (default: text)")
	reportFile := flag.String("report", "", "Output report file path (for sarif or json)")
	complianceReport := flag.Bool("compliance", false, "Include compliance report (EU AI Act, NIST AI RMF, OWASP LLM Top 10)")
	jsonStdout := flag.Bool("json", false, "Output JSON report to stdout instead of text report (deprecated, use --format=json)")
	configFile := flag.String("config", "", "Configuration file path (JSON format)")
	listPatterns := flag.Bool("list-patterns", false, "List available patterns")
	flag.Parse()

	// Load configuration from file if provided
	if *configFile != "" {
		if err := loadConfigFile(*configFile, scanPath, riskThreshold, jsonReport); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error loading config file: %v\n", err)
			os.Exit(1)
		}
	}

	// Initialize pattern registry
	registry := InitializeRegistry()

	// Handle --list-patterns flag
	if *listPatterns {
		listAvailablePatterns(registry)
		return
	}

	// Create scanner with pattern registry
	scanner := NewScanner(registry, 4, *riskThreshold)

	// Perform scan
	result, err := scanner.Scan(*scanPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Scan error: %v\n", err)
		os.Exit(1)
	}

	// Handle deprecated --json flag for backward compatibility
	if *jsonStdout && *format == "text" {
		*format = "json"
	}

	// Output results based on format flag
	switch *format {
	case "sarif":
		// Generate and output SARIF report
		generator := sarif.NewGenerator()
		sarifReport := generator.GenerateReport(result.Findings)
		jsonData, err := sarifReport.ToJSON()
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error generating SARIF report: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(jsonData))

		// Write SARIF to file if requested
		if *reportFile != "" {
			if err := os.WriteFile(*reportFile, jsonData, 0644); err != nil {
				fmt.Fprintf(os.Stderr, "❌ Error writing SARIF report: %v\n", err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "✅ SARIF report written to %s\n", *reportFile)
		}

	case "json", "JSON":
		// Output JSON to stdout
		outputJSONToStdout(result)

		// Write to file if requested
		if *reportFile != "" {
			if err := writeJSONReport(result, *reportFile); err != nil {
				fmt.Fprintf(os.Stderr, "❌ Error writing JSON report: %v\n", err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "✅ JSON report written to %s\n", *reportFile)
		}

	default: // text format
		// Print text report
		printReport(result)

		// Include compliance report if requested
		if *complianceReport {
			mapper := compliance.NewComplianceMapper()
			complianceRpt := mapper.GenerateComplianceReport(result.Findings)
			fmt.Print(mapper.FormatComplianceReport(complianceRpt))
		}
	}

	// Write JSON report to file if requested (backward compatibility)
	if *jsonReport != "" {
		if err := writeJSONReport(result, *jsonReport); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error writing report: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "✅ Report written to %s\n", *jsonReport)
	}

	// Determine exit code based on risk threshold
	if scanner.ShouldFailOnThreshold(result) {
		fmt.Fprintf(os.Stderr, "\n❌ Scan failed: Risk threshold '%s' exceeded\n", *riskThreshold)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "\n✅ Scan completed successfully\n")
}

// listAvailablePatterns displays all registered patterns
func listAvailablePatterns(registry *patterns.Registry) {
	fmt.Println("\n📋 Available Security Patterns:")
	fmt.Println("──────────────────────────────────────")

	for _, detector := range registry.GetAll() {
		pattern := detector.GetPattern()
		fmt.Printf("\n✓ %s (ID: %s)\n", pattern.Name, pattern.ID)
		fmt.Printf("  Severity: %s | CVSS: %.1f | Confidence: %.0f%%\n",
			pattern.Severity, pattern.CVSS, detector.GetConfidence()*100)
		fmt.Printf("  CWE: %v\n", pattern.CWEIDs)
		fmt.Printf("  Description: %s\n", pattern.Description)
	}

	fmt.Println("\n──────────────────────────────────────")
	fmt.Printf("Total patterns: %d\n", registry.Count())
}

// printReport displays the scan results to stdout
func printReport(result *patterns.ScanResult) {
	fmt.Println("\n" + repeatingString("═", 50))
	fmt.Println("        INKOG SECURITY SCAN REPORT")
	fmt.Println(repeatingString("═", 50))
	fmt.Println()

	// Summary metrics
	fmt.Printf("Risk Score:          %d/100\n", result.RiskScore)
	fmt.Printf("Scan Duration:       %s\n", result.ScanDuration)
	fmt.Printf("Files Scanned:       %d\n", result.FilesScanned)
	fmt.Printf("Files Skipped:       %d\n", result.SkippedFiles)
	fmt.Printf("Lines of Code:       %d\n", result.LinesOfCode)
	fmt.Printf("Patterns Checked:    %d\n", result.PatternsChecked)
	fmt.Println()

	// Findings summary
	fmt.Println("FINDINGS SUMMARY:")
	fmt.Printf("  Total:      %d\n", result.FindingsCount)
	fmt.Printf("  🔴 CRITICAL: %d\n", result.CriticalCount)
	fmt.Printf("  🔴 HIGH:     %d\n", result.HighCount)
	fmt.Printf("  🟠 MEDIUM:   %d\n", result.MediumCount)
	fmt.Printf("  🟡 LOW:      %d\n", result.LowCount)
	fmt.Println()

	// Detailed findings
	if result.FindingsCount > 0 {
		fmt.Println("FINDINGS DETAILS:")
		fmt.Println("──────────────────────────────────────")

		for i, f := range result.Findings {
			// Use Pattern as title, fallback to Message if Pattern is empty
			title := f.Pattern
			if title == "" {
				title = f.Message
			}

			fmt.Printf("\n%d. [%s] %s\n", i+1, f.Severity, title)
			fmt.Printf("   File:       %s:%d\n", f.File, f.Line)
			fmt.Printf("   Message:    %s\n", f.Message)

			// Only print CVSS if it's not 0.0 (hides missing CVSS values)
			if f.CVSS != 0.0 {
				fmt.Printf("   CWE:        %s | CVSS: %.1f\n", f.CWE, f.CVSS)
			} else if f.CWE != "" {
				fmt.Printf("   CWE:        %s\n", f.CWE)
			}

			fmt.Printf("   Confidence: %.0f%%\n", f.Confidence*100)
			if f.Code != "" && len(f.Code) < 100 {
				fmt.Printf("   Code:       %s\n", f.Code)
			}
		}
	}

	fmt.Println("\n" + repeatingString("═", 50))
}

// writeJSONReport writes scan results in JSON format
func writeJSONReport(result *patterns.ScanResult, filePath string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filePath, data, 0644)
}

// String helper for repeating characters
func repeatingString(s string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += s
	}
	return result
}

// outputJSONToStdout outputs the scan result as JSON to stdout
func outputJSONToStdout(result *patterns.ScanResult) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error marshalling JSON: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}

// ConfigFile represents the structure of a configuration file
type ConfigFile struct {
	Path          string `json:"path"`
	RiskThreshold string `json:"risk_threshold"`
	JSONReport    string `json:"json_report"`
}

// loadConfigFile loads configuration from a JSON file and updates flags
func loadConfigFile(filePath string, path, riskThreshold, jsonReport *string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var config ConfigFile
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	// Update flags from config file (only if not already set via command line)
	// Note: This is a simple implementation that prefers config file values
	if config.Path != "" {
		*path = config.Path
	}
	if config.RiskThreshold != "" {
		*riskThreshold = config.RiskThreshold
	}
	if config.JSONReport != "" {
		*jsonReport = config.JSONReport
	}

	return nil
}
