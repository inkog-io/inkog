package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

func main() {
	// Parse command line flags
	scanPath := flag.String("path", ".", "Path to scan")
	riskThreshold := flag.String("risk-threshold", "high", "Minimum risk level (critical, high, medium, low)")
	jsonReport := flag.String("json-report", "", "Output JSON report file path")
	jsonStdout := flag.Bool("json", false, "Output JSON report to stdout instead of text report")
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

	// Output results based on format flag
	if *jsonStdout {
		// Output JSON to stdout
		outputJSONToStdout(result)
	} else {
		// Print text report
		printReport(result)
	}

	// Write JSON report to file if requested
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
			fmt.Printf("\n%d. [%s] %s\n", i+1, f.Severity, f.Pattern)
			fmt.Printf("   File:       %s:%d\n", f.File, f.Line)
			fmt.Printf("   Message:    %s\n", f.Message)
			fmt.Printf("   CWE:        %s | CVSS: %.1f\n", f.CWE, f.CVSS)
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
