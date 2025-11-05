package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/inkog-io/inkog/action/pkg/models"
)

// Formatter handles output formatting
type Formatter struct {
	githubOutput string
}

// NewFormatter creates a new formatter
func NewFormatter(githubOutput string) *Formatter {
	return &Formatter{
		githubOutput: githubOutput,
	}
}

// FormatGitHubActions outputs GitHub Actions annotations
func (f *Formatter) FormatGitHubActions(result *models.ScanResult) string {
	var output strings.Builder

	// Sort findings by severity
	sortFindingsBySeverity(result.Findings)

	for _, finding := range result.Findings {
		annotation := f.buildAnnotation(finding)
		output.WriteString(annotation)
		output.WriteString("\n")
	}

	// Add summary
	summary := f.buildSummary(result)
	output.WriteString(summary)

	return output.String()
}

// buildAnnotation creates a GitHub Actions annotation for a finding
func (f *Formatter) buildAnnotation(finding models.Finding) string {
	command := "warning"
	if finding.Severity == models.RiskLevelHigh {
		command = "error"
	}

	message := fmt.Sprintf("%s: %s (confidence: %.0f%%)",
		finding.Pattern,
		finding.Message,
		finding.Confidence*100)

	return fmt.Sprintf("::%s file=%s,line=%d,col=%d::%s",
		command,
		finding.File,
		finding.Line,
		finding.Column,
		message)
}

// buildSummary creates a summary annotation
func (f *Formatter) buildSummary(result *models.ScanResult) string {
	summary := fmt.Sprintf(
		"::notice::Scan complete - Risk Score: %d/100 | Findings: %d (%d high, %d medium, %d low) | Duration: %s | Files: %d | LoC: %d",
		result.RiskScore,
		result.FindingsCount,
		result.HighRiskCount,
		result.MediumRiskCount,
		result.LowRiskCount,
		result.ScanDuration,
		result.FilesScanned,
		result.LinesOfCode,
	)
	return summary
}

// WriteJSON writes the result as formatted JSON
func (f *Formatter) WriteJSON(result *models.ScanResult, filePath string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	err = os.WriteFile(filePath, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write JSON file: %w", err)
	}

	return nil
}

// WriteGitHubOutput writes the result to GitHub output
func (f *Formatter) WriteGitHubOutput(result *models.ScanResult) error {
	if f.githubOutput == "" {
		return nil
	}

	// Append to the GitHub output file
	file, err := os.OpenFile(f.githubOutput, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open GitHub output file: %w", err)
	}
	defer file.Close()

	// Write the risk score
	fmt.Fprintf(file, "risk-score=%d\n", result.RiskScore)
	fmt.Fprintf(file, "findings-count=%d\n", result.FindingsCount)
	fmt.Fprintf(file, "high-risk-count=%d\n", result.HighRiskCount)

	return nil
}

// PrintReport prints a human-readable report to stdout
func (f *Formatter) PrintReport(result *models.ScanResult) {
	fmt.Println("\n========================================")
	fmt.Println("        INKOG SECURITY SCAN REPORT       ")
	fmt.Println("========================================")
	fmt.Println()

	fmt.Printf("Framework:        %s\n", result.Framework)
	fmt.Printf("Risk Score:       %d/100\n", result.RiskScore)
	fmt.Printf("Timestamp:        %s\n", result.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Printf("Duration:         %s\n", result.ScanDuration)
	fmt.Printf("Files Scanned:    %d\n", result.FilesScanned)
	fmt.Printf("Lines of Code:    %d\n", result.LinesOfCode)
	fmt.Println()

	fmt.Println("FINDINGS SUMMARY:")
	fmt.Printf("  Total:      %d\n", result.FindingsCount)
	fmt.Printf("  🔴 High:    %d\n", result.HighRiskCount)
	fmt.Printf("  🟠 Medium:  %d\n", result.MediumRiskCount)
	fmt.Printf("  🟡 Low:     %d\n", result.LowRiskCount)
	fmt.Println()

	if result.FindingsCount == 0 {
		fmt.Println("✅ No security issues detected!")
		fmt.Println()
		return
	}

	fmt.Println("DETAILED FINDINGS:")
	fmt.Println()

	// Sort findings by severity
	sortFindingsBySeverity(result.Findings)

	for i, finding := range result.Findings {
		severityIcon := "🔴"
		if finding.Severity == models.RiskLevelMedium {
			severityIcon = "🟠"
		} else if finding.Severity == models.RiskLevelLow {
			severityIcon = "🟡"
		}

		fmt.Printf("%d. %s %s [%s]\n", i+1, severityIcon, finding.Pattern, finding.Severity)
		fmt.Printf("   File:       %s:%d\n", finding.File, finding.Line)
		fmt.Printf("   Message:    %s\n", finding.Message)
		fmt.Printf("   Confidence: %.0f%%\n", finding.Confidence*100)
		fmt.Printf("   Remediation: %s\n", finding.Remediation)

		if len(finding.CWEIdentifiers) > 0 {
			fmt.Printf("   CWE:       %s\n", strings.Join(finding.CWEIdentifiers, ", "))
		}

		fmt.Printf("   Code:\n")
		for _, line := range strings.Split(finding.Code, "\n") {
			fmt.Printf("      %s\n", line)
		}
		fmt.Println()
	}

	fmt.Println("========================================")
}

// sortFindingsBySeverity sorts findings by severity level
func sortFindingsBySeverity(findings []models.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		severityOrder := map[models.RiskLevel]int{
			models.RiskLevelHigh:   0,
			models.RiskLevelMedium: 1,
			models.RiskLevelLow:    2,
		}

		if severityOrder[findings[i].Severity] != severityOrder[findings[j].Severity] {
			return severityOrder[findings[i].Severity] < severityOrder[findings[j].Severity]
		}

		// Secondary sort by confidence (highest first)
		return findings[i].Confidence > findings[j].Confidence
	})
}
