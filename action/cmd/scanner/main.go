package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/inkog-io/inkog/action/pkg/models"
	"github.com/inkog-io/inkog/action/pkg/parser"
	"github.com/inkog-io/inkog/action/pkg/patterns"
	"github.com/inkog-io/inkog/action/pkg/report"
)

func main() {
	// Parse command line arguments
	riskThreshold := flag.String("risk-threshold", "high", "Minimum risk level to fail (low, medium, high)")
	framework := flag.String("framework", "auto-detect", "Agent framework (auto-detect, langchain, crewai, autogen)")
	scanPath := flag.String("path", ".", "Path to scan")
	jsonReport := flag.String("json-report", "", "Output JSON report file path")
	githubOutput := flag.String("github-output", "", "GitHub output file path")
	flag.Parse()

	// Validate risk threshold
	validThresholds := map[string]bool{"low": true, "medium": true, "high": true}
	if !validThresholds[*riskThreshold] {
		fmt.Fprintf(os.Stderr, "Invalid risk threshold: %s\n", *riskThreshold)
		os.Exit(1)
	}

	// Start timing
	startTime := time.Now()

	// Initialize parser
	p, err := parser.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize parser: %v\n", err)
		os.Exit(1)
	}

	// Detect framework
	detectedFramework := detectFramework(*scanPath, *framework)

	// Parse directory
	fmt.Fprintf(os.Stderr, "🔍 Scanning %s for security issues...\n", *scanPath)
	files, err := p.ParseDirectory(*scanPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse directory: %v\n", err)
		os.Exit(1)
	}

	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "No supported files found in %s\n", *scanPath)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "📄 Found %d supported files\n", len(files))

	// Run pattern detection
	fmt.Fprintf(os.Stderr, "🔎 Running security pattern detection...\n")
	allFindings := detectPatterns(files)

	// Calculate metrics
	duration := time.Since(startTime)
	totalLOC := 0
	for _, f := range files {
		totalLOC += f.LOC
	}

	// Build scan result
	result := &models.ScanResult{
		Timestamp:       startTime,
		Framework:       detectedFramework,
		RiskScore:       models.CalculateRiskScore(allFindings),
		FindingsCount:   len(allFindings),
		Findings:        allFindings,
		ScanDuration:    duration.String(),
		FilesScanned:    len(files),
		LinesOfCode:     totalLOC,
	}

	// Count by severity
	for _, f := range allFindings {
		switch f.Severity {
		case models.RiskLevelHigh:
			result.HighRiskCount++
		case models.RiskLevelMedium:
			result.MediumRiskCount++
		case models.RiskLevelLow:
			result.LowRiskCount++
		}
	}

	// Output results
	fmt.Println("\n")
	formatter := report.NewFormatter(*githubOutput)

	// Print human-readable report
	formatter.PrintReport(result)

	// Write GitHub Actions annotations
	annotations := formatter.FormatGitHubActions(result)
	fmt.Println("\n" + annotations)

	// Write JSON report if requested
	if *jsonReport != "" {
		if err := formatter.WriteJSON(result, *jsonReport); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write JSON report: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "✅ JSON report written to %s\n", *jsonReport)
		}
	}

	// Write GitHub output if specified
	if err := formatter.WriteGitHubOutput(result); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write GitHub output: %v\n", err)
	}

	// Determine exit code based on risk threshold
	shouldFail := shouldFailOnRiskThreshold(result, *riskThreshold)

	if shouldFail {
		fmt.Fprintf(os.Stderr, "\n❌ Scan failed: Risk threshold '%s' exceeded\n", *riskThreshold)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "\n✅ Scan completed successfully\n")
	os.Exit(0)
}

// detectPatterns runs all pattern detectors on files concurrently
func detectPatterns(files []parser.FileInfo) []models.Finding {
	registry := patterns.NewRegistry()
	var findings []models.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Limit concurrent detection to 4
	semaphore := make(chan struct{}, 4)

	for _, file := range files {
		wg.Add(1)
		go func(f parser.FileInfo) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			fileFindings := registry.DetectAll(&f)
			if len(fileFindings) > 0 {
				mu.Lock()
				findings = append(findings, fileFindings...)
				mu.Unlock()
			}
		}(file)
	}

	wg.Wait()
	return findings
}

// detectFramework detects the agent framework used
func detectFramework(scanPath, specifiedFramework string) string {
	if specifiedFramework != "auto-detect" {
		return specifiedFramework
	}

	// Check for framework indicators
	indicatorFiles := map[string]string{
		"langchain":  "langchain",
		"crewai":     "crewai",
		"autogen":    "autogen",
		"openai":     "openai",
		"huggingface": "huggingface",
	}

	err := filepath.Walk(scanPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			dirName := filepath.Base(path)
			if framework, exists := indicatorFiles[dirName]; exists {
				return filepath.SkipDir // Found indicator
			}
		}

		return nil
	})

	if err == nil {
		return "auto-detected"
	}

	return "unknown"
}

// shouldFailOnRiskThreshold determines if scan should fail based on risk threshold
func shouldFailOnRiskThreshold(result *models.ScanResult, threshold string) bool {
	switch threshold {
	case "high":
		return result.HighRiskCount > 0
	case "medium":
		return result.HighRiskCount > 0 || result.MediumRiskCount > 0
	case "low":
		return result.FindingsCount > 0
	default:
		return false
	}
}
