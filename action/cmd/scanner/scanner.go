package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// Scanner orchestrates the security scanning process
type Scanner struct {
	registry    *patterns.Registry
	semaphore   chan struct{} // Limits concurrent file processing
	riskThreshold string
}

// NewScanner creates a new security scanner
func NewScanner(registry *patterns.Registry, maxConcurrency int, riskThreshold string) *Scanner {
	return &Scanner{
		registry:      registry,
		semaphore:     make(chan struct{}, maxConcurrency),
		riskThreshold: riskThreshold,
	}
}

// Scan performs a security scan on a directory
func (s *Scanner) Scan(dirPath string) (*patterns.ScanResult, error) {
	startTime := time.Now()

	fmt.Fprintf(os.Stderr, "🔍 Inkog AI Agent Security Scanner\n")
	fmt.Fprintf(os.Stderr, "📂 Scanning directory: %s\n", dirPath)
	fmt.Fprintf(os.Stderr, "🔍 Active patterns: %d\n\n", s.registry.Count())

	var findings []patterns.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup
	var filesCount, skippedCount, totalLOC int

	// Walk directory and scan files
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		// Skip unsupported files
		if !s.isSupportedFile(path) {
			return nil
		}

		// Skip vendor and dependency directories
		if s.shouldSkipDirectory(path) {
			skippedCount++
			return nil
		}

		filesCount++

		wg.Add(1)
		go func(filePath string) {
			defer wg.Done()

			// Acquire semaphore slot
			s.semaphore <- struct{}{}
			defer func() { <-s.semaphore }()

			// Read file
			content, err := os.ReadFile(filePath)
			if err != nil {
				return
			}

			totalLOC += s.countLines(content)

			// Run all detectors on this file
			fileFindings := s.scanFileWithAllDetectors(filePath, content)

			if len(fileFindings) > 0 {
				mu.Lock()
				findings = append(findings, fileFindings...)
				mu.Unlock()
			}
		}(path)

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error walking directory: %w", err)
	}

	// Wait for all scans to complete
	wg.Wait()

	// Calculate risk metrics
	duration := time.Since(startTime)
	result := s.buildScanResult(findings, duration, filesCount, skippedCount, totalLOC)

	return result, nil
}

// scanFileWithAllDetectors runs all detectors on a single file
func (s *Scanner) scanFileWithAllDetectors(filePath string, content []byte) []patterns.Finding {
	var findings []patterns.Finding

	for _, detector := range s.registry.GetAll() {
		detectorFindings, err := detector.Detect(filePath, content)
		if err != nil {
			// Log error but continue with other detectors
			fmt.Fprintf(os.Stderr, "⚠️  Error in detector %s: %v\n", detector.Name(), err)
			continue
		}

		findings = append(findings, detectorFindings...)
	}

	return findings
}

// buildScanResult constructs the final scan result
func (s *Scanner) buildScanResult(findings []patterns.Finding, duration time.Duration,
	filesCount, skippedCount, totalLOC int) *patterns.ScanResult {

	result := &patterns.ScanResult{
		Findings:        findings,
		FilesScanned:    filesCount,
		SkippedFiles:    skippedCount,
		LinesOfCode:     totalLOC,
		ScanDuration:    duration.String(),
		FindingsCount:   len(findings),
		PatternsChecked: s.registry.Count(),
	}

	// Count by severity
	for _, f := range findings {
		switch f.Severity {
		case "CRITICAL":
			result.CriticalCount++
		case "HIGH":
			result.HighCount++
		case "MEDIUM":
			result.MediumCount++
		case "LOW":
			result.LowCount++
		}
	}

	// Calculate risk score
	result.RiskScore = s.calculateRiskScore(findings)

	return result
}

// calculateRiskScore computes an overall risk score (0-100)
func (s *Scanner) calculateRiskScore(findings []patterns.Finding) int {
	if len(findings) == 0 {
		return 0
	}

	score := 0
	for _, f := range findings {
		score += patterns.RiskScoreMap[f.Severity]
	}

	// Cap at 100
	if score > 100 {
		return 100
	}

	return score
}

// isSupportedFile checks if file should be scanned
func (s *Scanner) isSupportedFile(path string) bool {
	supported := []string{".py", ".js", ".ts", ".jsx", ".tsx", ".go"}
	for _, ext := range supported {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// shouldSkipDirectory checks if directory should be skipped
func (s *Scanner) shouldSkipDirectory(path string) bool {
	skipDirs := []string{
		"node_modules", ".git", ".venv", "venv",
		"__pycache__", ".pytest_cache", "build", "dist",
		"vendor", ".terraform", ".env",
	}

	for _, skipDir := range skipDirs {
		if strings.Contains(path, string(filepath.Separator)+skipDir+string(filepath.Separator)) ||
			strings.Contains(path, string(filepath.Separator)+skipDir) {
			return true
		}
	}

	return false
}

// countLines counts the number of lines in content
func (s *Scanner) countLines(content []byte) int {
	return strings.Count(string(content), "\n") + 1
}

// ShouldFailOnThreshold determines if the scan should fail based on risk threshold
func (s *Scanner) ShouldFailOnThreshold(result *patterns.ScanResult) bool {
	switch s.riskThreshold {
	case "critical":
		return result.CriticalCount > 0
	case "high":
		return result.CriticalCount > 0 || result.HighCount > 0
	case "medium":
		return result.CriticalCount > 0 || result.HighCount > 0 || result.MediumCount > 0
	case "low":
		return result.FindingsCount > 0
	default:
		return result.CriticalCount > 0
	}
}
