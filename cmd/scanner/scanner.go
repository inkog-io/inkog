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
	var failedFiles []string
	var panicedDetectors []string

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
				fmt.Fprintf(os.Stderr, "⚠️  Cannot read file %s: %v\n", filePath, err)
				mu.Lock()
				failedFiles = append(failedFiles, filePath)
				mu.Unlock()
				return
			}

			totalLOC += s.countLines(content)

			// Run all detectors on this file
			panicedDets := s.scanFileWithAllDetectors(filePath, content)
			fileFindings := panicedDets.Findings

			if len(panicedDets.PanicedDetectors) > 0 {
				mu.Lock()
				panicedDetectors = append(panicedDetectors, panicedDets.PanicedDetectors...)
				mu.Unlock()
			}

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
	result := s.buildScanResult(findings, duration, filesCount, skippedCount, totalLOC, failedFiles, panicedDetectors)

	return result, nil
}

// DetectionResult holds findings and metadata from scanning a file
type DetectionResult struct {
	Findings         []patterns.Finding
	PanicedDetectors []string
}

// scanFileWithAllDetectors runs all detectors on a single file
func (s *Scanner) scanFileWithAllDetectors(filePath string, content []byte) DetectionResult {
	var findings []patterns.Finding
	var panicedDetectors []string

	for _, detector := range s.registry.GetAll() {
		// Wrap detector call with panic recovery
		detectorFindings, panicked := s.safeDetect(detector, filePath, content)
		findings = append(findings, detectorFindings...)
		if panicked {
			panicedDetectors = append(panicedDetectors, detector.Name())
		}
	}

	return DetectionResult{
		Findings:         findings,
		PanicedDetectors: panicedDetectors,
	}
}

// safeDetect wraps detector.Detect() with panic recovery
// Returns findings and a boolean indicating if a panic occurred
func (s *Scanner) safeDetect(detector patterns.Detector, filePath string, content []byte) (findings []patterns.Finding, panicOccurred bool) {
	findings = []patterns.Finding{}
	panicOccurred = false

	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "🚨 PANIC in detector %s: %v (file: %s)\n", detector.Name(), r, filePath)
			panicOccurred = true
			// Continue scanning - don't crash the entire tool
		}
	}()

	detectorFindings, err := detector.Detect(filePath, content)
	if err != nil {
		// Log error but continue with other detectors
		fmt.Fprintf(os.Stderr, "⚠️  Error in detector %s: %v\n", detector.Name(), err)
		return
	}

	findings = detectorFindings
	return
}

// buildScanResult constructs the final scan result
func (s *Scanner) buildScanResult(findings []patterns.Finding, duration time.Duration,
	filesCount, skippedCount, totalLOC int, failedFiles []string, panicedDetectors []string) *patterns.ScanResult {

	result := &patterns.ScanResult{
		Findings:         findings,
		FilesScanned:     filesCount,
		SkippedFiles:     skippedCount,
		LinesOfCode:      totalLOC,
		ScanDuration:     duration.String(),
		FindingsCount:    len(findings),
		PatternsChecked:  s.registry.Count(),
		FailedFiles:      failedFiles,
		FailedFilesCount: len(failedFiles),
		PanicedDetectors: panicedDetectors,
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
