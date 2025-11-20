package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/inkog-io/inkog/action/pkg/ast_engine/analysis"
	"github.com/inkog-io/inkog/action/pkg/ast_engine/parser"
	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// Scanner orchestrates the security scanning process
type Scanner struct {
	registry      *patterns.Registry
	semaphore     chan struct{} // Limits concurrent file processing
	riskThreshold string
	pythonParser  parser.Parser // Parser for extracting docstring ranges
	parserMu      sync.Mutex    // Protect parser instance
}

// NewScanner creates a new security scanner
func NewScanner(registry *patterns.Registry, maxConcurrency int, riskThreshold string) *Scanner {
	// Initialize Python parser for docstring detection
	pythonParser, err := parser.NewPythonParser(parser.DefaultConfig())
	if err != nil {
		// If parser initialization fails, continue with nil parser
		// The scanner will gracefully skip docstring extraction for Python files
		pythonParser = nil
	}

	return &Scanner{
		registry:      registry,
		semaphore:     make(chan struct{}, maxConcurrency),
		riskThreshold: riskThreshold,
		pythonParser:  pythonParser,
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

	// Extract ignored ranges for this file (e.g., docstrings for Python files)
	ignoredRanges := s.extractIgnoredRanges(filePath, content)

	for _, detector := range s.registry.GetAll() {
		// Wrap detector call with panic recovery
		detectorFindings, panicked := s.safeDetect(detector, filePath, content)

		// Filter findings to exclude those in ignored ranges
		filteredFindings := s.filterFindingsInIgnoredRanges(filePath, content, detectorFindings, ignoredRanges)
		findings = append(findings, filteredFindings...)

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

// extractIgnoredRanges extracts ignored ranges (docstrings, comments) from a file
func (s *Scanner) extractIgnoredRanges(filePath string, content []byte) *analysis.IgnoredRanges {
	ignoredRanges := analysis.NewIgnoredRanges()

	// Only extract docstrings for Python files
	if !strings.HasSuffix(filePath, ".py") {
		return ignoredRanges
	}

	// Check if Python parser is available
	if s.pythonParser == nil {
		return ignoredRanges
	}

	// Get or cast Python parser
	pythonParser, ok := s.pythonParser.(*parser.PythonParser)
	if !ok {
		return ignoredRanges
	}

	// Extract docstring ranges from Python source code
	sourceCode := string(content)
	docstringRanges := pythonParser.ExtractDocstringRanges(sourceCode)

	return docstringRanges
}

// lineColToByteOffset converts a line/column position to a byte offset in the source code
func lineColToByteOffset(content []byte, line int, col int) int {
	if line <= 0 || col < 0 {
		return 0
	}

	sourceStr := string(content)
	lines := strings.Split(sourceStr, "\n")

	byteOffset := 0

	// Add bytes from all lines before the target line
	for i := 0; i < line-1 && i < len(lines); i++ {
		byteOffset += len(lines[i])
		byteOffset += 1 // Account for the newline character
	}

	// Add column offset to the target line
	if line > 0 && line <= len(lines) {
		targetLine := lines[line-1]
		if col > len(targetLine) {
			byteOffset += len(targetLine)
		} else {
			byteOffset += col
		}
	}

	return byteOffset
}

// filterFindingsInIgnoredRanges removes findings that fall within ignored ranges
// It uses two strategies: AST-based filtering and regex fallback for extra safety
func (s *Scanner) filterFindingsInIgnoredRanges(filePath string, content []byte,
	findings []patterns.Finding, ignoredRanges *analysis.IgnoredRanges) []patterns.Finding {

	var filtered []patterns.Finding

	for _, finding := range findings {
		// Strategy 1: AST-based filtering (primary)
		if ignoredRanges != nil && ignoredRanges.Count() > 0 {
			byteOffset := lineColToByteOffset(content, finding.Line, finding.Column)
			if ignoredRanges.IsBytePositionIgnored(byteOffset) {
				// This finding is in an ignored range, skip it
				continue
			}
		}

		// Strategy 2: Regex fallback (safety net for edge cases)
		if isInCommentOrDocstring(content, finding.Line, finding.Column) {
			// This finding is in a comment or docstring, skip it
			continue
		}

		// Finding passed both filters, keep it
		filtered = append(filtered, finding)
	}

	return filtered
}

// isInCommentOrDocstring checks if a line/column position is within a comment or docstring
// This is a regex-based safety net to catch edge cases missed by AST analysis
func isInCommentOrDocstring(content []byte, line int, col int) bool {
	sourceStr := string(content)
	lines := strings.Split(sourceStr, "\n")

	if line <= 0 || line > len(lines) {
		return false
	}

	lineContent := lines[line-1]

	// Check 1: Is this line a comment (starts with # after trimming)?
	trimmedLine := strings.TrimSpace(lineContent)
	if strings.HasPrefix(trimmedLine, "#") {
		return true
	}

	// Check 2: Is this position inside a triple-quoted string (docstring)?
	// Look backward and forward for """ or ''' markers
	inTripleDouble := isInTripleQuoteBlock(sourceStr, line, col, `"""`)
	inTripleSingle := isInTripleQuoteBlock(sourceStr, line, col, `'''`)

	return inTripleDouble || inTripleSingle
}

// isInTripleQuoteBlock checks if a line/column position is inside a triple-quoted block
func isInTripleQuoteBlock(sourceStr string, targetLine int, targetCol int, quoteMarker string) bool {
	lines := strings.Split(sourceStr, "\n")
	quoteCount := 0

	// Iterate through all lines up to and including the target line
	for i := 0; i < len(lines); i++ {
		line := lines[i]

		// Count occurrences of the quote marker on this line
		parts := strings.Split(line, quoteMarker)
		quoteCount += len(parts) - 1

		// If we've reached the target line
		if i+1 == targetLine {
			// If quoteCount is odd, we're inside a triple-quoted block
			if quoteCount%2 == 1 {
				return true
			}
			return false
		}
	}

	return false
}
