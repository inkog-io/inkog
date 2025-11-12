package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Finding represents a security finding
type Finding struct {
	ID       string  `json:"id"`
	Pattern  string  `json:"pattern"`
	Severity string  `json:"severity"`
	File     string  `json:"file"`
	Line     int     `json:"line"`
	Message  string  `json:"message"`
	Code     string  `json:"code_snippet"`
}

// ScanResult represents the complete scan result
type ScanResult struct {
	RiskScore      int       `json:"risk_score"`
	FindingsCount  int       `json:"findings_count"`
	HighRiskCount  int       `json:"high_risk_count"`
	MediumRiskCount int      `json:"medium_risk_count"`
	LowRiskCount   int       `json:"low_risk_count"`
	Findings       []Finding `json:"findings"`
	ScanDuration   string    `json:"scan_duration"`
	FilesScanned   int       `json:"files_scanned"`
	LinesOfCode    int       `json:"lines_of_code"`
}

func main() {
	riskThreshold := flag.String("risk-threshold", "high", "Minimum risk level (low, medium, high)")
	_ = flag.String("framework", "auto-detect", "Agent framework") // for future use
	scanPath := flag.String("path", ".", "Path to scan")
	jsonReport := flag.String("json-report", "", "Output JSON report file path")
	flag.Parse()

	startTime := time.Now()

	fmt.Fprintf(os.Stderr, "🔍 Scanning %s for security issues...\n", *scanPath)

	findings := scanDirectory(*scanPath)
	duration := time.Since(startTime)

	// Calculate metrics
	totalLOC := 0
	filesCount := 0
	highRiskCount := 0
	mediumRiskCount := 0
	lowRiskCount := 0

	for _, f := range findings {
		switch f.Severity {
		case "high":
			highRiskCount++
		case "medium":
			mediumRiskCount++
		default:
			lowRiskCount++
		}
	}

	// Count files and LOC
	filepath.Walk(*scanPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && isSupportedFile(path) {
			filesCount++
			content, err := os.ReadFile(path)
			if err == nil {
				totalLOC += countLines(content)
			}
		}
		return nil
	})

	riskScore := calculateRiskScore(findings)

	result := &ScanResult{
		RiskScore:       riskScore,
		FindingsCount:   len(findings),
		HighRiskCount:   highRiskCount,
		MediumRiskCount: mediumRiskCount,
		LowRiskCount:    lowRiskCount,
		Findings:        findings,
		ScanDuration:    duration.String(),
		FilesScanned:    filesCount,
		LinesOfCode:     totalLOC,
	}

	// Print report
	printReport(result)

	// Write JSON if requested
	if *jsonReport != "" {
		writeJSON(result, *jsonReport)
		fmt.Fprintf(os.Stderr, "✅ Report written to %s\n", *jsonReport)
	}

	// Exit based on risk threshold
	shouldFail := false
	switch *riskThreshold {
	case "high":
		shouldFail = highRiskCount > 0
	case "medium":
		shouldFail = highRiskCount > 0 || mediumRiskCount > 0
	case "low":
		shouldFail = len(findings) > 0
	}

	if shouldFail {
		fmt.Fprintf(os.Stderr, "\n❌ Scan failed: Risk threshold exceeded\n")
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "\n✅ Scan completed successfully\n")
}

func scanDirectory(dirPath string) []Finding {
	var findings []Finding
	var mu sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 4)

	filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !isSupportedFile(path) {
			return nil
		}

		wg.Add(1)
		go func(filePath string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			content, err := os.ReadFile(filePath)
			if err != nil {
				return
			}

			fileFindings := scanFile(filePath, content)
			if len(fileFindings) > 0 {
				mu.Lock()
				findings = append(findings, fileFindings...)
				mu.Unlock()
			}
		}(path)

		return nil
	})

	wg.Wait()
	return findings
}

func scanFile(filePath string, content []byte) []Finding {
	var findings []Finding
	text := string(content)
	lines := strings.Split(text, "\n")

	// Pattern 1: Prompt Injection (f-strings and template literals)
	promptInjectionRegex := regexp.MustCompile(`(f["']|f"""|\$\{)[^"']*(?:prompt|query|user_input|request|message)[^"']*["']`)
	for i, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if promptInjectionRegex.MatchString(line) && trimmedLine != "" && !strings.HasPrefix(trimmedLine, "#") {
			findings = append(findings, Finding{
				ID:       "prompt_injection_" + fmt.Sprintf("%d", i),
				Pattern:  "Prompt Injection",
				Severity: "high",
				File:     filePath,
				Line:     i + 1,
				Message:  "Potential prompt injection: User input directly interpolated",
				Code:     line,
			})
		}
	}

	// Pattern 2: Hardcoded API Keys and Credentials
	// Multiple patterns to catch different credential formats
	apiKeyPatterns := []struct {
		regex    *regexp.Regexp
		name     string
		severity string
	}{
		// Known API key prefixes (OpenAI, Stripe, GitHub, Anthropic, etc.)
		{regexp.MustCompile(`(sk-|sk_|sk_live_|ghp_|sk-ant-)[a-zA-Z0-9_-]{20,}`), "Known API Key Format", "high"},
		// Variable names with "key", "secret", "token", "password" with long values
		{regexp.MustCompile(`(api_?key|secret_?key|secret|token|password|api_?secret)\s*[=:]\s*["']([a-zA-Z0-9_\-\.]{15,})["']`), "Hardcoded Credential", "high"},
		// Credentials assigned without quotes (dangerous)
		{regexp.MustCompile(`(OPENAI|STRIPE|GITHUB|ANTHROPIC|DATABASE|API|SECRET|TOKEN)_?(KEY|PASSWORD|SECRET|TOKEN)\s*=\s*["']([a-zA-Z0-9_\-\.]{15,})["']`), "Hardcoded Credential", "high"},
		// JWT and other token patterns
		{regexp.MustCompile(`(jwt|token|auth|bearer)\s*[=:]\s*["']([a-zA-Z0-9_\-\.]{20,})["']`), "Hardcoded Token", "high"},
		// Database credentials
		{regexp.MustCompile(`(db_?password|db_?user|db_?host|database_?url)\s*[=:]\s*["']([^"']{8,})["']`), "Hardcoded Database Credential", "high"},
	}

	for i, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimmedLine, "#") || strings.HasPrefix(trimmedLine, "//") {
			continue
		}

		for _, pattern := range apiKeyPatterns {
			if pattern.regex.MatchString(line) {
				findings = append(findings, Finding{
					ID:       "hardcoded_credential_" + fmt.Sprintf("%d", i),
					Pattern:  "Hardcoded Credentials",
					Severity: "high",
					File:     filePath,
					Line:     i + 1,
					Message:  "Hardcoded API key, credential, or token detected in source code",
					Code:     line,
				})
				break // Only add once per line
			}
		}
	}

	// Pattern 3: Infinite Loops
	infiniteLoopRegex := regexp.MustCompile(`while\s*(True|1|true)\s*:`)
	for i, line := range lines {
		if infiniteLoopRegex.MatchString(line) {
			findings = append(findings, Finding{
				ID:       "infinite_loop_" + fmt.Sprintf("%d", i),
				Pattern:  "Infinite Loop",
				Severity: "high",
				File:     filePath,
				Line:     i + 1,
				Message:  "Infinite loop detected: while True without break",
				Code:     line,
			})
		}
	}

	// Pattern 4: Unsafe Environment Access
	unsafeEnvRegex := regexp.MustCompile(`os\.environ\s*\[\s*["']`)
	for i, line := range lines {
		if unsafeEnvRegex.MatchString(line) && !strings.Contains(line, ".get(") {
			findings = append(findings, Finding{
				ID:       "unsafe_env_" + fmt.Sprintf("%d", i),
				Pattern:  "Unsafe Environment Access",
				Severity: "medium",
				File:     filePath,
				Line:     i + 1,
				Message:  "Unsafe environment variable access without default value",
				Code:     line,
			})
		}
	}

	return findings
}

func isSupportedFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".py" || ext == ".js" || ext == ".ts"
}

func countLines(content []byte) int {
	return strings.Count(string(content), "\n") + 1
}

func calculateRiskScore(findings []Finding) int {
	if len(findings) == 0 {
		return 0
	}

	score := 0
	for _, f := range findings {
		switch f.Severity {
		case "high":
			score += 30
		case "medium":
			score += 15
		default:
			score += 5
		}
	}

	if score > 100 {
		return 100
	}
	return score
}

func printReport(result *ScanResult) {
	fmt.Println("\n========================================")
	fmt.Println("        INKOG SECURITY SCAN REPORT       ")
	fmt.Println("========================================")
	fmt.Println()

	fmt.Printf("Risk Score:       %d/100\n", result.RiskScore)
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

	if result.FindingsCount > 0 {
		fmt.Println("FINDINGS:")
		for i, f := range result.Findings {
			fmt.Printf("%d. %s (%s)\n", i+1, f.Pattern, f.Severity)
			fmt.Printf("   File: %s:%d\n", f.File, f.Line)
			fmt.Printf("   Message: %s\n\n", f.Message)
		}
	}

	fmt.Println("========================================")
}

func writeJSON(result *ScanResult, filePath string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, data, 0644)
}
