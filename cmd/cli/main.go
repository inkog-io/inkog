package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

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

	// ANSI color codes for terminal output
	colorReset    = "\033[0m"
	colorCritical = "\033[91m" // bright red
	colorHigh     = "\033[93m" // bright yellow
	colorMedium   = "\033[33m" // yellow
	colorLow      = "\033[32m" // green
	colorGray     = "\033[90m" // gray for gutter

	HelpText = `Inkog - Security Scanner with Hybrid Privacy

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

	// Determine quiet mode (disable spinners/colors for JSON output or CI environments)
	isQuietMode := *outputFlag == "json" || os.Getenv("CI") != ""

	// Create scanner with quiet mode
	scanner := cli.NewHybridScanner(*pathFlag, serverURL, *verboseFlag, isQuietMode)

	if *verboseFlag && !isQuietMode {
		fmt.Println("🔐 Inkog Hybrid Privacy Scanner")
		fmt.Printf("📍 Scanning: %s\n", *pathFlag)
	}

	// Run scan
	result, err := scanner.Scan()
	if err != nil {
		log.Fatalf("❌ Scan failed: %v\n", err)
	}

	// Output results
	if err := outputResults(result, *outputFlag, *severityFlag, *verboseFlag, isQuietMode); err != nil {
		log.Fatalf("❌ Output failed: %v\n", err)
	}

	// Determine exit code based on findings
	totalFindings := len(result.AllFindings)
	if totalFindings > 0 {
		if !isQuietMode {
			fmt.Printf("\n⚠️  Scan complete: %d security issues found\n", totalFindings)
		}
		os.Exit(1)
	}

	if !isQuietMode {
		fmt.Println("\n✅ Scan complete: No security issues found")
	}
	os.Exit(0)
}

// outputResults formats and displays scan results
func outputResults(result *cli.ScanResult, format, minSeverity string, verbose, quiet bool) error {
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

// outputText provides human-readable text output in Ruff/Semgrep code frame style
func outputText(result *cli.ScanResult, minSeverity string, verbose bool) error {
	if len(result.AllFindings) == 0 {
		fmt.Println("✓ No security issues found")
		return nil
	}

	// Sort by file path, then line number for natural reading order
	sortFindingsByLocation(result.AllFindings)

	// Display each finding in code frame format
	for _, f := range result.AllFindings {
		displayCodeFrame(f)
	}

	// Compact summary (single line)
	displayCompactSummary(result.AllFindings)

	return nil
}

// getSeverityColor returns the ANSI color code for a severity level
func getSeverityColor(severity string) string {
	switch severity {
	case "CRITICAL":
		return colorCritical
	case "HIGH":
		return colorHigh
	case "MEDIUM":
		return colorMedium
	case "LOW":
		return colorLow
	default:
		return colorReset
	}
}

// displayCodeFrame renders a single finding in diagnostic format (Ruff/Semgrep style)
func displayCodeFrame(f contract.Finding) {
	// 1. Location line (clickable in VS Code: file:line:col)
	severityColor := getSeverityColor(f.Severity)
	col := f.Column
	if col == 0 {
		col = 1 // Default to column 1 if not specified
	}
	fmt.Printf("%s:%d:%d %s[%s]%s %s\n",
		f.File, f.Line, col,
		severityColor, f.Severity, colorReset,
		f.Pattern)

	// 2. Code frame with gutter
	if f.Code != "" {
		fmt.Printf("%s│%s\n", colorGray, colorReset)
		lines := strings.Split(f.Code, "\n")
		for i, line := range lines {
			lineNum := f.Line + i
			// Truncate long lines for readability
			if len(line) > 80 {
				line = line[:77] + "..."
			}
			fmt.Printf("%s%3d│%s  %s\n", colorGray, lineNum, colorReset, line)
		}
		// Underline highlight with message
		if col > 0 && f.Message != "" {
			underlineLen := 30
			if len(f.Message) < underlineLen {
				underlineLen = len(f.Message)
			}
			padding := strings.Repeat(" ", col-1)
			underline := strings.Repeat("^", underlineLen)
			fmt.Printf("%s   │%s  %s%s%s%s %s%s\n",
				colorGray, colorReset,
				padding, severityColor, underline, colorReset,
				f.Message, colorReset)
		}
		fmt.Printf("%s│%s\n", colorGray, colorReset)
	}

	// 3. Compliance footer
	compliance := []string{}
	if f.CWE != "" {
		compliance = append(compliance, f.CWE)
	}
	if f.OWASP != "" {
		compliance = append(compliance, f.OWASP)
	}
	if len(compliance) > 0 {
		fmt.Printf("%s= Compliance: %s%s\n", colorGray, strings.Join(compliance, " | "), colorReset)
	}
	fmt.Println()
}

// sortFindingsByLocation sorts findings by file path, then by line number
func sortFindingsByLocation(findings []contract.Finding) {
	// Simple bubble sort for stability (in production, use sort.Slice)
	for i := 0; i < len(findings); i++ {
		for j := i + 1; j < len(findings); j++ {
			// Compare by file first, then by line
			if findings[j].File < findings[i].File ||
				(findings[j].File == findings[i].File && findings[j].Line < findings[i].Line) {
				findings[i], findings[j] = findings[j], findings[i]
			}
		}
	}
}

// displayCompactSummary shows a single-line summary of findings
func displayCompactSummary(findings []contract.Finding) {
	counts := countBySeverity(findings)
	fmt.Printf("\nFound %d issues: %s%d critical%s, %s%d high%s, %s%d medium%s, %s%d low%s\n",
		len(findings),
		colorCritical, counts["CRITICAL"], colorReset,
		colorHigh, counts["HIGH"], colorReset,
		colorMedium, counts["MEDIUM"], colorReset,
		colorLow, counts["LOW"], colorReset)
}

// countBySeverity returns a map of severity levels to counts
func countBySeverity(findings []contract.Finding) map[string]int {
	counts := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
	}
	for _, f := range findings {
		counts[f.Severity]++
	}
	return counts
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

// outputJSON provides JSON output for integration with CI/CD
func outputJSON(result *cli.ScanResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

// Enterprise HTML Report - Dark Mode / Vercel-style
const htmlReportCSS = `
:root {
    --bg-primary: #0a0a0a;
    --bg-secondary: #171717;
    --bg-card: #1a1a1a;
    --text-primary: #fafafa;
    --text-secondary: #a1a1aa;
    --border: #27272a;
    --critical: #ef4444;
    --high: #f97316;
    --medium: #eab308;
    --low: #22c55e;
    --accent: #3b82f6;
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
    padding: 2rem;
    max-width: 1200px;
    margin: 0 auto;
}

header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 2rem;
    padding-bottom: 1rem;
    border-bottom: 1px solid var(--border);
}

header h1 {
    font-size: 1.5rem;
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

header h1::before {
    content: '🔒';
}

.timestamp {
    color: var(--text-secondary);
    font-size: 0.875rem;
}

.cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
}

.card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.25rem;
    text-align: center;
    transition: border-color 0.2s;
}

.card:hover {
    border-color: var(--text-secondary);
}

.card .value {
    font-size: 2.5rem;
    font-weight: 700;
    display: block;
    margin-bottom: 0.25rem;
}

.card .label {
    font-size: 0.75rem;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.card.risk .value { color: var(--accent); }
.card.critical .value { color: var(--critical); }
.card.high .value { color: var(--high); }
.card.medium .value { color: var(--medium); }
.card.low .value { color: var(--low); }

section {
    margin-bottom: 2rem;
}

section h2 {
    font-size: 1rem;
    font-weight: 600;
    margin-bottom: 1rem;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.compliance-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
}

.compliance-item {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.compliance-item .check {
    color: var(--text-secondary);
}

.compliance-item .status {
    font-weight: 600;
}

.compliance-item .status.pass { color: var(--low); }
.compliance-item .status.fail { color: var(--critical); }

.finding {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 0.75rem;
    overflow: hidden;
}

.finding-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1rem;
    cursor: pointer;
    transition: background 0.2s;
    gap: 1rem;
}

.finding-header:hover {
    background: var(--bg-card);
}

.finding-title {
    flex: 1;
    font-weight: 500;
    display: flex;
    align-items: center;
    gap: 0.75rem;
}

.finding-title .icon {
    opacity: 0.5;
    transition: transform 0.2s;
}

.finding.open .finding-title .icon {
    transform: rotate(90deg);
}

.finding-meta {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    color: var(--text-secondary);
    font-size: 0.875rem;
}

.finding-body {
    display: none;
    padding: 1rem;
    border-top: 1px solid var(--border);
    background: var(--bg-primary);
}

.finding.open .finding-body {
    display: block;
}

.finding-details {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    margin-bottom: 1rem;
}

.finding-details p {
    margin: 0;
}

.finding-details strong {
    color: var(--text-secondary);
    font-weight: 500;
    display: block;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 0.25rem;
}

.code-snippet {
    background: #000;
    padding: 1rem;
    border-radius: 6px;
    font-family: 'SF Mono', 'Monaco', 'Consolas', 'Liberation Mono', monospace;
    font-size: 0.8125rem;
    overflow-x: auto;
    white-space: pre;
    color: #e4e4e7;
    border: 1px solid var(--border);
}

.severity-badge {
    padding: 0.25rem 0.625rem;
    border-radius: 9999px;
    font-size: 0.6875rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.025em;
}

.severity-critical { background: var(--critical); color: white; }
.severity-high { background: var(--high); color: white; }
.severity-medium { background: var(--medium); color: #171717; }
.severity-low { background: var(--low); color: white; }

.empty-state {
    text-align: center;
    padding: 3rem;
    color: var(--text-secondary);
}

.empty-state .icon {
    font-size: 3rem;
    margin-bottom: 1rem;
}

footer {
    margin-top: 3rem;
    padding-top: 1rem;
    border-top: 1px solid var(--border);
    text-align: center;
    color: var(--text-secondary);
    font-size: 0.75rem;
}

footer a {
    color: var(--accent);
    text-decoration: none;
}

footer a:hover {
    text-decoration: underline;
}

/* Print styles for CISO-friendly PDF export */
@media print {
    /* Reset to light mode for printing */
    :root {
        --bg-primary: #ffffff;
        --bg-secondary: #f5f5f5;
        --bg-card: #ffffff;
        --text-primary: #171717;
        --text-secondary: #525252;
        --border: #e5e5e5;
    }

    body {
        background: white;
        color: black;
        padding: 0;
        max-width: none;
    }

    /* Hide interactive elements */
    .filter-buttons,
    .finding-title .icon,
    footer a {
        display: none !important;
    }

    /* Expand all findings */
    .finding-body {
        display: block !important;
    }

    /* Remove hover effects */
    .card:hover,
    .finding-header:hover {
        border-color: var(--border);
        background: transparent;
    }

    /* Ensure cards print in a row */
    .cards {
        display: flex;
        flex-wrap: wrap;
        gap: 0.5rem;
    }

    .card {
        flex: 1;
        min-width: 100px;
        border: 1px solid #ccc;
        page-break-inside: avoid;
    }

    /* Code snippets print-friendly */
    .code-snippet {
        background: #f5f5f5;
        color: #171717;
        border: 1px solid #ccc;
        white-space: pre-wrap;
        word-wrap: break-word;
    }

    /* Severity badges print-friendly */
    .severity-badge {
        border: 1px solid currentColor;
    }

    .severity-critical { background: #fee2e2; color: #991b1b; }
    .severity-high { background: #ffedd5; color: #9a3412; }
    .severity-medium { background: #fef3c7; color: #92400e; }
    .severity-low { background: #dcfce7; color: #166534; }

    /* Page breaks */
    .finding {
        page-break-inside: avoid;
        margin-bottom: 1rem;
    }

    section {
        page-break-before: auto;
    }

    /* Compliance section should not break */
    .compliance-grid {
        page-break-inside: avoid;
    }

    @page {
        margin: 2cm;
    }
}
`

const htmlReportJS = `
document.querySelectorAll('.finding-header').forEach(header => {
    header.addEventListener('click', () => {
        header.parentElement.classList.toggle('open');
    });
});
`

// outputHTML provides enterprise HTML report with dark mode / Vercel-style design
func outputHTML(result *cli.ScanResult, minSeverity string) error {
	// Calculate metrics
	criticalCount := len(filterFindingsBySeverity(result.AllFindings, "CRITICAL"))
	highCount := len(filterFindingsBySeverity(result.AllFindings, "HIGH"))
	mediumCount := len(filterFindingsBySeverity(result.AllFindings, "MEDIUM"))
	lowCount := len(filterFindingsBySeverity(result.AllFindings, "LOW"))
	totalCount := len(result.AllFindings)

	// Calculate risk score (0-10 scale)
	riskScore := float64(criticalCount)*2.5 + float64(highCount)*1.5 + float64(mediumCount)*0.5 + float64(lowCount)*0.1
	if riskScore > 10 {
		riskScore = 10
	}

	// Compliance checks
	noCritical := criticalCount == 0
	noHigh := highCount == 0
	compliant := noCritical && noHigh

	// Generate findings HTML
	findingsHTML := generateFindingsHTML(result.AllFindings)

	// Build the full HTML
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Inkog Security Report</title>
    <style>%s</style>
</head>
<body>
    <header>
        <h1>Inkog Security Report</h1>
        <span class="timestamp">Generated: %s</span>
    </header>

    <div class="cards">
        <div class="card risk">
            <span class="value">%.1f</span>
            <span class="label">Risk Score</span>
        </div>
        <div class="card critical">
            <span class="value">%d</span>
            <span class="label">Critical</span>
        </div>
        <div class="card high">
            <span class="value">%d</span>
            <span class="label">High</span>
        </div>
        <div class="card medium">
            <span class="value">%d</span>
            <span class="label">Medium</span>
        </div>
        <div class="card low">
            <span class="value">%d</span>
            <span class="label">Low</span>
        </div>
    </div>

    <section>
        <h2>Compliance Status</h2>
        <div class="compliance-grid">
            <div class="compliance-item">
                <span class="check">No Critical Issues</span>
                <span class="status %s">%s</span>
            </div>
            <div class="compliance-item">
                <span class="check">No High Issues</span>
                <span class="status %s">%s</span>
            </div>
            <div class="compliance-item">
                <span class="check">Overall Compliance</span>
                <span class="status %s">%s</span>
            </div>
        </div>
    </section>

    <section>
        <h2>Security Findings (%d)</h2>
        %s
    </section>

    <footer>
        <p>Report generated by <a href="https://inkog.io" target="_blank">Inkog</a> Security Scanner v%s</p>
    </footer>

    <script>%s</script>
</body>
</html>`,
		htmlReportCSS,
		// Timestamp
		currentTimestamp(),
		// Cards
		riskScore,
		criticalCount,
		highCount,
		mediumCount,
		lowCount,
		// Compliance - No Critical
		statusClass(noCritical), statusText(noCritical),
		// Compliance - No High
		statusClass(noHigh), statusText(noHigh),
		// Compliance - Overall
		statusClass(compliant), statusText(compliant),
		// Findings
		totalCount,
		findingsHTML,
		// Footer
		AppVersion,
		htmlReportJS,
	)

	fmt.Println(html)
	return nil
}

// generateFindingsHTML creates the HTML for all findings
func generateFindingsHTML(findings []contract.Finding) string {
	if len(findings) == 0 {
		return `<div class="empty-state">
            <div class="icon">✅</div>
            <p>No security issues found</p>
        </div>`
	}

	var sb strings.Builder
	for _, f := range findings {
		// Escape HTML in user content
		pattern := escapeHTML(f.Pattern)
		file := escapeHTML(f.File)
		message := escapeHTML(f.Message)
		code := escapeHTML(f.Code)
		if code == "" {
			code = "(No code snippet available)"
		}

		sb.WriteString(fmt.Sprintf(`
        <div class="finding">
            <div class="finding-header">
                <div class="finding-title">
                    <span class="icon">▶</span>
                    <span>%s</span>
                </div>
                <div class="finding-meta">
                    <span>%s:%d</span>
                    <span class="severity-badge severity-%s">%s</span>
                </div>
            </div>
            <div class="finding-body">
                <div class="finding-details">
                    <p>
                        <strong>File</strong>
                        %s:%d:%d
                    </p>
                    <p>
                        <strong>CWE</strong>
                        %s
                    </p>
                    <p>
                        <strong>OWASP</strong>
                        %s
                    </p>
                    <p>
                        <strong>Confidence</strong>
                        %.0f%%
                    </p>
                </div>
                <p style="margin-bottom: 1rem; color: var(--text-secondary);">%s</p>
                <div class="code-snippet">%s</div>
            </div>
        </div>`,
			pattern,
			file, f.Line,
			strings.ToLower(f.Severity), f.Severity,
			file, f.Line, f.Column,
			f.CWE,
			f.OWASP,
			f.Confidence*100,
			message,
			code,
		))
	}
	return sb.String()
}

// Helper functions for HTML report
func currentTimestamp() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

func statusClass(pass bool) string {
	if pass {
		return "pass"
	}
	return "fail"
}

func statusText(pass bool) string {
	if pass {
		return "PASS"
	}
	return "FAIL"
}

func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}
