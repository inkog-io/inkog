package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/inkog-io/inkog/pkg/contract"
	"github.com/inkog-io/inkog/pkg/patterns/secrets"
)

const (
	CLIVersion       = "1.0.0"
	ContractVersion  = "v1"
	DefaultServerURL = "https://api.inkog.io"
)

// DefaultScanExtensions defines file types to scan for security analysis.
// Supports: Python (CrewAI, AutoGen, LangChain), No-Code (n8n, Flowise), and more.
var DefaultScanExtensions = map[string]bool{
	// Python ecosystem
	".py":    true,
	".ipynb": true, // Jupyter notebooks (contains Python cells)

	// JavaScript/TypeScript
	".js":  true,
	".ts":  true,
	".tsx": true,

	// No-Code / Low-Code workflow configs
	".json": true, // n8n, Flowise, Langflow
	".yaml": true,
	".yml":  true,

	// Other languages
	".go":   true,
	".java": true,
	".rb":   true,
	".php":  true,
	".cs":   true,
	".rs":   true,
	".cpp":  true,
	".c":    true,
	".sh":   true,

	// Config files
	".xml":  true,
	".env":  true,
	".conf": true,
	".cfg":  true,
}

// ExcludedDirectories contains paths that should never be scanned.
var ExcludedDirectories = []string{
	"node_modules",
	"vendor",
	".git",
	".svn",
	"__pycache__",
	".venv",
	"venv",
	"dist",
	"build",
	".next",
	".nuxt",
	".pytest_cache",
	".mypy_cache",
	"egg-info",
}

// BlockedFiles contains filenames that should not be scanned (build/config noise).
var BlockedFiles = map[string]bool{
	"package.json":        true,
	"package-lock.json":   true,
	"tsconfig.json":       true,
	"jsconfig.json":       true,
	"yarn.lock":           true,
	"pnpm-lock.yaml":      true,
	"composer.json":       true,
	"composer.lock":       true,
	"Cargo.toml":          true,
	"Cargo.lock":          true,
	"go.sum":              true,
	"go.mod":              true,
	"Gemfile":             true,
	"Gemfile.lock":        true,
	"poetry.lock":         true,
	"Pipfile.lock":        true,
	".eslintrc.json":      true,
	".eslintrc.yaml":      true,
	".prettierrc.json":    true,
	".prettierrc.yaml":    true,
	"babel.config.json":   true,
	"nest-cli.json":       true,
	"angular.json":        true,
	"turbo.json":          true,
	"vercel.json":         true,
	"now.json":            true,
	"renovate.json":       true,
	"lerna.json":          true,
	".babelrc":            true,
	"webpack.config.js":   true,
	"rollup.config.js":    true,
	"vite.config.js":      true,
	"vite.config.ts":      true,
	"jest.config.js":      true,
	"jest.config.json":    true,
	"tsconfig.build.json": true,
	"tsconfig.spec.json":  true,
}

// HybridScanner performs client-side secret detection + server-side logic analysis
type HybridScanner struct {
	ServerURL  string
	SourcePath string
	Policy     string // Security policy to send to server
	MaxFiles   int    // Maximum files to upload (0 = default 500)
	Verbose    bool
	Quiet      bool // Disable spinners/colors (for JSON output or CI)
	progress   *ProgressReporter
	client     *InkogClient
}

const (
	DefaultMaxFiles   = 500
	MaxUploadSizeMB   = 95 // Client-side limit (server is 100MB, leave margin)
)

// ScanResult contains both local and remote findings
type ScanResult struct {
	LocalSecrets      []contract.Finding         `json:"local_secrets"`
	ServerFindings    []contract.Finding         `json:"server_findings"`
	AllFindings       []contract.Finding         `json:"all_findings"`
	ComplianceReport  *contract.ComplianceReport `json:"compliance_report,omitempty"`
	Report            string                     `json:"report"`

	// Governance fields (forwarded from server)
	GovernanceScore  int                               `json:"governance_score"`
	EUAIActReadiness string                            `json:"eu_ai_act_readiness"`
	ArticleMapping   map[string]contract.ArticleStatus `json:"article_mapping,omitempty"`
	FrameworkMapping map[string]contract.FrameworkStatus `json:"framework_mapping,omitempty"`
	TopologyMap      *contract.TopologyMap             `json:"topology_map,omitempty"`
}

// NewHybridScanner creates a new scanner instance
// Set quiet=true to disable spinners and colors (for JSON output or CI environments)
func NewHybridScanner(sourcePath, serverURL, policy string, verbose, quiet bool) *HybridScanner {
	if serverURL == "" {
		serverURL = DefaultServerURL
	}

	progress := NewProgressReporter(quiet)
	client := NewInkogClient(serverURL, quiet, progress)

	return &HybridScanner{
		ServerURL:  serverURL,
		SourcePath: sourcePath,
		Policy:     policy,
		MaxFiles:   DefaultMaxFiles,
		Verbose:    verbose,
		Quiet:      quiet,
		progress:   progress,
		client:     client,
	}
}

// Scan performs the complete hybrid scanning workflow
func (hs *HybridScanner) Scan() (*ScanResult, error) {
	if hs.Verbose && !hs.Quiet {
		fmt.Fprintf(os.Stderr, "🔍 Starting hybrid security scan...\n")
		fmt.Fprintf(os.Stderr, "   Source: %s\n", hs.SourcePath)
		fmt.Fprintf(os.Stderr, "   Server: %s\n", hs.ServerURL)
	}

	// STEP 1: Scan for secrets locally and collect all files
	hs.progress.Start("Scanning local files...")
	localSecrets, allFiles, err := hs.scanLocalSecretsAndCollectFiles()
	if err != nil {
		hs.progress.Fail("Local scan failed")
		return nil, fmt.Errorf("local secret scan failed: %w", err)
	}
	hs.progress.Success(fmt.Sprintf("Found %d local secrets in %d files", len(localSecrets), len(allFiles)))

	// STEP 2: Redact secrets from files
	hs.progress.Start("Redacting sensitive data...")
	redactedFiles, _, err := hs.redactSecretsFromFiles(allFiles)
	if err != nil {
		hs.progress.Fail("Redaction failed")
		return nil, fmt.Errorf("redaction failed: %w", err)
	}
	hs.progress.Success(fmt.Sprintf("Redacted secrets from %d files", len(allFiles)))

	// STEP 3: Send to server for logic analysis
	hs.progress.Start("Uploading to Inkog...")
	serverResult, err := hs.sendToServer(redactedFiles, len(localSecrets), len(allFiles))
	if err != nil {
		hs.progress.Fail("Server communication failed")
		return nil, err // Error is already formatted by client
	}
	hs.progress.Success(fmt.Sprintf("Server found %d logic issues", len(serverResult.Findings)))

	// STEP 4: Merge results
	allFindings := hs.mergeFindings(localSecrets, serverResult.Findings)

	// STEP 5: Update severity counts to include local secrets
	// Server counts only reflect server-side findings; local secrets must be added
	for _, f := range localSecrets {
		switch f.Severity {
		case "CRITICAL":
			serverResult.CriticalCount++
		case "HIGH":
			serverResult.HighCount++
		case "MEDIUM":
			serverResult.MediumCount++
		case "LOW":
			serverResult.LowCount++
		}
		serverResult.FindingsCount++
	}

	return &ScanResult{
		LocalSecrets:     localSecrets,
		ServerFindings:   serverResult.Findings,
		AllFindings:      allFindings,
		ComplianceReport: serverResult.ComplianceReport,

		// Forward all governance data from server
		GovernanceScore:  serverResult.GovernanceScore,
		EUAIActReadiness: serverResult.EUAIActReadiness,
		ArticleMapping:   serverResult.ArticleMapping,
		FrameworkMapping: serverResult.FrameworkMapping,
		TopologyMap:      serverResult.TopologyMap,
	}, nil
}

// scanLocalSecretsAndCollectFiles detects secrets and collects all source files for server analysis
func (hs *HybridScanner) scanLocalSecretsAndCollectFiles() ([]contract.Finding, map[string]bool, error) {
	var localFindings []contract.Finding
	allFiles := make(map[string]bool)

	// Load .gitignore patterns from root directory
	gitignore := LoadGitIgnore(hs.SourcePath)

	totalFound := 0

	err := filepath.Walk(hs.SourcePath, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Get relative path for gitignore matching
		relPath, relErr := filepath.Rel(hs.SourcePath, filePath)
		if relErr != nil {
			relPath = filePath
		}

		// Skip .gitignore'd paths (check directories too for early pruning)
		if relPath != "." && gitignore.Match(relPath, info.IsDir()) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip directories and non-source files
		if info.IsDir() || !shouldScanFile(filePath) {
			return nil
		}

		totalFound++

		content, err := os.ReadFile(filePath)
		if err != nil {
			return nil // Skip unreadable files
		}

		// Collect files for server analysis
		allFiles[filePath] = true

		// Detect secrets locally
		secretFindings := secrets.DetectSecrets(filePath, content)
		if len(secretFindings) > 0 {
			// Print privacy proof messages (verbose mode)
			if hs.Verbose && !hs.Quiet {
				displayPath, _ := filepath.Rel(hs.SourcePath, filePath)
				for _, sf := range secretFindings {
					fmt.Fprintf(os.Stderr, "[PRIVACY] ✓ Redacted potential %s in %s at line %d\n",
						sf.Type, displayPath, sf.Line)
				}
			}

			// Convert secret findings to contract findings
			for _, sf := range secretFindings {
				// Get CWE and OWASP from pattern definition
				var cwe, owasp string
				if pattern, ok := secrets.PatternDefinitions[sf.Type]; ok {
					cwe = pattern.CWE
					owasp = pattern.OWASP
				}

				// Use relative path to match server findings format
				findingPath := filePath
				if rel, err := filepath.Rel(hs.SourcePath, filePath); err == nil && rel != "." {
					findingPath = rel
				} else {
					findingPath = filepath.Base(filePath)
				}

				finding := contract.Finding{
					ID:         fmt.Sprintf("secret_%s_%d_%d", sf.Type, sf.Line, sf.Column),
					PatternID:  "hardcoded_credentials_" + sf.Type,
					Pattern:    "Hardcoded Credentials - " + strings.ToTitle(sf.Type),
					Source:     contract.SourceLocalCLI,
					File:       findingPath,
					Line:       sf.Line,
					Column:     sf.Column,
					Severity:   sf.Severity,
					Confidence: sf.Confidence,
					Message:    fmt.Sprintf("Hardcoded %s detected", sf.Type),
					CWE:        cwe,
					OWASP:      owasp,
					RedactedAt: &contract.RedactionInfo{
						Line:      sf.Line,
						Column:    sf.Column,
						Type:      sf.Type,
						PatternID: sf.Pattern,
					},
				}
				localFindings = append(localFindings, finding)
			}
		}

		return nil
	})

	// Enforce file count limit
	maxFiles := hs.MaxFiles
	if maxFiles <= 0 {
		maxFiles = DefaultMaxFiles
	}
	if len(allFiles) > maxFiles {
		if !hs.Quiet {
			fmt.Fprintf(os.Stderr, "\n⚠️  Found %d files (max: %d). Scanning first %d files.\n", len(allFiles), maxFiles, maxFiles)
			fmt.Fprintf(os.Stderr, "   Use -max-files to increase the limit, or add patterns to .gitignore to exclude files.\n\n")
		}
		allFiles = truncateFileMap(allFiles, maxFiles, hs.SourcePath)
	}

	return localFindings, allFiles, err
}

// truncateFileMap reduces the file map to maxFiles entries, prioritizing agent-related files.
func truncateFileMap(files map[string]bool, maxFiles int, basePath string) map[string]bool {
	type scoredFile struct {
		path  string
		score int // higher = more relevant
	}

	// Score files by relevance to agent security scanning
	agentKeywords := []string{"agent", "tool", "chain", "crew", "flow", "graph", "prompt", "llm", "model", "openai", "anthropic"}
	scored := make([]scoredFile, 0, len(files))
	for path := range files {
		relPath := path
		if rel, err := filepath.Rel(basePath, path); err == nil {
			relPath = rel
		}
		lower := strings.ToLower(relPath)
		score := 0
		for _, kw := range agentKeywords {
			if strings.Contains(lower, kw) {
				score += 10
			}
		}
		// Prioritize Python and TypeScript (most common agent code)
		ext := filepath.Ext(path)
		if ext == ".py" || ext == ".ts" || ext == ".js" {
			score += 5
		}
		// Deprioritize config/data files
		if ext == ".json" || ext == ".yaml" || ext == ".yml" {
			score -= 2
		}
		scored = append(scored, scoredFile{path: path, score: score})
	}

	// Sort by score descending, then alphabetically for stability
	sort.Slice(scored, func(i, j int) bool {
		if scored[i].score != scored[j].score {
			return scored[i].score > scored[j].score
		}
		return scored[i].path < scored[j].path
	})

	// Take top maxFiles
	result := make(map[string]bool, maxFiles)
	for i := 0; i < maxFiles && i < len(scored); i++ {
		result[scored[i].path] = true
	}
	return result
}

// redactSecretsFromFiles returns redacted file contents as a map
// Returns: map[fieldName]content, totalBytes, error
func (hs *HybridScanner) redactSecretsFromFiles(redactedFiles map[string]bool) (map[string][]byte, int, error) {
	if hs.Verbose && !hs.Quiet {
		fmt.Fprintf(os.Stderr, "📦 Adding files to upload:\n")
	}

	filesMap := make(map[string][]byte)
	totalBytes := 0
	filesAdded := 0
	totalRedactions := 0

	// Determine the base path for computing relative paths
	// When scanning a single file, use its parent directory as base
	basePath := hs.SourcePath
	sourceInfo, err := os.Stat(hs.SourcePath)
	if err == nil && !sourceInfo.IsDir() {
		// Source is a single file - use parent directory as base
		basePath = filepath.Dir(hs.SourcePath)
	}

	// For each file, redact secrets and store
	for filePath := range redactedFiles {
		content, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		// Detect ALL secrets for redaction (unfiltered — privacy first)
		secretFindings := secrets.DetectSecretsForRedaction(filePath, content)
		redactedContent := secrets.RedactSecrets(content, secretFindings)
		totalRedactions += len(secretFindings)

		// Create field name for multipart form using URL encoding
		// Use the base path (parent directory for single files) to get proper relative path
		relPath, err := filepath.Rel(basePath, filePath)
		if err != nil || relPath == "." {
			// Fallback: use just the filename if relative path fails or is "."
			relPath = filepath.Base(filePath)
		}
		encodedPath := url.PathEscape(relPath)
		fieldName := "file_" + encodedPath

		filesMap[fieldName] = redactedContent
		totalBytes += len(redactedContent)

		if hs.Verbose && !hs.Quiet {
			fmt.Fprintf(os.Stderr, "   ✓ %s (%d bytes)\n", relPath, len(redactedContent))
		}

		filesAdded++
	}

	if hs.Verbose && !hs.Quiet {
		fmt.Fprintf(os.Stderr, "📊 Total files added: %d\n", filesAdded)
		fmt.Fprintf(os.Stderr, "📦 Upload payload size: %d bytes\n", totalBytes)
		if totalRedactions > 0 {
			fmt.Fprintf(os.Stderr, "🔒 Privacy Summary: %d secrets redacted before upload\n", totalRedactions)
		}
	}

	return filesMap, totalBytes, nil
}

// sendToServer sends sanitized content to the Inkog server using the InkogClient
func (hs *HybridScanner) sendToServer(redactedFiles map[string][]byte, localSecretCount, redactedFileCount int) (*contract.ScanResult, error) {
	// Create scan request
	request := contract.ScanRequest{
		ContractVersion:   ContractVersion,
		CLIVersion:        CLIVersion,
		SecretsVersion:    secrets.SecretsVersionHash(),
		LocalSecrets:      localSecretCount,
		RedactedFileCount: redactedFileCount,
		ScanPolicy:        hs.Policy,
	}

	// Create multipart request
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Add request metadata
	jsonData, _ := json.Marshal(request)
	part, _ := writer.CreateFormField("request")
	part.Write(jsonData)

	// Add each redacted file as a form field
	for fieldName, content := range redactedFiles {
		part, _ := writer.CreateFormField(fieldName)
		part.Write(content)
	}

	writer.Close()

	// Pre-upload size validation (server limit is 100MB, check at 95MB to leave margin)
	uploadSizeMB := buf.Len() / (1024 * 1024)
	if buf.Len() > MaxUploadSizeMB*1024*1024 {
		return nil, fmt.Errorf("upload payload is %dMB (max: %dMB). Reduce file count with -max-files or add patterns to .gitignore", uploadSizeMB, MaxUploadSizeMB)
	}

	// Update progress to show we're waiting for analysis
	hs.progress.Update("Analyzing code...")

	// Send to server using the InkogClient (with retry logic)
	scanResponse, err := hs.client.SendScan(writer.FormDataContentType(), &buf)
	if err != nil {
		return nil, err
	}

	return &scanResponse.ScanResult, nil
}

// mergeFindings combines local and server findings into a single report
func (hs *HybridScanner) mergeFindings(localSecrets []contract.Finding, serverFindings []contract.Finding) []contract.Finding {
	// Start with local secrets
	merged := make([]contract.Finding, len(localSecrets))
	copy(merged, localSecrets)

	// Add server findings
	merged = append(merged, serverFindings...)

	// Sort by severity and line number
	sortFindings(merged)

	return merged
}

// Helper functions

// shouldScanFile determines if a file should be scanned.
// Uses package-level constants for easy configuration.
func shouldScanFile(path string) bool {
	// Check excluded directories
	for _, dir := range ExcludedDirectories {
		if strings.Contains(path, string(filepath.Separator)+dir+string(filepath.Separator)) ||
			strings.HasPrefix(path, dir+string(filepath.Separator)) {
			return false
		}
	}

	// Check blocked files
	filename := filepath.Base(path)
	if BlockedFiles[filename] {
		return false
	}

	// Check supported extensions
	ext := filepath.Ext(path)
	return DefaultScanExtensions[ext]
}

// sortFindings sorts findings by severity then line number
func sortFindings(findings []contract.Finding) {
	// Simple bubble sort (in production, use sort.Slice)
	for i := 0; i < len(findings); i++ {
		for j := i + 1; j < len(findings); j++ {
			if contract.SeverityLevels[findings[j].Severity] > contract.SeverityLevels[findings[i].Severity] {
				findings[i], findings[j] = findings[j], findings[i]
			} else if contract.SeverityLevels[findings[j].Severity] == contract.SeverityLevels[findings[i].Severity] &&
				findings[j].Line < findings[i].Line {
				findings[i], findings[j] = findings[j], findings[i]
			}
		}
	}
}
