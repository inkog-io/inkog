package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/inkog-io/inkog/pkg/contract"
	"github.com/inkog-io/inkog/pkg/patterns/secrets"
)

const (
	CLIVersion       = "1.0.0"
	ContractVersion  = "v1"
	DefaultServerURL = "https://api.inkog.io"
)

// HybridScanner performs client-side secret detection + server-side logic analysis
type HybridScanner struct {
	ServerURL  string
	SourcePath string
	Verbose    bool
}

// ScanResult contains both local and remote findings
type ScanResult struct {
	LocalSecrets   []contract.Finding `json:"local_secrets"`
	ServerFindings []contract.Finding `json:"server_findings"`
	AllFindings    []contract.Finding `json:"all_findings"`
	Report         string             `json:"report"`
}

// NewHybridScanner creates a new scanner instance
func NewHybridScanner(sourcePath, serverURL string, verbose bool) *HybridScanner {
	if serverURL == "" {
		serverURL = DefaultServerURL
	}
	return &HybridScanner{
		ServerURL:  serverURL,
		SourcePath: sourcePath,
		Verbose:    verbose,
	}
}

// Scan performs the complete hybrid scanning workflow
func (hs *HybridScanner) Scan() (*ScanResult, error) {
	if hs.Verbose {
		fmt.Println("🔍 Starting hybrid security scan...")
		fmt.Printf("   Source: %s\n", hs.SourcePath)
		fmt.Printf("   Server: %s\n", hs.ServerURL)
	}

	// STEP 1: Scan for secrets locally and collect all files
	localSecrets, allFiles, err := hs.scanLocalSecretsAndCollectFiles()
	if err != nil {
		return nil, fmt.Errorf("local secret scan failed: %w", err)
	}

	if hs.Verbose {
		fmt.Printf("✓ Found %d local secrets in %d files\n", len(localSecrets), len(allFiles))
	}

	// STEP 2: Redact secrets from files
	redactedFiles, _, err := hs.redactSecretsFromFiles(allFiles)
	if err != nil {
		return nil, fmt.Errorf("redaction failed: %w", err)
	}

	if hs.Verbose {
		fmt.Printf("✓ Redacted secrets from %d files\n", len(allFiles))
	}

	// STEP 3: Send to server for logic analysis
	serverResult, err := hs.sendToServer(redactedFiles, len(localSecrets), len(allFiles))
	if err != nil {
		return nil, fmt.Errorf("server communication failed: %w", err)
	}

	if hs.Verbose {
		fmt.Printf("✓ Server found %d logic issues\n", len(serverResult.Findings))
	}

	// STEP 4: Merge results
	allFindings := hs.mergeFindings(localSecrets, serverResult.Findings)

	return &ScanResult{
		LocalSecrets:   localSecrets,
		ServerFindings: serverResult.Findings,
		AllFindings:    allFindings,
	}, nil
}

// scanLocalSecretsAndCollectFiles detects secrets and collects all source files for server analysis
func (hs *HybridScanner) scanLocalSecretsAndCollectFiles() ([]contract.Finding, map[string]bool, error) {
	var localFindings []contract.Finding
	allFiles := make(map[string]bool)

	err := filepath.Walk(hs.SourcePath, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and non-source files
		if info.IsDir() || !shouldScanFile(filePath) {
			return nil
		}

		content, err := ioutil.ReadFile(filePath)
		if err != nil {
			return nil // Skip unreadable files
		}

		// Collect ALL files for server analysis
		allFiles[filePath] = true

		// Detect secrets locally
		secretFindings := secrets.DetectSecrets(filePath, content)
		if len(secretFindings) > 0 {
			// Convert secret findings to contract findings
			for _, sf := range secretFindings {
				// Get CWE and OWASP from pattern definition
				var cwe, owasp string
				if pattern, ok := secrets.PatternDefinitions[sf.Type]; ok {
					cwe = pattern.CWE
					owasp = pattern.OWASP
				}

				finding := contract.Finding{
					ID:         fmt.Sprintf("secret_%s_%d_%d", sf.Type, sf.Line, sf.Column),
					PatternID:  "hardcoded_credentials_" + sf.Type,
					Pattern:    "Hardcoded Credentials - " + strings.ToTitle(sf.Type),
					Source:     contract.SourceLocalCLI,
					File:       filePath,
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

	return localFindings, allFiles, err
}

// redactSecretsFromFiles returns redacted file contents as a map
// Returns: map[fieldName]content, totalBytes, error
func (hs *HybridScanner) redactSecretsFromFiles(redactedFiles map[string]bool) (map[string][]byte, int, error) {
	if hs.Verbose {
		fmt.Printf("📦 Adding files to upload:\n")
	}

	filesMap := make(map[string][]byte)
	totalBytes := 0
	filesAdded := 0

	// For each file, redact secrets and store
	for filePath := range redactedFiles {
		content, err := ioutil.ReadFile(filePath)
		if err != nil {
			continue
		}

		// Detect and redact secrets
		secretFindings := secrets.DetectSecrets(filePath, content)
		redactedContent := secrets.RedactSecrets(content, secretFindings)

		// Create field name for multipart form using URL encoding
		relPath, _ := filepath.Rel(hs.SourcePath, filePath)
		encodedPath := url.PathEscape(relPath)
		fieldName := "file_" + encodedPath

		filesMap[fieldName] = redactedContent
		totalBytes += len(redactedContent)

		if hs.Verbose {
			fmt.Printf("   ✓ %s (%d bytes)\n", relPath, len(redactedContent))
		}

		filesAdded++
	}

	if hs.Verbose {
		fmt.Printf("📊 Total files added: %d\n", filesAdded)
		fmt.Printf("📦 Upload payload size: %d bytes\n", totalBytes)
	}

	return filesMap, totalBytes, nil
}

// sendToServer sends sanitized content to the Inkog server
func (hs *HybridScanner) sendToServer(redactedFiles map[string][]byte, localSecretCount, redactedFileCount int) (*contract.ScanResult, error) {
	// Create scan request
	request := contract.ScanRequest{
		ContractVersion:   ContractVersion,
		CLIVersion:        CLIVersion,
		SecretsVersion:    secrets.SecretsVersionHash(),
		LocalSecrets:      localSecretCount,
		RedactedFileCount: redactedFileCount,
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

	// Send to server
	resp, err := http.Post(
		hs.ServerURL+"/api/v1/scan",
		writer.FormDataContentType(),
		&buf,
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("server error %d: %s", resp.StatusCode, string(body))
	}

	// Parse server response
	var scanResponse contract.ScanResponse
	if err := json.NewDecoder(resp.Body).Decode(&scanResponse); err != nil {
		return nil, fmt.Errorf("failed to parse server response: %w", err)
	}

	if !scanResponse.Success {
		return nil, fmt.Errorf("server returned error: %s", scanResponse.Error)
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

// shouldScanFile determines if a file should be scanned
func shouldScanFile(path string) bool {
	ext := filepath.Ext(path)
	scannableExts := map[string]bool{
		".py":   true,
		".js":   true,
		".ts":   true,
		".tsx":  true,
		".go":   true,
		".java": true,
		".rb":   true,
		".php":  true,
		".cs":   true,
		".rs":   true,
		".cpp":  true,
		".c":    true,
		".sh":   true,
		".yaml": true,
		".yml":  true,
		".json": true,
		".xml":  true,
		".env":  true,
		".conf": true,
		".cfg":  true,
	}
	return scannableExts[ext]
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
