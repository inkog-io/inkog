package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/inkog-io/inkog/pkg/contract"
	"github.com/inkog-io/inkog/pkg/patterns/secrets"
)

// LocalScanner performs fully offline scanning using the inkog-worker binary.
// This enables scanning without any network connection by spawning the worker
// as a subprocess and parsing its JSON output.
type LocalScanner struct {
	SourcePath string
	Verbose    bool
	Quiet      bool
	progress   *ProgressReporter
}

// NewLocalScanner creates a new local scanner instance
func NewLocalScanner(sourcePath string, verbose, quiet bool) *LocalScanner {
	return &LocalScanner{
		SourcePath: sourcePath,
		Verbose:    verbose,
		Quiet:      quiet,
		progress:   NewProgressReporter(quiet),
	}
}

// Scan performs a fully offline scan using the local worker binary
func (ls *LocalScanner) Scan() (*ScanResult, error) {
	// STEP 1: Find the worker binary
	workerPath, err := ls.findWorkerBinary()
	if err != nil {
		return nil, err
	}

	if ls.Verbose && !ls.Quiet {
		fmt.Fprintf(os.Stderr, "🔧 Using worker: %s\n", workerPath)
	}

	// STEP 2: Scan for secrets locally
	ls.progress.Start("Scanning for secrets...")
	localSecrets, err := ls.scanLocalSecrets()
	if err != nil {
		ls.progress.Fail("Local scan failed")
		return nil, fmt.Errorf("local secret scan failed: %w", err)
	}
	ls.progress.Success(fmt.Sprintf("Found %d local secrets", len(localSecrets)))

	// STEP 3: Run the worker binary
	ls.progress.Start("Running local analysis...")
	workerFindings, err := ls.runWorker(workerPath)
	if err != nil {
		ls.progress.Fail("Worker analysis failed")
		return nil, fmt.Errorf("worker analysis failed: %w", err)
	}
	ls.progress.Success(fmt.Sprintf("Found %d logic issues", len(workerFindings)))

	// STEP 4: Merge results
	allFindings := ls.mergeFindings(localSecrets, workerFindings)

	return &ScanResult{
		LocalSecrets:   localSecrets,
		ServerFindings: workerFindings,
		AllFindings:    allFindings,
	}, nil
}

// findWorkerBinary locates the inkog-worker binary
func (ls *LocalScanner) findWorkerBinary() (string, error) {
	// Check common locations in order of preference
	searchPaths := []string{
		// 1. INKOG_WORKER_PATH environment variable
		os.Getenv("INKOG_WORKER_PATH"),
		// 2. Same directory as the CLI binary
		filepath.Join(filepath.Dir(os.Args[0]), "inkog-worker"),
		// 3. Current directory
		"./inkog-worker",
		// 4. System PATH
		"inkog-worker",
	}

	for _, path := range searchPaths {
		if path == "" {
			continue
		}

		// Check if it's an absolute path or in PATH
		if filepath.IsAbs(path) || path == "inkog-worker" {
			if resolved, err := exec.LookPath(path); err == nil {
				return resolved, nil
			}
		} else {
			// Check relative path
			if _, err := os.Stat(path); err == nil {
				absPath, _ := filepath.Abs(path)
				return absPath, nil
			}
		}
	}

	return "", fmt.Errorf(`inkog-worker binary not found

The --local flag requires the inkog-worker binary for offline scanning.
This feature is available for Enterprise customers with self-hosted licenses.

For cloud-based scanning (recommended), remove the --local flag:
  inkog -path /path/to/scan

Contact sales@inkog.io for Enterprise self-hosted deployment options.
`)
}

// scanLocalSecrets detects secrets in files
func (ls *LocalScanner) scanLocalSecrets() ([]contract.Finding, error) {
	var findings []contract.Finding

	err := filepath.Walk(ls.SourcePath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !shouldScanFile(path) {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		secretFindings := secrets.DetectSecrets(path, content)
		for _, sf := range secretFindings {
			var cwe, owasp string
			if pattern, ok := secrets.PatternDefinitions[sf.Type]; ok {
				cwe = pattern.CWE
				owasp = pattern.OWASP
			}

			finding := contract.Finding{
				ID:         fmt.Sprintf("secret_%s_%d_%d", sf.Type, sf.Line, sf.Column),
				PatternID:  "hardcoded_credentials_" + sf.Type,
				Pattern:    "Hardcoded Credentials",
				Source:     contract.SourceLocalCLI,
				File:       path,
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
			findings = append(findings, finding)
		}

		return nil
	})

	return findings, err
}

// WorkerOutput represents the JSON output from inkog-worker
type WorkerOutput struct {
	Findings []WorkerFinding `json:"findings"`
	Summary  struct {
		TotalFiles   int `json:"total_files"`
		ScannedFiles int `json:"scanned_files"`
		SkippedFiles int `json:"skipped_files"`
		TotalNodes   int `json:"total_nodes"`
	} `json:"summary"`
}

// WorkerFinding represents a finding from the worker
type WorkerFinding struct {
	PatternID    string  `json:"pattern_id"`
	Pattern      string  `json:"pattern"`
	File         string  `json:"file"`
	Line         int     `json:"line"`
	Column       int     `json:"column"`
	Severity     string  `json:"severity"`
	Confidence   float32 `json:"confidence"`
	Message      string  `json:"message"`
	Category     string  `json:"category"`
	RiskTier     string  `json:"risk_tier"`
	CWE          string  `json:"cwe"`
	CVSS         float32 `json:"cvss"`
	OWASP        string  `json:"owasp"`
	InputTainted bool    `json:"input_tainted"`
	TaintSource  string  `json:"taint_source"`
	Code         string  `json:"code_snippet"`
}

// runWorker executes the inkog-worker binary and parses its output
func (ls *LocalScanner) runWorker(workerPath string) ([]contract.Finding, error) {
	// Get absolute path for scanning
	absPath, err := filepath.Abs(ls.SourcePath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve path: %w", err)
	}

	// Run the worker
	cmd := exec.Command(workerPath, "--path", absPath)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Check for specific error messages
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("worker failed (exit %d): %s", exitErr.ExitCode(), stderr.String())
		}
		return nil, fmt.Errorf("worker execution failed: %w", err)
	}

	// Parse the JSON output
	var output WorkerOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		// Try to show what we got
		if ls.Verbose {
			fmt.Fprintf(os.Stderr, "Worker output: %s\n", stdout.String())
		}
		return nil, fmt.Errorf("failed to parse worker output: %w", err)
	}

	// Convert worker findings to contract findings
	var findings []contract.Finding
	for _, wf := range output.Findings {
		finding := contract.Finding{
			ID:           fmt.Sprintf("%s_%s_%d", wf.PatternID, filepath.Base(wf.File), wf.Line),
			PatternID:    wf.PatternID,
			Pattern:      wf.Pattern,
			Source:       contract.SourceServerLogic,
			File:         wf.File,
			Line:         wf.Line,
			Column:       wf.Column,
			Severity:     wf.Severity,
			Confidence:   wf.Confidence,
			Message:      wf.Message,
			Category:     wf.Category,
			RiskTier:     wf.RiskTier,
			CWE:          wf.CWE,
			CVSS:         wf.CVSS,
			OWASP:        wf.OWASP,
			InputTainted: wf.InputTainted,
			TaintSource:  wf.TaintSource,
			Code:         wf.Code,
		}
		findings = append(findings, finding)
	}

	return findings, nil
}

// mergeFindings combines local and worker findings
func (ls *LocalScanner) mergeFindings(localSecrets, workerFindings []contract.Finding) []contract.Finding {
	merged := make([]contract.Finding, len(localSecrets))
	copy(merged, localSecrets)
	merged = append(merged, workerFindings...)
	sortFindings(merged)
	return merged
}
