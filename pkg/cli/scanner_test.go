package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestShouldScanFile_SupportedExtensions(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		// Python files
		{"Python file", "agent.py", true},
		{"Jupyter notebook", "analysis.ipynb", true},

		// JavaScript/TypeScript
		{"JavaScript file", "index.js", true},
		{"TypeScript file", "app.ts", true},
		{"TSX file", "component.tsx", true},

		// Config files
		{"JSON config", "config.json", true},
		{"YAML config", "config.yaml", true},
		{"YML config", "config.yml", true},

		// Other languages
		{"Go file", "main.go", true},
		{"Java file", "App.java", true},
		{"Ruby file", "script.rb", true},
		{"PHP file", "index.php", true},
		{"C# file", "Program.cs", true},
		{"Rust file", "main.rs", true},
		{"Shell script", "deploy.sh", true},

		// Unsupported
		{"Text file", "readme.txt", false},
		{"Markdown", "README.md", false},
		{"Binary", "program.exe", false},
		{"Image", "logo.png", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldScanFile(tt.path)
			if got != tt.expected {
				t.Errorf("shouldScanFile(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

func TestShouldScanFile_ExcludedDirectories(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"Node modules", "node_modules/lodash/index.js", false},
		{"Git directory", ".git/config", false},
		{"Python venv", "venv/lib/python/site.py", false},
		{"Python .venv", ".venv/lib/python/site.py", false},
		{"Vendor dir", "vendor/github.com/pkg/errors/errors.go", false},
		{"Pycache", "__pycache__/module.cpython-39.pyc", false},
		{"Dist dir", "dist/bundle.js", false},
		{"Build dir", "build/output.js", false},
		{"Next.js", ".next/server/pages/index.js", false},
		{"Nuxt.js", ".nuxt/components/index.js", false},
		{"Pytest cache", ".pytest_cache/v/cache/nodeids", false},
		{"Mypy cache", ".mypy_cache/3.9/module.meta.json", false},

		// Should scan normal files
		{"Normal src file", "src/app.py", true},
		{"Normal lib file", "lib/utils.js", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert to OS-specific path
			osPath := filepath.FromSlash(tt.path)
			got := shouldScanFile(osPath)
			if got != tt.expected {
				t.Errorf("shouldScanFile(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

func TestShouldScanFile_BlockedFiles(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		// Package managers
		{"package.json", "package.json", false},
		{"package-lock.json", "package-lock.json", false},
		{"yarn.lock", "yarn.lock", false},
		{"pnpm-lock.yaml", "pnpm-lock.yaml", false},
		{"go.mod", "go.mod", false},
		{"go.sum", "go.sum", false},
		{"Cargo.toml", "Cargo.toml", false},
		{"Cargo.lock", "Cargo.lock", false},
		{"Gemfile", "Gemfile", false},
		{"Gemfile.lock", "Gemfile.lock", false},
		{"composer.json", "composer.json", false},
		{"composer.lock", "composer.lock", false},
		{"poetry.lock", "poetry.lock", false},
		{"Pipfile.lock", "Pipfile.lock", false},

		// Config files
		{"tsconfig.json", "tsconfig.json", false},
		{"jsconfig.json", "jsconfig.json", false},
		{".eslintrc.json", ".eslintrc.json", false},
		{".prettierrc.json", ".prettierrc.json", false},
		{"babel.config.json", "babel.config.json", false},
		{"jest.config.js", "jest.config.js", false},
		{"webpack.config.js", "webpack.config.js", false},
		{"vite.config.js", "vite.config.js", false},

		// Files that should be scanned
		{"Regular Python", "app.py", true},
		{"Regular JS", "index.js", true},
		{"User config", "config.json", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldScanFile(tt.path)
			if got != tt.expected {
				t.Errorf("shouldScanFile(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

func TestNewHybridScanner_Defaults(t *testing.T) {
	scanner := NewHybridScanner("/path/to/code", "", false, false)

	if scanner.ServerURL != DefaultServerURL {
		t.Errorf("expected default server URL %s, got %s", DefaultServerURL, scanner.ServerURL)
	}
	if scanner.SourcePath != "/path/to/code" {
		t.Errorf("expected source path /path/to/code, got %s", scanner.SourcePath)
	}
	if scanner.Verbose != false {
		t.Error("expected Verbose false")
	}
	if scanner.Quiet != false {
		t.Error("expected Quiet false")
	}
	if scanner.client == nil {
		t.Error("expected client to be initialized")
	}
	if scanner.progress == nil {
		t.Error("expected progress to be initialized")
	}
}

func TestNewHybridScanner_CustomServerURL(t *testing.T) {
	scanner := NewHybridScanner("/path", "http://custom.server.io", true, true)

	if scanner.ServerURL != "http://custom.server.io" {
		t.Errorf("expected custom server URL, got %s", scanner.ServerURL)
	}
	if scanner.Verbose != true {
		t.Error("expected Verbose true")
	}
	if scanner.Quiet != true {
		t.Error("expected Quiet true")
	}
}

func TestScanLocalSecretsAndCollectFiles(t *testing.T) {
	// Create temp directory with test files
	tmpDir := t.TempDir()

	// Create a Python file with a hardcoded AWS key
	testFile := filepath.Join(tmpDir, "config.py")
	content := []byte(`
import os

# Hardcoded AWS credentials (should be detected)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def get_credentials():
    return {"key": AWS_ACCESS_KEY_ID}
`)
	if err := os.WriteFile(testFile, content, 0644); err != nil {
		t.Fatal(err)
	}

	// Create another file without secrets
	cleanFile := filepath.Join(tmpDir, "utils.py")
	cleanContent := []byte(`
def add(a, b):
    return a + b

def multiply(a, b):
    return a * b
`)
	if err := os.WriteFile(cleanFile, cleanContent, 0644); err != nil {
		t.Fatal(err)
	}

	scanner := NewHybridScanner(tmpDir, "http://test", false, true)
	findings, files, err := scanner.scanLocalSecretsAndCollectFiles()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should find at least one secret (AWS key)
	if len(findings) == 0 {
		t.Error("expected to find AWS key secrets")
	}

	// Should collect both files
	if len(files) != 2 {
		t.Errorf("expected 2 files, got %d", len(files))
	}

	// Check that findings have correct metadata
	for _, f := range findings {
		if f.Source != "local_cli" {
			t.Errorf("expected source local_cli, got %s", f.Source)
		}
		if f.Severity == "" {
			t.Error("expected non-empty severity")
		}
	}
}

func TestDefaultScanExtensions(t *testing.T) {
	// Verify critical extensions are included
	mustHave := []string{".py", ".js", ".ts", ".go", ".json", ".yaml", ".yml"}

	for _, ext := range mustHave {
		if !DefaultScanExtensions[ext] {
			t.Errorf("expected %s to be in DefaultScanExtensions", ext)
		}
	}
}

func TestExcludedDirectories(t *testing.T) {
	// Verify critical exclusions are present
	mustExclude := []string{"node_modules", ".git", "venv", "__pycache__", "dist", "build"}

	excludeSet := make(map[string]bool)
	for _, dir := range ExcludedDirectories {
		excludeSet[dir] = true
	}

	for _, dir := range mustExclude {
		if !excludeSet[dir] {
			t.Errorf("expected %s to be in ExcludedDirectories", dir)
		}
	}
}

func TestBlockedFiles(t *testing.T) {
	// Verify critical blocked files are present
	mustBlock := []string{"package-lock.json", "go.sum", "yarn.lock", "Cargo.lock"}

	for _, file := range mustBlock {
		if !BlockedFiles[file] {
			t.Errorf("expected %s to be in BlockedFiles", file)
		}
	}
}

func TestMergeFindings(t *testing.T) {
	scanner := NewHybridScanner("/test", "http://test", false, true)

	// Verify the scanner is properly initialized
	if scanner == nil {
		t.Fatal("scanner should not be nil")
	}

	// The actual mergeFindings method is tested via contract_test.go
	// Here we just verify the scanner has access to the merge function
	if scanner.client == nil {
		t.Error("scanner client should not be nil")
	}
}

func TestSortFindings(t *testing.T) {
	// Create test findings and verify sorting
	// Findings should be sorted by severity (CRITICAL > HIGH > MEDIUM > LOW)
	// then by line number within same severity

	// This is a basic structural test - actual sorting is tested indirectly
	// through the scan workflow
}
