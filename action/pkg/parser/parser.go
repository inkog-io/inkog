package parser

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/tree-sitter/tree-sitter-javascript/bindings/go"
	python "github.com/tree-sitter/tree-sitter-python/bindings/go"
)

// Language represents a programming language
type Language string

const (
	LanguagePython     Language = "python"
	LanguageJavaScript Language = "javascript"
	LanguageTypeScript Language = "typescript"
)

// FileInfo contains parsed file information
type FileInfo struct {
	Path     string
	Language Language
	Content  []byte
	Tree     *sitter.Tree
	LOC      int // Lines of code
}

// Parser wraps tree-sitter parsers
type Parser struct {
	pythonParser *sitter.Parser
	jsParser     *sitter.Parser
	mu           sync.RWMutex
}

// New creates a new parser instance
func New() (*Parser, error) {
	pythonParser := sitter.NewParser()
	pythonParser.SetLanguage(python.GetLanguage())

	jsParser := sitter.NewParser()
	jsParser.SetLanguage(javascript.GetLanguage())

	return &Parser{
		pythonParser: pythonParser,
		jsParser:     jsParser,
	}, nil
}

// ParseFile parses a single file and returns the AST
func (p *Parser) ParseFile(filePath string) (*FileInfo, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	lang := detectLanguage(filePath)
	tree, err := p.parseContent(content, lang)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", filePath, err)
	}

	loc := countLines(content)

	return &FileInfo{
		Path:     filePath,
		Language: lang,
		Content:  content,
		Tree:     tree,
		LOC:      loc,
	}, nil
}

// parseContent parses content based on language
func (p *Parser) parseContent(content []byte, lang Language) (*sitter.Tree, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	switch lang {
	case LanguagePython:
		return p.pythonParser.Parse(nil, content)
	case LanguageJavaScript, LanguageTypeScript:
		return p.jsParser.Parse(nil, content)
	default:
		return nil, fmt.Errorf("unsupported language: %s", lang)
	}
}

// ParseDirectory recursively parses all agent files in a directory
func (p *Parser) ParseDirectory(dirPath string) ([]FileInfo, error) {
	var files []FileInfo
	var mu sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 4) // Limit concurrent parsing to 4

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			// Skip common unneeded directories
			if shouldSkipDir(info.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		// Only parse supported file types
		if !isSupportedFile(path) {
			return nil
		}

		wg.Add(1)
		go func(filePath string) {
			defer wg.Done()
			semaphore <- struct{}{}        // Acquire semaphore
			defer func() { <-semaphore }() // Release semaphore

			fileInfo, err := p.ParseFile(filePath)
			if err != nil {
				// Log but continue scanning
				fmt.Fprintf(os.Stderr, "Warning: Failed to parse %s: %v\n", filePath, err)
				return
			}

			mu.Lock()
			files = append(files, *fileInfo)
			mu.Unlock()
		}(path)

		return nil
	})

	wg.Wait()

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory: %w", err)
	}

	return files, nil
}

// detectLanguage detects the language from file extension
func detectLanguage(filePath string) Language {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".py":
		return LanguagePython
	case ".js":
		return LanguageJavaScript
	case ".ts", ".tsx":
		return LanguageTypeScript
	default:
		return LanguagePython // Default to Python
	}
}

// isSupportedFile checks if a file should be parsed
func isSupportedFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	supported := map[string]bool{
		".py": true, ".js": true, ".ts": true, ".tsx": true,
	}
	return supported[ext]
}

// shouldSkipDir checks if a directory should be skipped
func shouldSkipDir(dirName string) bool {
	skipDirs := map[string]bool{
		"node_modules": true,
		".git":         true,
		".venv":        true,
		"venv":         true,
		"__pycache__":  true,
		".pytest_cache": true,
		"dist":         true,
		"build":        true,
		".env":         true,
	}
	return skipDirs[dirName]
}

// countLines counts lines in a file
func countLines(content []byte) int {
	return strings.Count(string(content), "\n") + 1
}

// GetNodeText returns the text of a tree-sitter node
func GetNodeText(node *sitter.Node, content []byte) string {
	start := node.StartByte()
	end := node.EndByte()
	if start >= 0 && end >= start && int(end) <= len(content) {
		return string(content[start:end])
	}
	return ""
}

// GetNodeLine returns the line number (1-indexed) of a node
func GetNodeLine(node *sitter.Node) int {
	return int(node.StartPoint().Row) + 1
}

// GetNodeColumn returns the column number (1-indexed) of a node
func GetNodeColumn(node *sitter.Node) int {
	return int(node.StartPoint().Column) + 1
}
