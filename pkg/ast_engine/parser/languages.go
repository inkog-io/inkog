package parser

import (
	"sync"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/python"
	"github.com/smacker/go-tree-sitter/typescript/typescript"
	"github.com/smacker/go-tree-sitter/typescript/tsx"
)

// LanguageManager manages Tree-sitter language grammars with singleton pattern
// Grammars are loaded ONCE at program startup, not re-loaded for every file
type LanguageManager struct {
	pythonLang     *sitter.Language
	jsLang         *sitter.Language
	tsLang         *sitter.Language
	tsxLang        *sitter.Language
	mu             sync.RWMutex
}

var langManager *LanguageManager
var initOnce sync.Once

// init() ensures grammars are loaded exactly once when the package is imported
func init() {
	initOnce.Do(func() {
		langManager = &LanguageManager{
			pythonLang: python.GetLanguage(),
			jsLang:     javascript.GetLanguage(),
			tsLang:     typescript.GetLanguage(),
			tsxLang:    tsx.GetLanguage(),
		}
	})
}

// GetPythonLanguage returns the Python language grammar (singleton)
func GetPythonLanguage() *sitter.Language {
	langManager.mu.RLock()
	defer langManager.mu.RUnlock()
	return langManager.pythonLang
}

// GetJavaScriptLanguage returns the JavaScript language grammar (singleton)
func GetJavaScriptLanguage() *sitter.Language {
	langManager.mu.RLock()
	defer langManager.mu.RUnlock()
	return langManager.jsLang
}

// GetTypeScriptLanguage returns the TypeScript language grammar (singleton)
func GetTypeScriptLanguage() *sitter.Language {
	langManager.mu.RLock()
	defer langManager.mu.RUnlock()
	return langManager.tsLang
}

// GetTSXLanguage returns the TypeScript JSX (.tsx) language grammar (singleton)
func GetTSXLanguage() *sitter.Language {
	langManager.mu.RLock()
	defer langManager.mu.RUnlock()
	return langManager.tsxLang
}
