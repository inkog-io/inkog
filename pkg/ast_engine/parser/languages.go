package parser

import (
	"sync"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/python"
	"github.com/smacker/go-tree-sitter/typescript/typescript"
	"github.com/smacker/go-tree-sitter/typescript/tsx"
)

// Lazy-loaded singleton language grammars
// Each language is loaded on-demand using sync.Once to avoid C library deadlocks
// during program startup. This prevents the initialization hang that occurred when
// all grammars were loaded at init() time.

var (
	pythonLang   *sitter.Language
	pythonOnce   sync.Once

	jsLang       *sitter.Language
	jsOnce       sync.Once

	tsLang       *sitter.Language
	tsOnce       sync.Once

	tsxLang      *sitter.Language
	tsxOnce      sync.Once
)

// GetPythonLanguage returns the Python language grammar (lazy singleton)
// The grammar is loaded on first call, not during program initialization.
func GetPythonLanguage() *sitter.Language {
	pythonOnce.Do(func() {
		pythonLang = python.GetLanguage()
	})
	return pythonLang
}

// GetJavaScriptLanguage returns the JavaScript language grammar (lazy singleton)
// The grammar is loaded on first call, not during program initialization.
func GetJavaScriptLanguage() *sitter.Language {
	jsOnce.Do(func() {
		jsLang = javascript.GetLanguage()
	})
	return jsLang
}

// GetTypeScriptLanguage returns the TypeScript language grammar (lazy singleton)
// The grammar is loaded on first call, not during program initialization.
func GetTypeScriptLanguage() *sitter.Language {
	tsOnce.Do(func() {
		tsLang = typescript.GetLanguage()
	})
	return tsLang
}

// GetTSXLanguage returns the TypeScript JSX (.tsx) language grammar (lazy singleton)
// The grammar is loaded on first call, not during program initialization.
func GetTSXLanguage() *sitter.Language {
	tsxOnce.Do(func() {
		tsxLang = tsx.GetLanguage()
	})
	return tsxLang
}
