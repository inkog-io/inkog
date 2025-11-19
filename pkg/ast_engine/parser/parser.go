package parser

import (
	"context"
	"sync"

	"github.com/inkog-io/inkog/action/pkg/ast_engine/analysis"
	"github.com/inkog-io/inkog/action/pkg/ast_engine/ast"
)

// Parser is the interface all language-specific parsers must implement
type Parser interface {
	// ParseFile parses source code and returns an AST
	ParseFile(filePath string, content []byte) (*ast.ParseResult, error)

	// Query finds AST nodes matching an S-expression query
	Query(root *ast.Node, queryStr string) ([]*ast.Node, error)

	// Language returns the language this parser handles
	Language() ast.Language

	// BuildSymbolTable builds scope and symbol information
	BuildSymbolTable(root *ast.Node) (*analysis.SymbolTable, error)

	// FindFunctionCalls finds all function calls in the tree
	FindFunctionCalls(root *ast.Node) ([]*ast.FunctionCallInfo, error)

	// FindVariableRefs finds all variable references
	FindVariableRefs(root *ast.Node) ([]*ast.VariableInfo, error)

	// GetSourceLocation returns source code range for a node
	GetSourceLocation(node *ast.Node) (line, col int)

	// IsInitialized returns whether parser is ready
	IsInitialized() bool
}

// ParserPool manages a thread-safe pool of parser instances
type ParserPool struct {
	parsers map[ast.Language]Parser
	mu      sync.RWMutex
	cache   *ParserCache
}

// ParserCache caches compiled queries
type ParserCache struct {
	queries map[string]interface{}
	mu      sync.RWMutex
}

// NewParserPool creates a new parser pool
func NewParserPool() *ParserPool {
	return &ParserPool{
		parsers: make(map[ast.Language]Parser),
		cache: &ParserCache{
			queries: make(map[string]interface{}),
		},
	}
}

// RegisterParser registers a parser for a language
func (pp *ParserPool) RegisterParser(language ast.Language, parser Parser) error {
	pp.mu.Lock()
	defer pp.mu.Unlock()

	if !parser.IsInitialized() {
		return ErrParserNotInitialized
	}

	pp.parsers[language] = parser
	return nil
}

// GetParser retrieves a parser for a language
func (pp *ParserPool) GetParser(language ast.Language) (Parser, error) {
	pp.mu.RLock()
	defer pp.mu.RUnlock()

	parser, exists := pp.parsers[language]
	if !exists {
		return nil, ErrLanguageNotSupported
	}

	return parser, nil
}

// ParseFile parses a file with the appropriate parser
func (pp *ParserPool) ParseFile(ctx context.Context, filePath string, content []byte, language ast.Language) (*ast.ParseResult, error) {
	parser, err := pp.GetParser(language)
	if err != nil {
		return nil, err
	}

	// Use context for cancellation support
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	return parser.ParseFile(filePath, content)
}

// QueryWithCache executes a query with caching
func (pp *ParserPool) QueryWithCache(ctx context.Context, parser Parser, root *ast.Node, queryStr string) ([]*ast.Node, error) {
	// Check cache first
	pp.cache.mu.RLock()
	cachedQuery, exists := pp.cache.queries[queryStr]
	pp.cache.mu.RUnlock()

	if exists {
		_ = cachedQuery // Use the cached query if needed
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	return parser.Query(root, queryStr)
}

// CacheQuery stores a compiled query
func (pp *ParserPool) CacheQuery(queryStr string, compiled interface{}) {
	pp.cache.mu.Lock()
	defer pp.cache.mu.Unlock()

	pp.cache.queries[queryStr] = compiled
}

// DetectLanguage detects the language from file extension
func DetectLanguage(filePath string) ast.Language {
	// Import strings to check file extension
	// This will be implemented in main package
	// For now, return unknown
	return ast.LanguagePython
}

// ParserConfig holds configuration for a parser
type ParserConfig struct {
	MaxFileSize     int64 // Maximum file size to parse
	CacheSize       int   // Query cache size
	SymbolCacheSize int   // Symbol table cache size
	Timeout         int   // Parse timeout in milliseconds
	ThreadSafe      bool  // Enable thread-safe mode
}

// DefaultConfig returns default parser configuration
func DefaultConfig() *ParserConfig {
	return &ParserConfig{
		MaxFileSize:     10 * 1024 * 1024, // 10MB
		CacheSize:       1000,
		SymbolCacheSize: 500,
		Timeout:         5000, // 5 seconds
		ThreadSafe:      true,
	}
}

// BaseParser provides common functionality for all parsers
type BaseParser struct {
	languageType ast.Language
	Initialized  bool
	Config       *ParserConfig
	mu           sync.RWMutex
}

// Language returns the language
func (bp *BaseParser) Language() ast.Language {
	bp.mu.RLock()
	defer bp.mu.RUnlock()

	return bp.languageType
}

// GetInitialized returns initialization status
func (bp *BaseParser) IsInitialized() bool {
	bp.mu.RLock()
	defer bp.mu.RUnlock()

	return bp.Initialized
}

// SetInitialized sets initialization status
func (bp *BaseParser) SetInitialized(initialized bool) {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	bp.Initialized = initialized
}
