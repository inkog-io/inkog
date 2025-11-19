package query

import (
	"fmt"
	"strings"
	"sync"

	"github.com/inkog-io/inkog/action/pkg/ast_engine/ast"
)

// Engine provides S-expression query matching against AST nodes
type Engine struct {
	compiledQueries map[string]*CompiledQuery
	mu              sync.RWMutex
}

// CompiledQuery represents a compiled S-expression query
type CompiledQuery struct {
	Original  string
	Pattern   *QueryPattern
	Compiled  bool
}

// QueryPattern represents the parsed query structure
type QueryPattern struct {
	Type       PatternType
	NodeType   ast.NodeType
	Conditions []*Condition
	Children   []*QueryPattern
	Modifiers  map[string]string
}

// PatternType represents the type of query pattern
type PatternType string

const (
	PatternTypeNode     PatternType = "node"
	PatternTypeCall     PatternType = "call"
	PatternTypeCapture  PatternType = "capture"
	PatternTypeAnd      PatternType = "and"
	PatternTypeOr       PatternType = "or"
)

// Condition represents a condition in a query
type Condition struct {
	Field    string      // Node field to check
	Operator CondOp
	Value    interface{}
}

// CondOp represents a comparison operator
type CondOp string

const (
	OpEq    CondOp = "eq"
	OpNeq   CondOp = "neq"
	OpMatch CondOp = "match"  // Regex match
	OpContains CondOp = "contains"
	OpStartsWith CondOp = "startswith"
	OpEndsWith CondOp = "endswith"
)

// NewEngine creates a new query engine
func NewEngine() *Engine {
	return &Engine{
		compiledQueries: make(map[string]*CompiledQuery),
	}
}

// Query executes an S-expression query and returns matching nodes
func (e *Engine) Query(root *ast.Node, queryStr string) ([]*ast.Node, error) {
	if root == nil {
		return nil, fmt.Errorf("root node is nil")
	}

	// Check cache
	e.mu.RLock()
	compiled, exists := e.compiledQueries[queryStr]
	e.mu.RUnlock()

	if !exists {
		// Parse and compile the query
		var err error
		compiled, err = e.compileQuery(queryStr)
		if err != nil {
			return nil, err
		}

		// Cache it
		e.mu.Lock()
		e.compiledQueries[queryStr] = compiled
		e.mu.Unlock()
	}

	// Execute the compiled query
	var results []*ast.Node
	e.matchPattern(root, compiled.Pattern, &results)
	return results, nil
}

// compileQuery parses and compiles an S-expression query
func (e *Engine) compileQuery(queryStr string) (*CompiledQuery, error) {
	// Parse the S-expression
	pattern, err := e.parseQuery(queryStr)
	if err != nil {
		return nil, err
	}

	return &CompiledQuery{
		Original: queryStr,
		Pattern:  pattern,
		Compiled: true,
	}, nil
}

// parseQuery parses an S-expression into a QueryPattern
func (e *Engine) parseQuery(queryStr string) (*QueryPattern, error) {
	queryStr = strings.TrimSpace(queryStr)

	// Handle simple node type queries: "function_call", "call", etc.
	if !strings.HasPrefix(queryStr, "(") && !strings.HasPrefix(queryStr, "[") {
		return &QueryPattern{
			Type:     PatternTypeNode,
			NodeType: ast.NodeType(queryStr),
		}, nil
	}

	// Handle S-expression queries: (call function: "eval" arguments: ...)
	if strings.HasPrefix(queryStr, "(") && strings.HasSuffix(queryStr, ")") {
		return e.parseExpression(queryStr[1 : len(queryStr)-1])
	}

	return nil, fmt.Errorf("invalid query syntax: %s", queryStr)
}

// parseExpression parses an S-expression without outer parentheses
func (e *Engine) parseExpression(expr string) (*QueryPattern, error) {
	tokens := e.tokenize(expr)
	if len(tokens) == 0 {
		return nil, fmt.Errorf("empty expression")
	}

	// First token determines the pattern type
	firstToken := tokens[0]
	pattern := &QueryPattern{
		Type:       PatternTypeNode,
		Conditions: make([]*Condition, 0),
		Modifiers:  make(map[string]string),
	}

	// Check for node type
	if nodeType, isNodeType := e.isNodeType(firstToken); isNodeType {
		pattern.NodeType = nodeType
	} else {
		pattern.NodeType = ast.NodeType(firstToken)
	}

	// Parse conditions and modifiers
	i := 1
	for i < len(tokens) {
		token := tokens[i]

		// Handle modifiers like "function:", "arguments:", etc.
		if strings.HasSuffix(token, ":") {
			key := strings.TrimSuffix(token, ":")
			if i+1 < len(tokens) {
				value := tokens[i+1]
				pattern.Modifiers[key] = value
				i += 2
			} else {
				i++
			}
		} else {
			i++
		}
	}

	return pattern, nil
}

// tokenize splits an expression into tokens
func (e *Engine) tokenize(expr string) []string {
	var tokens []string
	var current strings.Builder
	inQuote := false

	for i := 0; i < len(expr); i++ {
		ch := expr[i]

		switch ch {
		case '"':
			inQuote = !inQuote
			current.WriteByte(ch)
		case ' ', '\t', '\n':
			if !inQuote {
				if current.Len() > 0 {
					tokens = append(tokens, current.String())
					current.Reset()
				}
			} else {
				current.WriteByte(ch)
			}
		case '(', ')':
			if !inQuote {
				if current.Len() > 0 {
					tokens = append(tokens, current.String())
					current.Reset()
				}
				tokens = append(tokens, string(ch))
			} else {
				current.WriteByte(ch)
			}
		default:
			current.WriteByte(ch)
		}
	}

	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}

	return tokens
}

// isNodeType checks if a token is a known node type
func (e *Engine) isNodeType(token string) (ast.NodeType, bool) {
	// Map of string representations to NodeType
	nodeTypes := map[string]ast.NodeType{
		"call":        ast.NodeTypeFunctionCall,
		"function":    ast.NodeTypeFunctionDef,
		"identifier":  ast.NodeTypeIdentifier,
		"assignment":  ast.NodeTypeAssignment,
		"method":      ast.NodeTypeMethodCall,
		"eval":        ast.NodeTypeFunctionCall,
		"exec":        ast.NodeTypeFunctionCall,
		"import":      ast.NodeTypeImport,
		"for":         ast.NodeTypeForStatement,
		"while":       ast.NodeTypeWhileStatement,
		"if":          ast.NodeTypeIfStatement,
	}

	if nodeType, exists := nodeTypes[token]; exists {
		return nodeType, true
	}

	return "", false
}

// matchPattern recursively matches a pattern against nodes
func (e *Engine) matchPattern(node *ast.Node, pattern *QueryPattern, results *[]*ast.Node) {
	if node == nil {
		return
	}

	// Check if this node matches the pattern
	if e.nodeMatches(node, pattern) {
		*results = append(*results, node)
	}

	// Recursively check children (thread-safe access)
	children := node.GetChildren()

	for _, child := range children {
		e.matchPattern(child, pattern, results)
	}
}

// nodeMatches checks if a node matches a pattern
func (e *Engine) nodeMatches(node *ast.Node, pattern *QueryPattern) bool {
	// Check node type
	if pattern.NodeType != "" && node.Type != pattern.NodeType {
		return false
	}

	// Check modifiers/conditions
	for key, value := range pattern.Modifiers {
		// Check node properties based on key
		nodeProp, exists := node.GetProperty(key)
		if !exists {
			// Try to match against text content
			if key == "function" && e.textContains(node.GetText(), value) {
				continue
			}
			if key == "arguments" {
				// For arguments, check if it's a parameter-like node
				continue
			}
			return false
		}

		// Simple string comparison
		if str, ok := nodeProp.(string); ok {
			if !strings.Contains(str, value) {
				return false
			}
		}
	}

	return true
}

// textContains checks if text contains a pattern
func (e *Engine) textContains(text, pattern string) bool {
	// Remove quotes from pattern if present
	pattern = strings.Trim(pattern, "\"")
	return strings.Contains(text, pattern)
}

// QueryForFunctionCall finds all function calls matching a specific function name
func (e *Engine) QueryForFunctionCall(root *ast.Node, functionName string) ([]*ast.Node, error) {
	query := fmt.Sprintf(`(call function: "%s")`, functionName)
	return e.Query(root, query)
}

// QueryForVariableRef finds all references to a specific variable
func (e *Engine) QueryForVariableRef(root *ast.Node, varName string) ([]*ast.Node, error) {
	query := fmt.Sprintf(`(identifier "%s")`, varName)
	return e.Query(root, query)
}

// ClearCache clears the compiled query cache
func (e *Engine) ClearCache() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.compiledQueries = make(map[string]*CompiledQuery)
}

// CacheStats returns cache statistics
func (e *Engine) CacheStats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return map[string]interface{}{
		"compiled_queries": len(e.compiledQueries),
	}
}
