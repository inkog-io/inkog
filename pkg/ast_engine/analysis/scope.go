package analysis

import (
	"fmt"
	"sync"

	"github.com/inkog-io/inkog/action/pkg/ast_engine/ast"
)

// Scope represents a lexical scope (function, block, class, etc.)
type Scope struct {
	// Identity
	ID            string // Unique scope ID
	ScopeType     ScopeType
	Name          string // Function name, class name, etc.
	ParentScope   *Scope
	ChildScopes   []*Scope

	// Content
	Variables     map[string]*ast.VariableInfo // Variables in this scope
	Functions     map[string]*ScopeFunction
	Imports       map[string]*ImportInfo
	DefinedAtNode *ast.Node

	// Location
	StartLine int
	EndLine   int

	// Concurrency
	mu sync.RWMutex
}

// ScopeType represents the type of scope
type ScopeType string

const (
	ScopeTypeFile     ScopeType = "file"
	ScopeTypeFunction ScopeType = "function"
	ScopeTypeClass    ScopeType = "class"
	ScopeTypeBlock    ScopeType = "block"      // if/for/while blocks
	ScopeTypeAsync    ScopeType = "async"      // async function
	ScopeTypeModule   ScopeType = "module"     // module scope
)

// ScopeFunction represents a function in a scope
type ScopeFunction struct {
	Name       string
	Parameters []string
	ReturnType string
	DefinedAt  *ast.Node
}

// ImportInfo represents an import statement
type ImportInfo struct {
	Module       string   // Module name
	Items        []string // Imported items (e.g., ["function1", "function2"])
	Alias        string   // Alias if imported as (e.g., "import X as Y")
	DefinedAt    *ast.Node
	SourceModule string // Full module path
}

// NewScope creates a new scope
func NewScope(id string, scopeType ScopeType, name string) *Scope {
	return &Scope{
		ID:        id,
		ScopeType: scopeType,
		Name:      name,
		Variables: make(map[string]*ast.VariableInfo),
		Functions: make(map[string]*ScopeFunction),
		Imports:   make(map[string]*ImportInfo),
		ChildScopes: make([]*Scope, 0),
	}
}

// AddVariable adds or updates a variable in this scope
func (s *Scope) AddVariable(varInfo *ast.VariableInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Variables[varInfo.Name] = varInfo
}

// GetVariable retrieves a variable, checking parent scopes if not found
func (s *Scope) GetVariable(name string) *ast.VariableInfo {
	s.mu.RLock()

	// Check current scope
	if varInfo, exists := s.Variables[name]; exists {
		s.mu.RUnlock()
		return varInfo
	}

	s.mu.RUnlock()

	// Check parent scope
	if s.ParentScope != nil {
		return s.ParentScope.GetVariable(name)
	}

	return nil
}

// LookupVariableLocal retrieves a variable only from this scope (not parents)
func (s *Scope) LookupVariableLocal(name string) *ast.VariableInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	varInfo, _ := s.Variables[name]
	return varInfo
}

// AddFunction adds a function declaration
func (s *Scope) AddFunction(name string, fn *ScopeFunction) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Functions[name] = fn
}

// GetFunction retrieves a function, checking parent scopes
func (s *Scope) GetFunction(name string) *ScopeFunction {
	s.mu.RLock()

	if fn, exists := s.Functions[name]; exists {
		s.mu.RUnlock()
		return fn
	}

	s.mu.RUnlock()

	if s.ParentScope != nil {
		return s.ParentScope.GetFunction(name)
	}

	return nil
}

// AddImport adds an import statement
func (s *Scope) AddImport(varName string, importInfo *ImportInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Imports[varName] = importInfo
}

// GetImport retrieves an import, checking parent scopes
func (s *Scope) GetImport(name string) *ImportInfo {
	s.mu.RLock()

	if imp, exists := s.Imports[name]; exists {
		s.mu.RUnlock()
		return imp
	}

	s.mu.RUnlock()

	if s.ParentScope != nil {
		return s.ParentScope.GetImport(name)
	}

	return nil
}

// AddChildScope adds a child scope
func (s *Scope) AddChildScope(child *Scope) {
	s.mu.Lock()
	defer s.mu.Unlock()

	child.ParentScope = s
	s.ChildScopes = append(s.ChildScopes, child)
}

// GetAllVariables returns all variables visible in this scope (including inherited)
func (s *Scope) GetAllVariables() map[string]*ast.VariableInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]*ast.VariableInfo)

	// Add parent scope variables first
	if s.ParentScope != nil {
		parentVars := s.ParentScope.GetAllVariables()
		for name, varInfo := range parentVars {
			result[name] = varInfo
		}
	}

	// Override with local variables
	for name, varInfo := range s.Variables {
		result[name] = varInfo
	}

	return result
}

// IsGlobalScope checks if this is global scope
func (s *Scope) IsGlobalScope() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.ScopeType == ScopeTypeFile || s.ScopeType == ScopeTypeModule
}

// GetParentFunctionScope gets the parent function scope
func (s *Scope) GetParentFunctionScope() *Scope {
	current := s
	for current != nil {
		if current.ScopeType == ScopeTypeFunction || current.ScopeType == ScopeTypeAsync {
			return current
		}
		current = current.ParentScope
	}
	return nil
}

// SymbolTable represents the complete symbol table for a file
type SymbolTable struct {
	FileScope      *Scope
	CurrentScope   *Scope
	AllScopes      []*Scope
	SourceLocation map[string]*ast.Node // Map of variable name to definition node
	TaintAnalysis  map[string]*TaintInfo // Taint tracking

	mu sync.RWMutex
}

// NewSymbolTable creates a new symbol table
func NewSymbolTable() *SymbolTable {
	fileScope := NewScope("file_0", ScopeTypeFile, "")
	return &SymbolTable{
		FileScope:      fileScope,
		CurrentScope:   fileScope,
		AllScopes:      []*Scope{fileScope},
		SourceLocation: make(map[string]*ast.Node),
		TaintAnalysis:  make(map[string]*TaintInfo),
	}
}

// PushScope enters a new scope
func (st *SymbolTable) PushScope(scope *Scope) {
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.CurrentScope != nil {
		st.CurrentScope.AddChildScope(scope)
	}
	st.CurrentScope = scope
	st.AllScopes = append(st.AllScopes, scope)
}

// PopScope exits the current scope
func (st *SymbolTable) PopScope() error {
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.CurrentScope == nil || st.CurrentScope.ParentScope == nil {
		return fmt.Errorf("cannot pop root scope")
	}

	st.CurrentScope = st.CurrentScope.ParentScope
	return nil
}

// AddVariable adds a variable to the current scope
func (st *SymbolTable) AddVariable(varInfo *ast.VariableInfo) {
	st.mu.Lock()
	defer st.mu.Unlock()

	st.CurrentScope.AddVariable(varInfo)
	st.SourceLocation[varInfo.Name] = varInfo.SourceNode
}

// GetVariable retrieves a variable from the current scope hierarchy
func (st *SymbolTable) GetVariable(name string) *ast.VariableInfo {
	st.mu.RLock()
	defer st.mu.RUnlock()

	return st.CurrentScope.GetVariable(name)
}

// AddTaintInfo adds taint information
func (st *SymbolTable) AddTaintInfo(varName string, taintInfo *TaintInfo) {
	st.mu.Lock()
	defer st.mu.Unlock()

	st.TaintAnalysis[varName] = taintInfo
}

// GetTaintInfo retrieves taint information
func (st *SymbolTable) GetTaintInfo(varName string) *TaintInfo {
	st.mu.RLock()
	defer st.mu.RUnlock()

	return st.TaintAnalysis[varName]
}

// TaintInfo represents taint state of a variable
type TaintInfo struct {
	VariableName   string
	TaintState     string      // "clean", "tainted", "unknown"
	Source         string      // Where the taint came from
	SourceNodes    []*ast.Node // Nodes that introduced the taint
	PropagatedFrom []string    // Variables this was assigned from
	Confidence     float64     // Confidence level (0.0 - 1.0)

	mu sync.RWMutex
}

// NewTaintInfo creates new taint information
func NewTaintInfo(varName, taintState, source string) *TaintInfo {
	return &TaintInfo{
		VariableName:   varName,
		TaintState:     taintState,
		Source:         source,
		SourceNodes:    make([]*ast.Node, 0),
		PropagatedFrom: make([]string, 0),
		Confidence:     1.0,
	}
}

// AddSourceNode adds a source node for taint
func (ti *TaintInfo) AddSourceNode(node *ast.Node) {
	ti.mu.Lock()
	defer ti.mu.Unlock()

	ti.SourceNodes = append(ti.SourceNodes, node)
}

// AddPropagation adds a propagation source
func (ti *TaintInfo) AddPropagation(fromVar string) {
	ti.mu.Lock()
	defer ti.mu.Unlock()

	ti.PropagatedFrom = append(ti.PropagatedFrom, fromVar)
}

// IsTainted checks if variable is tainted
func (ti *TaintInfo) IsTainted() bool {
	ti.mu.RLock()
	defer ti.mu.RUnlock()

	return ti.TaintState == "tainted" || ti.TaintState == "unknown"
}

// SetTaintState sets the taint state
func (ti *TaintInfo) SetTaintState(state string) {
	ti.mu.Lock()
	defer ti.mu.Unlock()

	ti.TaintState = state
}
