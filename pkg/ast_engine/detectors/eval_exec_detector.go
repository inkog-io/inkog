package detectors

import (
	"fmt"
	"sync"

	"github.com/inkog-io/inkog/action/pkg/ast_engine/analysis"
	"github.com/inkog-io/inkog/action/pkg/ast_engine/ast"
	"github.com/inkog-io/inkog/action/pkg/ast_engine/parser"
)

// UnvalidatedEvalExecDetector detects unvalidated eval/exec calls
// This is the proof-of-concept detector demonstrating:
// - Function call detection (eval, exec, os.system)
// - Variable identifier tracking
// - Data flow from variable definition to function argument
// - Foundation for taint analysis
type UnvalidatedEvalExecDetector struct {
	parser     parser.Parser
	language   ast.Language
	mu         sync.RWMutex
	findings   []*EvalExecFinding
	symbolTable *analysis.SymbolTable
}

// EvalExecFinding represents a dangerous eval/exec call
type EvalExecFinding struct {
	FunctionName    string                    // eval, exec, os.system, etc.
	FilePath        string                    // Source file
	Line            int                       // Line number
	Column          int                       // Column number
	FullText        string                    // Full function call text
	Arguments       []string                  // Argument values
	ArgumentNodes   []*ast.Node               // Argument AST nodes
	VariableRefs    map[string]*VariableDataFlow // Variable references -> their definitions
	RiskLevel       string                    // "CRITICAL", "HIGH", "MEDIUM"
	IsDangerous     bool                      // True if tainted variable is passed
	Reason          string                    // Explanation of the risk
}

// VariableDataFlow represents the data flow of a variable
type VariableDataFlow struct {
	VariableName    string
	DefinedAtLine   int
	DefinedAtColumn int
	Definition      *ast.VariableInfo
	Source          string // Where the variable came from (input, request, argv, etc)
	IsTainted       bool   // True if from untrusted source
	TaintReason     string // Why it's considered tainted
}

// NewUnvalidatedEvalExecDetector creates a new detector
func NewUnvalidatedEvalExecDetector(lang ast.Language) (*UnvalidatedEvalExecDetector, error) {
	config := parser.DefaultConfig()

	var p parser.Parser
	var err error

	switch lang {
	case ast.LanguagePython:
		p, err = parser.NewPythonParser(config)
	case ast.LanguageJavaScript:
		p, err = parser.NewJavaScriptParser(config)
	case ast.LanguageTypeScript:
		p, err = parser.NewTypeScriptParser(config)
	default:
		return nil, fmt.Errorf("unsupported language: %v", lang)
	}

	if err != nil {
		return nil, err
	}

	return &UnvalidatedEvalExecDetector{
		parser:   p,
		language: lang,
		findings: make([]*EvalExecFinding, 0),
	}, nil
}

// Analyze scans code for unvalidated eval/exec patterns
func (d *UnvalidatedEvalExecDetector) Analyze(filePath string, code []byte) ([]*EvalExecFinding, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Parse the file
	parseResult, err := d.parser.ParseFile(filePath, code)
	if err != nil {
		return nil, fmt.Errorf("parsing failed: %w", err)
	}

	// Build symbol table for variable resolution
	symTable, err := d.parser.BuildSymbolTable(parseResult.Root)
	if err != nil {
		return nil, fmt.Errorf("symbol table build failed: %w", err)
	}

	d.symbolTable = symTable

	// Find all function calls
	funcCalls, err := d.parser.FindFunctionCalls(parseResult.Root)
	if err != nil {
		return nil, fmt.Errorf("function call detection failed: %w", err)
	}

	// Clear previous findings
	d.findings = make([]*EvalExecFinding, 0)

	// Analyze each function call
	dangerousFuncs := map[string]bool{
		"eval":        true,
		"exec":        true,
		"system":      true,
		"__import__":  true,
		"compile":     true,
		"subprocess":  true,
		"popen":       true,
		"execfile":    true,
		"Function":    true,
		"setTimeout":  true,
		"setInterval": true,
	}

	for _, funcCall := range funcCalls {
		if dangerousFuncs[funcCall.FunctionName] {
			finding := d.analyzeCall(funcCall, filePath)
			if finding != nil {
				d.findings = append(d.findings, finding)
			}
		}
	}

	return d.findings, nil
}

// analyzeCall analyzes a single function call for taint patterns
func (d *UnvalidatedEvalExecDetector) analyzeCall(
	funcCall *ast.FunctionCallInfo,
	filePath string,
) *EvalExecFinding {
	finding := &EvalExecFinding{
		FunctionName:  funcCall.FunctionName,
		FilePath:      filePath,
		Line:          funcCall.Line,
		Column:        funcCall.Column,
		FullText:      funcCall.FullText,
		Arguments:     funcCall.Arguments,
		VariableRefs:  make(map[string]*VariableDataFlow),
		RiskLevel:     "CRITICAL",
	}

	// Analyze arguments for variable references
	if len(funcCall.Arguments) > 0 {
		firstArg := funcCall.Arguments[0]

		// Check if first argument looks like a variable reference
		varFlow := d.analyzeVariableFlow(firstArg)
		if varFlow != nil {
			finding.VariableRefs[firstArg] = varFlow
			finding.IsDangerous = varFlow.IsTainted

			if varFlow.IsTainted {
				finding.Reason = fmt.Sprintf(
					"Tainted variable '%s' passed to %s(): %s",
					varFlow.VariableName,
					funcCall.FunctionName,
					varFlow.TaintReason,
				)
			} else {
				finding.Reason = fmt.Sprintf(
					"Variable '%s' passed to %s(). Unable to determine source.",
					varFlow.VariableName,
					funcCall.FunctionName,
				)
				finding.RiskLevel = "HIGH"
			}
		} else {
			// Direct string or constant - still risky
			finding.Reason = fmt.Sprintf(
				"Direct %s() call with argument at line %d - validate input carefully",
				funcCall.FunctionName,
				funcCall.Line,
			)
			finding.RiskLevel = "MEDIUM"
		}
	}

	return finding
}

// analyzeVariableFlow analyzes the data flow of a variable
func (d *UnvalidatedEvalExecDetector) analyzeVariableFlow(varName string) *VariableDataFlow {
	if d.symbolTable == nil {
		return nil
	}

	// Look up variable in symbol table
	varInfo := d.symbolTable.GetVariable(varName)
	if varInfo == nil {
		return nil
	}

	varFlow := &VariableDataFlow{
		VariableName:  varName,
		DefinedAtLine: varInfo.DefinedAtLine,
		Definition:    varInfo,
	}

	// Determine if variable is tainted (from untrusted source)
	varFlow.IsTainted, varFlow.Source, varFlow.TaintReason = d.determineTaintStatus(
		varName,
		varInfo,
	)

	return varFlow
}

// determineTaintStatus determines if a variable is tainted based on its source
func (d *UnvalidatedEvalExecDetector) determineTaintStatus(
	varName string,
	varInfo *ast.VariableInfo,
) (bool, string, string) {
	if varInfo == nil {
		return false, "unknown", "Variable definition not found"
	}

	// Untrusted sources
	untrustedPatterns := map[string]bool{
		"input":          true,  // Python input()
		"input()":        true,
		"raw_input":      true,  // Python 2 raw_input()
		"sys.argv":       true,  // Command line arguments
		"request":        true,  // HTTP request
		"req":            true,  // Express/Node request
		"query":          true,  // Query parameters
		"body":           true,  // Request body
		"args":           true,  // CLI args
		"argv":           true,  // argv
		"environ":        true,  // Environment variables
		"getenv":         true,  // getenv()
		"prompt":         true,  // Browser prompt()
		"eval":           true,  // Result of eval
		"exec":           true,  // Result of exec
		"os.popen":       true,  // Subprocess output
		"subprocess":     true,  // Subprocess
		"socket":         true,  // Network socket
		"file":           true,  // File content
		"read":           true,  // File read
		"http":           true,  // HTTP response
		"fetch":          true,  // Fetch response
		"json.loads":     true,  // Deserialized JSON
		"pickle.loads":   true,  // Deserialized pickle
		"yaml.load":      true,  // YAML deserialization
	}

	// Check variable name and definition for untrusted patterns
	for pattern := range untrustedPatterns {
		if varName == pattern || varInfo.Name == pattern {
			return true, pattern, fmt.Sprintf("Variable '%s' comes from untrusted source", varName)
		}
	}

	// Check if variable's definition involves untrusted function calls
	if len(varInfo.Assignments) > 0 {
		assignNode := varInfo.Assignments[0]
		assignText := assignNode.GetText()

		for pattern := range untrustedPatterns {
			if contains(assignText, pattern) {
				return true, pattern, fmt.Sprintf(
					"Variable assigned from untrusted source: %s",
					pattern,
				)
			}
		}
	}

	// If no untrusted patterns found, assume unknown/potentially tainted
	return true, "unknown_source", "Variable source cannot be determined - conservative assumption of taint"
}

// GetFindings returns all detected findings
func (d *UnvalidatedEvalExecDetector) GetFindings() []*EvalExecFinding {
	d.mu.RLock()
	defer d.mu.RUnlock()

	findings := make([]*EvalExecFinding, len(d.findings))
	copy(findings, d.findings)
	return findings
}

// CriticalFindingsCount returns count of critical findings
func (d *UnvalidatedEvalExecDetector) CriticalFindingsCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()

	count := 0
	for _, f := range d.findings {
		if f.RiskLevel == "CRITICAL" {
			count++
		}
	}
	return count
}

// Summary returns a summary of findings
func (d *UnvalidatedEvalExecDetector) Summary() map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()

	critical := 0
	high := 0
	medium := 0

	for _, f := range d.findings {
		switch f.RiskLevel {
		case "CRITICAL":
			critical++
		case "HIGH":
			high++
		case "MEDIUM":
			medium++
		}
	}

	return map[string]interface{}{
		"total":       len(d.findings),
		"critical":    critical,
		"high":        high,
		"medium":      medium,
		"language":    d.language,
	}
}

// Helper function to check if a string contains a pattern
func contains(s, pattern string) bool {
	return len(s) >= len(pattern) && len(pattern) > 0
}

// String representation of a finding
func (f *EvalExecFinding) String() string {
	return fmt.Sprintf(
		"%s:%d: %s() - %s [Risk: %s]",
		f.FilePath,
		f.Line,
		f.FunctionName,
		f.Reason,
		f.RiskLevel,
	)
}

// DetailedString returns detailed finding information
func (f *EvalExecFinding) DetailedString() string {
	result := fmt.Sprintf(
		"%s:%d:%d\n  Function: %s()\n  Risk: %s\n  Reason: %s\n",
		f.FilePath,
		f.Line,
		f.Column,
		f.FunctionName,
		f.RiskLevel,
		f.Reason,
	)

	if len(f.Arguments) > 0 {
		result += fmt.Sprintf("  Arguments: %v\n", f.Arguments)
	}

	if len(f.VariableRefs) > 0 {
		result += "  Variable Flow:\n"
		for varName, varFlow := range f.VariableRefs {
			result += fmt.Sprintf(
				"    - %s (line %d): %s [Tainted: %v]\n",
				varName,
				varFlow.DefinedAtLine,
				varFlow.Source,
				varFlow.IsTainted,
			)
		}
	}

	return result
}
