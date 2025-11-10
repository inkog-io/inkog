package detectors

import (
	"strings"
)

// ASTAnalysisFramework provides shared semantic analysis capabilities for all detectors.
// This framework enables:
// - Variable tracking and assignment chains
// - Data flow analysis (how data moves through code)
// - Call graph building (function relationships)
// - Control flow analysis (code path reachability)
//
// Patterns can reuse these components for consistent, enterprise-grade analysis.
type ASTAnalysisFramework struct {
	// Core analysis components
	variableTracker *VariableTracker
	dataFlow        *DataFlowAnalyzer
	callGraph       *CallGraphBuilder
	controlFlow     *ControlFlowAnalyzer

	// Configuration
	includeComments bool
	multiLanguage   bool // Support multiple languages
}

// NewASTAnalysisFramework creates a new shared analysis framework
func NewASTAnalysisFramework() *ASTAnalysisFramework {
	return &ASTAnalysisFramework{
		variableTracker: NewVariableTracker(),
		dataFlow:        NewDataFlowAnalyzer(),
		callGraph:       NewCallGraphBuilder(),
		controlFlow:     NewControlFlowAnalyzer(),
		includeComments: false,
		multiLanguage:   true,
	}
}

// AnalyzeCode performs full semantic analysis on source code
func (f *ASTAnalysisFramework) AnalyzeCode(filePath string, lines []string) *CodeAnalysis {
	analysis := &CodeAnalysis{
		FilePath:         filePath,
		Lines:            lines,
		Variables:        make(map[string]*Variable),
		Functions:        make(map[string]*Function),
		DataFlows:        make([]DataFlow, 0),
		CallRelations:    make([]CallRelation, 0),
		ControlFlows:     make([]ControlFlowPath, 0),
	}

	// Pass 1: Extract variables and assignments
	analysis.Variables = f.variableTracker.TrackVariables(lines)

	// Pass 2: Extract functions and signatures
	analysis.Functions = f.callGraph.ExtractFunctions(lines)

	// Pass 3: Build call graph
	analysis.CallRelations = f.callGraph.BuildCallGraph(lines, analysis.Functions)

	// Pass 4: Analyze data flows
	analysis.DataFlows = f.dataFlow.AnalyzeDataFlows(lines, analysis.Variables)

	// Pass 5: Analyze control flow
	analysis.ControlFlows = f.controlFlow.AnalyzePaths(lines)

	return analysis
}

// CodeAnalysis represents complete semantic analysis of source code
type CodeAnalysis struct {
	FilePath       string
	Lines          []string
	Variables      map[string]*Variable
	Functions      map[string]*Function
	DataFlows      []DataFlow
	CallRelations  []CallRelation
	ControlFlows   []ControlFlowPath
}

// Variable represents a tracked variable in the code
type Variable struct {
	Name              string
	FirstSeenLine     int
	Assignments       []Assignment
	Usages            []Usage
	IsUserInput       bool
	IsLLMOutput       bool
	IsCredential      bool
	IsSanitized       bool
	FlowsToSinks      []string // Functions/outputs it flows to
}

// Assignment represents a variable assignment
type Assignment struct {
	LineNum  int
	SourceType string // "user_input", "llm_output", "constant", "function_call", etc.
	Value   string
	RHS     string // Right-hand side of assignment
}

// Usage represents a variable usage
type Usage struct {
	LineNum int
	Context string // What the variable is used for
	IsDangerous bool
}

// Function represents an extracted function/method
type Function struct {
	Name      string
	StartLine int
	EndLine   int
	CallsTo   []string   // Functions it calls
	CalledBy  []string   // Functions that call it
	Params    []string
	Returns   []string
}

// DataFlow represents how data moves through code
type DataFlow struct {
	Source      string // user_input, request.args, llm.response
	Path        []string // [user_input, variable_x, prompt, llm.call]
	Sink        string // Where it ends (dangerous function, network call, etc.)
	LineNumbers []int
	RiskLevel   float32
}

// CallRelation represents a function call relationship
type CallRelation struct {
	Caller    string
	Callee    string
	LineNum   int
	IsRecursive bool // Direct or indirect recursion
}

// ControlFlowPath represents a code execution path
type ControlFlowPath struct {
	StartLine   int
	EndLine     int
	Conditions  []string // What conditions must be true
	HasBreak    bool
	HasReturn   bool
	IsReachable bool
}

// GetVariableFlow traces a variable's flow through the code
// Used by Pattern 1 (Prompt Injection) to track user_input → prompt → llm
func (f *ASTAnalysisFramework) GetVariableFlow(analysis *CodeAnalysis, varName string) []string {
	if variable, exists := analysis.Variables[varName]; exists {
		return variable.FlowsToSinks
	}
	return []string{}
}

// GetFunctionCalls gets all functions that call a given function
// Used by Pattern 3 (Infinite Loops) to build call chains
func (f *ASTAnalysisFramework) GetFunctionCalls(analysis *CodeAnalysis, funcName string) []CallRelation {
	var results []CallRelation
	for _, relation := range analysis.CallRelations {
		if relation.Callee == funcName {
			results = append(results, relation)
		}
	}
	return results
}

// IsDataFlowDangerous checks if a data flow is dangerous
// Used by all patterns to understand data movement risk
func (f *ASTAnalysisFramework) IsDataFlowDangerous(flow DataFlow) bool {
	// Data flows are dangerous if they end in sinks
	dangerousSinks := []string{
		"eval", "exec", "system", "subprocess.run", "os.system",
		"os.environ", "process.env", "open", "read", "write",
		"llm.call", "invoke", "execute",
	}

	for _, sink := range dangerousSinks {
		if strings.Contains(strings.ToLower(flow.Sink), strings.ToLower(sink)) {
			return true
		}
	}
	return false
}

// GetReachableBreaks checks if break/return statements are reachable
// Used by Pattern 3 (Infinite Loops) to determine loop termination
func (f *ASTAnalysisFramework) GetReachableBreaks(analysis *CodeAnalysis, startLine int, endLine int) int {
	reachableCount := 0
	for _, path := range analysis.ControlFlows {
		if path.StartLine >= startLine && path.EndLine <= endLine && path.IsReachable {
			if path.HasBreak || path.HasReturn {
				reachableCount++
			}
		}
	}
	return reachableCount
}

// DetectMutualRecursion detects circular function calls
// Used by Pattern 3 (Infinite Loops) to find mutual recursion
func (f *ASTAnalysisFramework) DetectMutualRecursion(analysis *CodeAnalysis) [][]string {
	var cycles [][]string

	// Build adjacency list
	callGraph := make(map[string][]string)
	for _, relation := range analysis.CallRelations {
		callGraph[relation.Caller] = append(callGraph[relation.Caller], relation.Callee)
	}

	// DFS to find cycles
	visited := make(map[string]bool)
	recStack := make(map[string]bool)

	var dfs func(node string, path []string)
	dfs = func(node string, path []string) {
		visited[node] = true
		recStack[node] = true
		path = append(path, node)

		for _, neighbor := range callGraph[node] {
			if recStack[neighbor] {
				// Found a cycle
				cycleStart := -1
				for i, p := range path {
					if p == neighbor {
						cycleStart = i
						break
					}
				}
				if cycleStart >= 0 {
					cycle := path[cycleStart:]
					cycle = append(cycle, neighbor)
					cycles = append(cycles, cycle)
				}
			} else if !visited[neighbor] {
				dfs(neighbor, path)
			}
		}

		recStack[node] = false
	}

	for node := range callGraph {
		if !visited[node] {
			dfs(node, []string{})
		}
	}

	return cycles
}

// GetDataFlowAnalyzer returns the data flow analyzer component
// Used by patterns to access detailed data flow analysis results
func (f *ASTAnalysisFramework) GetDataFlowAnalyzer() *DataFlowAnalyzer {
	return f.dataFlow
}

// GetVariableTracker returns the variable tracker component
// Used by patterns to access variable tracking results
func (f *ASTAnalysisFramework) GetVariableTracker() *VariableTracker {
	return f.variableTracker
}

// GetCallGraphBuilder returns the call graph builder component
// Used by patterns to access function relationship analysis
func (f *ASTAnalysisFramework) GetCallGraphBuilder() *CallGraphBuilder {
	return f.callGraph
}

// GetControlFlowAnalyzer returns the control flow analyzer component
// Used by patterns to access control flow analysis results
func (f *ASTAnalysisFramework) GetControlFlowAnalyzer() *ControlFlowAnalyzer {
	return f.controlFlow
}

// EnhanceConfidenceScore enhances confidence based on semantic analysis
// Used by all patterns to provide context-aware scoring
func (f *ASTAnalysisFramework) EnhanceConfidenceScore(baseScore float32, analysis *CodeAnalysis, lineNum int) float32 {
	enhanced := baseScore

	// Check if line contains user input
	for _, variable := range analysis.Variables {
		if variable.IsUserInput {
			for _, assignment := range variable.Assignments {
				if assignment.LineNum <= lineNum {
					enhanced += 0.05 // User input nearby
				}
			}
		}
	}

	// Check for sanitization in nearby lines
	for varName, variable := range analysis.Variables {
		if variable.IsSanitized {
			for _, usage := range variable.Usages {
				if usage.LineNum >= lineNum-5 && usage.LineNum <= lineNum+5 {
					enhanced -= 0.15 // Sanitization found nearby
				}
			}
		}
	}

	// Clamp score
	if enhanced < 0.0 {
		enhanced = 0.0
	}
	if enhanced > 1.0 {
		enhanced = 1.0
	}

	return enhanced
}
