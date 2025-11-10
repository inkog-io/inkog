package detectors

import (
	"regexp"
	"strings"
)

// CallGraphBuilder constructs call graphs and detects function relationships
// Reusable by: Pattern 3 (mutual recursion detection), Patterns 5-7
type CallGraphBuilder struct {
	functionDefPattern *regexp.Regexp
	functionCallPattern *regexp.Regexp
}

// NewCallGraphBuilder creates a new call graph builder
func NewCallGraphBuilder() *CallGraphBuilder {
	return &CallGraphBuilder{
		// Matches: def func_name, function func_name, func func_name, method, etc.
		functionDefPattern: regexp.MustCompile(`(?i)(?:def|function|func|method|async\s+def|async\s+function)\s+(\w+)\s*\(`),
		// Matches function calls: func_name(), Module.func_name(), etc.
		functionCallPattern: regexp.MustCompile(`(\w+)\s*\(`),
	}
}

// ExtractFunctions finds all function definitions in the code
func (cgb *CallGraphBuilder) ExtractFunctions(lines []string) map[string]*Function {
	functions := make(map[string]*Function)

	for lineNum, line := range lines {
		// Skip comments
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}

		// Find function definitions
		matches := cgb.functionDefPattern.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			if len(match) >= 2 {
				funcName := match[1]

				// Extract parameters
				params := cgb.extractParameters(line)

				functions[funcName] = &Function{
					Name:      funcName,
					StartLine: lineNum + 1,
					EndLine:   cgb.findFunctionEnd(lines, lineNum),
					CallsTo:   make([]string, 0),
					CalledBy:  make([]string, 0),
					Params:    params,
				}
			}
		}
	}

	return functions
}

// BuildCallGraph creates relationships between functions
func (cgb *CallGraphBuilder) BuildCallGraph(lines []string, functions map[string]*Function) []CallRelation {
	var relations []CallRelation

	for funcName, function := range functions {
		// Look for calls within this function's body
		for lineNum := function.StartLine; lineNum <= function.EndLine && lineNum <= len(lines); lineNum++ {
			line := lines[lineNum-1] // Convert to 0-indexed

			// Find all function calls on this line
			callMatches := cgb.functionCallPattern.FindAllStringSubmatch(line, -1)
			for _, callMatch := range callMatches {
				if len(callMatch) >= 1 {
					calledFunc := callMatch[1]

					// Check if this is a known function (not a builtin)
					if _, isFunctionDef := functions[calledFunc]; isFunctionDef {
						relation := CallRelation{
							Caller:      funcName,
							Callee:      calledFunc,
							LineNum:     lineNum,
							IsRecursive: cgb.isRecursiveCall(funcName, calledFunc, functions),
						}
						relations = append(relations, relation)

						// Update the function's call lists
						function.CallsTo = append(function.CallsTo, calledFunc)
						functions[calledFunc].CalledBy = append(functions[calledFunc].CalledBy, funcName)
					}
				}
			}
		}
	}

	return relations
}

// extractParameters extracts function parameters from definition line
func (cgb *CallGraphBuilder) extractParameters(line string) []string {
	var params []string

	// Find parameters between parentheses
	startIdx := strings.Index(line, "(")
	endIdx := strings.Index(line, ")")

	if startIdx > 0 && endIdx > startIdx {
		paramStr := line[startIdx+1 : endIdx]
		paramStr = strings.TrimSpace(paramStr)

		if paramStr == "" || paramStr == "self" {
			return params
		}

		// Split by comma and clean up
		paramParts := strings.Split(paramStr, ",")
		for _, param := range paramParts {
			param = strings.TrimSpace(param)
			// Extract just the parameter name
			if idx := strings.Index(param, "="); idx > 0 {
				param = param[:idx]
			}
			param = strings.TrimSpace(param)
			if param != "" && param != "self" {
				params = append(params, param)
			}
		}
	}

	return params
}

// findFunctionEnd finds the approximate end line of a function
func (cgb *CallGraphBuilder) findFunctionEnd(lines []string, startLine int) int {
	if startLine+1 >= len(lines) {
		return startLine
	}

	// Get indentation of function definition
	defLine := lines[startLine]
	defIndent := len(defLine) - len(strings.TrimLeft(defLine, " \t"))

	// Find next function or class definition at same or lower indentation
	for i := startLine + 1; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		// Skip empty lines and comments
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Check indentation
		lineIndent := len(line) - len(strings.TrimLeft(line, " \t"))

		// If we find another function/class at same level, that's our end
		if lineIndent <= defIndent && (strings.HasPrefix(trimmed, "def ") ||
			strings.HasPrefix(trimmed, "function ") ||
			strings.HasPrefix(trimmed, "class ")) {
			return i
		}
	}

	return len(lines)
}

// isRecursiveCall checks if a call is recursive (direct or indirect)
func (cgb *CallGraphBuilder) isRecursiveCall(caller string, callee string, functions map[string]*Function) bool {
	return caller == callee // Direct recursion
}

// FindMutualRecursion detects functions that call each other (direct mutual recursion)
func (cgb *CallGraphBuilder) FindMutualRecursion(relations []CallRelation) [][]string {
	var cycles [][]string

	// Build adjacency list
	callGraph := make(map[string][]string)
	for _, relation := range relations {
		callGraph[relation.Caller] = append(callGraph[relation.Caller], relation.Callee)
	}

	// Check for direct mutual recursion (A→B→A)
	visited := make(map[string]map[string]bool)

	for _, relation := range relations {
		caller := relation.Caller
		callee := relation.Callee

		// Check if callee calls back to caller
		for _, subcall := range callGraph[callee] {
			if subcall == caller {
				// Found A→B→A
				cycle := []string{caller, callee, caller}
				cycles = append(cycles, cycle)
			}
		}
	}

	return cycles
}

// FindIndirectRecursion detects longer call chains (A→B→C→A)
func (cgb *CallGraphBuilder) FindIndirectRecursion(relations []CallRelation, maxDepth int) [][]string {
	var cycles [][]string

	// Build adjacency list
	callGraph := make(map[string][]string)
	for _, relation := range relations {
		callGraph[relation.Caller] = append(callGraph[relation.Caller], relation.Callee)
	}

	// DFS-based cycle detection
	visited := make(map[string]bool)
	recStack := make(map[string]bool)

	var dfs func(node string, path []string)
	dfs = func(node string, path []string) {
		if len(path) > maxDepth {
			return
		}

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
					cycle := append([]string{}, path[cycleStart:]...)
					cycle = append(cycle, neighbor)
					cycles = append(cycles, cycle)
				}
			} else if !visited[neighbor] {
				dfs(neighbor, append([]string{}, path...))
			}
		}

		recStack[node] = false
	}

	// Start DFS from each node
	for node := range callGraph {
		if !visited[node] {
			dfs(node, []string{})
		}
	}

	return cycles
}

// GetFunctionCallsWithin gets all function calls within a specific function
func (cgb *CallGraphBuilder) GetFunctionCallsWithin(function *Function, relations []CallRelation) []CallRelation {
	var calls []CallRelation
	for _, relation := range relations {
		if relation.Caller == function.Name {
			calls = append(calls, relation)
		}
	}
	return calls
}

// GetFunctionCallers gets all functions that call a specific function
func (cgb *CallGraphBuilder) GetFunctionCallers(funcName string, relations []CallRelation) []string {
	var callers []string
	callerSet := make(map[string]bool)

	for _, relation := range relations {
		if relation.Callee == funcName && !callerSet[relation.Caller] {
			callers = append(callers, relation.Caller)
			callerSet[relation.Caller] = true
		}
	}

	return callers
}

// IsInfiniteRecursionRisk checks if a function has high risk of infinite recursion
func (cgb *CallGraphBuilder) IsInfiniteRecursionRisk(function *Function, relations []CallRelation) bool {
	// Check if function calls itself
	for _, relation := range relations {
		if relation.Caller == function.Name && relation.IsRecursive {
			return true
		}
	}

	// Check for mutual recursion
	mutualCycles := cgb.FindMutualRecursion(relations)
	for _, cycle := range mutualCycles {
		for _, funcInCycle := range cycle {
			if funcInCycle == function.Name {
				return true
			}
		}
	}

	// Check for deeper cycles (A→B→C→A)
	indirectCycles := cgb.FindIndirectRecursion(relations, 10)
	for _, cycle := range indirectCycles {
		for _, funcInCycle := range cycle {
			if funcInCycle == function.Name {
				return true
			}
		}
	}

	return false
}
