package detectors

import (
	"regexp"
	"strings"
)

// ControlFlowAnalyzer analyzes code execution paths and control flow
// Reusable by: Pattern 3 (infinite loop detection), Patterns 5, 8
type ControlFlowAnalyzer struct {
	loopPatterns      *regexp.Regexp
	breakPatterns     *regexp.Regexp
	returnPatterns    *regexp.Regexp
	conditionPatterns *regexp.Regexp
}

// NewControlFlowAnalyzer creates a new control flow analyzer
func NewControlFlowAnalyzer() *ControlFlowAnalyzer {
	return &ControlFlowAnalyzer{
		// Matches: for, while, do-while, foreach, loop, until
		loopPatterns: regexp.MustCompile(`(?i)\b(for|while|do|foreach|loop|until|repeat)\b`),
		// Matches: break, continue, exit
		breakPatterns: regexp.MustCompile(`(?i)\b(break|continue|exit)\b`),
		// Matches: return, yield, throw
		returnPatterns: regexp.MustCompile(`(?i)\b(return|yield|throw)\b`),
		// Matches: conditions in if/while/for statements
		conditionPatterns: regexp.MustCompile(`(?i)(?:if|while|for)\s*\([^)]+\)`),
	}
}

// AnalyzePaths analyzes control flow paths in code
func (cfa *ControlFlowAnalyzer) AnalyzePaths(lines []string) []ControlFlowPath {
	var paths []ControlFlowPath

	loopStack := make([]LoopInfo, 0) // Stack to track nested loops

	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}

		// Detect loop start
		if cfa.loopPatterns.MatchString(line) {
			loopInfo := LoopInfo{
				StartLine:   lineNum + 1,
				Condition:   cfa.extractCondition(line),
				HasBreak:    false,
				HasReturn:   false,
				IsConstant:  cfa.isConstantCondition(line),
				NestedLevel: len(loopStack),
			}
			loopStack = append(loopStack, loopInfo)
			continue
		}

		// Track break/return statements within loops
		if len(loopStack) > 0 {
			if cfa.breakPatterns.MatchString(line) {
				loopStack[len(loopStack)-1].HasBreak = true
			}
			if cfa.returnPatterns.MatchString(line) {
				loopStack[len(loopStack)-1].HasReturn = true
			}
		}

		// Detect loop end (closing brace, dedent, or next statement at same level)
		if len(loopStack) > 0 && cfa.isLoopEnd(lines, lineNum, loopStack[len(loopStack)-1]) {
			loop := loopStack[len(loopStack)-1]
			loopStack = loopStack[:len(loopStack)-1] // Pop from stack

			path := ControlFlowPath{
				StartLine:   loop.StartLine,
				EndLine:     lineNum + 1,
				Conditions:  []string{loop.Condition},
				HasBreak:    loop.HasBreak,
				HasReturn:   loop.HasReturn,
				IsReachable: cfa.isPathReachable(lines, loop.StartLine, lineNum+1, loop.IsConstant),
			}

			paths = append(paths, path)
		}
	}

	// Handle unclosed loops at end of file
	for _, loop := range loopStack {
		path := ControlFlowPath{
			StartLine:   loop.StartLine,
			EndLine:     len(lines),
			Conditions:  []string{loop.Condition},
			HasBreak:    loop.HasBreak,
			HasReturn:   loop.HasReturn,
			IsReachable: cfa.isPathReachable(lines, loop.StartLine, len(lines), loop.IsConstant),
		}
		paths = append(paths, path)
	}

	return paths
}

// LoopInfo tracks information about a loop during analysis
type LoopInfo struct {
	StartLine   int
	Condition   string
	HasBreak    bool
	HasReturn   bool
	IsConstant  bool
	NestedLevel int
}

// extractCondition extracts the condition from a loop statement
func (cfa *ControlFlowAnalyzer) extractCondition(line string) string {
	matches := cfa.conditionPatterns.FindStringSubmatch(line)
	if len(matches) > 0 {
		return matches[0]
	}

	// For simple while/for without parentheses
	if strings.Contains(strings.ToLower(line), "for") && strings.Contains(line, ":") {
		return "for_loop"
	}
	if strings.Contains(strings.ToLower(line), "while") {
		return "while_loop"
	}

	return ""
}

// isConstantCondition checks if a loop has a constant condition (infinite loop pattern)
func (cfa *ControlFlowAnalyzer) isConstantCondition(line string) bool {
	lowerLine := strings.ToLower(line)

	// Constant true conditions
	constantPatterns := []string{
		"while(true",
		"while true",
		"while 1",
		"while(1)",
		"for(;;)",
		"for;;",
		"loop {",
		"for {",
		"loop()",
		"while (true)",
		"while(true)",
		"for ::",
		"repeat",
		"until false",
		"do {",
		"do while(true)",
	}

	for _, pattern := range constantPatterns {
		if strings.Contains(lowerLine, pattern) {
			return true
		}
	}

	// Check for Python-style infinite loops
	if strings.Contains(lowerLine, "while ") && strings.Contains(line, ":") {
		afterWhile := strings.SplitN(line, "while", 2)
		if len(afterWhile) > 1 {
			condition := strings.TrimSpace(afterWhile[1])
			condition = strings.TrimSuffix(condition, ":")
			condition = strings.TrimSpace(condition)
			if condition == "True" || condition == "true" || condition == "1" {
				return true
			}
		}
	}

	return false
}

// isLoopEnd detects if we've reached the end of a loop block
func (cfa *ControlFlowAnalyzer) isLoopEnd(lines []string, currentLine int, loop LoopInfo) bool {
	if currentLine+1 >= len(lines) {
		return true // End of file
	}

	currentIndent := cfa.getIndentation(lines[loop.StartLine-1])
	nextLine := lines[currentLine+1]
	nextTrimmed := strings.TrimSpace(nextLine)

	// End of loop if next line is empty or comment
	if nextTrimmed == "" || strings.HasPrefix(nextTrimmed, "#") || strings.HasPrefix(nextTrimmed, "//") {
		return false
	}

	nextIndent := cfa.getIndentation(nextLine)

	// Loop ends if indentation returns to or goes below loop start indentation
	// (for indentation-based languages like Python)
	if nextIndent <= currentIndent {
		return true
	}

	return false
}

// getIndentation returns the indentation level of a line
func (cfa *ControlFlowAnalyzer) getIndentation(line string) int {
	count := 0
	for _, ch := range line {
		if ch == ' ' {
			count++
		} else if ch == '\t' {
			count += 4 // Tab = 4 spaces
		} else {
			break
		}
	}
	return count
}

// isPathReachable determines if a code path is reachable
func (cfa *ControlFlowAnalyzer) isPathReachable(lines []string, startLine int, endLine int, isConstant bool) bool {
	// If loop condition is constant (true), the loop is always reachable
	if isConstant {
		return true
	}

	// Check if there are any break statements that would exit the loop
	for lineNum := startLine; lineNum < endLine && lineNum <= len(lines); lineNum++ {
		line := lines[lineNum-1]

		if cfa.breakPatterns.MatchString(line) {
			// Break found - path could be exited
			return true
		}

		if cfa.returnPatterns.MatchString(line) {
			// Return found - path could be exited
			return true
		}
	}

	// Default to reachable
	return true
}

// IsInfiniteLoop checks if a loop is likely infinite based on control flow analysis
// Used by Pattern 3 to determine infinite loop risk
func (cfa *ControlFlowAnalyzer) IsInfiniteLoop(path ControlFlowPath, functions map[string]*Function, relations []CallRelation) bool {
	// Constant condition without break/return = infinite
	if cfa.hasConstantCondition(path.Conditions) && !path.HasBreak && !path.HasReturn {
		return true
	}

	// No break/return and non-trivial condition = potential infinite
	if !path.HasBreak && !path.HasReturn {
		return true
	}

	return false
}

// hasConstantCondition checks if any condition is constant
func (cfa *ControlFlowAnalyzer) hasConstantCondition(conditions []string) bool {
	for _, condition := range conditions {
		lowerCond := strings.ToLower(condition)
		if strings.Contains(lowerCond, "true") ||
			strings.Contains(lowerCond, "1") ||
			strings.Contains(lowerCond, ";;") ||
			strings.Contains(lowerCond, "for") && strings.Contains(lowerCond, "{") {
			return true
		}
	}
	return false
}

// GetLoopsInFunction gets all loops within a specific function's scope
// Used by Pattern 3 to analyze loops within function bodies
func (cfa *ControlFlowAnalyzer) GetLoopsInFunction(paths []ControlFlowPath, function *Function) []ControlFlowPath {
	var loops []ControlFlowPath
	for _, path := range paths {
		if path.StartLine >= function.StartLine && path.EndLine <= function.EndLine {
			loops = append(loops, path)
		}
	}
	return loops
}

// DetectUnterminatedLoops finds loops with no reachable exit condition
// Used by Pattern 3 to detect infinite loops
func (cfa *ControlFlowAnalyzer) DetectUnterminatedLoops(paths []ControlFlowPath) []ControlFlowPath {
	var unTerminated []ControlFlowPath
	for _, path := range paths {
		// Loop is unterminated if no break/return and no dynamic condition
		if !path.HasBreak && !path.HasReturn {
			unTerminated = append(unTerminated, path)
		}
	}
	return unTerminated
}

// TraceLoopConditionDependencies identifies variables used in loop conditions
// Used by Pattern 3 to understand loop termination dependencies
func (cfa *ControlFlowAnalyzer) TraceLoopConditionDependencies(condition string) []string {
	var variables []string

	// Extract variable names from condition
	varPattern := regexp.MustCompile(`\b([a-zA-Z_]\w*)\b`)
	matches := varPattern.FindAllString(condition, -1)

	seen := make(map[string]bool)
	for _, match := range matches {
		if !seen[match] {
			// Skip keywords
			if !cfa.isKeyword(match) {
				variables = append(variables, match)
				seen[match] = true
			}
		}
	}

	return variables
}

// isKeyword checks if a string is a language keyword
func (cfa *ControlFlowAnalyzer) isKeyword(word string) bool {
	keywords := map[string]bool{
		"if": true, "else": true, "while": true, "for": true, "do": true,
		"switch": true, "case": true, "default": true, "break": true, "continue": true,
		"return": true, "true": true, "false": true, "True": true, "False": true,
		"null": true, "nil": true, "None": true, "undefined": true,
		"and": true, "or": true, "not": true, "is": true, "in": true,
		"try": true, "catch": true, "finally": true, "throw": true, "throws": true,
		"function": true, "def": true, "async": true, "await": true,
		"class": true, "struct": true, "interface": true, "enum": true,
		"public": true, "private": true, "protected": true, "static": true,
	}
	return keywords[word]
}
