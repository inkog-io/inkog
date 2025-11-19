package analysis

import (
	"sync"

	"github.com/inkog-io/inkog/action/pkg/ast_engine/ast"
)

// ExitConditionType represents the type of loop exit
type ExitConditionType string

const (
	ExitCounter         ExitConditionType = "counter"        // i < 10
	ExitBreak           ExitConditionType = "break"          // explicit break
	ExitException       ExitConditionType = "exception"      // try/except
	ExitNonDeterministic ExitConditionType = "non_deterministic" // llm_call()
	ExitUnknown         ExitConditionType = "unknown"
)

// ExitCondition describes how a loop can exit
type ExitCondition struct {
	Type      ExitConditionType
	Evidence  *ast.Node // The node proving the exit
	IsHard    bool      // true if guaranteed exit (counter/break), false if might not exit
	Details   string    // Additional info
}

// LoopInfo contains analysis information for a single loop
type LoopInfo struct {
	Node                *ast.Node
	ConditionText       string
	ConditionNodes      []*ast.Node
	Body                []*ast.Node
	ExitConditions      []*ExitCondition
	BreakCounterVar     *string  // e.g., "i" if loop has counter
	MaxIterations       *int     // If determinable
	IsDeterministic     bool     // Does condition depend on non-deterministic source?
	HasLLMCallInBody    bool     // Does loop body call LLM?
	LLMCallNodes        []*ast.Node
	DataGrowthVars      []string // Variables that grow unbounded
	Line                int
}

// ControlFlowGraph analyzes control flow structure
type ControlFlowGraph struct {
	root   *ast.Node
	loops  []*LoopInfo
	taint  *TaintTracker
	mu     sync.RWMutex
}

// NewControlFlowGraph creates a new control flow graph analyzer
func NewControlFlowGraph(root *ast.Node, taint *TaintTracker) *ControlFlowGraph {
	cfg := &ControlFlowGraph{
		root:  root,
		loops: make([]*LoopInfo, 0),
		taint: taint,
	}

	if root != nil {
		cfg.analyzeControlFlow(root)
	}

	return cfg
}

// ExtractLoops finds and analyzes all loops in the AST
func (cfg *ControlFlowGraph) ExtractLoops() []*LoopInfo {
	cfg.mu.RLock()
	defer cfg.mu.RUnlock()

	result := make([]*LoopInfo, len(cfg.loops))
	copy(result, cfg.loops)
	return result
}

// analyzeControlFlow recursively analyzes control flow
func (cfg *ControlFlowGraph) analyzeControlFlow(node *ast.Node) {
	if node == nil {
		return
	}

	// Check if this is a loop
	if node.Type == ast.NodeTypeLoop {
		loopInfo := cfg.analyzeLoop(node)
		cfg.loops = append(cfg.loops, loopInfo)
	}

	// Recurse through children
	children := node.GetChildren()
	for _, child := range children {
		cfg.analyzeControlFlow(child)
	}
}

// analyzeLoop analyzes a single loop node
func (cfg *ControlFlowGraph) analyzeLoop(loopNode *ast.Node) *LoopInfo {
	loopInfo := &LoopInfo{
		Node:           loopNode,
		ExitConditions: make([]*ExitCondition, 0),
		LLMCallNodes:   make([]*ast.Node, 0),
		Body:           loopNode.GetChildren(),
		Line:           loopNode.StartLine,
	}

	// Extract condition text if available
	if condText, ok := loopNode.GetProperty("condition"); ok && condText != nil {
		loopInfo.ConditionText = condText.(string)
	}

	// Analyze condition for non-determinism
	loopInfo.ConditionNodes = loopNode.GetChildren()
	loopInfo.IsDeterministic = cfg.isConditionDeterministic(loopInfo)

	// Find exit conditions and counter
	loopInfo.BreakCounterVar = cfg.findBreakCounter(loopNode)
	loopInfo.ExitConditions = cfg.analyzeExitConditions(loopNode)

	// Check for LLM calls in body
	cfg.findLLMCalls(loopNode, loopInfo)

	// Check for unbounded data growth
	loopInfo.DataGrowthVars = cfg.findDataGrowth(loopNode)

	return loopInfo
}

// isConditionDeterministic checks if a loop condition depends on non-deterministic sources
func (cfg *ControlFlowGraph) isConditionDeterministic(loopInfo *LoopInfo) bool {
	// Non-deterministic keywords
	nonDetKeywords := []string{
		"llm_call", "gpt", "chat", "completion", "ollama",
		"random", "rand", "choice", "shuffle",
		"request", "get", "post", "fetch",
		"input", "stdin",
	}

	conditionText := loopInfo.ConditionText
	for _, keyword := range nonDetKeywords {
		if contains(conditionText, keyword) {
			return false
		}
	}

	return true
}

// findBreakCounter extracts a counter variable if the loop has one
func (cfg *ControlFlowGraph) findBreakCounter(loopNode *ast.Node) *string {
	// Look for patterns like: i < 10, count < MAX, iterations > 0
	condText, ok := loopNode.GetProperty("condition")
	if !ok || condText == nil {
		return nil
	}

	conditionStr := condText.(string)

	// Simple pattern matching for counter variables
	// Look for: variable < number, variable > number, variable <= number, etc
	counterVars := []string{"i", "j", "k", "count", "counter", "iterations", "attempts", "retries", "max_"}

	for _, varName := range counterVars {
		if contains(conditionStr, varName) && (
			contains(conditionStr, "<") || contains(conditionStr, ">") ||
			contains(conditionStr, "<=") || contains(conditionStr, ">=")) {
			return &varName
		}
	}

	return nil
}

// analyzeExitConditions analyzes how the loop can exit
func (cfg *ControlFlowGraph) analyzeExitConditions(loopNode *ast.Node) []*ExitCondition {
	conditions := make([]*ExitCondition, 0)

	// Check for hard counter
	if counterVar := cfg.findBreakCounter(loopNode); counterVar != nil {
		conditions = append(conditions, &ExitCondition{
			Type:     ExitCounter,
			Evidence: loopNode,
			IsHard:   true,
			Details:  "Counter variable: " + *counterVar,
		})
	}

	// Check for explicit break statements
	if cfg.hasExplicitBreak(loopNode) {
		conditions = append(conditions, &ExitCondition{
			Type:     ExitBreak,
			Evidence: loopNode,
			IsHard:   true,
			Details:  "Explicit break statement",
		})
	}

	// Check if condition is non-deterministic
	if !cfg.isConditionDeterministic(&LoopInfo{
		ConditionText:  getConditionText(loopNode),
		ConditionNodes: loopNode.GetChildren(),
	}) {
		conditions = append(conditions, &ExitCondition{
			Type:     ExitNonDeterministic,
			Evidence: loopNode,
			IsHard:   false,
			Details:  "Loop condition depends on non-deterministic source (LLM/network)",
		})
	}

	// Check for exception-based exit
	children := loopNode.GetChildren()
	for _, child := range children {
		if child.Type == ast.NodeTypeErrorHandling {
			conditions = append(conditions, &ExitCondition{
				Type:     ExitException,
				Evidence: child,
				IsHard:   false,
				Details:  "Exception handling",
			})
			break
		}
	}

	return conditions
}

// hasExplicitBreak checks if loop has explicit break statement
func (cfg *ControlFlowGraph) hasExplicitBreak(loopNode *ast.Node) bool {
	// Simplified: look for "break" in loop body
	bodyText := loopNode.GetText()
	return contains(bodyText, "break")
}

// findLLMCalls finds all LLM calls in loop body
func (cfg *ControlFlowGraph) findLLMCalls(loopNode *ast.Node, loopInfo *LoopInfo) {
	llmKeywords := []string{
		"llm_call", "gpt", "chat", "completion", "ollama",
		"invoke", "generate", "call",
	}

	cfg.findLLMCallsRecursive(loopNode, llmKeywords, loopInfo)

	loopInfo.HasLLMCallInBody = len(loopInfo.LLMCallNodes) > 0
}

// findLLMCallsRecursive recursively finds LLM calls
func (cfg *ControlFlowGraph) findLLMCallsRecursive(node *ast.Node, keywords []string, loopInfo *LoopInfo) {
	if node == nil {
		return
	}

	// Check if this is a function call
	if node.Type == ast.NodeTypeFunctionCall {
		if funcName, ok := node.GetProperty("function"); ok && funcName != nil {
			funcStr := funcName.(string)
			for _, keyword := range keywords {
				if contains(funcStr, keyword) {
					loopInfo.LLMCallNodes = append(loopInfo.LLMCallNodes, node)
					break
				}
			}
		}
	}

	// Recurse
	children := node.GetChildren()
	for _, child := range children {
		cfg.findLLMCallsRecursive(child, keywords, loopInfo)
	}
}

// findDataGrowth finds variables that grow unbounded in loops
func (cfg *ControlFlowGraph) findDataGrowth(loopNode *ast.Node) []string {
	growthVars := make([]string, 0)
	growthKeywords := []string{"append", "extend", "add", "push", "+=", ".add(", ".extend("}

	cfg.findDataGrowthRecursive(loopNode, growthKeywords, &growthVars)

	return growthVars
}

// findDataGrowthRecursive finds data growth patterns
func (cfg *ControlFlowGraph) findDataGrowthRecursive(node *ast.Node, keywords []string, vars *[]string) {
	if node == nil {
		return
	}

	nodeText := node.GetText()
	for _, keyword := range keywords {
		if contains(nodeText, keyword) {
			// Extract variable name
			if varName, ok := node.GetProperty("variable"); ok && varName != nil {
				*vars = append(*vars, varName.(string))
			}
			break
		}
	}

	// Recurse
	children := node.GetChildren()
	for _, child := range children {
		cfg.findDataGrowthRecursive(child, keywords, vars)
	}
}

// HasDoomLoopPattern checks if a loop matches the Doom Loop pattern:
// - Has LLM call in condition or body
// - No hard break counter
// - Non-deterministic exit condition
func (cfg *ControlFlowGraph) HasDoomLoopPattern(loopInfo *LoopInfo) bool {
	// Must have LLM calls
	if !loopInfo.HasLLMCallInBody && !cfg.conditionHasLLMCall(loopInfo.ConditionText) {
		return false
	}

	// Must NOT have hard counter
	if loopInfo.BreakCounterVar != nil {
		return false
	}

	// Must have non-deterministic exit
	if loopInfo.IsDeterministic {
		return false
	}

	// Must have non-hard exit conditions
	for _, exitCond := range loopInfo.ExitConditions {
		if exitCond.IsHard {
			return false
		}
	}

	return true
}

// HasContextExhaustionPattern checks for unbounded context growth:
// - Variables grow in loop (append, extend)
// - No size limit or truncation
func (cfg *ControlFlowGraph) HasContextExhaustionPattern(loopInfo *LoopInfo) bool {
	if len(loopInfo.DataGrowthVars) == 0 {
		return false
	}

	bodyText := loopInfo.Node.GetText()

	// SAFE PATTERN A: deque with maxlen
	// Look for: deque(..., maxlen=...) or deque(maxlen=...)
	if contains(bodyText, "deque") && contains(bodyText, "maxlen=") {
		return false
	}

	// SAFE PATTERN B: Truncation logic
	// Look for: if len(...) > N: ... x = x[-N:] or x = x[...:N]
	if cfg.hasExplicitTruncation(bodyText) {
		return false
	}

	// SAFE PATTERN C: Pop operations (ring buffer pattern)
	// Look for: .pop(0) or .popleft() to remove old elements
	if contains(bodyText, ".pop(0)") || contains(bodyText, ".popleft()") ||
		contains(bodyText, ".pop(") || contains(bodyText, "del ") {
		return false
	}

	// SAFE PATTERN D: Explicit reset/session management
	// Look for: if size >= max: reset, clear, or reassign to empty
	if cfg.hasExplicitReset(bodyText) {
		return false
	}

	// SAFE PATTERN E: Other bounded collection patterns
	if contains(bodyText, "fixed") || contains(bodyText, "circular") ||
		contains(bodyText, "max_size") || contains(bodyText, "maxlen") {
		return false
	}

	return true
}

// hasExplicitTruncation checks for truncation logic patterns
func (cfg *ControlFlowGraph) hasExplicitTruncation(text string) bool {
	// Look for patterns like:
	// if len(x) > N: x = x[-N:]
	// if len(x) > N: x = "\n".join(lines[-20:])
	// if len(x) > max: ... x = x[:]  etc

	truncationPatterns := []string{
		"x[-",      // x[-20:] or x[-N:]
		"len(",     // len(x) pattern (often in if statements)
	}

	hasLen := false
	hasSlicing := false

	for _, pattern := range truncationPatterns {
		if contains(text, pattern) {
			if pattern == "len(" {
				hasLen = true
			}
			if pattern == "x[-" || contains(text, "[") && contains(text, ":") {
				hasSlicing = true
			}
		}
	}

	// If we have both len() checks and slicing, likely truncation
	if hasLen && hasSlicing {
		return true
	}

	// Check for split and rejoin (common truncation pattern)
	if contains(text, "split(") && contains(text, "join(") {
		return true
	}

	return false
}

// hasExplicitReset checks for explicit reset/clear patterns
func (cfg *ControlFlowGraph) hasExplicitReset(text string) bool {
	// Look for patterns like:
	// if session_size >= max_session_size: messages = []; session_size = 0
	// if size > limit: clear()
	// if count > max: reset

	resetPatterns := []string{
		"= []",        // Reassign to empty list
		"= \"\"",      // Reassign to empty string
		".clear()",    // Clear method
		"reset()",     // Reset method
		"= {}",        // Empty dict
	}

	// Check if there's a size/count check
	sizeCheckPatterns := []string{
		">=",
		">",
		"<=",
		"<",
	}

	hasSizeCheck := false
	for _, pattern := range sizeCheckPatterns {
		if contains(text, pattern) && (contains(text, "size") || contains(text, "count") ||
			contains(text, "len(") || contains(text, "max_")) {
			hasSizeCheck = true
			break
		}
	}

	hasReset := false
	for _, pattern := range resetPatterns {
		if contains(text, pattern) {
			hasReset = true
			break
		}
	}

	return hasSizeCheck && hasReset
}

// conditionHasLLMCall checks if condition text contains LLM calls
func (cfg *ControlFlowGraph) conditionHasLLMCall(conditionText string) bool {
	llmKeywords := []string{
		"llm_call", "gpt", "chat", "completion", "ollama",
		"invoke", "generate",
	}

	for _, keyword := range llmKeywords {
		if contains(conditionText, keyword) {
			return true
		}
	}

	return false
}

// getConditionText extracts condition text from a loop node
func getConditionText(node *ast.Node) string {
	if condText, ok := node.GetProperty("condition"); ok && condText != nil {
		return condText.(string)
	}
	return node.GetText()
}

// GetLoopStats returns statistics about all loops
func (cfg *ControlFlowGraph) GetLoopStats() *LoopStats {
	cfg.mu.RLock()
	defer cfg.mu.RUnlock()

	stats := &LoopStats{
		TotalLoops:        len(cfg.loops),
		LoopsWithCounter:  0,
		NonDeterministic:  0,
		WithLLMCalls:      0,
		WithDataGrowth:    0,
	}

	for _, loopInfo := range cfg.loops {
		if loopInfo.BreakCounterVar != nil {
			stats.LoopsWithCounter++
		}
		if !loopInfo.IsDeterministic {
			stats.NonDeterministic++
		}
		if loopInfo.HasLLMCallInBody {
			stats.WithLLMCalls++
		}
		if len(loopInfo.DataGrowthVars) > 0 {
			stats.WithDataGrowth++
		}
	}

	return stats
}

// LoopStats contains statistics about loops
type LoopStats struct {
	TotalLoops       int
	LoopsWithCounter int
	NonDeterministic int
	WithLLMCalls     int
	WithDataGrowth   int
}
