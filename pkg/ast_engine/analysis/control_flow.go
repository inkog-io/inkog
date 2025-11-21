package analysis

import (
	"log"
	"strings"
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
	root        *ast.Node
	loops       []*LoopInfo
	taint       *TaintTracker
	symbolTable *SymbolTable // For inter-procedural analysis
	mu          sync.RWMutex
}

// NewControlFlowGraph creates a new control flow graph analyzer
func NewControlFlowGraph(root *ast.Node, taint *TaintTracker) *ControlFlowGraph {
	cfg := &ControlFlowGraph{
		root:        root,
		loops:       make([]*LoopInfo, 0),
		taint:       taint,
		symbolTable: nil, // Will be set if provided
	}

	if root != nil {
		cfg.analyzeControlFlow(root)
	}

	return cfg
}

// SetSymbolTable provides symbol table for inter-procedural analysis
func (cfg *ControlFlowGraph) SetSymbolTable(symTable *SymbolTable) {
	cfg.mu.Lock()
	defer cfg.mu.Unlock()
	cfg.symbolTable = symTable
}

// ResolveFunctionDefinition resolves a function call node to its definition
// Handles:
// 1. Direct calls (func()) -> looks in file scope
// 2. Method calls (obj.method()) -> looks in file scope by method name
// 3. Self method calls (self.method()) -> looks in enclosing class scope (Python/JS)
func (cfg *ControlFlowGraph) ResolveFunctionDefinition(callNode *ast.Node) *ScopeFunction {
	if cfg.symbolTable == nil || callNode == nil {
		return nil
	}

	// Extract function name from the call node
	var funcName string

	// Handle function property (direct function call)
	if funcProp, ok := callNode.GetProperty("function"); ok && funcProp != nil {
		funcName = funcProp.(string)
	} else {
		return nil
	}

	// Check if this is a self.method() or this.method() call (class method)
	if strings.HasPrefix(funcName, "self.") || strings.HasPrefix(funcName, "this.") {
		log.Printf("[TAINT_DEBUG] Resolving method call: %s", funcName)

		// Extract method name
		var methodName string
		if strings.HasPrefix(funcName, "self.") {
			methodName = strings.TrimPrefix(funcName, "self.")
		} else {
			methodName = strings.TrimPrefix(funcName, "this.")
		}

		// Try to find the enclosing class definition
		enclosingClass := cfg.findEnclosingClass(callNode, cfg.root)
		if enclosingClass != nil {
			// Look for the method in the class body
			if methodDef := cfg.findMethodInClass(enclosingClass, methodName); methodDef != nil {
				className, _ := enclosingClass.GetProperty("name")
				log.Printf("[TAINT_DEBUG] Resolved 'self.%s': Found in class '%v'", methodName, className)
				return methodDef
			}
		}

		// Fallback: if no class found or method not in class body, try file scope
		// This handles unit tests and cases where full AST isn't available
		if cfg.symbolTable.FileScope != nil && cfg.symbolTable.FileScope.Functions != nil {
			if fn, exists := cfg.symbolTable.FileScope.Functions[methodName]; exists {
				log.Printf("[TAINT_DEBUG] Resolved 'self.%s': Found in file scope (fallback)", methodName)
				return fn
			}
		}

		log.Printf("[TAINT_DEBUG] Failed to resolve 'self.%s'", methodName)
		return nil
	}

	// For non-self method calls like obj.method(), get the last part
	if contains(funcName, ".") {
		parts := strings.Split(funcName, ".")
		if len(parts) > 0 {
			funcName = parts[len(parts)-1]
		}
	}

	// Search for function definition in symbol table
	// Start with file scope and traverse scope chain
	if cfg.symbolTable.FileScope != nil && cfg.symbolTable.FileScope.Functions != nil {
		if fn, exists := cfg.symbolTable.FileScope.Functions[funcName]; exists {
			log.Printf("[TAINT_DEBUG] Resolved function '%s' from file scope", funcName)
			return fn
		}
	}

	log.Printf("[TAINT_DEBUG] Failed to resolve function '%s'", funcName)
	return nil
}

// findEnclosingClass traverses up the AST to find the class definition containing this node
func (cfg *ControlFlowGraph) findEnclosingClass(node *ast.Node, root *ast.Node) *ast.Node {
	if node == nil || root == nil {
		return nil
	}

	// Search for the class that contains this node
	return cfg.findEnclosingClassInTree(node, root)
}

// findEnclosingClassInTree recursively searches for a class containing the target node
func (cfg *ControlFlowGraph) findEnclosingClassInTree(targetNode *ast.Node, currentNode *ast.Node) *ast.Node {
	if currentNode == nil {
		return nil
	}

	// Check if current node is a class definition
	if currentNode.Type == ast.NodeTypeClass {
		// Check if targetNode is contained within this class
		if cfg.nodeContains(currentNode, targetNode) {
			return currentNode
		}
	}

	// Recursively search children
	for _, child := range currentNode.GetChildren() {
		if result := cfg.findEnclosingClassInTree(targetNode, child); result != nil {
			return result
		}
	}

	return nil
}

// nodeContains checks if parentNode contains childNode in its subtree
func (cfg *ControlFlowGraph) nodeContains(parentNode *ast.Node, childNode *ast.Node) bool {
	if parentNode == nil || childNode == nil {
		return false
	}

	if parentNode == childNode {
		return true
	}

	for _, child := range parentNode.GetChildren() {
		if cfg.nodeContains(child, childNode) {
			return true
		}
	}

	return false
}

// findMethodInClass searches for a method definition in a class body
func (cfg *ControlFlowGraph) findMethodInClass(classNode *ast.Node, methodName string) *ScopeFunction {
	if classNode == nil || classNode.Type != ast.NodeTypeClass {
		return nil
	}

	// Get class name for logging
	var className string
	if name, ok := classNode.GetProperty("name"); ok && name != nil {
		className = name.(string)
	}

	// Search through class body for function definitions
	for _, child := range classNode.GetChildren() {
		if child.Type == ast.NodeTypeFunctionDef {
			if funcName, ok := child.GetProperty("name"); ok && funcName != nil {
				if funcName.(string) == methodName {
					log.Printf("[TAINT_DEBUG] Found method '%s' in class '%s'", methodName, className)
					return &ScopeFunction{
						Name:      methodName,
						DefinedAt: child,
					}
				}
			}
		}
	}

	return nil
}

// AnalyzeFunctionReturnTaint analyzes if a function returns tainted (non-deterministic) data
// Uses visited set to prevent infinite recursion for mutually recursive functions
func (cfg *ControlFlowGraph) AnalyzeFunctionReturnTaint(funcDef *ScopeFunction, visitedFuncs map[string]bool) bool {
	if funcDef == nil || funcDef.DefinedAt == nil {
		return false
	}

	log.Printf("[TAINT_DEBUG] Analyzing function return taint: %s", funcDef.Name)

	// Prevent infinite recursion
	if visitedFuncs == nil {
		visitedFuncs = make(map[string]bool)
	}
	if visitedFuncs[funcDef.Name] {
		log.Printf("[TAINT_DEBUG] Function '%s' already visited (cyclic), assuming not tainted", funcDef.Name)
		return false // Assume not tainted for cyclic functions
	}
	visitedFuncs[funcDef.Name] = true

	// Find all return statements in the function
	returnNodes := cfg.findReturnStatements(funcDef.DefinedAt)

	// If no returns found, assume function returns nil/void (not tainted)
	if len(returnNodes) == 0 {
		log.Printf("[TAINT_DEBUG] Function '%s' has no return statements, assuming CLEAN", funcDef.Name)
		return false
	}

	log.Printf("[TAINT_DEBUG] Function '%s' has %d return statement(s)", funcDef.Name, len(returnNodes))

	// Check each return statement for taint
	for i, retNode := range returnNodes {
		log.Printf("[TAINT_DEBUG] Checking return statement %d of %d in function '%s'", i+1, len(returnNodes), funcDef.Name)
		if cfg.isReturnValueTainted(retNode, visitedFuncs) {
			log.Printf("[TAINT_DEBUG] Function '%s' returns TAINTED data", funcDef.Name)
			return true // Found a tainted return path
		}
	}

	log.Printf("[TAINT_DEBUG] Function '%s' all return statements are CLEAN", funcDef.Name)
	return false // All return paths are clean
}

// findReturnStatements recursively finds all return statements in a function
func (cfg *ControlFlowGraph) findReturnStatements(node *ast.Node) []*ast.Node {
	var returns []*ast.Node

	if node == nil {
		return returns
	}

	// Check if this node is a return statement
	if node.Type == ast.NodeTypeReturnStmt {
		returns = append(returns, node)
	}

	// Don't recurse into nested function definitions beyond the first level
	// to avoid analyzing nested functions as part of parent function returns
	if node.Type == ast.NodeTypeFunctionDef {
		// Skip recursion for nested functions
		return returns
	}

	// Recurse into children
	for _, child := range node.GetChildren() {
		returns = append(returns, cfg.findReturnStatements(child)...)
	}

	return returns
}

// isReturnValueTainted checks if a return statement returns a tainted value
func (cfg *ControlFlowGraph) isReturnValueTainted(retNode *ast.Node, visitedFuncs map[string]bool) bool {
	if retNode == nil {
		return false
	}

	// Get the expression being returned
	returnChildren := retNode.GetChildren()
	if len(returnChildren) == 0 {
		return false
	}

	returnExpr := returnChildren[0]

	// Non-deterministic keywords
	nonDetKeywords := []string{
		"llm_call", "gpt", "chat", "completion", "ollama",
		"random", "rand", "choice", "shuffle",
		"request", "get", "post", "fetch",
		"input", "stdin",
		// Modern SDK patterns
		"completions.create", "embeddings.create", "messages.create",
		"invoke", "stream", "batch",
	}

	// Check if return expression is a function call that might be tainted
	if returnExpr.Type == ast.NodeTypeFunctionCall {
		if funcName, ok := returnExpr.GetProperty("function"); ok && funcName != nil {
			fname := funcName.(string)
			// Check if it's a non-deterministic function
			for _, keyword := range nonDetKeywords {
				if contains(fname, keyword) {
					log.Printf("[TAINT_DEBUG] Return value is TAINTED: detected LLM/external call '%s'", fname)
					return true
				}
			}

			// Try to resolve and recursively analyze the called function
			if def := cfg.ResolveFunctionDefinition(returnExpr); def != nil {
				log.Printf("[TAINT_DEBUG] Recursively analyzing return value from function call: %s", fname)
				isTainted := cfg.AnalyzeFunctionReturnTaint(def, visitedFuncs)
				if isTainted {
					log.Printf("[TAINT_DEBUG] Return value is TAINTED: called function '%s' returns tainted data", fname)
				}
				return isTainted
			}
		}
	}

	// Check if return is a variable that might be tainted
	if returnExpr.Type == ast.NodeTypeVariableRef {
		if varName, ok := returnExpr.GetProperty("name"); ok && varName != nil {
			vname := varName.(string)
			// Check if variable is tainted via taint tracker
			if cfg.taint != nil && cfg.taint.IsVariableTainted(vname) {
				log.Printf("[TAINT_DEBUG] Return value is TAINTED: variable '%s' is marked as tainted", vname)
				return true
			}
			log.Printf("[TAINT_DEBUG] Return value is CLEAN: variable '%s' has no taint sources", vname)
		}
	}

	// Fallback: check return expression text for non-deterministic keywords
	returnText := returnExpr.GetText()
	for _, keyword := range nonDetKeywords {
		if contains(returnText, keyword) {
			log.Printf("[TAINT_DEBUG] Return value is TAINTED: detected keyword '%s' in return expression", keyword)
			return true // Return is tainted
		}
	}

	log.Printf("[TAINT_DEBUG] Return value is CLEAN: no taint sources detected")
	return false // Return appears to be clean
}

// HasFunctionCallInCondition finds if there's a function call in loop condition
func (cfg *ControlFlowGraph) HasFunctionCallInCondition(loopInfo *LoopInfo) *ast.Node {
	if loopInfo == nil {
		return nil
	}

	// Check condition nodes for function calls
	for _, condNode := range loopInfo.ConditionNodes {
		callNode := cfg.findFirstFunctionCall(condNode)
		if callNode != nil {
			return callNode
		}
	}

	return nil
}

// findFirstFunctionCall recursively finds the first function call in a node tree
func (cfg *ControlFlowGraph) findFirstFunctionCall(node *ast.Node) *ast.Node {
	if node == nil {
		return nil
	}

	if node.Type == ast.NodeTypeFunctionCall {
		return node
	}

	// Recurse into children
	for _, child := range node.GetChildren() {
		if result := cfg.findFirstFunctionCall(child); result != nil {
			return result
		}
	}

	return nil
}

// ExtractLoops finds and analyzes all loops in the AST
func (cfg *ControlFlowGraph) ExtractLoops() []*LoopInfo {
	cfg.mu.RLock()
	defer cfg.mu.RUnlock()

	result := make([]*LoopInfo, len(cfg.loops))
	copy(result, cfg.loops)

	// DEBUG: Log all extracted loops
	log.Printf("[CFG_DEBUG] ExtractLoops found %d total loops", len(cfg.loops))
	for i, loop := range cfg.loops {
		log.Printf("[CFG_DEBUG]   Loop %d: Line %d, IsDeterministic=%v, Condition: %s",
			i, loop.Line, loop.IsDeterministic, loop.ConditionText)
	}

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
		Line:           loopNode.StartLine + 1, // Convert from 0-indexed AST to 1-indexed display format
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

// containsLLMKeywords checks if function body text contains high-risk LLM keywords
// This is a heuristic fallback when inter-procedural taint analysis doesn't catch tainted returns
func (cfg *ControlFlowGraph) containsLLMKeywords(funcDef *ScopeFunction) bool {
	if funcDef == nil || funcDef.DefinedAt == nil {
		return false
	}

	// LLM keywords that indicate non-deterministic behavior
	llmKeywords := []string{
		"chat.completions", "openai", "llm", "invoke", "predict",
		"messages.create", "anthropic", "langchain",
		"generate_content", "vertex", "replicate", "together", "cohere",
		"huggingface", "completions.create", "embeddings.create",
		"client.chat", "client.messages",
	}

	// Get function body text
	bodyText := cfg.getFunctionBodyText(funcDef.DefinedAt)

	for _, keyword := range llmKeywords {
		if contains(bodyText, keyword) {
			log.Printf("[TAINT_DEBUG] Heuristic detected LLM keyword '%s' in function '%s' body", keyword, funcDef.Name)
			return true
		}
	}

	return false
}

// getFunctionBodyText extracts the text content of a function's body
func (cfg *ControlFlowGraph) getFunctionBodyText(node *ast.Node) string {
	if node == nil {
		return ""
	}

	bodyText := ""
	for _, child := range node.Children {
		if child != nil && child.Text != "" {
			bodyText += child.Text + " "
		}
	}
	return bodyText
}

// isConditionDeterministic checks if a loop condition depends on non-deterministic sources
// Implements four strategies:
// 1. Direct keyword matching
// 2. Inter-procedural taint analysis for function calls
// 3. Deterministic built-in whitelist to prevent false positives
// 4. Heuristic body text check - fallback when formal analysis fails
func (cfg *ControlFlowGraph) isConditionDeterministic(loopInfo *LoopInfo) bool {
	// Non-deterministic keywords
	nonDetKeywords := []string{
		"llm_call", "gpt", "chat", "completion", "ollama",
		"random", "rand", "choice", "shuffle",
		"request", "get", "post", "fetch",
		"input", "stdin",
		// Modern SDK patterns
		"completions.create", "embeddings.create", "messages.create",
		"invoke", "stream", "batch",
	}

	log.Printf("[TAINT_DEBUG] Checking loop condition determinism: %s", loopInfo.ConditionText)

	// STRATEGY 1: Direct keyword matching
	conditionText := loopInfo.ConditionText
	for _, keyword := range nonDetKeywords {
		if contains(conditionText, keyword) {
			log.Printf("[TAINT_DEBUG] Condition is NON-DETERMINISTIC: detected keyword '%s' in condition text", keyword)
			return false
		}
	}

	// STRATEGY 2: Check for function calls in condition
	// If found, analyze if they return tainted (non-deterministic) data
	callNode := cfg.HasFunctionCallInCondition(loopInfo)
	if callNode != nil {
		log.Printf("[TAINT_DEBUG] Found function call in loop condition")
		// Try to resolve function definition
		funcDef := cfg.ResolveFunctionDefinition(callNode)
		if funcDef != nil {
			log.Printf("[TAINT_DEBUG] Resolved function '%s' from symbol table", funcDef.Name)
			// Analyze if the function returns tainted data
			if cfg.AnalyzeFunctionReturnTaint(funcDef, nil) {
				log.Printf("[TAINT_DEBUG] Condition is NON-DETERMINISTIC: function '%s' returns tainted data", funcDef.Name)
				return false // Function returns tainted data
			}
			log.Printf("[TAINT_DEBUG] Function '%s' returns clean data, checking heuristic fallback", funcDef.Name)

			// STRATEGY 4: Heuristic body text check (fallback when formal analysis fails)
			if cfg.containsLLMKeywords(funcDef) {
				log.Printf("[TAINT_DEBUG] Condition is NON-DETERMINISTIC: function '%s' body contains LLM keywords (heuristic)", funcDef.Name)
				return false // Function body contains LLM keywords, likely non-deterministic
			}

			log.Printf("[TAINT_DEBUG] Condition is DETERMINISTIC: function '%s' returns clean data and no LLM keywords", funcDef.Name)
			return true // Function returns clean data and no LLM keywords found
		}

		log.Printf("[TAINT_DEBUG] Function not found in symbol table, checking whitelist")

		// Function not found in symbol table - check whitelist
		// STRATEGY 3: Deterministic Built-in Whitelist
		// This prevents false positives on functions like len(), range(), etc.
		// that are guaranteed deterministic but not defined in user code
		deterministicBuiltins := cfg.getDeterministicBuiltinWhitelist()

		if funcName, ok := callNode.GetProperty("function"); ok && funcName != nil {
			fname := funcName.(string)

			// For method calls like obj.method(), get the last part
			if contains(fname, ".") {
				parts := strings.Split(fname, ".")
				if len(parts) > 0 {
					fname = parts[len(parts)-1]
				}
			}

			// If function is in the whitelist, it's deterministic
			if deterministicBuiltins[fname] {
				log.Printf("[TAINT_DEBUG] Condition is DETERMINISTIC: '%s' is in built-in whitelist", fname)
				return true
			}

			// If function is not found and not in whitelist, assume non-deterministic (safe default)
			log.Printf("[TAINT_DEBUG] Condition is NON-DETERMINISTIC: '%s' not found in symbol table and not in whitelist", fname)
			return false
		}
	}

	log.Printf("[TAINT_DEBUG] Condition is DETERMINISTIC: no non-deterministic patterns detected")
	return true
}

// getDeterministicBuiltinWhitelist returns the set of Python built-in functions
// and common safe methods that are guaranteed to be deterministic
func (cfg *ControlFlowGraph) getDeterministicBuiltinWhitelist() map[string]bool {
	return map[string]bool{
		// Python built-in functions
		"len":        true,
		"range":      true,
		"enumerate":  true,
		"zip":        true,
		"isinstance": true,
		"type":       true,
		"str":        true,
		"int":        true,
		"float":      true,
		"bool":       true,
		"list":       true,
		"dict":       true,
		"set":        true,
		"tuple":      true,
		"abs":        true,
		"min":        true,
		"max":        true,
		"sum":        true,
		"sorted":     true,
		"reversed":   true,
		"all":        true,
		"any":        true,
		"iter":       true,
		"next":       true,
		"ord":        true,
		"chr":        true,
		"hex":        true,
		"oct":        true,
		"bin":        true,
		"hash":       true,

		// Common safe string methods
		"strip":      true,
		"lstrip":     true,
		"rstrip":     true,
		"upper":      true,
		"lower":      true,
		"split":      true,
		"join":       true,
		"replace":    true,
		"startswith": true,
		"endswith":   true,
		"find":       true,
		"format":     true,

		// Common safe list/dict methods
		"append":  true,
		"extend":  true,
		"pop":     true,
		"remove":  true,
		"clear":   true,
		"count":   true,
		"index":   true,
		"sort":    true,
		"reverse": true,
		"copy":    true,
		"keys":    true,
		"values":  true,
		"items":   true,
		"get":     true,
		"update":  true,

		// Type checking helpers
		"callable": true,
		"hasattr":  true,
		"getattr":  true,
		"setattr":  true,
	}
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
	// SIGNATURE: "should_continue" pattern is a high-confidence infinite loop indicator
	// This pattern is commonly used in agent loops (LangGraph, AutoGPT, etc.)
	// where the LLM decides whether to continue, implying non-deterministic behavior
	if contains(loopInfo.ConditionText, "_should_continue_") ||
		contains(loopInfo.ConditionText, "should_continue") {
		log.Printf("[DOOM_LOOP_DEBUG] Detected 'should_continue' signature in condition: %s", loopInfo.ConditionText)
		return true
	}

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
