package analysis

import (
	"sync"

	"github.com/inkog-io/inkog/action/pkg/ast_engine/ast"
)

// TaintStatus represents the taintedness level of a variable
type TaintStatus string

const (
	TaintClean    TaintStatus = "clean"
	TaintTainted  TaintStatus = "tainted"
	TaintUnknown  TaintStatus = "unknown"
)

// TaintEvent represents a taint propagation event
type TaintEvent struct {
	Variable    string
	Status      TaintStatus
	Source      string // e.g., "llm_call", "network", "user_input"
	LineNumber  int
	Evidence    *ast.Node
}

// TaintTracker tracks variable taintedness through data flow
type TaintTracker struct {
	resolver    *ReferenceResolver
	taintMap    map[string]TaintStatus
	taintEvents map[string][]*TaintEvent
	sources     []string // Known taint sources
	sanitizers  []string // Known sanitizers
	mu          sync.RWMutex
}

// NewTaintTracker creates a new taint tracker
func NewTaintTracker(resolver *ReferenceResolver) *TaintTracker {
	return &TaintTracker{
		resolver:    resolver,
		taintMap:    make(map[string]TaintStatus),
		taintEvents: make(map[string][]*TaintEvent),
		sources: []string{
			"llm_call", "gpt", "chat", "completion", "ollama", "generate",
			"request", "get", "post", "fetch", "recv",
			"input", "argv", "environ", "getenv",
			"read", "stdin", "socket",
		},
		sanitizers: []string{
			"escape", "sanitize", "validate", "strip", "encode",
			"urlencode", "htmlencode", "quote", "format",
		},
	}
}

// IsVariableTainted checks if a variable has tainted status
func (tt *TaintTracker) IsVariableTainted(varName string) bool {
	tt.mu.RLock()
	defer tt.mu.RUnlock()

	status, exists := tt.taintMap[varName]
	return exists && status == TaintTainted
}

// GetTaintStatus returns the current taint status of a variable
func (tt *TaintTracker) GetTaintStatus(varName string) TaintStatus {
	tt.mu.RLock()
	defer tt.mu.RUnlock()

	if status, exists := tt.taintMap[varName]; exists {
		return status
	}
	return TaintUnknown
}

// MarkTainted marks a variable as tainted from a source
func (tt *TaintTracker) MarkTainted(varName string, sourceType string, line int, evidence *ast.Node) {
	tt.mu.Lock()
	defer tt.mu.Unlock()

	tt.taintMap[varName] = TaintTainted
	tt.taintEvents[varName] = append(tt.taintEvents[varName], &TaintEvent{
		Variable:   varName,
		Status:     TaintTainted,
		Source:     sourceType,
		LineNumber: line,
		Evidence:   evidence,
	})
}

// MarkClean marks a variable as clean (sanitized)
func (tt *TaintTracker) MarkClean(varName string, sanitizer string, line int, evidence *ast.Node) {
	tt.mu.Lock()
	defer tt.mu.Unlock()

	tt.taintMap[varName] = TaintClean
	tt.taintEvents[varName] = append(tt.taintEvents[varName], &TaintEvent{
		Variable:   varName,
		Status:     TaintClean,
		Source:     sanitizer,
		LineNumber: line,
		Evidence:   evidence,
	})
}

// PropagateTaint propagates taint through assignments and function calls
// If a = b and b is tainted, then a becomes tainted
func (tt *TaintTracker) PropagateTaint(node *ast.Node) {
	if node == nil {
		return
	}

	tt.mu.Lock()
	defer tt.mu.Unlock()

	switch node.Type {
	case ast.NodeTypeAssignment:
		// Extract variable and value
		varName, ok := node.GetProperty("variable")
		if !ok || varName == nil {
			return
		}

		varStr := varName.(string)
		valueStr, ok := node.GetProperty("value")
		if !ok {
			return
		}

		// Check if value is a known taint source
		if valueStr != nil {
			valueString := valueStr.(string)
			if tt.isSourceCall(valueString) {
				tt.taintMap[varStr] = TaintTainted
				tt.taintEvents[varStr] = append(tt.taintEvents[varStr], &TaintEvent{
					Variable:   varStr,
					Status:     TaintTainted,
					Source:     valueString,
					LineNumber: node.StartLine,
					Evidence:   node,
				})
				return
			}

			// Check if value is a sanitizer call
			if tt.isSanitizerCall(valueString) {
				tt.taintMap[varStr] = TaintClean
				tt.taintEvents[varStr] = append(tt.taintEvents[varStr], &TaintEvent{
					Variable:   varStr,
					Status:     TaintClean,
					Source:     valueString,
					LineNumber: node.StartLine,
					Evidence:   node,
				})
				return
			}

			// Check if value is a tainted variable
			if status, exists := tt.taintMap[valueString]; exists && status == TaintTainted {
				tt.taintMap[varStr] = TaintTainted
				tt.taintEvents[varStr] = append(tt.taintEvents[varStr], &TaintEvent{
					Variable:   varStr,
					Status:     TaintTainted,
					Source:     "from_" + valueString,
					LineNumber: node.StartLine,
					Evidence:   node,
				})
			}
		}

	case ast.NodeTypeFunctionCall:
		// If function call is to a sanitizer, the result is clean
		funcName, ok := node.GetProperty("function")
		if !ok || funcName == nil {
			return
		}

		// This would be marked clean if assigned to a variable
		// The propagation happens at assignment level
	}
}

// TraceDataFlow returns the taint event chain for a variable
func (tt *TaintTracker) TraceDataFlow(varName string) []*TaintEvent {
	tt.mu.RLock()
	defer tt.mu.RUnlock()

	if events, exists := tt.taintEvents[varName]; exists {
		return events
	}
	return nil
}

// DetectTaintedFunctionArgument checks if a function argument comes from tainted source
func (tt *TaintTracker) DetectTaintedFunctionArgument(callInfo *ast.FunctionCallInfo) (bool, string) {
	tt.mu.RLock()
	defer tt.mu.RUnlock()

	for _, arg := range callInfo.Arguments {
		// Check if argument is a tainted variable
		if status, exists := tt.taintMap[arg]; exists && status == TaintTainted {
			return true, arg
		}
	}

	return false, ""
}

// isSourceCall checks if a string represents a known taint source
func (tt *TaintTracker) isSourceCall(valueStr string) bool {
	for _, source := range tt.sources {
		if contains(valueStr, source) {
			return true
		}
	}
	return false
}

// isSanitizerCall checks if a string represents a known sanitizer
func (tt *TaintTracker) isSanitizerCall(valueStr string) bool {
	for _, sanitizer := range tt.sanitizers {
		if contains(valueStr, sanitizer) {
			return true
		}
	}
	return false
}

// contains checks if s contains substr
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// AnalyzeVariableFlow analyzes the complete data flow for a variable
func (tt *TaintTracker) AnalyzeVariableFlow(varName string, root *ast.Node) *VariableFlow {
	tt.mu.RLock()
	defer tt.mu.RUnlock()

	flow := &VariableFlow{
		Variable: varName,
		Status:   tt.GetTaintStatus(varName),
		Events:   tt.TraceDataFlow(varName),
	}

	return flow
}

// VariableFlow represents the complete flow information for a variable
type VariableFlow struct {
	Variable string
	Status   TaintStatus
	Events   []*TaintEvent
}

// AddSource adds a custom taint source to the tracker
func (tt *TaintTracker) AddSource(source string) {
	tt.mu.Lock()
	defer tt.mu.Unlock()

	tt.sources = append(tt.sources, source)
}

// AddSanitizer adds a custom sanitizer to the tracker
func (tt *TaintTracker) AddSanitizer(sanitizer string) {
	tt.mu.Lock()
	defer tt.mu.Unlock()

	tt.sanitizers = append(tt.sanitizers, sanitizer)
}
