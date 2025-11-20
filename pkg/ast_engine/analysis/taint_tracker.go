package analysis

import (
	"log"
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

// SinkCategory identifies the type of dangerous function sink
type SinkCategory int

const (
	CodeExecutionSink SinkCategory = iota // eval, exec, os.system, subprocess.run
	LoggingSink                             // print, logger.info, logger.debug
	DataAccessSink                          // read, query
)

// String returns the string representation of a sink category
func (sc SinkCategory) String() string {
	switch sc {
	case CodeExecutionSink:
		return "CodeExecution"
	case LoggingSink:
		return "Logging"
	case DataAccessSink:
		return "DataAccess"
	default:
		return "Unknown"
	}
}

// TaintTracker tracks variable taintedness through data flow
type TaintTracker struct {
	resolver               *ReferenceResolver
	taintMap               map[string]TaintStatus
	taintEvents            map[string][]*TaintEvent
	sources                []string // Known taint sources
	sanitizers             []string // Known sanitizers
	codeExecutionSinks     []string // RCE/Command Injection sinks
	loggingSinks           []string // Sensitive data exposure sinks
	mu                     sync.RWMutex
}

// NewTaintTracker creates a new taint tracker
func NewTaintTracker(resolver *ReferenceResolver) *TaintTracker {
	return &TaintTracker{
		resolver:    resolver,
		taintMap:    make(map[string]TaintStatus),
		taintEvents: make(map[string][]*TaintEvent),
		sources: []string{
			// LLM Core keywords
			"llm_call", "gpt", "chat", "completion", "ollama", "generate",
			// Modern SDK patterns (OpenAI v1)
			"completions.create", "embeddings.create", "chat.completions",
			// Anthropic SDK
			"messages.create", "beta.messages",
			// LangChain patterns
			"invoke", "stream", "batch", "LLMChain", "run",
			// Google Vertex
			"predictions.create", "generate_content",
			// Other LLM providers
			"replicate", "together", "cohere", "huggingface",
			// Network/External
			"request", "get", "post", "put", "delete", "patch", "fetch", "recv",
			"http", "requests", "urllib", "httpx",
			// User input
			"input", "argv", "environ", "getenv",
			// File/Stream operations
			"read", "stdin", "socket", "file",
		},
		sanitizers: []string{
			"escape", "sanitize", "validate", "strip", "encode",
			"urlencode", "htmlencode", "quote", "format",
		},
		codeExecutionSinks: []string{
			// Direct code execution
			"eval", "exec", "system", "subprocess",
			// Python-specific
			"os.system", "subprocess.run", "subprocess.call", "subprocess.Popen",
			// JavaScript-specific
			"eval", "Function", "setTimeout", "setInterval",
			// Template engines
			"Jinja2.from_string", "render_template_string",
		},
		loggingSinks: []string{
			// Python logging
			"print", "log", "logger.info", "logger.debug", "logger.warning", "logger.error",
			// JavaScript/Node logging
			"console.log", "console.error", "console.debug",
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
// It handles both simple keywords and chained method patterns
func (tt *TaintTracker) isSourceCall(valueStr string) bool {
	for _, source := range tt.sources {
		// Check for exact substring match (e.g., "chat" in "client.chat.completions.create")
		if contains(valueStr, source) {
			// Additional validation for method chain patterns to avoid false positives
			// For example, "request" should match "requests.get()" but also standalone "request()"
			if source == "get" || source == "post" {
				// For HTTP methods, be more careful - check context
				if matchesHTTPPattern(valueStr) {
					log.Printf("[TAINT_DEBUG] Detected taint source '%s' in: %s", source, valueStr)
					return true
				}
			} else {
				log.Printf("[TAINT_DEBUG] Detected taint source '%s' in: %s", source, valueStr)
				return true
			}
		}
	}
	return false
}

// matchesHTTPPattern checks if a value string is an HTTP request pattern
func matchesHTTPPattern(valueStr string) bool {
	httpPatterns := []string{
		"requests.", "urllib.", "httpx.", "http.", ".get(", ".post(",
		".put(", ".delete(", ".patch(", ".fetch(",
	}
	for _, pattern := range httpPatterns {
		if contains(valueStr, pattern) {
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

// GetSinkCategory identifies which category a sink function belongs to
// Returns the category and true if found, or Unknown category and false if not found
func (tt *TaintTracker) GetSinkCategory(funcName string) (SinkCategory, bool) {
	tt.mu.RLock()
	defer tt.mu.RUnlock()

	// Check code execution sinks first (highest severity)
	for _, sink := range tt.codeExecutionSinks {
		if contains(funcName, sink) {
			return CodeExecutionSink, true
		}
	}

	// Check logging sinks (medium severity)
	for _, sink := range tt.loggingSinks {
		if contains(funcName, sink) {
			return LoggingSink, true
		}
	}

	// Not a known sink
	return DataAccessSink, false
}

// IsCodeExecutionSink checks if a function is a code execution sink
func (tt *TaintTracker) IsCodeExecutionSink(funcName string) bool {
	tt.mu.RLock()
	defer tt.mu.RUnlock()

	for _, sink := range tt.codeExecutionSinks {
		if contains(funcName, sink) {
			return true
		}
	}
	return false
}

// IsLoggingSink checks if a function is a logging sink
func (tt *TaintTracker) IsLoggingSink(funcName string) bool {
	tt.mu.RLock()
	defer tt.mu.RUnlock()

	for _, sink := range tt.loggingSinks {
		if contains(funcName, sink) {
			return true
		}
	}
	return false
}
