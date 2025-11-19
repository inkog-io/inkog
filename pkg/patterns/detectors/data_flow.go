package detectors

import (
	"regexp"
	"strings"
)

// DataFlowAnalyzer tracks how data moves through code
// Reusable by: Pattern 1 (user_input → prompt → llm), Pattern 2, all TIER 2+
type DataFlowAnalyzer struct {
	sourcePatterns map[string]string // Maps source identifiers to source types
}

// NewDataFlowAnalyzer creates a new data flow analyzer
func NewDataFlowAnalyzer() *DataFlowAnalyzer {
	return &DataFlowAnalyzer{
		sourcePatterns: map[string]string{
			"request.args":   "user_input",
			"request.form":   "user_input",
			"request.get":    "user_input",
			"request.post":   "user_input",
			"sys.argv":       "user_input",
			"input(":         "user_input",
			"getenv(":        "environment",
			"os.environ":     "environment",
			"response":       "llm_output",
			".choices":       "llm_output",
			"completion":     "llm_output",
		},
	}
}

// AnalyzeDataFlows traces all data flows in the code
func (dfa *DataFlowAnalyzer) AnalyzeDataFlows(lines []string, variables map[string]*Variable) []DataFlow {
	var flows []DataFlow

	// Identify source variables (user_input, llm_output, etc.)
	sources := dfa.identifySources(variables)

	// For each source, trace its flow to sinks
	for sourceVar, sourceType := range sources {
		if variable, exists := variables[sourceVar]; exists {
			for _, sink := range variable.FlowsToSinks {
				flow := DataFlow{
					Source:      sourceType,
					Sink:        sink,
					Path:        []string{sourceVar},
					RiskLevel:   dfa.calculateRiskLevel(sourceType, sink),
				}

				// Find line numbers in the flow
				for _, assignment := range variable.Assignments {
					flow.LineNumbers = append(flow.LineNumbers, assignment.LineNum)
				}
				for _, usage := range variable.Usages {
					if usage.Context == sink {
						flow.LineNumbers = append(flow.LineNumbers, usage.LineNum)
					}
				}

				flows = append(flows, flow)
			}
		}
	}

	return flows
}

// identifySources finds all source variables in the code
func (dfa *DataFlowAnalyzer) identifySources(variables map[string]*Variable) map[string]string {
	sources := make(map[string]string)

	for varName, variable := range variables {
		if variable.IsUserInput {
			sources[varName] = "user_input"
		}
		if variable.IsLLMOutput {
			sources[varName] = "llm_output"
		}
		if variable.IsCredential {
			sources[varName] = "credential"
		}
	}

	return sources
}

// calculateRiskLevel determines how dangerous a data flow is
func (dfa *DataFlowAnalyzer) calculateRiskLevel(source string, sink string) float32 {
	riskScore := float32(0.5) // Base risk

	// User input to dangerous sinks is highest risk
	if source == "user_input" {
		dangerousSinks := []string{
			"eval", "exec", "system", "invoke", "run",
			"print", "log", "send", "open", "write",
		}

		for _, dangerous := range dangerousSinks {
			if strings.Contains(strings.ToLower(sink), strings.ToLower(dangerous)) {
				riskScore = 0.95 // Very high risk
				break
			}
		}

		// Medium-high for other sinks
		if riskScore < 0.8 {
			riskScore = 0.75
		}
	}

	// LLM output is moderately risky
	if source == "llm_output" {
		if strings.Contains(strings.ToLower(sink), "eval") ||
			strings.Contains(strings.ToLower(sink), "exec") {
			riskScore = 0.90
		} else {
			riskScore = 0.70
		}
	}

	// Environment variables have medium risk
	if source == "environment" {
		riskScore = 0.65
	}

	// Credentials have high risk if exfiltrated
	if source == "credential" {
		exfilSinks := []string{"print", "log", "send", "write", "http"}
		for _, exfilSink := range exfilSinks {
			if strings.Contains(strings.ToLower(sink), exfilSink) {
				riskScore = 0.90
				break
			}
		}
		if riskScore < 0.8 {
			riskScore = 0.75
		}
	}

	return riskScore
}

// IsFlowDangerous checks if a specific data flow is dangerous
// Used by detectors to quickly assess flow risk
func (dfa *DataFlowAnalyzer) IsFlowDangerous(flow DataFlow) bool {
	return flow.RiskLevel > 0.65
}

// GetFlowsToSink returns all data flows that reach a specific sink
// Used by Pattern 1 to find all ways user input reaches llm.call
func (dfa *DataFlowAnalyzer) GetFlowsToSink(flows []DataFlow, sink string) []DataFlow {
	var result []DataFlow
	for _, flow := range flows {
		if strings.Contains(strings.ToLower(flow.Sink), strings.ToLower(sink)) {
			result = append(result, flow)
		}
	}
	return result
}

// TraceVariableChain traces the complete path of a variable through the code
// Used by Pattern 1 to track: user_input → prompt_var → llm.call(prompt_var)
func (dfa *DataFlowAnalyzer) TraceVariableChain(lines []string, startVar string) []string {
	chain := []string{startVar}

	// Assignment pattern
	assignmentPattern := regexp.MustCompile(`(?:^|[\s;])(\w+)\s*(?:=|:=)\s*([^#;]+)`)

	// Look for assignments where startVar appears on RHS
	for _, line := range lines {
		if strings.Contains(line, startVar) {
			matches := assignmentPattern.FindAllStringSubmatch(line, -1)
			for _, match := range matches {
				if len(match) >= 3 {
					lhs := strings.TrimSpace(match[1])
					rhs := strings.TrimSpace(match[2])

					if strings.Contains(rhs, startVar) && lhs != startVar {
						chain = append(chain, lhs)
					}
				}
			}
		}
	}

	return chain
}

// IdentifyExfiltrationPaths finds paths where sensitive data leaves the system
// Used by Pattern 2 to identify credential exposure
func (dfa *DataFlowAnalyzer) IdentifyExfiltrationPaths(flows []DataFlow) []DataFlow {
	var exfilPaths []DataFlow

	exfilSinks := []string{
		"print", "log", "write", "send", "http", "request",
		"socket", "network", "return", "yield",
	}

	for _, flow := range flows {
		for _, exfilSink := range exfilSinks {
			if strings.Contains(strings.ToLower(flow.Sink), exfilSink) {
				exfilPaths = append(exfilPaths, flow)
				break
			}
		}
	}

	return exfilPaths
}

// GetFlowsBySource returns all flows originating from a specific source type
// Used to filter flows by source (e.g., all user_input flows)
func (dfa *DataFlowAnalyzer) GetFlowsBySource(flows []DataFlow, sourceType string) []DataFlow {
	var result []DataFlow
	for _, flow := range flows {
		if flow.Source == sourceType {
			result = append(result, flow)
		}
	}
	return result
}
