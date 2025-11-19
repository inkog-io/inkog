package detectors

import (
	"regexp"
	"strings"
)

// VariableTracker analyzes variable assignments and tracks their characteristics
// Reusable by: Pattern 1 (user_input tracking), Pattern 2 (credential tracking), all TIER 2+
type VariableTracker struct {
	userInputPatterns    []string
	llmOutputPatterns    []string
	credentialPatterns   []string
	sanitizationPatterns []string
}

// NewVariableTracker creates a new variable tracking system
func NewVariableTracker() *VariableTracker {
	return &VariableTracker{
		userInputPatterns: []string{
			"request.args", "request.form", "request.json", "request.get",
			"request.post", "sys.argv", "input(", "raw_input(",
			"stdin", "user_input", "user_query", "query", "message",
			"@param", "get_user", "getenv",
		},
		llmOutputPatterns: []string{
			"response", "completion", ".choices", ".content", ".message",
			"llm.run", "chain.run", "invoke(", "predict(", "generate(",
			"openai", "anthropic", "bedrock", "llama", "mistral",
		},
		credentialPatterns: []string{
			"api_key", "secret", "password", "token", "apikey",
			"api_secret", "client_secret", "access_token", "private_key",
			"ssh_key", "aws_secret", "db_password",
		},
		sanitizationPatterns: []string{
			"shlex.quote", "escape", "sanitize", "validate",
			"whitelist", "is_safe", "filter", "quote",
		},
	}
}

// TrackVariables extracts and analyzes all variables in the code
func (vt *VariableTracker) TrackVariables(lines []string) map[string]*Variable {
	variables := make(map[string]*Variable)

	// Assignment patterns for different languages
	assignmentPattern := regexp.MustCompile(`(?:^|[\s;])(\w+)\s*(?:=|:=)\s*(.+?)(?:$|[;#])`)

	for lineNum, line := range lines {
		// Skip comments
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}

		// Find all assignments on this line
		matches := assignmentPattern.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			if len(match) >= 3 {
				varName := strings.TrimSpace(match[1])
				rhs := strings.TrimSpace(match[2])

				if varName == "" || len(varName) > 50 {
					continue // Skip invalid variable names
				}

				// Create or update variable
				if _, exists := variables[varName]; !exists {
					variables[varName] = &Variable{
						Name:          varName,
						FirstSeenLine: lineNum + 1,
						Assignments:   make([]Assignment, 0),
						Usages:        make([]Usage, 0),
						FlowsToSinks:  make([]string, 0),
					}
				}

				// Classify assignment source
				sourceType := vt.classifyAssignmentSource(rhs, varName)

				// Create assignment record
				assignment := Assignment{
					LineNum:    lineNum + 1,
					SourceType: sourceType,
					RHS:        rhs,
				}

				variables[varName].Assignments = append(variables[varName].Assignments, assignment)

				// Update variable characteristics
				if sourceType == "user_input" {
					variables[varName].IsUserInput = true
				}
				if sourceType == "llm_output" {
					variables[varName].IsLLMOutput = true
				}
				if sourceType == "credential" {
					variables[varName].IsCredential = true
				}
				if vt.isSanitized(rhs) {
					variables[varName].IsSanitized = true
				}
			}
		}

		// Track variable usages
		for varName := range variables {
			if strings.Contains(line, varName) {
				// Make sure it's not the assignment itself
				if !assignmentPattern.MatchString(varName + " =") {
					usageContext := vt.getUsageContext(line, varName)
					usage := Usage{
						LineNum:     lineNum + 1,
						Context:     usageContext,
						IsDangerous: vt.isDangerousUsage(usageContext),
					}
					variables[varName].Usages = append(variables[varName].Usages, usage)
				}
			}
		}
	}

	// Post-process to find where variables flow
	vt.traceFlows(variables)

	return variables
}

// classifyAssignmentSource determines the type of the assignment source
func (vt *VariableTracker) classifyAssignmentSource(rhs string, varName string) string {
	lowerRHS := strings.ToLower(rhs)
	lowerVarName := strings.ToLower(varName)

	// Check if it's a credential
	for _, pattern := range vt.credentialPatterns {
		if strings.Contains(lowerVarName, strings.ToLower(pattern)) {
			return "credential"
		}
	}

	// Check if it's from user input
	for _, pattern := range vt.userInputPatterns {
		if strings.Contains(lowerRHS, strings.ToLower(pattern)) {
			return "user_input"
		}
	}

	// Check if it's from LLM output
	for _, pattern := range vt.llmOutputPatterns {
		if strings.Contains(lowerRHS, strings.ToLower(pattern)) {
			return "llm_output"
		}
	}

	// Check if it's a constant
	if (strings.HasPrefix(rhs, "\"") && strings.HasSuffix(rhs, "\"")) ||
		(strings.HasPrefix(rhs, "'") && strings.HasSuffix(rhs, "'")) {
		return "constant"
	}

	return "function_call"
}

// isSanitized checks if a value has been sanitized
func (vt *VariableTracker) isSanitized(value string) bool {
	lowerValue := strings.ToLower(value)
	for _, pattern := range vt.sanitizationPatterns {
		if strings.Contains(lowerValue, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// getUsageContext extracts the context of how a variable is used
func (vt *VariableTracker) getUsageContext(line string, varName string) string {
	// Look for dangerous function calls
	dangerousFunctions := []string{
		"print", "log", "eval", "exec", "system", "call",
		"invoke", "run", "open", "write", "send", "request",
	}

	lowerLine := strings.ToLower(line)
	for _, fn := range dangerousFunctions {
		if strings.Contains(lowerLine, fn+"(") {
			// Check if variable is in the function call
			pattern := regexp.MustCompile(`\b` + fn + `\s*\([^)]*` + varName + `[^)]*\)`)
			if pattern.MatchString(lowerLine) {
				return fn
			}
		}
	}

	// Check for string interpolation
	if strings.Contains(line, "${"+varName) || strings.Contains(line, "${"+varName+"}") {
		return "string_interpolation"
	}
	if strings.Contains(line, "{"+varName) {
		return "format_string"
	}
	if strings.Contains(line, "+"+varName) || strings.Contains(line, varName+"+") {
		return "concatenation"
	}

	return "general_use"
}

// isDangerousUsage checks if a usage context is dangerous
func (vt *VariableTracker) isDangerousUsage(context string) bool {
	dangerousContexts := []string{
		"eval", "exec", "system", "call", "invoke", "open",
		"print", "log", "send", "request", "write",
	}

	lowerContext := strings.ToLower(context)
	for _, dangerous := range dangerousContexts {
		if lowerContext == strings.ToLower(dangerous) {
			return true
		}
	}
	return false
}

// traceFlows builds the flow paths for variables (which functions/outputs they reach)
func (vt *VariableTracker) traceFlows(variables map[string]*Variable) {
	for _, variable := range variables {
		sinks := make([]string, 0)

		// Look at usages to see where the variable flows
		for _, usage := range variable.Usages {
			if usage.IsDangerous {
				sinks = append(sinks, usage.Context)
			}
		}

		variable.FlowsToSinks = sinks
	}
}

// GetCredentialsWithUsage returns credentials and how they're used
// Used by Pattern 2 to understand credential exfiltration
func (vt *VariableTracker) GetCredentialsWithUsage(variables map[string]*Variable) map[string][]string {
	credUsage := make(map[string][]string)

	for varName, variable := range variables {
		if variable.IsCredential {
			usageContexts := make([]string, 0)
			for _, usage := range variable.Usages {
				usageContexts = append(usageContexts, usage.Context)
			}
			if len(usageContexts) > 0 {
				credUsage[varName] = usageContexts
			}
		}
	}

	return credUsage
}

// GetDataFlowPath traces the path of a variable from assignment to usage
// Used by Pattern 1 to track user_input → prompt → llm.call chains
func (vt *VariableTracker) GetDataFlowPath(variables map[string]*Variable, startVar string) []string {
	path := []string{startVar}

	// This is a simplified flow trace
	// In a full implementation, we'd do more sophisticated data flow analysis
	if variable, exists := variables[startVar]; exists {
		path = append(path, variable.FlowsToSinks...)
	}

	return path
}
