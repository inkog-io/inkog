package detectors

import (
	"regexp"
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// ContextWindowAccumulationDetector detects unbounded conversation history accumulation in AI agents
// This pattern identifies cases where conversation/context grows without bounds, leading to:
// - Excessive token consumption
// - Memory exhaustion
// - Performance degradation
// - Cost explosion (for API-based LLMs)
//
// Examples:
// - ConversationBufferMemory (unbounded memory accumulation)
// - Append-only conversation lists without bounding
// - Token buffer without max_token_limit
// - Manual history accumulation in loops
type ContextWindowAccumulationDetector struct {
	// Patterns for unbounded context accumulation
	conversationBufferPattern *regexp.Regexp              // LangChain ConversationBufferMemory
	bufferWindowMissingKPattern *regexp.Regexp             // ConversationBufferWindowMemory without k
	tokenBufferMissingLimitPattern *regexp.Regexp          // ConversationTokenBufferMemory without max
	appendToHistoryPattern   *regexp.Regexp              // Direct append to conversation list
	stringConcatHistoryPattern *regexp.Regexp             // String concatenation for history
	sliceAssignmentPattern   *regexp.Regexp              // Direct slice assignment (+=)
	crewaiBehaviorPattern    *regexp.Regexp              // CrewAI task history
	floswiseThreadPattern    *regexp.Regexp              // Flowise thread context
	difyConversationPattern  *regexp.Regexp              // Dify conversation memory
	pythonListAppendPattern  *regexp.Regexp              // Python list.append patterns
	pythonExtendPattern      *regexp.Regexp              // Python list.extend patterns
	javascriptPushPattern    *regexp.Regexp              // JavaScript array.push patterns
	goAppendPattern          *regexp.Regexp              // Go append() patterns
	loopAccumulationPattern  *regexp.Regexp              // Loop-based accumulation
	conversationVarPattern   *regexp.Regexp              // Variable names suggest conversation
	historySizeCheckPattern  *regexp.Regexp              // Bounding logic check
	popPattern               *regexp.Regexp              // Removing oldest entries (mitigation)
	summarizePattern         *regexp.Regexp              // Summarization as mitigation
	windowPattern            *regexp.Regexp              // Windowing mechanism
}

// NewContextWindowAccumulationDetector creates a new context window accumulation detector
func NewContextWindowAccumulationDetector() *ContextWindowAccumulationDetector {
	return &ContextWindowAccumulationDetector{
		// LangChain patterns
		conversationBufferPattern: regexp.MustCompile(
			`(?i)ConversationBufferMemory\s*\(`,
		),
		bufferWindowMissingKPattern: regexp.MustCompile(
			`(?i)ConversationBufferWindowMemory\s*\(\s*(?:ai_prefix|human_prefix|input_key|output_key|memory_key)[^)]*\)`,
		),
		tokenBufferMissingLimitPattern: regexp.MustCompile(
			`(?i)ConversationTokenBufferMemory\s*\(\s*(?:ai_prefix|human_prefix|input_key|output_key|llm)[^)]*\)`,
		),

		// Direct accumulation patterns
		appendToHistoryPattern: regexp.MustCompile(
			`(?i)(history|conversation|messages|context|dialog|chat)\s*\.\s*append\s*\(`,
		),
		stringConcatHistoryPattern: regexp.MustCompile(
			`(?i)(history|conversation|messages|context)\s*\+=\s*["\']`,
		),
		sliceAssignmentPattern: regexp.MustCompile(
			`(?i)(history|conversation|messages|context|chat_history)\s*\+=\s*\[`,
		),

		// Framework-specific patterns
		crewaiBehaviorPattern: regexp.MustCompile(
			`(?i)(task\.outputs|execute_task|task_history)\s*\+=|history\s*\+=`,
		),
		floswiseThreadPattern: regexp.MustCompile(
			`(?i)(thread_messages|conversation_history)\s*\.\s*(push|append|add)\s*\(`,
		),
		difyConversationPattern: regexp.MustCompile(
			`(?i)(DifyConversation|conversation_memory|message_list)\s*\.\s*(append|add)\s*\(`,
		),

		// Language-specific patterns
		pythonListAppendPattern: regexp.MustCompile(
			`(?i)(?:history|conversation|messages|context|dialog|transcript)\s*\.\s*append\s*\(\s*(?:message|response|text|chat)\s*\)`,
		),
		pythonExtendPattern: regexp.MustCompile(
			`(?i)(?:history|conversation|messages|context)\s*\.\s*extend\s*\(`,
		),
		javascriptPushPattern: regexp.MustCompile(
			`(?i)(?:history|conversation|messages|context|dialog)\s*\.\s*push\s*\(`,
		),
		goAppendPattern: regexp.MustCompile(
			`(?i)(?:history|conversation|messages|context)\s*=\s*append\s*\(`,
		),

		// Loop-based accumulation
		loopAccumulationPattern: regexp.MustCompile(
			`(?i)(for|while)\s+(?:\w+\s+)?in\s+|for\s+(?:\w+\s*,\s*)*\w+\s*:=?\s*range\s+`,
		),

		// Variable naming that suggests conversation/history
		conversationVarPattern: regexp.MustCompile(
			`(?i)(history|conversation|messages|context|dialog|chat|log|transcript|memory)\s*[=:]\s*(?:\[\]|{}|list\(\)|dict\(\)|new\s+Array|new\s+Map)`,
		),

		// Bounding mechanisms (mitigations)
		historySizeCheckPattern: regexp.MustCompile(
			`(?i)(?:len|size|length|count)\s*\(\s*(?:history|conversation|messages|context)\s*\)|k\s*=|max_.*=|limit\s*=`,
		),
		popPattern: regexp.MustCompile(
			`(?i)(?:history|conversation|messages|context|log)\s*\.\s*(?:pop|remove|shift|popleft)\s*\(`,
		),
		summarizePattern: regexp.MustCompile(
			`(?i)(?:summarize|summary|compress|condense)\s*\(|ConversationSummary`,
		),
		windowPattern: regexp.MustCompile(
			`(?i)(?:window|sliding|truncate|trim|k\s*=|max_tokens|max_messages)`,
		),
	}
}

// Detect performs context window accumulation detection
func (d *ContextWindowAccumulationDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	sourceStr := string(src)
	lines := strings.Split(sourceStr, "\n")
	var findings []patterns.Finding

	// Determine language
	lang := d.detectLanguage(filePath, sourceStr)

	// First pass: Build context maps
	contextMap := d.buildContextMap(sourceStr, lines)

	// Second pass: Report findings
	for i, line := range lines {
		lineNum := i + 1
		trimmedLine := strings.TrimSpace(line)

		// Skip empty lines
		if trimmedLine == "" {
			continue
		}

		// Skip lines that are only comments (but process lines with code after comments)
		if strings.HasPrefix(trimmedLine, "//") || strings.HasPrefix(trimmedLine, "#") {
			continue
		}

		// Check for unbounded buffer memory (LangChain)
		if d.conversationBufferPattern.MatchString(line) {
			finding := d.createFinding(
				filePath,
				lineNum,
				"Unbounded ConversationBufferMemory",
				"ConversationBufferMemory accumulates all conversation history without bounds. This will cause unlimited memory growth and token consumption. Use ConversationSummaryMemory or ConversationBufferWindowMemory with a fixed k parameter instead.",
				"CRITICAL",
				0.95,
			)
			findings = append(findings, finding)
			continue
		}

		// Check for ConversationBufferWindowMemory without k parameter
		if strings.Contains(line, "ConversationBufferWindowMemory") && strings.Contains(line, "(") {
			// Need to check if k parameter is present in the block
			fullBlock := d.extractFunctionBlock(lines, i)
			if !strings.Contains(fullBlock, "k=") && !strings.Contains(fullBlock, "k :") {
				finding := d.createFinding(
					filePath,
					lineNum,
					"ConversationBufferWindowMemory without k parameter",
					"ConversationBufferWindowMemory must have a fixed k parameter to limit context. Without it, history grows unbounded.",
					"CRITICAL",
					0.90,
				)
				findings = append(findings, finding)
			}
		}

		// Check for ConversationTokenBufferMemory without max_token_limit
		if d.tokenBufferMissingLimitPattern.MatchString(line) {
			fullBlock := d.extractFunctionBlock(lines, i)
			if !strings.Contains(fullBlock, "max_token_limit") {
				finding := d.createFinding(
					filePath,
					lineNum,
					"ConversationTokenBufferMemory without max_token_limit",
					"ConversationTokenBufferMemory requires max_token_limit parameter to bound memory usage.",
					"CRITICAL",
					0.90,
				)
				findings = append(findings, finding)
			}
		}

		// Check for unbounded append patterns
		if d.appendToHistoryPattern.MatchString(line) {
			varName := d.extractVariableName(line, `(?i)(history|conversation|messages|context|dialog|chat)`)
			if varName != "" {
				// Check if this variable is being bounded elsewhere
				isBounded := d.hasBoundingLogic(contextMap, i)

				// If not explicitly bounded, it's likely unbounded
				if !isBounded && !contextMap.isBounded[varName] {
					confidence := d.calculateConfidence(line, contextMap, i)
					if confidence > 0.5 {
						finding := d.createFinding(
							filePath,
							lineNum,
							"Unbounded conversation history accumulation",
							"Appending to conversation/history without bounding logic will cause memory exhaustion. Add max size checks or use summarization.",
							"HIGH",
							confidence,
						)
						findings = append(findings, finding)
					}
				}
			} else if d.isConversationVariable(line) {
				// Even if we can't extract the name, if it looks like a conversation variable
				confidence := d.calculateConfidence(line, contextMap, i)
				if confidence > 0.5 && !d.hasBoundingLogic(contextMap, i) {
					finding := d.createFinding(
						filePath,
						lineNum,
						"Unbounded conversation history accumulation",
						"Appending to conversation/history without bounding logic will cause memory exhaustion. Add max size checks or use summarization.",
						"HIGH",
						confidence,
					)
					findings = append(findings, finding)
				}
			}
		}

		// Check for string concatenation history (both direct and indirect)
		if (d.stringConcatHistoryPattern.MatchString(line) ||
			(strings.Contains(line, "+=") && d.isConversationVariable(line))) &&
			!d.hasSummarizationLogic(sourceStr, i) {
			varName := d.extractVariableName(line, `(?i)(history|conversation|messages|context)`)
			if varName != "" && !contextMap.isBounded[varName] {
				finding := d.createFinding(
					filePath,
					lineNum,
					"Unbounded string/data concatenation for conversation history",
					"Concatenating/accumulating to conversation context indefinitely will cause unbounded growth. Use windowing or summarization.",
					"HIGH",
					0.85,
				)
				findings = append(findings, finding)
			}
		}

		// Check for slice assignment accumulation
		if d.sliceAssignmentPattern.MatchString(line) && !d.hasBoundingLogic(contextMap, i) {
			varName := d.extractVariableName(line, `(?i)(history|conversation|messages|context|chat_history)`)
			if varName != "" && !contextMap.isBounded[varName] {
				finding := d.createFinding(
					filePath,
					lineNum,
					"Unbounded slice assignment to context",
					"Using += to accumulate slices/lists without bounding will cause memory growth. Add size limits.",
					"HIGH",
					0.80,
				)
				findings = append(findings, finding)
			}
		}

		// Check for CrewAI task history accumulation
		if d.crewaiBehaviorPattern.MatchString(line) && lang == "python" {
			if !d.hasBoundingLogic(contextMap, i) {
				finding := d.createFinding(
					filePath,
					lineNum,
					"CrewAI task history unbounded accumulation",
					"Task outputs and history accumulate without bounds in CrewAI agents. Implement history windowing.",
					"MEDIUM",
					0.75,
				)
				findings = append(findings, finding)
			}
		}

		// Check for Flowise thread accumulation
		if d.floswiseThreadPattern.MatchString(line) && !d.hasBoundingLogic(contextMap, i) {
			finding := d.createFinding(
				filePath,
				lineNum,
				"Flowise thread messages unbounded accumulation",
				"Flowise thread messages accumulate indefinitely. Implement message trimming or windowing.",
				"MEDIUM",
				0.70,
			)
			findings = append(findings, finding)
		}

		// Check for Dify conversation memory
		if d.difyConversationPattern.MatchString(line) && !d.hasBoundingLogic(contextMap, i) {
			finding := d.createFinding(
				filePath,
				lineNum,
				"Dify conversation memory unbounded accumulation",
				"Dify conversation memory grows without bounds. Add message limits or summarization.",
				"MEDIUM",
				0.70,
			)
			findings = append(findings, finding)
		}

		// Check for JavaScript array operations (push, unshift, concat without bounds)
		if lang == "javascript" || strings.HasSuffix(filePath, ".js") || strings.HasSuffix(filePath, ".ts") {
			if (strings.Contains(line, ".push(") || strings.Contains(line, ".unshift(")) &&
				(d.conversationVarPattern.MatchString(line) || d.isConversationVariable(line)) {
				if !d.hasBoundingLogic(contextMap, i) {
					finding := d.createFinding(
						filePath,
						lineNum,
						"Unbounded JavaScript array accumulation",
						"Pushing to conversation/message array without size limits causes unbounded growth.",
						"HIGH",
						0.80,
					)
					findings = append(findings, finding)
				}
			}
		}

		// Check for Go append without bounds
		if lang == "go" || strings.HasSuffix(filePath, ".go") {
			if strings.Contains(line, "= append(") && d.isConversationVariable(line) {
				if !d.hasBoundingLogic(contextMap, i) {
					finding := d.createFinding(
						filePath,
						lineNum,
						"Unbounded Go slice accumulation",
						"Using append() to accumulate conversation/history without bounds will cause memory growth.",
						"HIGH",
						0.75,
					)
					findings = append(findings, finding)
				}
			}
		}

		// Check for any variable with conversation naming in a loop context
		if d.loopAccumulationPattern.MatchString(line) && d.isConversationVariable(line) {
			finding := d.createFinding(
				filePath,
				lineNum,
				"Unbounded loop accumulation with conversation context",
				"Loop that accumulates conversation data without bounding logic will cause unbounded growth.",
				"MEDIUM",
				0.70,
			)
			findings = append(findings, finding)
		}

		// Check for LLM calls with unbounded context variables in the next few lines
		if d.isLLMCallLine(line) {
			// Look back a few lines for accumulation
			for j := i - 1; j >= 0 && j > i-5; j-- {
				if d.isConversationVariable(lines[j]) && d.loopAccumulationPattern.MatchString(lines[j]) {
					finding := d.createFinding(
						filePath,
						lineNum,
						"LLM call with unbounded accumulated context",
						"LLM receiving accumulated context from unbounded loop will cause token exhaustion.",
						"HIGH",
						0.85,
					)
					findings = append(findings, finding)
					break
				}
			}
		}
	}

	return findings, nil
}

// isConversationVariable checks if a line contains conversation-related variable names
func (d *ContextWindowAccumulationDetector) isConversationVariable(line string) bool {
	conversationKeywords := []string{"history", "conversation", "messages", "context", "dialog", "chat", "log", "transcript"}
	for _, keyword := range conversationKeywords {
		if strings.Contains(strings.ToLower(line), keyword) {
			return true
		}
	}
	return false
}

// contextMapData holds context information for analysis
type contextMapData struct {
	isBounded map[string]bool        // Variables with bounding logic
	hasSummary map[string]bool        // Variables using summarization
	loopVars  map[string]bool        // Variables modified in loops
	llmUsage  map[string]bool        // Variables passed to LLM
}

// buildContextMap analyzes code to build context about variable usage
func (d *ContextWindowAccumulationDetector) buildContextMap(sourceStr string, lines []string) *contextMapData {
	cmap := &contextMapData{
		isBounded: make(map[string]bool),
		hasSummary: make(map[string]bool),
		loopVars: make(map[string]bool),
		llmUsage: make(map[string]bool),
	}

	for _, line := range lines {
		// Track bounding logic
		if d.historySizeCheckPattern.MatchString(line) {
			varNames := d.extractConversationVariables(line)
			for _, v := range varNames {
				cmap.isBounded[v] = true
			}
		}

		// Track summarization usage
		if d.summarizePattern.MatchString(line) {
			varNames := d.extractConversationVariables(line)
			for _, v := range varNames {
				cmap.hasSummary[v] = true
			}
		}

		// Track loop context
		if d.loopAccumulationPattern.MatchString(line) {
			varNames := d.extractConversationVariables(line)
			for _, v := range varNames {
				cmap.loopVars[v] = true
			}
		}

		// Track LLM usage (simplified heuristic)
		if d.isLLMCallLine(line) {
			varNames := d.extractConversationVariables(sourceStr)
			for _, v := range varNames {
				cmap.llmUsage[v] = true
			}
		}
	}

	return cmap
}

// extractFunctionBlock extracts the entire function call block starting at line i
func (d *ContextWindowAccumulationDetector) extractFunctionBlock(lines []string, startIdx int) string {
	var block strings.Builder
	parenCount := 0
	started := false

	for i := startIdx; i < len(lines) && i < startIdx+20; i++ { // Limit to 20 lines
		line := lines[i]
		block.WriteString(line)
		block.WriteString("\n")

		for _, ch := range line {
			if ch == '(' {
				parenCount++
				started = true
			} else if ch == ')' {
				parenCount--
				if started && parenCount == 0 {
					return block.String()
				}
			}
		}
	}

	return block.String()
}

// hasBoundingLogic checks if there is bounding/limit logic near this line
func (d *ContextWindowAccumulationDetector) hasBoundingLogic(cmap *contextMapData, lineIdx int) bool {
	// This is a simplified check - in real code, we'd analyze surrounding lines more thoroughly
	// For now, check if any bounding is mentioned in the context map
	return len(cmap.isBounded) > 0
}

// hasSummarizationLogic checks if summarization is used as mitigation
func (d *ContextWindowAccumulationDetector) hasSummarizationLogic(sourceStr string, lineIdx int) bool {
	return d.summarizePattern.MatchString(sourceStr) || strings.Contains(sourceStr, "ConversationSummary")
}

// calculateConfidence calculates confidence based on context
func (d *ContextWindowAccumulationDetector) calculateConfidence(line string, cmap *contextMapData, lineIdx int) float32 {
	confidence := float32(0.70) // Start higher for direct append/concatenation

	// Check for loop context (higher risk)
	if d.loopAccumulationPattern.MatchString(line) {
		confidence += 0.15
	}

	// Check for conversation variables (indicator of context)
	if d.isConversationVariable(line) {
		confidence += 0.10
	}

	// Check for LLM usage (indicates token concern)
	if d.isLLMCallLine(line) {
		confidence += 0.10
	}

	// Reduce if bounding is present
	if d.historySizeCheckPattern.MatchString(line) {
		confidence -= 0.15
	}

	// Reduce if summarization is used
	if d.summarizePattern.MatchString(line) {
		confidence -= 0.20
	}

	// Cap at 0.95
	if confidence > 0.95 {
		confidence = 0.95
	}

	// Floor at minimum threshold to catch clear violations
	if confidence < 0.65 {
		confidence = 0.65 // Minimum for clear append/concat patterns
	}

	return confidence
}

// detectLanguage determines code language from file extension and content
func (d *ContextWindowAccumulationDetector) detectLanguage(filePath string, sourceStr string) string {
	if strings.HasSuffix(filePath, ".py") {
		return "python"
	}
	if strings.HasSuffix(filePath, ".js") || strings.HasSuffix(filePath, ".ts") || strings.HasSuffix(filePath, ".jsx") || strings.HasSuffix(filePath, ".tsx") {
		return "javascript"
	}
	if strings.HasSuffix(filePath, ".go") {
		return "go"
	}
	// Fallback: check content
	if strings.Contains(sourceStr, "def ") && strings.Contains(sourceStr, "import ") {
		return "python"
	}
	if strings.Contains(sourceStr, "function ") || strings.Contains(sourceStr, "const ") {
		return "javascript"
	}
	if strings.Contains(sourceStr, "func ") && strings.Contains(sourceStr, "package ") {
		return "go"
	}
	return "unknown"
}

// extractVariableName extracts variable name from a pattern match
func (d *ContextWindowAccumulationDetector) extractVariableName(line string, pattern string) string {
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(line)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// extractConversationVariables extracts all conversation-related variables from text
func (d *ContextWindowAccumulationDetector) extractConversationVariables(text string) []string {
	re := regexp.MustCompile(`(?i)(history|conversation|messages|context|dialog|chat|log|transcript)`)
	matches := re.FindAllString(text, -1)
	return matches
}

// isLLMCallLine checks if a line contains an LLM call
func (d *ContextWindowAccumulationDetector) isLLMCallLine(line string) bool {
	llmPatterns := []string{
		"(?i)openai",
		"(?i)llm\\.",
		"(?i)completion",
		"(?i)generate\\(",
		"(?i)chat\\.",
		"(?i)predict\\(",
		"(?i)\\.invoke\\(",
	}

	for _, pattern := range llmPatterns {
		if matched, _ := regexp.MatchString(pattern, line); matched {
			return true
		}
	}
	return false
}

// createFinding creates a Finding struct with provided parameters
func (d *ContextWindowAccumulationDetector) createFinding(
	filePath string,
	lineNum int,
	title string,
	message string,
	severity string,
	confidence float32,
) patterns.Finding {
	return patterns.Finding{
		File:       filePath,
		Line:       lineNum,
		Message:    title + ": " + message,
		Severity:   severity,
		Confidence: confidence,
		PatternID:  "context_window_accumulation",
	}
}

// Name returns the detector name
func (d *ContextWindowAccumulationDetector) Name() string {
	return "context_window_accumulation"
}

// GetPattern returns the pattern metadata
func (d *ContextWindowAccumulationDetector) GetPattern() patterns.Pattern {
	return patterns.Pattern{
		ID:          "context_window_accumulation",
		Name:        "Context Window Accumulation",
		Version:     "1.0",
		Category:    "resource_exhaustion",
		Severity:    "HIGH",
		CVSS:        7.5,
		CWEIDs:      []string{"CWE-770", "CWE-400"},
		OWASP:       "A05:2021 Resource Exhaustion",
		Description: "Detects unbounded context/conversation history accumulation in AI agents",
	}
}

// GetConfidence returns the confidence score for this detector
func (d *ContextWindowAccumulationDetector) GetConfidence() float32 {
	return 0.80
}
