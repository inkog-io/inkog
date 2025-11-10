package detectors

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// PromptInjectionDetectorV2 provides comprehensive prompt injection detection
// with support for multiple attack vectors, evasion techniques, false positive reduction,
// and AST-based semantic analysis for accurate variable and data flow tracking.
type PromptInjectionDetectorV2 struct {
	pattern    patterns.Pattern
	confidence float32

	// AST framework components for semantic analysis
	astFramework *ASTAnalysisFramework

	// Core injection patterns
	injectionKeywords    *regexp.Regexp
	injectionSynonyms    *regexp.Regexp
	roleInjectionPattern *regexp.Regexp
	systemPromptPattern  *regexp.Regexp

	// Dangerous sinks (execution points)
	dangerousSinks   *regexp.Regexp
	execPatterns     *regexp.Regexp
	evalPatterns     *regexp.Regexp
	systemCallPattern *regexp.Regexp

	// String formatting methods
	formatString     *regexp.Regexp
	concatenation    *regexp.Regexp
	templateLiteral  *regexp.Regexp

	// Evasion techniques
	base64Pattern    *regexp.Regexp
	hexPattern       *regexp.Regexp
	shellMetachars   *regexp.Regexp

	// Safe patterns (to reduce false positives)
	parameterizedQuery *regexp.Regexp
	safeTemplate       *regexp.Regexp
	sanitizationCall   *regexp.Regexp
	allowListPattern   *regexp.Regexp

	// Multi-language support
	javaStringConcat *regexp.Regexp
	csharpInterp     *regexp.Regexp
	rubyInterp       *regexp.Regexp
}

// NewPromptInjectionDetectorV2 creates an enhanced prompt injection detector
func NewPromptInjectionDetectorV2() *PromptInjectionDetectorV2 {
	pattern := patterns.Pattern{
		ID:       "prompt_injection",
		Name:     "Prompt Injection - Advanced Detection",
		Version:  "2.0",
		Category: "injection",
		Severity: "HIGH",
		CVSS:     8.8,
		CWEIDs:   []string{"CWE-74", "CWE-94", "CWE-95", "CWE-89", "CWE-78", "CWE-200"},
		OWASP:    "LLM01",
		Description: "Detects unvalidated user input in LLM prompts, dangerous execution sinks, string interpolation, evasion techniques, and indirect injection vectors. Maps to multiple CVEs including LangChain PALChain (CVE-2023-44467), GraphCypher (CVE-2024-8309), and Flowise (CVE-2025-59528)",
		Remediation: "1) Use parameterized prompts with input_variables instead of string interpolation. 2) Implement strict input validation and allowlisting. 3) Never eval() or exec() model outputs. 4) Use sandboxing for code generation. 5) Apply output filtering and confidence scoring. 6) Implement multi-layer defense (system prompt + runtime checks)",
		FinancialImpact: struct {
			Severity    string
			Description string
			RiskPerYear float32
		}{
			Severity:    "CRITICAL",
			Description: "OpenAI key compromise = $50K/month. Database credential breach = $500K-$7.3M. Auto-GPT RCE = full system compromise. Average incident cost = $4.8M. Prompt injection is OWASP #1 LLM risk.",
			RiskPerYear: 500000, // Conservative $500K - can be $4.8M to $7.3M in real incidents
		},
	}

	detector := &PromptInjectionDetectorV2{
		pattern:      pattern,
		confidence:   0.90,
		astFramework: NewASTAnalysisFramework(),
	}

	// PRIORITY 1: Injection keywords and synonyms (25+ patterns)
	detector.injectionKeywords = regexp.MustCompile(`(?i)\b(ignore|disregard|forget|override|bypass|disable|cancel|abort|stop|drop|skip|suppress)\s+(all|the|any)\s+(prior|previous|prior|earlier|above|preceding)\s+(instructions|directives|rules|constraints|guidelines|policies|limits|restrictions|commands)\b`)

	detector.injectionSynonyms = regexp.MustCompile(`(?i)\b(you are now|act as|from now on|pretend to be|simulate|imagine you are|assume you are|roleplay as|behave as if|treat me as|consider yourself as|you are a|you will be)\s+(?:developer|admin|god|root|unrestricted|jailbroken|uncensored)\b`)

	detector.roleInjectionPattern = regexp.MustCompile(`(?i)(system|assistant|user|admin|root)\s*:\s*[\w\s"'{}[\]()]+`)

	detector.systemPromptPattern = regexp.MustCompile(`(?i)(<\|system\|>|<\|assistant\|>|<SYSTEM>|<ASSISTANT>|##\s*System|---\s*System)`)

	// PRIORITY 1: Dangerous sinks (execution points)
	detector.dangerousSinks = regexp.MustCompile(`(?i)\b(exec|eval|execute|run|system|call|invoke|apply|spawn|popen|compile|interpret|load|import|require)\s*\(`)

	detector.execPatterns = regexp.MustCompile(`(?i)\b(exec|os\.system|subprocess\.popen|subprocess\.call|subprocess\.run|commands\.getoutput|os\.popen|popen|shell_exec)\s*\(`)

	detector.evalPatterns = regexp.MustCompile(`(?i)\b(eval|exec|compile|new\s+Function|Function\(|eval_expr)\s*\(`)

	detector.systemCallPattern = regexp.MustCompile(`(?i)(rm\s+-rf|chmod|chown|kill|shutdown|reboot|format|dd\s+if=|powershell|bash|sh\s+-c|cmd\s+/c)\b`)

	// PRIORITY 2: String formatting methods
	detector.formatString = regexp.MustCompile(`(%[sd]|%\{[^}]+\}|\$\{[^}]+\}|{\d*}|{\w+})`)

	detector.concatenation = regexp.MustCompile(`(\+\s*["']|["']\s*\+\s*)`)

	detector.templateLiteral = regexp.MustCompile(`([f]?["'`+"`"+`]\s*{[^}]*}|\\$\{[^}]*\})`)

	// PRIORITY 3: Evasion techniques
	detector.base64Pattern = regexp.MustCompile(`[A-Za-z0-9+/]{44,}={0,2}`)

	detector.hexPattern = regexp.MustCompile(`\\x[0-9a-fA-F]{2}|0x[0-9a-fA-F]+`)

	detector.shellMetachars = regexp.MustCompile(`([&|;`+"`"+`]{2,}|[;&|]{1,}|rm\s+-rf|chmod|powershell|cmd\s+/c)`)

	// PRIORITY 2: Safe patterns (reduce false positives)
	detector.parameterizedQuery = regexp.MustCompile(`(?i)(input_variables|parameters\s*=|where\s+id\s*=\s*\?|\$\d+|:\w+)`)

	detector.safeTemplate = regexp.MustCompile(`(?i)(chatprompttemplate|prompttemplate|jinja|j2|template\.from_|format_prompt)`)

	detector.sanitizationCall = regexp.MustCompile(`(?i)(sanitize|escape|validate|filter|clean|strip|remove|replace|regex|re\.sub|allowlist|whitelist|re\.match)`)

	detector.allowListPattern = regexp.MustCompile(`(?i)(if\s+.*\s+in\s+\[|isalnum|isalpha|startswith|endswith|match|pattern)`)

	// PRIORITY 3: Multi-language support
	detector.javaStringConcat = regexp.MustCompile(`"[^"]*"\s*\+\s*[a-zA-Z_]\w*|new\s+StringBuilder`)

	detector.csharpInterp = regexp.MustCompile(`\$"[^"]*{[^}]+}"`)

	detector.rubyInterp = regexp.MustCompile(`%[Wq]\(|%[Wq]\{|%[Wq]\[|#\{[^}]+\}`)

	return detector
}

// Name returns the detector name
func (d *PromptInjectionDetectorV2) Name() string {
	return "prompt_injection"
}

// GetPattern returns the pattern metadata
func (d *PromptInjectionDetectorV2) GetPattern() patterns.Pattern {
	return d.pattern
}

// GetConfidence returns confidence score
func (d *PromptInjectionDetectorV2) GetConfidence() float32 {
	return d.confidence
}

// Detect analyzes code for prompt injection vulnerabilities using both regex patterns and AST-based semantic analysis
func (d *PromptInjectionDetectorV2) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	var findings []patterns.Finding

	// Skip unsupported files
	if !isSupportedFile(filePath) {
		return findings, nil
	}

	// Skip test files (false positive reduction)
	if isTestFile(filePath) {
		return findings, nil
	}

	lines := strings.Split(string(src), "\n")

	// PASS 1: Perform AST-based semantic analysis for accurate variable and data flow tracking
	analysis := d.astFramework.AnalyzeCode(filePath, lines)

	// PASS 2: Identify dangerous data flows (user_input → prompt → llm chains)
	dataFlowAnalyzer := d.astFramework.GetDataFlowAnalyzer()
	userInputFlows := dataFlowAnalyzer.GetFlowsBySource(analysis.DataFlows, "user_input")
	dangerousFlows := make([]DataFlow, 0)
	for _, flow := range userInputFlows {
		// Check if flow reaches a dangerous sink (eval, exec, system, llm.call)
		if d.astFramework.IsDataFlowDangerous(flow) {
			dangerousFlows = append(dangerousFlows, flow)
		}
	}

	// Check each dangerous flow for injection vulnerability
	for _, flow := range dangerousFlows {
		for _, lineNum := range flow.LineNumbers {
			if lineNum <= 0 || lineNum > len(lines) {
				continue
			}

			line := lines[lineNum-1]
			trimmedLine := strings.TrimSpace(line)

			// Skip comments and empty lines
			if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") || strings.HasPrefix(trimmedLine, "//") {
				continue
			}

			// High confidence finding: direct user input to dangerous sink
			confidence := d.astFramework.EnhanceConfidenceScore(0.85, analysis, lineNum)

			findings = append(findings, d.createFinding(
				filePath, lineNum-1, line, "CRITICAL",
				"Data flow vulnerability: user input to dangerous sink",
				"User-controlled data flows to "+flow.Sink+". AST analysis confirms: "+strings.Join(flow.Path, " → "),
				confidence,
			))
		}
	}

	// PASS 3: Traditional regex-based detection (faster for specific patterns)
	for i, line := range lines {
		trimmedLine := strings.TrimSpace(line)

		// Skip comments and empty lines
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") || strings.HasPrefix(trimmedLine, "//") {
			continue
		}

		// PRIORITY 1: Check for dangerous sinks with untrusted input
		if d.hasDangerousSink(line, filePath, i) {
			// Skip if already found by AST analysis
			var alreadyReported bool
			for _, f := range findings {
				if f.Line == i+1 && strings.Contains(f.Message, "Data flow vulnerability") {
					alreadyReported = true
					break
				}
			}
			if alreadyReported {
				continue
			}

			findings = append(findings, d.createFinding(
				filePath, i, line, "CRITICAL",
				"Code execution with untrusted input",
				"LLM output or user input is being executed. This enables arbitrary code execution (CWE-94).",
				0.95,
			))
			continue
		}

		// PRIORITY 1: Check for injection keywords
		if d.hasInjectionKeywords(line) {
			confidence := d.calculateConfidence(line, filePath, i)
			confidence = d.astFramework.EnhanceConfidenceScore(confidence, analysis, i+1)

			if confidence < 0.5 {
				continue // Too many mitigations, skip
			}

			findings = append(findings, d.createFinding(
				filePath, i, line, "HIGH",
				"Prompt injection attempt detected",
				"Code contains prompt injection keywords attempting to override instructions.",
				confidence,
			))
			continue
		}

		// PRIORITY 1: Check for string interpolation in prompts
		if d.hasUnsafeStringInterpolation(line) {
			confidence := d.calculateConfidence(line, filePath, i)
			confidence = d.astFramework.EnhanceConfidenceScore(confidence, analysis, i+1)

			if confidence < 0.65 {
				continue // Strong mitigations present
			}

			findings = append(findings, d.createFinding(
				filePath, i, line, "HIGH",
				"Unvalidated user input in prompt",
				"User input is directly interpolated into LLM prompt without sanitization.",
				confidence,
			))
			continue
		}

		// PRIORITY 2: Check for evasion techniques
		if d.hasEvasionTechnique(line) {
			confidence := d.calculateConfidence(line, filePath, i)
			confidence = d.astFramework.EnhanceConfidenceScore(confidence, analysis, i+1)

			if confidence < 0.60 {
				continue
			}

			findings = append(findings, d.createFinding(
				filePath, i, line, "MEDIUM",
				"Potential obfuscated injection attempt",
				"Code contains patterns consistent with obfuscated payload injection (Base64, hex, shell metacharacters).",
				confidence,
			))
		}
	}

	return findings, nil
}

// hasDangerousSink checks if line contains code execution with untrusted input
func (d *PromptInjectionDetectorV2) hasDangerousSink(line, filePath string, lineNum int) bool {
	// Check if it contains dangerous function calls
	if !d.dangerousSinks.MatchString(line) {
		return false
	}

	// Check for specific dangerous patterns
	if d.execPatterns.MatchString(line) || d.evalPatterns.MatchString(line) {
		// Check if the dangerous call appears to contain untrusted input indicators
		hasUserInput := d.hasUserInputIndicators(line)
		hasLLMOutput := d.hasLLMOutputIndicators(line)

		return hasUserInput || hasLLMOutput
	}

	return false
}

// hasUserInputIndicators checks for signs of user-controlled data
func (d *PromptInjectionDetectorV2) hasUserInputIndicators(line string) bool {
	userInputPatterns := []string{
		"user_input", "user_query", "request", "input", "query",
		"message", "text", "content", "data", "payload",
		"cmd", "command", "instruction", "user_request",
		"req.body", "req.query", "req.params", "get_user",
		"input()", "raw_input()", "stdin", "argv",
	}

	lowerLine := strings.ToLower(line)
	for _, pattern := range userInputPatterns {
		if strings.Contains(lowerLine, pattern) {
			return true
		}
	}
	return false
}

// hasLLMOutputIndicators checks for signs of LLM-generated data being executed
func (d *PromptInjectionDetectorV2) hasLLMOutputIndicators(line string) bool {
	llmOutputPatterns := []string{
		"response", "completion", "generated", "output", "result",
		"llm.run", "chain.run", "invoke", "predict", "generate",
		"openai", "anthropic", "bedrock", "llama", "mistral",
		"['choices'][0]", "[\"choices\"][0]", ".choices[0]",
		".text", ".content", ".message",
	}

	lowerLine := strings.ToLower(line)
	for _, pattern := range llmOutputPatterns {
		if strings.Contains(lowerLine, pattern) {
			return true
		}
	}
	return false
}

// hasInjectionKeywords checks for prompt injection attempt keywords
func (d *PromptInjectionDetectorV2) hasInjectionKeywords(line string) bool {
	// Normalize unicode to detect homoglyphs
	normalized := d.normalizeUnicode(line)

	if d.injectionKeywords.MatchString(normalized) ||
		d.injectionSynonyms.MatchString(normalized) ||
		d.roleInjectionPattern.MatchString(normalized) ||
		d.systemPromptPattern.MatchString(normalized) {
		return true
	}

	return false
}

// hasUnsafeStringInterpolation checks for user input directly in prompts
func (d *PromptInjectionDetectorV2) hasUnsafeStringInterpolation(line string) bool {
	// Must have string formatting AND an LLM context indicator
	if !d.isInLLMContext(line) {
		return false
	}

	// Check for string interpolation methods
	hasFormatting := d.formatString.MatchString(line) ||
		d.concatenation.MatchString(line) ||
		d.templateLiteral.MatchString(line)

	if !hasFormatting {
		return false
	}

	// Check for user input indicators in the interpolation
	return d.hasUserInputIndicators(line)
}

// hasEvasionTechnique checks for obfuscated injection attempts
func (d *PromptInjectionDetectorV2) hasEvasionTechnique(line string) bool {
	// Check for Base64-encoded payloads in prompts
	if d.base64Pattern.MatchString(line) && d.isInLLMContext(line) {
		// Check if it's actually suspicious (long base64 in a string literal)
		if strings.ContainsAny(line, `"'`) {
			return true
		}
	}

	// Check for hex-encoded content
	if d.hexPattern.MatchString(line) && d.isInLLMContext(line) {
		return true
	}

	// Check for shell metacharacters that shouldn't be there
	if d.shellMetachars.MatchString(line) && (d.isInLLMContext(line) || d.hasUserInputIndicators(line)) {
		return true
	}

	return false
}

// isInLLMContext determines if code is in an LLM/AI context
func (d *PromptInjectionDetectorV2) isInLLMContext(line string) bool {
	llmIndicators := []string{
		// LLM API calls
		"openai", "anthropic", "azure", "bedrock", "cohere", "huggingface",
		"llama", "mistral", "together", "replicate",

		// Framework functions
		"llmchain", "chain.run", "agent.run", "agent.invoke",
		".chat(", ".invoke(", ".predict(", ".complete(", ".generate(",
		"apredict(", "ainvoke(", "async_invoke(",

		// LLM variable names
		"prompt", "system_prompt", "llm_prompt", "user_prompt",
		"messages", "message", "instruction", "system",
		"completion", "generation", "response", "result",

		// Framework classes
		"ChatOpenAI", "Anthropic", "LangChain", "CrewAI", "AutoGen",
	}

	lowerLine := strings.ToLower(line)
	for _, indicator := range llmIndicators {
		if strings.Contains(lowerLine, indicator) {
			return true
		}
	}

	return false
}

// calculateConfidence computes a risk score based on multiple factors
func (d *PromptInjectionDetectorV2) calculateConfidence(line, filePath string, lineNum int) float32 {
	confidence := float32(0.5) // Base score

	// Increase confidence for risk factors
	if d.hasUserInputIndicators(line) {
		confidence += 0.15
	}

	if d.hasLLMOutputIndicators(line) {
		confidence += 0.15
	}

	if d.hasInjectionKeywords(line) {
		confidence += 0.20
	}

	if d.hasDangerousSink(line, filePath, lineNum) {
		confidence += 0.25
	}

	// Decrease confidence for mitigating factors
	if d.hasSanitization(line) {
		confidence -= 0.25
	}

	if d.hasSafePattern(line) {
		confidence -= 0.30
	}

	if d.hasInputValidation(line) {
		confidence -= 0.20
	}

	// Clamp confidence to valid range
	if confidence < 0.0 {
		confidence = 0.0
	}
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// hasSanitization checks if input is being sanitized
func (d *PromptInjectionDetectorV2) hasSanitization(line string) bool {
	return d.sanitizationCall.MatchString(line)
}

// hasSafePattern checks for known safe patterns
func (d *PromptInjectionDetectorV2) hasSafePattern(line string) bool {
	if d.safeTemplate.MatchString(line) {
		return true
	}

	if d.parameterizedQuery.MatchString(line) {
		return true
	}

	return false
}

// hasInputValidation checks for input validation/allowlisting
func (d *PromptInjectionDetectorV2) hasInputValidation(line string) bool {
	return d.allowListPattern.MatchString(line)
}

// normalizeUnicode handles Unicode homoglyphs and normalization
func (d *PromptInjectionDetectorV2) normalizeUnicode(text string) string {
	// Simple normalization: convert common homoglyphs to ASCII
	replacements := map[rune]rune{
		// Fullwidth ASCII characters
		'ａ': 'a', 'ｂ': 'b', 'ｃ': 'c', 'ｄ': 'd', 'ｅ': 'e',
		'ｆ': 'f', 'ｇ': 'g', 'ｈ': 'h', 'ｉ': 'i', 'ｊ': 'j',
		'ｋ': 'k', 'ｌ': 'l', 'ｍ': 'm', 'ｎ': 'n', 'ｏ': 'o',
		'ｐ': 'p', 'ｑ': 'q', 'ｒ': 'r', 'ｓ': 's', 'ｔ': 't',
		'ｕ': 'u', 'ｖ': 'v', 'ｗ': 'w', 'ｘ': 'x', 'ｙ': 'y',
		'ｚ': 'z',
		'Ａ': 'A', 'Ｂ': 'B', 'Ｃ': 'C', 'Ｄ': 'D', 'Ｅ': 'E',
		'Ｆ': 'F', 'Ｇ': 'G', 'Ｈ': 'H', 'Ｉ': 'I', 'Ｊ': 'J',
		'Ｚ': 'Z',
		// Cyrillic lookalikes
		'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E',
		'К': 'K', 'М': 'M', 'О': 'O', 'Р': 'P',
		'Т': 'T', 'У': 'Y', 'Х': 'X',
		'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y',
		// Greek lookalikes
		'Ο': 'O', 'ο': 'o', 'Ρ': 'P', 'ρ': 'p',
	}

	var result []rune
	for _, r := range text {
		if replacement, ok := replacements[r]; ok {
			result = append(result, replacement)
		} else {
			result = append(result, r)
		}
	}

	return string(result)
}

// createFinding generates a finding report
func (d *PromptInjectionDetectorV2) createFinding(filePath string, lineNum int, code, severity, title, message string, confidence float32) patterns.Finding {
	trimmedCode := strings.TrimSpace(code)
	if len(trimmedCode) > 120 {
		trimmedCode = trimmedCode[:117] + "..."
	}

	return patterns.Finding{
		ID:             fmt.Sprintf("prompt_injection_%d_%s", lineNum, filePath),
		PatternID:      d.pattern.ID,
		Pattern:        d.pattern.Name,
		File:           filePath,
		Line:           lineNum + 1,
		Column:         len(code) - len(strings.TrimSpace(code)) + 1,
		Message:        title + " - " + message,
		Code:           trimmedCode,
		Severity:       severity,
		Confidence:     confidence,
		CWE:            "CWE-94",
		CVSS:           d.pattern.CVSS,
		OWASP:          d.pattern.OWASP,
		FinancialRisk:  "Code execution, data exfiltration, system compromise. Avg loss: $4.8M per incident.",
	}
}
