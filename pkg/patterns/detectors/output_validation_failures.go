package detectors

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
	"github.com/inkog-io/inkog/action/pkg/patterns/metadata"
)

// OutputValidationFailuresDetector detects improper handling of LLM/untrusted output without validation or sanitization
// Pattern: LLM output used directly in dangerous sinks (eval/exec, HTML rendering, command execution, SQL)
// CWE: CWE-79 (XSS), CWE-94 (Code Injection), CWE-77/78 (Command Injection), CWE-89 (SQL Injection), CWE-20 (Untrusted Input)
//
// Examples:
// - eval(llm_output) or exec(model_response) without validation
// - element.innerHTML = chatbot_response without sanitization
// - dangerouslySetInnerHTML={{ __html: llm_text }}
// - st.markdown(answer, unsafe_allow_html=True)
// - os.system(f"command {llm_suggestion}") without escaping
// - template.HTML(untrusted_content) in Go
// - format string injection: cursor.execute(f"SELECT * FROM users WHERE id = {llm_output}")
// - Writing user/LLM content to HTML response without escaping
type OutputValidationFailuresDetector struct {
	// Code execution patterns (Python/JS/Go)
	pythonEvalPattern              *regexp.Regexp // eval(...)
	pythonExecPattern              *regexp.Regexp // exec(...)
	pythonCompilePattern           *regexp.Regexp // compile(...)
	osSystemPattern                *regexp.Regexp // os.system(...)
	subprocessPattern              *regexp.Regexp // subprocess.run, Popen, call
	jsEvalPattern                  *regexp.Regexp // eval(...)
	jsFunctionConstructorPattern   *regexp.Regexp // Function(...) or new Function
	jsExecPattern                  *regexp.Regexp // exec(...)
	jsExecFilePattern              *regexp.Regexp // execFile(...)
	childProcessPattern            *regexp.Regexp // child_process exec/spawn
	goExecPattern                  *regexp.Regexp // exec.Command(...)

	// HTML injection patterns (XSS/Web rendering)
	innerHTMLPattern               *regexp.Regexp // .innerHTML = ...
	dangerouslySetInnerHTMLPattern *regexp.Regexp // dangerouslySetInnerHTML
	streamlitUnsafeHTMLPattern     *regexp.Regexp // st.markdown(..., unsafe_allow_html=True)
	templateHTMLPattern            *regexp.Regexp // template.HTML(...)
	ipythonHTMLPattern             *regexp.Regexp // IPython.display.HTML(...)
	innerHTMLSetPattern            *regexp.Regexp // element.innerHTML = ...
	eventHandlerPattern            *regexp.Regexp // onerror=, onload=, onclick=
	javascriptURLPattern           *regexp.Regexp // javascript: in URLs
	writeHTMLResponsePattern       *regexp.Regexp // Response.Write, http.ResponseWriter write
	formatStringHTMLPattern        *regexp.Regexp // f-string or % format with HTML tags
	goTemplateUnsafePattern        *regexp.Regexp // template.JS, template.URL, template.Attr

	// Command injection patterns
	formatStringCommandPattern     *regexp.Regexp // f"command {var}" or "command " + var
	shellCommandPattern            *regexp.Regexp // shell=True in subprocess
	backtickCommandPattern         *regexp.Regexp // `command`

	// URL-based attack patterns
	windowOpenPattern              *regexp.Regexp // window.open(...) with untrusted URL
	locationAssignPattern          *regexp.Regexp // window.location = ... or location.href = ...

	// SQL injection patterns
	formatStringSQLPattern         *regexp.Regexp // f"SELECT ... WHERE id = {var}" or string concat
	stringConcatSQLPattern         *regexp.Regexp // "SELECT * FROM " + table + " WHERE " + ...

	// LLM/untrusted input indicators (for source identification)
	llmOutputPattern               *regexp.Regexp // llm., openai., response, model_output, agent.
	userInputPattern               *regexp.Regexp // user_input, request.*, user_output, prompt

	// Safe patterns (sanitization/escaping) - reduces confidence
	bleachCleanPattern             *regexp.Regexp // bleach.clean(...)
	markupsafeEscapePattern        *regexp.Regexp // markupsafe.escape or autoescaping
	htmlEscapeStringPattern        *regexp.Regexp // html.EscapeString(...)
	textContentPattern             *regexp.Regexp // textContent, innerText (safe alternatives)
	parameterizedQueryPattern      *regexp.Regexp // ? or %s in SQL with tuple args
	sanitizeInputPattern           *regexp.Regexp // sanitize, htmlsanitizer, dompurify
	quotedArgumentPattern          *regexp.Regexp // shlex.quote, argument list
	htmlTemplatePattern            *regexp.Regexp // html/template (auto-escaping in Go)
}

// NewOutputValidationFailuresDetector creates a new output validation failures detector
func NewOutputValidationFailuresDetector() *OutputValidationFailuresDetector {
	return &OutputValidationFailuresDetector{
		// Python execution
		pythonEvalPattern: regexp.MustCompile(`(?i)\beval\s*\(`),
		pythonExecPattern: regexp.MustCompile(`(?i)\bexec\s*\(`),
		pythonCompilePattern: regexp.MustCompile(`(?i)\bcompile\s*\(`),

		// OS/subprocess execution
		osSystemPattern: regexp.MustCompile(`(?i)\b(os|system)\.(system|popen|startProcess)\s*\(`),
		subprocessPattern: regexp.MustCompile(`(?i)\b(subprocess|sp)\.(run|Popen|popen|call|spawn)\s*\(`),

		// JavaScript execution
		jsEvalPattern: regexp.MustCompile(`(?i)\beval\s*\(`),
		jsFunctionConstructorPattern: regexp.MustCompile(`(?i)\b(new\s+)?Function\s*\(`),
		jsExecPattern: regexp.MustCompile(`(?i)\bexec\s*\(`),
		jsExecFilePattern: regexp.MustCompile(`(?i)\bexecFile\s*\(`),
		childProcessPattern: regexp.MustCompile(`(?i)require\s*\(\s*['"](child_process|cp)['"]\s*\)|import.*child_process`),

		// Go execution
		goExecPattern: regexp.MustCompile(`(?i)exec\.Command\s*\(`),

		// HTML injection (XSS)
		innerHTMLPattern: regexp.MustCompile(`\.innerHTML\s*=`),
		dangerouslySetInnerHTMLPattern: regexp.MustCompile(`dangerouslySetInnerHTML`),
		streamlitUnsafeHTMLPattern: regexp.MustCompile(`(?i)st\.markdown\s*\([^)]*unsafe_allow_html\s*=\s*True`),
		templateHTMLPattern: regexp.MustCompile(`(?i)template\.HTML\s*\(`),
		ipythonHTMLPattern: regexp.MustCompile(`(?i)IPython\.display\.HTML\s*\(|^[^#]*\bHTML\s*\(`),
		innerHTMLSetPattern: regexp.MustCompile(`(?i)\.innerHTML\s*=|setHTML\s*\(`),
		eventHandlerPattern: regexp.MustCompile(`(?i)(onerror|onload|onclick|onmouseover|onkeypress)\s*=`),
		javascriptURLPattern: regexp.MustCompile(`(?i)javascript:`),
		writeHTMLResponsePattern: regexp.MustCompile(`(?i)(\.Write|\.WriteString|fmt\.Fprintf)\s*\([^)]*response[^)]*\)`),
		formatStringHTMLPattern: regexp.MustCompile(`(?i)f["\'].*<[a-z]/|["\'].*<[a-z]/.*[{%]`),
		goTemplateUnsafePattern: regexp.MustCompile(`(?i)template\.(JS|URL|Attr|HTMLAttr)\s*\(`),

		// Command injection
		formatStringCommandPattern: regexp.MustCompile(`(?i)f["\'].*\$\{|f["\'].*\{.*\}|["\'].*\+.*var|os\.system|subprocess`),
		shellCommandPattern: regexp.MustCompile(`(?i)shell\s*=\s*True|shell\s*=\s*true`),
		backtickCommandPattern: regexp.MustCompile("(?i)`[^`]*\\$|`[^`]*\\{"),

		// URL-based attacks
		windowOpenPattern: regexp.MustCompile(`(?i)window\.open\s*\(`),
		locationAssignPattern: regexp.MustCompile(`(?i)window\.location\s*=|location\.href\s*=|location\.assign\s*\(`),

		// SQL injection
		formatStringSQLPattern: regexp.MustCompile(`(?i)f["\'].*(?:SELECT|INSERT|UPDATE|DELETE|DROP).*\{.*\}|f["\'].*WHERE.*\{`),
		stringConcatSQLPattern: regexp.MustCompile(`(?i)(?:SELECT|INSERT|UPDATE|DELETE|DROP).*["']\s*\+|WHERE.*["']\s*\+`),

		// LLM/untrusted input indicators (matches snake_case and camelCase)
		llmOutputPattern: regexp.MustCompile(`(?i)llm\.|openai\.|response|model_output|modelOutput|model[Rr]esponse|agent\.|agentResponse|completion\.|chatbot|ai_|llmResponse|generatedContent|generated[Cc]ontent`),
		userInputPattern: regexp.MustCompile(`(?i)user_|userInput|request\.|user_?output|userOutput|userContent|userParam|userSupplied|user[A-Z]|prompt|form\[|query\[|args\[|fromUser|untrustedInput|getFromApi|fromApi`),

		// Safe patterns
		bleachCleanPattern: regexp.MustCompile(`(?i)bleach\.clean\s*\(`),
		markupsafeEscapePattern: regexp.MustCompile(`(?i)markupsafe\.escape|autoescape\s*=\s*True|\|\s*safe`),
		htmlEscapeStringPattern: regexp.MustCompile(`(?i)html\.EscapeString\s*\(`),
		textContentPattern: regexp.MustCompile(`(?i)textContent|innerText|text\(\)`),
		parameterizedQueryPattern: regexp.MustCompile(`\?\s*,|\%s\s*,|\$\d+\s*,|execute\s*\([^)]*,\s*\[`),
		sanitizeInputPattern: regexp.MustCompile(`(?i)sanitize|htmlsanitizer|dompurify|escape|normalize`),
		quotedArgumentPattern: regexp.MustCompile(`(?i)shlex\.quote|subprocess.*\[\s*["']|exec\.Command\s*\([^)]*,\s*["\']`),
		htmlTemplatePattern: regexp.MustCompile(`(?i)html/template|html\.Template`),
	}
}

// Detect performs output validation failure detection
func (d *OutputValidationFailuresDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	var findings []patterns.Finding
	sourceStr := string(src)
	lines := strings.Split(sourceStr, "\n")
	lang := detectLanguage(filePath)

	// Check for dangerous code execution patterns
	findings = append(findings, d.checkCodeExecution(filePath, sourceStr, lines, lang)...)

	// Check for HTML/XSS injection
	findings = append(findings, d.checkHTMLInjection(filePath, sourceStr, lines, lang)...)

	// NOTE: Skip checkCommandInjection() to avoid duplicates with UnvalidatedExecEvalDetector
	// UnvalidatedExecEvalDetector provides higher-fidelity command injection detection
	// findings = append(findings, d.checkCommandInjection(filePath, sourceStr, lines, lang)...)

	// Check for SQL injection
	findings = append(findings, d.checkSQLInjection(filePath, sourceStr, lines, lang)...)

	// Apply context-aware confidence adjustments
	findings = d.applyContextAwareness(sourceStr, lines, findings)

	return findings, nil
}

// checkCodeExecution detects eval, exec, and similar dangerous functions
func (d *OutputValidationFailuresDetector) checkCodeExecution(filePath string, source string, lines []string, lang string) []patterns.Finding {
	var findings []patterns.Finding

	for i, line := range lines {
		// Skip comments and safe patterns
		if strings.HasPrefix(strings.TrimSpace(line), "#") || strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}

		// Check dangerous patterns based on language
		patternsList := []struct {
			pattern *regexp.Regexp
			severity string
			message string
			cwe string
		}{
			{d.pythonEvalPattern, "CRITICAL", "eval() used on untrusted input - allows arbitrary code execution", "CWE-94"},
			{d.pythonExecPattern, "CRITICAL", "exec() used on untrusted input - allows arbitrary code execution", "CWE-94"},
			{d.osSystemPattern, "CRITICAL", "os.system() with untrusted input - command injection vulnerability", "CWE-78"},
			{d.subprocessPattern, "CRITICAL", "subprocess call with untrusted input - potential command injection", "CWE-78"},
			{d.jsEvalPattern, "CRITICAL", "JavaScript eval() with untrusted input - code injection", "CWE-94"},
			{d.jsFunctionConstructorPattern, "HIGH", "Function constructor with untrusted input - potential code injection", "CWE-94"},
			{d.childProcessPattern, "HIGH", "child_process usage detected - validate inputs to prevent command injection", "CWE-78"},
			{d.goExecPattern, "HIGH", "exec.Command call detected - ensure arguments are properly escaped", "CWE-78"},
		}

		for _, p := range patternsList {
			if p.pattern.MatchString(line) {
				// Check if from untrusted source
				if d.isFromUntrustedSource(source, i) {
					// Check if properly sanitized
					if !d.hasSanitization(source, i) {
						finding := patterns.Finding{
							ID:          fmt.Sprintf("output_validation_%d", i+1),
							PatternID:   "output_validation_failures",
							Pattern:     "Output Validation Failures",
							File:        filePath,
							Confidence:  0.95,
							Line:        i + 1,
							Column:      1,
							Severity:    p.severity,
							Message:     p.message,
							Code:        strings.TrimSpace(line),
							CWE:         p.cwe,
							CVSS:        8.0,
						}
						findings = append(findings, finding)
					}
				}
			}
		}
	}

	return findings
}

// checkHTMLInjection detects XSS vulnerabilities (innerHTML, dangerouslySetInnerHTML, etc.)
func (d *OutputValidationFailuresDetector) checkHTMLInjection(filePath string, source string, lines []string, lang string) []patterns.Finding {
	var findings []patterns.Finding

	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "#") || strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}

		htmlPatternsList := []struct {
			pattern *regexp.Regexp
			severity string
			message string
			cwe string
		}{
			{d.innerHTMLPattern, "HIGH", "innerHTML assignment detected - susceptible to XSS if content not sanitized", "CWE-79"},
			{d.dangerouslySetInnerHTMLPattern, "HIGH", "dangerouslySetInnerHTML usage detected - requires validated input", "CWE-79"},
			{d.streamlitUnsafeHTMLPattern, "HIGH", "Streamlit markdown with unsafe_allow_html=True - content must be sanitized", "CWE-79"},
			{d.templateHTMLPattern, "HIGH", "template.HTML() call detected - marks content as safe, must validate input", "CWE-79"},
			{d.ipythonHTMLPattern, "HIGH", "IPython.display.HTML() with untrusted content - XSS vulnerability", "CWE-79"},
			{d.eventHandlerPattern, "HIGH", "Event handler injection detected - could enable XSS", "CWE-79"},
			{d.javascriptURLPattern, "MEDIUM", "javascript: URL scheme detected - validate URL schemes", "CWE-79"},
			{d.goTemplateUnsafePattern, "HIGH", "Unsafe template conversion detected - content must be validated", "CWE-79"},
			{d.windowOpenPattern, "HIGH", "window.open() with untrusted URL - could enable open redirect or javascript: URI attacks", "CWE-601"},
			{d.locationAssignPattern, "HIGH", "window.location assignment with untrusted URL - open redirect vulnerability", "CWE-601"},
		}

		for _, p := range htmlPatternsList {
			if p.pattern.MatchString(line) {
				// For URL-based patterns (window.open, location), only require untrusted source
				// For HTML patterns, require both HTML context and untrusted source
				isURLBased := p.cwe == "CWE-601"
				needsHTMLContext := !isURLBased

				if d.isFromUntrustedSource(source, i) {
					if !needsHTMLContext || d.isHTMLContext(source, i) {
						if !d.hasSanitization(source, i) {
							finding := patterns.Finding{
								ID:          fmt.Sprintf("output_validation_%d", i+1),
								PatternID:   "output_validation_failures",
								Pattern:     "Output Validation Failures",
								File:        filePath,
								Confidence:  0.90,
								Line:        i + 1,
								Column:      1,
								Severity:    p.severity,
								Message:     p.message,
								Code:        strings.TrimSpace(line),
								CWE:         p.cwe,
								CVSS:        7.5,
							}
							findings = append(findings, finding)
						}
					}
				}
			}
		}
	}

	return findings
}

// checkCommandInjection detects command injection vulnerabilities
func (d *OutputValidationFailuresDetector) checkCommandInjection(source string, lines []string, lang string) []patterns.Finding {
	var findings []patterns.Finding

	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "#") || strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}

		if d.formatStringCommandPattern.MatchString(line) || d.shellCommandPattern.MatchString(line) {
			if d.isFromUntrustedSource(source, i) && !d.isProperlyQuoted(source, i) {
				finding := patterns.Finding{
					PatternID:   "output_validation_failures",
					Confidence:  0.88,
					Line:        i + 1,
					Column:      1,
					Severity:    "CRITICAL",
					Message:     "Command injection risk - untrusted input in shell command execution",
					Code:        strings.TrimSpace(line),
					CWE:         "CWE-78",
					CVSS:        9.0,
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// checkSQLInjection detects SQL injection vulnerabilities
func (d *OutputValidationFailuresDetector) checkSQLInjection(filePath string, source string, lines []string, lang string) []patterns.Finding {
	var findings []patterns.Finding

	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "#") || strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}

		if d.formatStringSQLPattern.MatchString(line) || d.stringConcatSQLPattern.MatchString(line) {
			// Check if not using parameterized query
			if !d.parameterizedQueryPattern.MatchString(line) && d.isFromUntrustedSource(source, i) {
				finding := patterns.Finding{
					ID:          fmt.Sprintf("output_validation_%d", i+1),
					PatternID:   "output_validation_failures",
					Pattern:     "Output Validation Failures",
					File:        filePath,
					Confidence:  0.92,
					Line:        i + 1,
					Column:      1,
					Severity:    "CRITICAL",
					Message:     "SQL injection risk - untrusted input in query without parameterization",
					Code:        strings.TrimSpace(line),
					CWE:         "CWE-89",
					CVSS:        9.1,
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// isFromUntrustedSource checks if line involves untrusted data (LLM, user input, API response)
func (d *OutputValidationFailuresDetector) isFromUntrustedSource(source string, lineIdx int) bool {
	lines := strings.Split(source, "\n")
	if lineIdx < 0 || lineIdx >= len(lines) {
		return false
	}

	line := strings.ToLower(lines[lineIdx])

	// Check if line references LLM or user input
	if d.llmOutputPattern.MatchString(line) || d.userInputPattern.MatchString(line) {
		return true
	}

	// Look at previous 5 lines for variable assignment from untrusted source
	for j := lineIdx - 1; j >= 0 && j > lineIdx-5; j-- {
		prevLine := strings.ToLower(lines[j])
		if d.llmOutputPattern.MatchString(prevLine) || d.userInputPattern.MatchString(prevLine) {
			// Check if same variable is used on current line
			return true
		}
	}

	return false
}

// hasSanitization checks if content was sanitized/escaped before use
func (d *OutputValidationFailuresDetector) hasSanitization(source string, lineIdx int) bool {
	lines := strings.Split(source, "\n")
	lowerSource := strings.ToLower(source)

	if lineIdx < 0 || lineIdx >= len(lines) {
		return false
	}

	line := strings.ToLower(lines[lineIdx])

	// Check current line for sanitization
	if d.bleachCleanPattern.MatchString(line) ||
	   d.markupsafeEscapePattern.MatchString(line) ||
	   d.htmlEscapeStringPattern.MatchString(line) ||
	   d.sanitizeInputPattern.MatchString(line) {
		return true
	}

	// Check previous 10 lines for sanitization of the variable
	for j := lineIdx - 1; j >= 0 && j > lineIdx-10; j-- {
		prevLine := strings.ToLower(lines[j])
		if d.bleachCleanPattern.MatchString(prevLine) ||
		   d.markupsafeEscapePattern.MatchString(prevLine) ||
		   d.htmlEscapeStringPattern.MatchString(prevLine) ||
		   d.sanitizeInputPattern.MatchString(prevLine) {
			return true
		}
	}

	// Check if using safe APIs
	if d.textContentPattern.MatchString(line) || // textContent is safe
	   d.parameterizedQueryPattern.MatchString(line) || // Parameterized SQL is safe
	   d.htmlTemplatePattern.MatchString(lowerSource) { // html/template auto-escapes
		return true
	}

	return false
}

// isHTMLContext checks if line is in an HTML rendering context
func (d *OutputValidationFailuresDetector) isHTMLContext(source string, lineIdx int) bool {
	lines := strings.Split(source, "\n")
	if lineIdx < 0 || lineIdx >= len(lines) {
		return false
	}

	line := strings.ToLower(lines[lineIdx])

	// Direct HTML indicators
	htmlIndicators := []string{
		"html", "render", "display", "write", "response",
		"template", "markdown", "innerhtml", "displayhtml",
		"http.ResponseWriter", "fmt.Fprintf",
	}

	for _, indicator := range htmlIndicators {
		if strings.Contains(line, indicator) {
			return true
		}
	}

	return false
}

// isProperlyQuoted checks if arguments are properly quoted/escaped for shell
func (d *OutputValidationFailuresDetector) isProperlyQuoted(source string, lineIdx int) bool {
	lines := strings.Split(source, "\n")
	if lineIdx < 0 || lineIdx >= len(lines) {
		return false
	}

	line := strings.ToLower(lines[lineIdx])

	// Safe patterns: using argument lists instead of shell strings
	if d.quotedArgumentPattern.MatchString(line) {
		return true
	}

	// Check if using safe subprocess (with list args)
	if strings.Contains(line, "subprocess.run([") || strings.Contains(line, "exec.Command(") {
		return true
	}

	return false
}

// applyContextAwareness adjusts confidence based on code context
func (d *OutputValidationFailuresDetector) applyContextAwareness(source string, lines []string, findings []patterns.Finding) []patterns.Finding {
	for i := range findings {
		lineIdx := findings[i].Line - 1
		if lineIdx < 0 || lineIdx >= len(lines) {
			continue
		}

		// Reduce confidence if in test code
		if strings.Contains(strings.ToLower(findings[i].Code), "test") {
			findings[i].Confidence *= 0.85
		}

		// Reduce confidence if has # nosec comment
		if lineIdx+1 < len(lines) && strings.Contains(lines[lineIdx+1], "nosec") {
			findings[i].Confidence *= 0.70
		}

		// Keep high confidence for LLM output patterns
		if d.llmOutputPattern.MatchString(strings.ToLower(findings[i].Code)) {
			findings[i].Confidence = 0.95
		}
	}

	return findings
}

// detectLanguage determines the programming language from file path
func detectLanguage(filePath string) string {
	if strings.HasSuffix(filePath, ".py") {
		return "python"
	}
	if strings.HasSuffix(filePath, ".js") || strings.HasSuffix(filePath, ".jsx") || strings.HasSuffix(filePath, ".ts") || strings.HasSuffix(filePath, ".tsx") {
		return "javascript"
	}
	if strings.HasSuffix(filePath, ".go") {
		return "go"
	}
	if strings.HasSuffix(filePath, ".java") {
		return "java"
	}
	if strings.HasSuffix(filePath, ".cs") {
		return "csharp"
	}
	if strings.HasSuffix(filePath, ".php") {
		return "php"
	}
	return "unknown"
}

// Name returns detector name
func (d *OutputValidationFailuresDetector) Name() string {
	return "output_validation_failures"
}

// GetPatternID returns the canonical detector ID (implements Detector interface)
func (d *OutputValidationFailuresDetector) GetPatternID() string {
	return metadata.ID_OUTPUT_VALIDATION
}


// GetPattern returns the pattern metadata
func (d *OutputValidationFailuresDetector) GetPattern() patterns.Pattern {
	return patterns.Pattern{
		ID:          "output_validation_failures",
		Name:        "Output Validation Failures",
		Version:     "1.0",
		Category:    "injection",
		Severity:    "CRITICAL",
		CVSS:        9.0,
		CWEIDs:      []string{"CWE-79", "CWE-94"},
		OWASP:       "A03:2021 Injection",
		Description: "Detects unvalidated LLM outputs that could lead to injection attacks",
	}
}

// GetConfidence returns the confidence score for this detector
func (d *OutputValidationFailuresDetector) GetConfidence() float32 {
	return 0.78
}
