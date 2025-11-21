package detectors

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
	"github.com/inkog-io/inkog/action/pkg/patterns/metadata"
)

// SQLInjectionViaLLMDetector detects SQL injection vulnerabilities where LLM-generated queries
// are executed directly against databases without sanitization.
//
// This pattern detects:
// 1. Known vulnerable LLM chains (GraphCypherQAChain, SQLDatabaseChain)
// 2. Raw query execution with user-controlled or LLM-generated input
// 3. Data flow from LLM output to database execution
// 4. Missing safeguards (parameterization, safe flags, validation)
//
// Real CVEs:
// - CVE-2024-8309: LangChain GraphCypherQAChain Cypher injection
// - CVE-2024-7042: LangChain drop all nodes attack
// - CVE-2025-29189: Flowise tableName SQL injection
// - CVE-2025-0185: Dify Pandas query injection
type SQLInjectionViaLLMDetector struct {
	pattern patterns.Pattern
}

// NewSQLInjectionViaLLMDetector creates a new SQL injection via LLM detector
func NewSQLInjectionViaLLMDetector() *SQLInjectionViaLLMDetector {
	pattern := patterns.Pattern{
		ID:       "sql_injection_via_llm",
		Name:     "SQL Injection via LLM",
		Version:  "1.0",
		Category: "injection",
		Severity: "CRITICAL",
		CVSS:     9.1,
		CWEIDs:   []string{"CWE-89", "CWE-74"},
		OWASP:    "A03:2021 Injection",
		Description: "LLM-generated SQL/Cypher queries executed directly without sanitization allow database injection. " +
			"Attackers can manipulate LLM prompts to generate DROP/DELETE queries, exfiltrate data, or cause DoS.",
		Remediation: "Use parameterized queries, prepared statements, or validate/sanitize LLM output. " +
			"For LangChain: use allow_dangerous_requests=False, implement query whitelists.",
		FinancialImpact: struct {
			Severity    string
			Description string
			RiskPerYear float32
		}{
			Severity:    "CRITICAL",
			Description: "Database compromise, data exfiltration, multi-tenant data breach, table deletion attacks",
			RiskPerYear: 5000000, // $5M+ for data exfiltration/loss
		},
	}

	return &SQLInjectionViaLLMDetector{
		pattern: pattern,
	}
}

// Name returns the detector name
func (d *SQLInjectionViaLLMDetector) Name() string {
	return "sql_injection_via_llm"
}

// GetPatternID returns the canonical detector ID (implements Detector interface)
func (d *SQLInjectionViaLLMDetector) GetPatternID() string {
	return metadata.ID_SQL_INJECTION_LLM
}


// GetPattern returns the pattern metadata
func (d *SQLInjectionViaLLMDetector) GetPattern() patterns.Pattern {
	return d.pattern
}

// Detect analyzes code for SQL injection via LLM patterns
func (d *SQLInjectionViaLLMDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	var findings []patterns.Finding

	// Skip unsupported files
	if !isSupportedFile(filePath) {
		return findings, nil
	}

	sourceStr := string(src)
	lines := strings.Split(sourceStr, "\n")

	// Detect Python patterns
	if isPythonFile(filePath) {
		d.detectPythonSQLInjection(lines, filePath, sourceStr, &findings)
	}

	// Detect JavaScript patterns
	if isJavaScriptFile(filePath) {
		d.detectJavaScriptSQLInjection(lines, filePath, sourceStr, &findings)
	}

	return findings, nil
}

// detectPythonSQLInjection detects Python SQL injection via LLM patterns
func (d *SQLInjectionViaLLMDetector) detectPythonSQLInjection(
	lines []string,
	filePath string,
	sourceStr string,
	findings *[]patterns.Finding,
) {
	// Pattern 1: Known vulnerable LangChain chains (including aliased imports and factory methods)
	graphCypherPattern := regexp.MustCompile(`(?i)GraphCypherQAChain\s*\(`)
	sqlDatabasePattern := regexp.MustCompile(`(?i)SQLDatabaseChain\s*\(`)
	sqlDatabaseFactoryPattern := regexp.MustCompile(`(?i)SQLDatabaseChain\s*\.\s*from_llm\s*\(`)
	graphCypherImportPattern := regexp.MustCompile(`(?i)from\s+langchain.*import.*GraphCypherQAChain`)
	sqlDatabaseImportPattern := regexp.MustCompile(`(?i)from\s+langchain.*import.*SQLDatabaseChain`)

	// Pattern 2: Known vulnerable Dify/Vanna patterns
	vanaPattern := regexp.MustCompile(`(?i)get_training_plan_generic\s*\(`)
	pandasQueryPattern := regexp.MustCompile(`(?i)df\.query\s*\([^)]*{`)

	// Pattern 3: Raw query execution with string formatting (f-strings, format, %)
	rawExecutePattern := regexp.MustCompile(`(?i)(cursor|db|connection)\.(execute|exec|query|QueryRow)\s*\(\s*f["']|\.run\(\s*f["']`)
	formatExecutePattern := regexp.MustCompile(`(?i)(cursor|db|connection)\.(execute|exec|query)\s*\([^)]*\.format\(`)

	// Pattern 3b: Simple execute with variable (for LLM-generated variables)
	executeWithVarPattern := regexp.MustCompile(`(?i)(cursor|db|connection|execute)\.(execute|exec|query|run)\s*\(\s*(\w+)`)

	// Pattern 4: LLM API calls that might generate queries
	llmGeneratePattern := regexp.MustCompile(`(?i)(openai|anthropic|claude|gpt|llm)\.(ChatCompletion|Completion|chat|generate)\.create`)
	openaiGeneratePattern := regexp.MustCompile(`(?i)openai.*\.generate|openai_api\.generate|llm\.(generate|invoke|call)`)

	// Pattern 5: String concatenation with user input or LLM variables
	concatPattern := regexp.MustCompile(`\+\s*(?:user_|request\.|input|sql|query|prompt)`)

	// Pattern 6: Parameterized queries (safe indicator)
	parameterizedPattern := regexp.MustCompile(`(?i)(WHERE\s+\w+\s*=\s*(%s|\$\d+|[?:]|{[0-9]})|\?|\$\d+|:[a-zA-Z_]\w*)`)

	// Pattern 7: Safe flags (LangChain v0.2.19+)
	safeFlagPattern := regexp.MustCompile(`(?i)allow_dangerous_requests\s*=\s*(False|false)`)

	// Build context map: Track vulnerable chains and their usage
	vulnerableChains := make(map[string]int) // chainName -> lineNumber
	llmOutputVars := make(map[string]bool)   // variableName -> comes from LLM
	chainAliases := make(map[string]bool)    // Track aliased vulnerable chains
	parameterizedQueries := make(map[int]bool) // lineNumber -> isParameterized
	hasSafeFlag := false

	// First pass: Identify vulnerable patterns, context, and build variable flow map
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}

		// Check for safe flags
		if safeFlagPattern.MatchString(line) {
			hasSafeFlag = true
		}

		// Track aliased imports of vulnerable chains
		if graphCypherImportPattern.MatchString(line) {
			// Extract alias if present: from langchain import GraphCypherQAChain as GC
			aliasMatch := regexp.MustCompile(`(?i)GraphCypherQAChain\s+as\s+(\w+)`).FindStringSubmatch(line)
			if len(aliasMatch) > 1 {
				chainAliases[aliasMatch[1]] = true
			} else {
				chainAliases["GraphCypherQAChain"] = true
			}
		}
		if sqlDatabaseImportPattern.MatchString(line) {
			aliasMatch := regexp.MustCompile(`(?i)SQLDatabaseChain\s+as\s+(\w+)`).FindStringSubmatch(line)
			if len(aliasMatch) > 1 {
				chainAliases[aliasMatch[1]] = true
			} else {
				chainAliases["SQLDatabaseChain"] = true
			}
		}

		// Track vulnerable chain instantiations
		if graphCypherPattern.MatchString(line) {
			vulnerableChains["GraphCypherQAChain"] = i
		}
		if sqlDatabasePattern.MatchString(line) {
			vulnerableChains["SQLDatabaseChain"] = i
		}
		if sqlDatabaseFactoryPattern.MatchString(line) {
			vulnerableChains["SQLDatabaseChain.from_llm"] = i
		}

		// Track aliased chain instantiations
		// First check if this line is defining a chain variable with an alias
		for alias := range chainAliases {
			// Pattern: chain = GC(...) where GC is an aliased class
			if regexp.MustCompile(`(?i)[\w_]+\s*=\s*` + regexp.QuoteMeta(alias) + `\s*\(`).MatchString(line) {
				vulnerableChains[alias] = i
			}
		}

		// Track LLM output variables
		if llmGeneratePattern.MatchString(line) || openaiGeneratePattern.MatchString(line) {
			// Extract variable name if assignment: var = openai_api.generate(...)
			varMatch := regexp.MustCompile(`(\w+)\s*=\s*`).FindStringSubmatch(line)
			if len(varMatch) > 1 {
				llmOutputVars[varMatch[1]] = true
			}
		}

		// Check for parameterized queries (safe)
		if parameterizedPattern.MatchString(line) {
			parameterizedQueries[i] = true
		}
	}

	// Second pass: Report vulnerabilities with context-aware confidence
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}

		// Skip if parameterized (safe)
		if parameterizedQueries[i] {
			continue
		}

		// Check 1: Known vulnerable chain with .run() method or instantiation
		// Check both direct patterns and chains that were detected as vulnerable in first pass
		isVulnerableChain := graphCypherPattern.MatchString(line) || sqlDatabasePattern.MatchString(line) || sqlDatabaseFactoryPattern.MatchString(line)

		// Also check for aliased chain instantiations
		var foundChainName string
		if !isVulnerableChain {
			for alias := range chainAliases {
				if regexp.MustCompile(`(?i)[\w_]+\s*=\s*` + regexp.QuoteMeta(alias) + `\s*\(`).MatchString(line) {
					isVulnerableChain = true
					if strings.Contains(alias, "SQLDatabase") {
						foundChainName = "SQLDatabaseChain"
					} else {
						foundChainName = "GraphCypherQAChain"
					}
					break
				}
			}
		}

		if isVulnerableChain {
			chainName := foundChainName
			if chainName == "" {
				chainName = "GraphCypherQAChain"
				if sqlDatabasePattern.MatchString(line) || sqlDatabaseFactoryPattern.MatchString(line) {
					chainName = "SQLDatabaseChain"
				}
			}

			// Check if safe flag is set
			if hasSafeFlag {
				continue // Skip if safe default is configured
			}

			// Look ahead for .run() calls in next 10 lines
			foundRunCall := false
			for j := i; j < len(lines) && j < i+10; j++ {
				if strings.Contains(lines[j], ".run(") {
					foundRunCall = true
					// Check if .run argument is user-controlled
					runLine := lines[j]
					isUserControlled := d.isUserControlledInput(runLine, llmOutputVars, lines, j)

					confidence := d.calculatePythonConfidence(
						chainName,
						isUserControlled,
						hasSafeFlag,
						sourceStr,
					)

					if confidence >= 0.70 {
						finding := patterns.Finding{
							ID:        fmt.Sprintf("sql_injection_via_llm_chain_%d_%s", j, filePath),
							PatternID: d.pattern.ID,
							Pattern:   d.pattern.Name,
							File:      filePath,
							Line:      j + 1,
							Column:    len(runLine) - len(strings.TrimSpace(runLine)) + 1,
							Message:   fmt.Sprintf("Vulnerable LangChain %s with user/LLM input: %s", chainName, d.getConfidenceReason(confidence)),
							Code:      runLine,
							Severity:  d.determineSeverity(isUserControlled, hasSafeFlag),
							Confidence: confidence,
							CWE:       "CWE-89",
							CVSS:      9.1,
							OWASP:     "A03:2021",
							FinancialRisk: "Database compromise, data exfiltration, table deletion",
						}
						*findings = append(*findings, finding)
					}
					break
				}
			}

			// If no .run() found in lookahead, still flag as CRITICAL because chains are inherently risky
			if !foundRunCall {
				confidence := d.calculatePythonConfidence(
					chainName,
					true,
					hasSafeFlag,
					sourceStr,
				)

				if confidence >= 0.70 {
					finding := patterns.Finding{
						ID:        fmt.Sprintf("sql_injection_via_llm_chain_%d_%s", i, filePath),
						PatternID: d.pattern.ID,
						Pattern:   d.pattern.Name,
						File:      filePath,
						Line:      i + 1,
						Column:    len(line) - len(trimmed) + 1,
						Message:   fmt.Sprintf("Vulnerable LangChain %s instantiation without safe flags", chainName),
						Code:      line,
						Severity:  d.determineSeverity(true, hasSafeFlag),
						Confidence: confidence,
						CWE:       "CWE-89",
						CVSS:      9.1,
						OWASP:     "A03:2021",
						FinancialRisk: "Database compromise, data exfiltration, table deletion",
					}
					*findings = append(*findings, finding)
				}
			}
		}

		// Check 2: Raw query execution with string formatting
		if (rawExecutePattern.MatchString(line) || formatExecutePattern.MatchString(line)) && !parameterizedQueries[i] {
			// Extract what's being executed
			execMatch := regexp.MustCompile(`(?i)\.execute\(([^)]+)\)|\.run\(([^)]+)\)|\.query\(([^)]+)\)`).FindStringSubmatch(line)
			if len(execMatch) > 0 {
				executed := execMatch[1]
				if executed == "" {
					executed = execMatch[2]
				}
				if executed == "" {
					executed = execMatch[3]
				}

				// Check if it contains f-string or LLM variable
				isFString := strings.Contains(executed, "f\"") || strings.Contains(executed, "f'")
				isLLMVar := d.containsLLMVariable(executed, llmOutputVars, lines, i)

				if isFString || isLLMVar {
					var confidence float32 = 0.75
					if isLLMVar {
						confidence = 0.85
					}

					finding := patterns.Finding{
						ID:        fmt.Sprintf("sql_injection_via_llm_raw_exec_%d_%s", i, filePath),
						PatternID: d.pattern.ID,
						Pattern:   d.pattern.Name,
						File:      filePath,
						Line:      i + 1,
						Column:    len(line) - len(trimmed) + 1,
						Message:   "Raw SQL execution with user input or LLM output - SQL injection vulnerability",
						Code:      line,
						Severity:  "CRITICAL",
						Confidence: confidence,
						CWE:       "CWE-89",
						CVSS:      9.1,
						OWASP:     "A03:2021",
						FinancialRisk: "Database compromise, data exfiltration",
					}
					*findings = append(*findings, finding)
				}
			}
		}

		// Check 2b: Execute with variable (including LLM-generated)
		if executeWithVarPattern.MatchString(line) && !parameterizedQueries[i] {
			// Extract variable name: cursor.execute(sql)
			varMatch := regexp.MustCompile(`\.(?:execute|exec|query|run)\s*\(\s*(\w+)`).FindStringSubmatch(line)
			if len(varMatch) > 1 {
				varName := varMatch[1]
				// Check if this variable comes from LLM or concatenation
				if llmOutputVars[varName] {
					finding := patterns.Finding{
						ID:        fmt.Sprintf("sql_injection_via_llm_exec_var_%d_%s", i, filePath),
						PatternID: d.pattern.ID,
						Pattern:   d.pattern.Name,
						File:      filePath,
						Line:      i + 1,
						Column:    len(line) - len(trimmed) + 1,
						Message:   fmt.Sprintf("SQL execution with LLM-generated variable '%s' - SQL injection vulnerability", varName),
						Code:      line,
						Severity:  "CRITICAL",
						Confidence: 0.85,
						CWE:       "CWE-89",
						CVSS:      9.1,
						OWASP:     "A03:2021",
						FinancialRisk: "Database compromise, data exfiltration",
					}
					*findings = append(*findings, finding)
				}
			}
		}

		// Check 2c: Indirect function calls with LLM variables
		// Detect: func_name(llm_var) where func_name might execute SQL
		for llmVar := range llmOutputVars {
			// Look for patterns like: run_query(sql) or execute_query(sql)
			if regexp.MustCompile(`(?i)(?:run|execute|query|call)\s*\(\s*` + regexp.QuoteMeta(llmVar)).MatchString(line) {
				finding := patterns.Finding{
					ID:        fmt.Sprintf("sql_injection_via_llm_indirect_call_%d_%s", i, filePath),
					PatternID: d.pattern.ID,
					Pattern:   d.pattern.Name,
					File:      filePath,
					Line:      i + 1,
					Column:    len(line) - len(trimmed) + 1,
					Message:   fmt.Sprintf("Indirect SQL execution via function call with LLM-generated variable '%s'", llmVar),
					Code:      line,
					Severity:  "CRITICAL",
					Confidence: 0.80,
					CWE:       "CWE-89",
					CVSS:      9.1,
					OWASP:     "A03:2021",
					FinancialRisk: "Database compromise, data exfiltration",
				}
				*findings = append(*findings, finding)
			}
		}

		// Check 3: String concatenation with SQL and user input
		if concatPattern.MatchString(line) && !parameterizedQueries[i] {
			// Look for patterns like: "SELECT * FROM users WHERE name = '" + variable + "'"
			if strings.Contains(strings.ToUpper(line), "SELECT") || strings.Contains(strings.ToUpper(line), "DELETE") ||
				strings.Contains(strings.ToUpper(line), "INSERT") || strings.Contains(strings.ToUpper(line), "UPDATE") {
				finding := patterns.Finding{
					ID:        fmt.Sprintf("sql_injection_via_llm_concat_%d_%s", i, filePath),
					PatternID: d.pattern.ID,
					Pattern:   d.pattern.Name,
					File:      filePath,
					Line:      i + 1,
					Column:    len(line) - len(trimmed) + 1,
					Message:   "SQL query constructed via string concatenation - SQL injection vulnerability",
					Code:      line,
					Severity:  "CRITICAL",
					Confidence: 0.78,
					CWE:       "CWE-89",
					CVSS:      9.1,
					OWASP:     "A03:2021",
					FinancialRisk: "Database compromise, data exfiltration",
				}
				*findings = append(*findings, finding)
			}
		}

		// Check 4: Dify/Vanna patterns
		if vanaPattern.MatchString(line) {
			// Check for unsanitized DataFrame
			if strings.Contains(sourceStr, "pd.DataFrame(user") || strings.Contains(sourceStr, "pd.DataFrame(request") {
				finding := patterns.Finding{
					ID:        fmt.Sprintf("sql_injection_via_llm_vanna_%d_%s", i, filePath),
					PatternID: d.pattern.ID,
					Pattern:   d.pattern.Name,
					File:      filePath,
					Line:      i + 1,
					Column:    len(line) - len(trimmed) + 1,
					Message:   "Dify Vanna get_training_plan_generic() with unsanitized DataFrame - CVE-2025-0185",
					Code:      line,
					Severity:  "CRITICAL",
					Confidence: 0.82,
					CWE:       "CWE-89",
					CVSS:      9.1,
					OWASP:     "A03:2021",
					FinancialRisk: "Pandas query injection, possible RCE",
				}
				*findings = append(*findings, finding)
			}
		}

		// Check 5: Pandas query injection with dict/format
		if pandasQueryPattern.MatchString(line) {
			finding := patterns.Finding{
				ID:        fmt.Sprintf("sql_injection_via_llm_pandas_%d_%s", i, filePath),
				PatternID: d.pattern.ID,
				Pattern:   d.pattern.Name,
				File:      filePath,
				Line:      i + 1,
				Column:    len(line) - len(trimmed) + 1,
				Message:   "Pandas DataFrame.query() with format/dict injection - unsafe evaluation",
				Code:      line,
				Severity:  "HIGH",
				Confidence: 0.78,
				CWE:       "CWE-89",
				CVSS:      8.0,
				OWASP:     "A03:2021",
				FinancialRisk: "Query injection, potential code execution",
			}
			*findings = append(*findings, finding)
		}
	}
}

// detectJavaScriptSQLInjection detects JavaScript SQL injection via LLM patterns
func (d *SQLInjectionViaLLMDetector) detectJavaScriptSQLInjection(
	lines []string,
	filePath string,
	sourceStr string,
	findings *[]patterns.Finding,
) {
	// Pattern 1: Template literal with variable (string interpolation in query)
	templateLiteralPattern := regexp.MustCompile(`SELECT.*FROM\s+\$\{|DELETE.*FROM\s+\$\{|DROP\s+\$\{|INSERT.*INTO\s+\$\{`)

	// Pattern 2: String concatenation in query construction
	// Detect: "SELECT ... " + variable + "..." or similar patterns
	concatSQLPattern := regexp.MustCompile(`(?i)['"].*(?:SELECT|DELETE|INSERT|UPDATE|DROP).*['"][^;]*\+\s*\w+`)

	// Pattern 3: Query assignment with concatenation
	// Detect: const query = '...' + variable + '...'
	queryAssignConcatPattern := regexp.MustCompile(`(?i)(?:const|var|let)\s+\w+\s*=\s*['"][^'"]*['"].*\+`)

	// Pattern 4: db.query() or similar with concatenated/template literal argument
	dbQueryPattern := regexp.MustCompile(`(?i)(?:db|client|connection)\.(query|execute|run)\s*\([^)]*\+`)

	// Pattern 5: Flowise-specific tableName injection (CVE-2025-29189)
	flowisePattern := regexp.MustCompile(`(?i)(req\.body\.|request\.)tableName|const\s+tableName\s*=\s*req`)

	// Build variable map for JavaScript (LLM outputs)
	jsLLMVars := make(map[string]bool)
	llmApiPattern := regexp.MustCompile(`(?i)openai|anthropic|claude|gpt|llm.*generate|api.*generate`)

	// First pass: Track LLM variables
	for _, line := range lines {
		if llmApiPattern.MatchString(line) {
			// Extract variable: const answer = openai_api.generate(...)
			varMatch := regexp.MustCompile(`(?:const|var|let)\s+(\w+)\s*=\s*`).FindStringSubmatch(line)
			if len(varMatch) > 1 {
				jsLLMVars[varMatch[1]] = true
			}
		}
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
			continue
		}

		// Check for template literal SQL injection
		if templateLiteralPattern.MatchString(line) {
			finding := patterns.Finding{
				ID:        fmt.Sprintf("sql_injection_via_llm_js_template_%d_%s", i, filePath),
				PatternID: d.pattern.ID,
				Pattern:   d.pattern.Name,
				File:      filePath,
				Line:      i + 1,
				Column:    len(line) - len(trimmed) + 1,
				Message:   "JavaScript template literal SQL injection - variable interpolated in query",
				Code:      line,
				Severity:  "CRITICAL",
				Confidence: 0.88,
				CWE:       "CWE-89",
				CVSS:      9.1,
				OWASP:     "A03:2021",
				FinancialRisk: "Database compromise",
			}
			*findings = append(*findings, finding)
		}

		// Check for string concatenation SQL patterns
		if concatSQLPattern.MatchString(line) {
			finding := patterns.Finding{
				ID:        fmt.Sprintf("sql_injection_via_llm_js_concat_%d_%s", i, filePath),
				PatternID: d.pattern.ID,
				Pattern:   d.pattern.Name,
				File:      filePath,
				Line:      i + 1,
				Column:    len(line) - len(trimmed) + 1,
				Message:   "JavaScript SQL query constructed via string concatenation - SQL injection",
				Code:      line,
				Severity:  "CRITICAL",
				Confidence: 0.82,
				CWE:       "CWE-89",
				CVSS:      9.0,
				OWASP:     "A03:2021",
				FinancialRisk: "Database compromise",
			}
			*findings = append(*findings, finding)
		}

		// Check for query assignment with concatenation
		if queryAssignConcatPattern.MatchString(line) {
			// Look ahead to see if this query variable is used in db.query()
			for j := i; j < len(lines) && j < i+10; j++ {
				if regexp.MustCompile(`(?:db|client)\.(query|execute)\s*\(`).MatchString(lines[j]) {
					// Extract variable name from assignment
					varMatch := regexp.MustCompile(`(?:const|var|let)\s+(\w+)\s*=\s*`).FindStringSubmatch(line)
					if len(varMatch) > 1 {
						varName := varMatch[1]
						// Check if the query() call uses this variable
						if strings.Contains(lines[j], varName) {
							finding := patterns.Finding{
								ID:        fmt.Sprintf("sql_injection_via_llm_js_query_concat_%d_%s", j, filePath),
								PatternID: d.pattern.ID,
								Pattern:   d.pattern.Name,
								File:      filePath,
								Line:      j + 1,
								Column:    len(lines[j]) - len(strings.TrimSpace(lines[j])) + 1,
								Message:   "JavaScript query variable constructed via string concatenation - SQL injection",
								Code:      lines[j],
								Severity:  "CRITICAL",
								Confidence: 0.85,
								CWE:       "CWE-89",
								CVSS:      9.1,
								OWASP:     "A03:2021",
								FinancialRisk: "Database compromise",
							}
							*findings = append(*findings, finding)
						}
					}
				}
			}
		}

		// Check for db.query() with concatenation
		if dbQueryPattern.MatchString(line) {
			finding := patterns.Finding{
				ID:        fmt.Sprintf("sql_injection_via_llm_js_dbquery_%d_%s", i, filePath),
				PatternID: d.pattern.ID,
				Pattern:   d.pattern.Name,
				File:      filePath,
				Line:      i + 1,
				Column:    len(line) - len(trimmed) + 1,
				Message:   "JavaScript db.query() with string concatenation - SQL injection",
				Code:      line,
				Severity:  "CRITICAL",
				Confidence: 0.80,
				CWE:       "CWE-89",
				CVSS:      9.0,
				OWASP:     "A03:2021",
				FinancialRisk: "Database compromise",
			}
			*findings = append(*findings, finding)
		}

		// Check for Flowise tableName injection (CVE-2025-29189)
		if flowisePattern.MatchString(line) {
			// Look ahead for query construction
			for j := i; j < len(lines) && j < i+5; j++ {
				if strings.Contains(lines[j], "query") || strings.Contains(lines[j], "execute") {
					if strings.Contains(lines[j], "tableName") {
						finding := patterns.Finding{
							ID:        fmt.Sprintf("sql_injection_via_llm_flowise_%d_%s", j, filePath),
							PatternID: d.pattern.ID,
							Pattern:   d.pattern.Name,
							File:      filePath,
							Line:      j + 1,
							Column:    len(lines[j]) - len(strings.TrimSpace(lines[j])) + 1,
							Message:   "Flowise tableName parameter SQL injection (CVE-2025-29189)",
							Code:      lines[j],
							Severity:  "CRITICAL",
							Confidence: 0.91,
							CWE:       "CWE-89",
							CVSS:      9.1,
							OWASP:     "A03:2021",
							FinancialRisk: "Database compromise via unsanitized tableName",
						}
						*findings = append(*findings, finding)
					}
				}
			}
		}
	}
}

// calculatePythonConfidence calculates confidence based on context
func (d *SQLInjectionViaLLMDetector) calculatePythonConfidence(
	chainName string,
	isUserControlled bool,
	hasSafeFlag bool,
	sourceStr string,
) float32 {
	confidence := float32(0.60) // Base: uncertain without context

	// +0.25 for known vulnerable class
	confidence += 0.25

	// +0.15 if input is user-controlled
	if isUserControlled {
		confidence += 0.15
	}

	// +0.10 if LLM is used in context
	if strings.Contains(sourceStr, "openai") || strings.Contains(sourceStr, "anthropic") ||
		strings.Contains(sourceStr, "gpt") || strings.Contains(sourceStr, "claude") {
		confidence += 0.10
	}

	// -0.25 if safe flag is present
	if hasSafeFlag {
		confidence -= 0.25
	}

	// Cap at reasonable bounds
	if confidence > 0.95 {
		confidence = 0.95
	}
	if confidence < 0.60 {
		confidence = 0.60
	}

	return confidence
}

// determineSeverity determines severity based on context
func (d *SQLInjectionViaLLMDetector) determineSeverity(isUserControlled bool, hasSafeFlag bool) string {
	if hasSafeFlag {
		return "MEDIUM" // Mitigated by safe flag
	}
	// Known vulnerable chains (GraphCypherQAChain, SQLDatabaseChain) are CRITICAL by design
	// because they're specifically designed to execute LLM-generated queries
	return "CRITICAL"
}

// isUserControlledInput checks if input comes from untrusted source with interprocedural analysis
func (d *SQLInjectionViaLLMDetector) isUserControlledInput(line string, llmOutputVars map[string]bool, lines []string, currentLineIdx int) bool {
	// Check for direct LLM variables
	for varName := range llmOutputVars {
		if strings.Contains(line, varName) {
			return true
		}
	}

	// Check for request/user input patterns
	untrustedSources := []string{
		"user_input", "request.", "prompt", "question", "query",
		"user_data", "user_prompt", "input", "params",
	}

	for _, source := range untrustedSources {
		if strings.Contains(strings.ToLower(line), strings.ToLower(source)) {
			return true
		}
	}

	// Interprocedural analysis: check if line uses a variable that was assigned from LLM data
	// Extract variable names from the line
	varNames := d.extractVariableNames(line)
	for varName := range varNames {
		// Look back up to 20 lines to find where this variable was assigned
		isFromLLM := d.traceVariableSource(varName, lines, currentLineIdx, llmOutputVars)
		if isFromLLM {
			return true
		}
	}

	return false
}

// extractVariableNames extracts all variable names from a line that might be used in expressions
func (d *SQLInjectionViaLLMDetector) extractVariableNames(line string) map[string]bool {
	result := make(map[string]bool)

	// Pattern to extract variables in function calls or expressions
	// Matches: word characters followed by ( or used in string concatenation
	varPattern := regexp.MustCompile(`(?:execute|query|run|execute_sql)\s*\(\s*([a-zA-Z_]\w*)`)
	matches := varPattern.FindAllStringSubmatch(line, -1)
	for _, match := range matches {
		if len(match) > 1 {
			result[match[1]] = true
		}
	}

	// Also look for variables in f-strings
	fstringPattern := regexp.MustCompile(`f["'][^"']*{([a-zA-Z_]\w*)}`)
	matches = fstringPattern.FindAllStringSubmatch(line, -1)
	for _, match := range matches {
		if len(match) > 1 {
			result[match[1]] = true
		}
	}

	return result
}

// traceVariableSource performs interprocedural data flow analysis to trace if a variable comes from LLM
func (d *SQLInjectionViaLLMDetector) traceVariableSource(varName string, lines []string, currentLineIdx int, llmOutputVars map[string]bool) bool {
	// Base case: variable is directly from LLM
	if llmOutputVars[varName] {
		return true
	}

	// Look back up to 20 lines to find assignment
	lookbackStart := currentLineIdx - 20
	if lookbackStart < 0 {
		lookbackStart = 0
	}

	for i := currentLineIdx - 1; i >= lookbackStart; i-- {
		line := strings.TrimSpace(lines[i])

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		// Look for assignment: varName = ...
		assignmentPattern := regexp.MustCompile(`(?:^|\s)` + regexp.QuoteMeta(varName) + `\s*=\s*(.+)`)
		match := assignmentPattern.FindStringSubmatch(line)

		if len(match) > 1 {
			rhs := match[1]

			// Check if RHS contains an LLM variable
			for llmVar := range llmOutputVars {
				if strings.Contains(rhs, llmVar) {
					return true
				}
			}

			// Check if RHS is another variable - recursively trace it
			rhsVars := regexp.MustCompile(`[a-zA-Z_]\w*`).FindAllString(rhs, -1)
			for _, rhsVar := range rhsVars {
				if d.traceVariableSource(rhsVar, lines, i, llmOutputVars) {
					return true
				}
			}
		}
	}

	return false
}

// containsLLMVariable checks if query contains LLM-generated variable with interprocedural analysis
func (d *SQLInjectionViaLLMDetector) containsLLMVariable(executed string, llmOutputVars map[string]bool, lines []string, currentLineIdx int) bool {
	// Direct check for LLM variables
	for varName := range llmOutputVars {
		if strings.Contains(executed, varName) {
			return true
		}
	}

	// Interprocedural analysis: check if executed string uses variables derived from LLM
	varNames := d.extractVariableNames(executed)
	for varName := range varNames {
		if d.traceVariableSource(varName, lines, currentLineIdx, llmOutputVars) {
			return true
		}
	}

	return false
}

// getConfidenceReason returns a human-readable explanation of confidence
func (d *SQLInjectionViaLLMDetector) getConfidenceReason(confidence float32) string {
	if confidence >= 0.85 {
		return "(high confidence - known vulnerable pattern)"
	}
	if confidence >= 0.75 {
		return "(medium-high confidence - suspicious but unconfirmed)"
	}
	return "(medium confidence - requires validation)"
}

// isPythonFile checks if file is Python
func isPythonFile(filePath string) bool {
	return strings.HasSuffix(filePath, ".py")
}

// isJavaScriptFile checks if file is JavaScript
func isJavaScriptFile(filePath string) bool {
	return strings.HasSuffix(filePath, ".js") || strings.HasSuffix(filePath, ".ts") ||
		strings.HasSuffix(filePath, ".jsx") || strings.HasSuffix(filePath, ".tsx")
}

// GetConfidence returns the confidence score for this detector
func (d *SQLInjectionViaLLMDetector) GetConfidence() float32 {
	return 0.85
}
