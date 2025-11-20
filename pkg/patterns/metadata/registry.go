package metadata

import "fmt"

// Vulnerability ID Constants - Single Source of Truth
const (
	ID_INFINITE_LOOP              = "infinite_loop_semantic"
	ID_CONTEXT_EXHAUSTION         = "context_exhaustion_semantic"
	ID_TAINTED_EVAL               = "tainted_eval"
	ID_LOGGING_SENSITIVE_DATA     = "logging_sensitive_data"
	ID_UNVALIDATED_EXEC_EVAL      = "unvalidated_exec_eval"
	ID_OUTPUT_VALIDATION          = "output_validation_failures"
	ID_PROMPT_INJECTION           = "prompt_injection"
	ID_SQL_INJECTION_LLM          = "sql_injection_via_llm"
	ID_HARDCODED_CREDENTIALS      = "hardcoded_credentials"
	ID_CROSS_TENANT_DATA_LEAKAGE  = "cross_tenant_data_leakage"
	ID_UNSAFE_ENV_ACCESS          = "unsafe_env_access"
	ID_UNSAFE_PICKLE              = "unsafe_pickle_deserialization"
	ID_UNSAFE_YAML                = "unsafe_yaml_loading"
	ID_REGEX_DENIAL_OF_SERVICE    = "regex_denial_of_service"
	ID_INSECURE_RANDOM            = "insecure_random_generation"
	ID_UNSAFE_DESERIALIZATION     = "unsafe_deserialization"
	ID_UNVALIDATED_REDIRECT       = "unvalidated_redirect"
	ID_MISSING_AUTH_CHECK         = "missing_authentication_check"
	ID_PATH_TRAVERSAL             = "path_traversal"
	ID_RACE_CONDITION             = "race_condition"
)

// VulnerabilityMetadata represents canonical metadata for a vulnerability type
type VulnerabilityMetadata struct {
	ID                    string
	Title                 string
	Description           string
	DefaultSeverity       string
	CVSS                  float32
	CWEIDs                []string
	Remediation           string
	Category              string // e.g., "AI Security", "Code Injection", "Data Exposure"
	RemediationSteps      []string // Detector-specific step-by-step remediation
	EUAIActArticles       []string // EU AI Act compliance articles (e.g., "Article 14: Human Oversight")
	NISTAIRMFCategories   []string // NIST AI RMF categories (e.g., "MAP 1.1: Input/Output Validation")
	OWASPLLMTop10         []string // OWASP LLM Top 10 mappings (e.g., "LLM01", "LLM04")
}

// Registry maps vulnerability IDs to their canonical metadata
var registry = map[string]*VulnerabilityMetadata{
	ID_INFINITE_LOOP: {
		ID:              ID_INFINITE_LOOP,
		Title:           "Infinite Loop in LLM-Dependent Code",
		Description:     "Loop condition depends on LLM output without deterministic termination guarantee",
		DefaultSeverity: "CRITICAL",
		CVSS:            9.0,
		CWEIDs:          []string{"CWE-835"},
		Remediation:     "Add maximum iteration counter with hard break, implement timeout mechanisms, validate loop termination conditions",
		Category:        "Resource Exhaustion",
		RemediationSteps: []string{
			"1. Add max_iterations counter to loop condition",
			"2. Implement timeout() mechanism using time.Sleep() or context.WithTimeout()",
			"3. Add explicit break statement when counter reaches maximum",
			"4. Log all iterations and breaks for monitoring",
			"5. Test with worst-case inputs that trigger LLM calls",
		},
		EUAIActArticles: []string{"Article 15: Accuracy, Robustness and Cybersecurity"},
		NISTAIRMFCategories: []string{"MAP 1.3: System Reliability", "MEASURE 2.4: AI System Risks"},
		OWASPLLMTop10: []string{"LLM10: Unbounded Consumption"},
	},
	ID_CONTEXT_EXHAUSTION: {
		ID:              ID_CONTEXT_EXHAUSTION,
		Title:           "Context Window Exhaustion",
		Description:     "Unbounded accumulation of context/message history leads to exponential token consumption",
		DefaultSeverity: "HIGH",
		CVSS:            7.5,
		CWEIDs:          []string{"CWE-400"},
		Remediation:     "Use bounded collections (deque with maxlen), implement context truncation, set explicit size limits",
		Category:        "Resource Exhaustion",
		RemediationSteps: []string{
			"1. Replace unbounded list with deque(maxlen=N) for bounded storage",
			"2. OR: Add truncation logic (if len(context) > max: context = context[-max:])",
			"3. OR: Implement ring buffer with explicit pop operations",
			"4. Add metrics to monitor context size growth over time",
			"5. Set alerts for when context approaches maximum size",
			"6. Test with long conversation histories to verify bounded behavior",
		},
		EUAIActArticles: []string{"Article 15: Accuracy, Robustness and Cybersecurity"},
		NISTAIRMFCategories: []string{"MAP 1.1: Input/Output Validation", "MEASURE 2.4: AI System Risks"},
		OWASPLLMTop10: []string{"LLM10: Unbounded Consumption"},
	},
	ID_TAINTED_EVAL: {
		ID:              ID_TAINTED_EVAL,
		Title:           "Tainted Code Execution (eval/exec)",
		Description:     "LLM-generated or user-controlled code executed via eval(), exec(), or equivalent",
		DefaultSeverity: "CRITICAL",
		CVSS:            9.8,
		CWEIDs:          []string{"CWE-94", "CWE-95"},
		Remediation:     "Remove dynamic code evaluation, use function dispatch tables, validate against whitelist, use AST parsing",
		Category:        "Code Injection",
		RemediationSteps: []string{
			"1. REMOVE all eval(), exec(), compile() calls immediately",
			"2. Replace with function dispatch table or switch statement",
			"3. Validate LLM output against strict whitelist of allowed operations",
			"4. Use AST parsing to analyze generated code safely (if needed)",
			"5. Implement sandbox environment if dynamic execution is unavoidable",
			"6. Add comprehensive logging and monitoring for any code generation",
			"7. Require human approval for code execution in production",
		},
		EUAIActArticles: []string{"Article 14: Human Oversight", "Article 15: Accuracy, Robustness and Cybersecurity"},
		NISTAIRMFCategories: []string{"MAP 1.1: Input/Output Validation", "MEASURE 2.4: AI System Risks"},
		OWASPLLMTop10: []string{"LLM02: Insecure Output Handling", "LLM04: Unbounded Consumption"},
	},
	ID_LOGGING_SENSITIVE_DATA: {
		ID:              ID_LOGGING_SENSITIVE_DATA,
		Title:           "Logging of Sensitive Data",
		Description:     "LLM responses or user input containing secrets/PII logged without sanitization",
		DefaultSeverity: "MEDIUM",
		CVSS:            4.0,
		CWEIDs:          []string{"CWE-532", "CWE-200"},
		Remediation:     "Sanitize logs, redact secrets/PII patterns, use structured logging with field masking",
		Category:        "Data Exposure",
		RemediationSteps: []string{
			"1. Identify all log statements handling LLM output or user input",
			"2. Add redaction filters for PII patterns (emails, phone numbers, SSN, etc.)",
			"3. Use structured logging libraries with field masking support",
			"4. Implement secret scanning in CI/CD to catch credentials in logs",
			"5. Configure log retention policies to minimize exposure window",
			"6. Ensure logs are encrypted at rest and in transit",
			"7. Audit log access and implement role-based access control",
			"8. Test redaction filters with real-world examples of sensitive data",
		},
		EUAIActArticles: []string{"Article 14: Human Oversight", "Article 15: Accuracy, Robustness and Cybersecurity"},
		NISTAIRMFCategories: []string{"MAP 1.2: Data Governance", "MEASURE 2.3: Input/Output Validation"},
		OWASPLLMTop10: []string{"LLM06: Sensitive Information Disclosure"},
	},
	ID_UNVALIDATED_EXEC_EVAL: {
		ID:              ID_UNVALIDATED_EXEC_EVAL,
		Title:           "Unvalidated Code Execution",
		Description:     "Command execution, subprocess calls, or code evaluation without input validation",
		DefaultSeverity: "CRITICAL",
		CVSS:            9.8,
		CWEIDs:          []string{"CWE-78", "CWE-94"},
		Remediation:     "Use parameterized execution, validate input against whitelist, avoid shell interpretation",
		Category:        "Code Injection",
		RemediationSteps: []string{
			"1. Use argument lists instead of shell strings (e.g., exec.Command('ls', '-la'))",
			"2. Validate all inputs against strict whitelist",
			"3. Use context.WithTimeout() to enforce execution timeouts",
			"4. Avoid shell=True or shell interpretation",
			"5. Implement sandboxing for untrusted code",
			"6. Log all command execution for audit trails",
		},
		EUAIActArticles: []string{"Article 14: Human Oversight", "Article 15: Accuracy, Robustness and Cybersecurity"},
		NISTAIRMFCategories: []string{"MAP 1.1: Input/Output Validation", "MEASURE 2.4: AI System Risks"},
		OWASPLLMTop10: []string{"LLM02: Insecure Output Handling"},
	},
	ID_OUTPUT_VALIDATION: {
		ID:              ID_OUTPUT_VALIDATION,
		Title:           "Output Validation Failures",
		Description:     "LLM output used in dangerous sinks without validation (eval, HTML, SQL, commands)",
		DefaultSeverity: "HIGH",
		CVSS:            8.0,
		CWEIDs:          []string{"CWE-79", "CWE-89", "CWE-94"},
		Remediation:     "Validate and sanitize all untrusted output before use in dangerous contexts",
		Category:        "Input Validation",
		RemediationSteps: []string{
			"1. Implement output validators for each sink type (eval, HTML, SQL, command)",
			"2. Use parameterized queries for SQL, safe HTML libraries for markup",
			"3. Whitelist allowed values or operations for code/command execution",
			"4. Add type checking and format validation for LLM output",
			"5. Implement output size limits to prevent overflow attacks",
			"6. Log all output validation failures for security monitoring",
		},
		EUAIActArticles: []string{"Article 15: Accuracy, Robustness and Cybersecurity"},
		NISTAIRMFCategories: []string{"MAP 1.1: Input/Output Validation", "MEASURE 2.4: AI System Risks"},
		OWASPLLMTop10: []string{"LLM02: Insecure Output Handling"},
	},
	ID_PROMPT_INJECTION: {
		ID:              ID_PROMPT_INJECTION,
		Title:           "Prompt Injection",
		Description:     "Unsanitized user input embedded in prompts allowing attacker to override system instructions",
		DefaultSeverity: "HIGH",
		CVSS:            7.5,
		CWEIDs:          []string{"CWE-94"},
		Remediation:     "Validate user input, use role-based prompts, implement few-shot examples, add output filtering",
		Category:        "Prompt Security",
		RemediationSteps: []string{
			"1. Validate all user inputs for suspicious patterns (delimiters, role keywords)",
			"2. Use system prompts that clarify role and constraints clearly",
			"3. Implement few-shot examples showing expected behavior",
			"4. Add output filtering to detect instruction-following attempts",
			"5. Use prompt templates with clear separation of user input",
			"6. Monitor for unusual behavior changes in LLM responses",
			"7. Implement rate limiting on user input changes",
		},
		EUAIActArticles: []string{"Article 14: Human Oversight"},
		NISTAIRMFCategories: []string{"MAP 1.1: Input/Output Validation"},
		OWASPLLMTop10: []string{"LLM01: Prompt Injection"},
	},
	ID_SQL_INJECTION_LLM: {
		ID:              ID_SQL_INJECTION_LLM,
		Title:           "SQL Injection via LLM",
		Description:     "LLM-generated SQL queries concatenated without parameterization",
		DefaultSeverity: "CRITICAL",
		CVSS:            9.1,
		CWEIDs:          []string{"CWE-89"},
		Remediation:     "Use parameterized queries, prepared statements, validate LLM output against expected types",
		Category:        "SQL Injection",
		RemediationSteps: []string{
			"1. Use parameterized queries (?) or ORM prepared statements exclusively",
			"2. NEVER concatenate user/LLM input into SQL strings",
			"3. Validate LLM output against expected types/formats",
			"4. Use database role with minimal permissions (principle of least privilege)",
			"5. Implement SQL statement whitelist for allowed operations",
			"6. Use stored procedures with input validation",
			"7. Add query logging and monitoring for anomalies",
		},
		EUAIActArticles: []string{"Article 15: Accuracy, Robustness and Cybersecurity"},
		NISTAIRMFCategories: []string{"MAP 1.1: Input/Output Validation", "MEASURE 2.4: AI System Risks"},
		OWASPLLMTop10: []string{"LLM01: Prompt Injection"},
	},
	ID_HARDCODED_CREDENTIALS: {
		ID:              ID_HARDCODED_CREDENTIALS,
		Title:           "Hardcoded Credentials",
		Description:     "API keys, passwords, or tokens hardcoded in source files",
		DefaultSeverity: "CRITICAL",
		CVSS:            9.1,
		CWEIDs:          []string{"CWE-798"},
		Remediation:     "Move credentials to environment variables or secure vaults, rotate immediately in production",
		Category:        "Sensitive Data",
		RemediationSteps: []string{
			"1. Extract credentials to .env file or secrets manager",
			"2. Load using environment variables or secrets API",
			"3. NEVER commit credentials to version control",
			"4. Rotate credentials immediately in production",
			"5. Implement credential scanning in CI/CD pipeline",
			"6. Use short-lived tokens (e.g., OAuth, temporary credentials)",
			"7. Audit all access to credentials in logs",
		},
		EUAIActArticles: []string{"Article 15: Accuracy, Robustness and Cybersecurity"},
		NISTAIRMFCategories: []string{"MAP 1.2: Data Governance"},
		OWASPLLMTop10: []string{},
	},
	ID_CROSS_TENANT_DATA_LEAKAGE: {
		ID:              ID_CROSS_TENANT_DATA_LEAKAGE,
		Title:           "Cross-Tenant Data Leakage",
		Description:     "Data from one tenant accessible to another due to improper isolation",
		DefaultSeverity: "CRITICAL",
		CVSS:            9.9,
		CWEIDs:          []string{"CWE-639"},
		Remediation:     "Implement strict tenant isolation, validate permissions on every access, use separate connections per tenant",
		Category:        "Access Control",
		RemediationSteps: []string{
			"1. Implement tenant-aware data filtering at database query level",
			"2. Use separate database schemas or credentials per tenant",
			"3. Validate tenant context in every API call",
			"4. Implement row-level security policies in database",
			"5. Audit all data access by tenant",
			"6. Regular security testing for tenant isolation",
			"7. Use cryptographic isolation keys per tenant",
		},
		EUAIActArticles: []string{"Article 14: Human Oversight", "Article 15: Accuracy, Robustness and Cybersecurity"},
		NISTAIRMFCategories: []string{"MAP 1.2: Data Governance", "MEASURE 2.3: Input/Output Validation"},
		OWASPLLMTop10: []string{},
	},
	ID_UNSAFE_ENV_ACCESS: {
		ID:              ID_UNSAFE_ENV_ACCESS,
		Title:           "Unsafe Environment Variable Access",
		Description:     "Environment variables accessed without validation or proper access controls",
		DefaultSeverity: "HIGH",
		CVSS:            7.5,
		CWEIDs:          []string{"CWE-15"},
		Remediation:     "Validate environment variable access, implement access control, use secrets management",
		Category:        "Configuration",
		RemediationSteps: []string{
			"1. Use explicit variable names instead of wildcard access",
			"2. Validate environment variable values at startup",
			"3. Implement schema validation for required variables",
			"4. Use type-safe configuration loaders",
			"5. Never log environment variable values",
			"6. Restrict environment variable scope",
			"7. Use secrets management systems for sensitive values",
		},
		EUAIActArticles: []string{"Article 15: Accuracy, Robustness and Cybersecurity"},
		NISTAIRMFCategories: []string{"MAP 1.2: Data Governance"},
		OWASPLLMTop10: []string{},
	},
	ID_UNSAFE_PICKLE: {
		ID:              ID_UNSAFE_PICKLE,
		Title:           "Unsafe Pickle Deserialization",
		Description:     "Untrusted data deserialized via pickle allowing arbitrary code execution",
		DefaultSeverity: "CRITICAL",
		CVSS:            9.8,
		CWEIDs:          []string{"CWE-502"},
		Remediation:     "Use safe serialization formats (JSON), validate data source, implement code signing",
		Category:        "Deserialization",
	},
	ID_UNSAFE_YAML: {
		ID:              ID_UNSAFE_YAML,
		Title:           "Unsafe YAML Loading",
		Description:     "YAML loaded with unsafe options allowing arbitrary code execution",
		DefaultSeverity: "CRITICAL",
		CVSS:            9.8,
		CWEIDs:          []string{"CWE-502"},
		Remediation:     "Use safe YAML loaders, restrict constructors, validate schema",
		Category:        "Deserialization",
	},
	ID_REGEX_DENIAL_OF_SERVICE: {
		ID:              ID_REGEX_DENIAL_OF_SERVICE,
		Title:           "Regular Expression Denial of Service",
		Description:     "Vulnerable regex patterns causing exponential backtracking on input",
		DefaultSeverity: "HIGH",
		CVSS:            7.5,
		CWEIDs:          []string{"CWE-1333"},
		Remediation:     "Use regex timeout, simplify patterns, test with worst-case input",
		Category:        "Denial of Service",
	},
	ID_INSECURE_RANDOM: {
		ID:              ID_INSECURE_RANDOM,
		Title:           "Insecure Random Number Generation",
		Description:     "Using predictable random numbers for security-sensitive operations",
		DefaultSeverity: "HIGH",
		CVSS:            7.5,
		CWEIDs:          []string{"CWE-338"},
		Remediation:     "Use cryptographically secure random generators, validate randomness quality",
		Category:        "Cryptography",
	},
	ID_UNSAFE_DESERIALIZATION: {
		ID:              ID_UNSAFE_DESERIALIZATION,
		Title:           "Unsafe Deserialization",
		Description:     "Untrusted serialized data deserialized without proper validation",
		DefaultSeverity: "CRITICAL",
		CVSS:            9.8,
		CWEIDs:          []string{"CWE-502"},
		Remediation:     "Validate deserialization input, use safe formats, implement type checking",
		Category:        "Deserialization",
	},
	ID_UNVALIDATED_REDIRECT: {
		ID:              ID_UNVALIDATED_REDIRECT,
		Title:           "Unvalidated Redirect",
		Description:     "HTTP redirects to user-controlled URLs without validation",
		DefaultSeverity: "MEDIUM",
		CVSS:            6.1,
		CWEIDs:          []string{"CWE-601"},
		Remediation:     "Validate redirect URLs against allowlist, use relative redirects",
		Category:        "Web Security",
	},
	ID_MISSING_AUTH_CHECK: {
		ID:              ID_MISSING_AUTH_CHECK,
		Title:           "Missing Authentication Check",
		Description:     "Sensitive operations performed without authentication verification",
		DefaultSeverity: "CRITICAL",
		CVSS:            9.1,
		CWEIDs:          []string{"CWE-306"},
		Remediation:     "Add authentication checks before all sensitive operations, use standard auth frameworks",
		Category:        "Access Control",
	},
	ID_PATH_TRAVERSAL: {
		ID:              ID_PATH_TRAVERSAL,
		Title:           "Path Traversal",
		Description:     "File paths constructed from untrusted input allowing access outside intended directory",
		DefaultSeverity: "HIGH",
		CVSS:            7.5,
		CWEIDs:          []string{"CWE-22"},
		Remediation:     "Canonicalize paths, validate against whitelist, use safe path APIs",
		Category:        "File Access",
	},
	ID_RACE_CONDITION: {
		ID:              ID_RACE_CONDITION,
		Title:           "Race Condition",
		Description:     "Time-of-check to time-of-use vulnerability allowing concurrent access conflicts",
		DefaultSeverity: "HIGH",
		CVSS:            7.0,
		CWEIDs:          []string{"CWE-362"},
		Remediation:     "Use atomic operations, proper locking, transactional consistency",
		Category:        "Concurrency",
	},
}

// Get retrieves metadata by vulnerability ID, supporting legacy detector aliases
func Get(id string) *VulnerabilityMetadata {
	// Legacy detector ID aliases mapping to canonical registry IDs
	aliases := map[string]string{
		"context_window_accumulation":  ID_CONTEXT_EXHAUSTION,
		"missing_human_oversight":      ID_TAINTED_EVAL,
		"output_validation_failures":   ID_OUTPUT_VALIDATION,
		"unvalidated_exec_eval":        ID_UNVALIDATED_EXEC_EVAL,
	}

	// Check if this is a legacy alias and resolve to canonical ID
	if canonical, ok := aliases[id]; ok {
		id = canonical
	}

	// Look up in registry
	if meta, ok := registry[id]; ok {
		return meta
	}

	// Fallback for unknown vulnerabilities
	return &VulnerabilityMetadata{
		ID:              id,
		Title:           fmt.Sprintf("Unknown Vulnerability (%s)", id),
		Description:     "No metadata available for this vulnerability",
		DefaultSeverity: "MEDIUM",
		CVSS:            5.0,
		CWEIDs:          []string{},
		Remediation:     "Review findings and implement appropriate mitigations",
		Category:        "Unknown",
	}
}

// GetByTitle retrieves metadata by vulnerability title (for backward compatibility)
func GetByTitle(title string) *VulnerabilityMetadata {
	for _, meta := range registry {
		if meta.Title == title {
			return meta
		}
	}
	return nil
}

// GetAll returns all registered vulnerability metadata
func GetAll() []*VulnerabilityMetadata {
	var all []*VulnerabilityMetadata
	for _, meta := range registry {
		all = append(all, meta)
	}
	return all
}

// Register allows adding new vulnerability metadata (for extensions)
func Register(meta *VulnerabilityMetadata) error {
	if meta == nil || meta.ID == "" {
		return fmt.Errorf("metadata must have non-empty ID")
	}
	registry[meta.ID] = meta
	return nil
}

// GetRemediationSteps returns detailed step-by-step remediation for a vulnerability
func GetRemediationSteps(id string) []string {
	meta := Get(id)
	if meta != nil && len(meta.RemediationSteps) > 0 {
		return meta.RemediationSteps
	}
	return []string{"Review vulnerability description and apply appropriate remediation"}
}

// GetComplianceFrameworks returns all compliance frameworks a vulnerability maps to
type ComplianceMapping struct {
	EUAIAct     []string
	NISTAIRMFs  []string
	OWASPLLMTop10 []string
}

// GetComplianceMappings returns all compliance framework mappings for a vulnerability
func GetComplianceMappings(id string) *ComplianceMapping {
	meta := Get(id)
	if meta == nil {
		return &ComplianceMapping{}
	}
	return &ComplianceMapping{
		EUAIAct:       meta.EUAIActArticles,
		NISTAIRMFs:    meta.NISTAIRMFCategories,
		OWASPLLMTop10: meta.OWASPLLMTop10,
	}
}

// GetVulnerabilitiesByComplianceFramework returns all vulnerabilities affecting a compliance framework
func GetVulnerabilitiesByComplianceFramework(framework string) []*VulnerabilityMetadata {
	var matches []*VulnerabilityMetadata
	for _, meta := range registry {
		for _, article := range meta.EUAIActArticles {
			if article == framework {
				matches = append(matches, meta)
				break
			}
		}
		// Check NIST
		for _, category := range meta.NISTAIRMFCategories {
			if category == framework {
				matches = append(matches, meta)
				break
			}
		}
		// Check OWASP
		for _, owasp := range meta.OWASPLLMTop10 {
			if owasp == framework {
				matches = append(matches, meta)
				break
			}
		}
	}
	return matches
}

// GetVulnerabilitiesByCategory returns all vulnerabilities in a specific category
func GetVulnerabilitiesByCategory(category string) []*VulnerabilityMetadata {
	var matches []*VulnerabilityMetadata
	for _, meta := range registry {
		if meta.Category == category {
			matches = append(matches, meta)
		}
	}
	return matches
}

// GetVulnerabilitiesBySeverity returns all vulnerabilities at or above a minimum severity
func GetVulnerabilitiesBySeverity(minSeverity string) []*VulnerabilityMetadata {
	severityMap := map[string]int{
		"CRITICAL": 4,
		"HIGH":     3,
		"MEDIUM":   2,
		"LOW":      1,
	}
	minScore := severityMap[minSeverity]

	var matches []*VulnerabilityMetadata
	for _, meta := range registry {
		if severityMap[meta.DefaultSeverity] >= minScore {
			matches = append(matches, meta)
		}
	}
	return matches
}
