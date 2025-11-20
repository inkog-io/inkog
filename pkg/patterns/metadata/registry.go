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
	ID            string
	Title         string
	Description   string
	DefaultSeverity string
	CVSS          float32
	CWEIDs        []string
	Remediation   string
	Category      string // e.g., "AI Security", "Code Injection", "Data Exposure"
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

// Get retrieves metadata by vulnerability ID
func Get(id string) *VulnerabilityMetadata {
	if meta, ok := registry[id]; ok {
		return meta
	}
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
