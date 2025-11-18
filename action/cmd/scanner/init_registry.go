package main

import (
	"github.com/inkog-io/inkog/action/pkg/patterns"
	"github.com/inkog-io/inkog/action/pkg/patterns/detectors"
)

// InitializeRegistry creates and populates the pattern registry with all available detectors
func InitializeRegistry() *patterns.Registry {
	registry := patterns.NewRegistry()


	// TIER 1: Financial Impact Patterns
	// HYBRID PHASE 1: Using clean, tested implementations
	// Pattern 1: Hardcoded Credentials - API keys, tokens, private keys (CRITICAL severity)
	registry.Register(detectors.NewHardcodedCredentialsDetector())
	// Pattern 2: Prompt Injection - user input in LLM prompts (HIGH severity)
	registry.Register(detectors.NewPromptInjectionDetector())
	// Pattern 3: Infinite Loops - while(true), recursion, missing breaks (HIGH severity)
	registry.Register(detectors.NewInfiniteLoopDetector())
	// Pattern 4: Unsafe Environment Access - dangerous system calls (HIGH severity)
	registry.Register(detectors.NewUnsafeEnvAccessDetector())

	// TIER 2: Resource Exhaustion Patterns
	// Pattern 5: Token Bombing - unbounded LLM API calls causing DoS or cost explosion
	registry.Register(detectors.NewTokenBombingDetector())
	// Pattern 6: Recursive Tool Calling - agent delegation loops and unbounded recursion
	registry.Register(detectors.NewRecursiveToolCallingDetector())

	// TIER 2 (Continued): Additional Resource & Logic Patterns
	// Pattern 7: Context Window Accumulation - unbounded context growth
	registry.Register(detectors.NewContextWindowAccumulationDetector())
	// Pattern 8: Missing Rate Limits - uncontrolled API rate exposure
	registry.Register(detectors.NewMissingRateLimitsDetector())
	// Pattern 9: RAG Over-Fetching - excessive document retrieval risks
	registry.Register(detectors.NewRAGOverFetchingDetector())

	// TIER 3: Data Protection & Code Execution Patterns
	// Pattern 10: Logging Sensitive Data - PII/credentials in logs
	registry.Register(detectors.NewLoggingSensitiveDataDetector())
	// Pattern 11: Output Validation Failures - unvalidated LLM outputs
	registry.Register(detectors.NewOutputValidationFailuresDetector())
	// Pattern 12: SQL Injection via LLM - LLM-generated SQL without sanitization
	registry.Register(detectors.NewSQLInjectionViaLLMDetector())
	// Pattern 13: Unvalidated Code Execution - exec/eval without safety
	registry.Register(detectors.NewUnvalidatedExecEvalDetector())

	// TIER 3 (Continued): Governance & Compliance Patterns
	// Pattern 14: Missing Human Oversight - autonomous actions without approval
	registry.Register(detectors.NewMissingHumanOversightDetector())
	// Pattern 15: Cross-Tenant Data Leakage - multi-tenant isolation failures
	registry.Register(detectors.NewCrossTenantDataLeakageDetector())

	return registry
}
