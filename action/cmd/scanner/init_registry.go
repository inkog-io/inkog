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

	// TIER 3: Data Protection Patterns
	// Will be added in Phase 3

	return registry
}
