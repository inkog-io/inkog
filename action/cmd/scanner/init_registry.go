package main

import (
	"github.com/inkog-io/inkog/action/pkg/patterns"
	"github.com/inkog-io/inkog/action/pkg/patterns/detectors"
)

// InitializeRegistry creates and populates the pattern registry with all available detectors
func InitializeRegistry() *patterns.Registry {
	registry := patterns.NewRegistry()

	// TIER 1: Financial Impact Patterns
	// These cause $5K -> $50K monthly cost explosions
	// Using enhanced V2 detector for Prompt Injection with comprehensive coverage
	// of CVEs (LangChain PALChain CVE-2023-44467, GraphCypher CVE-2024-8309, etc.)
	registry.Register(detectors.NewPromptInjectionDetectorV2())
	// Using enhanced V2 detector for Hardcoded Credentials with 30+ credential format
	// detection, private keys, encoding/obfuscation, entropy analysis, and confidence scoring
	// Coverage: AWS, Azure, GCP, Stripe, GitHub, SendGrid, Slack, Twilio, JWT, PEM keys
	registry.Register(detectors.NewHardcodedCredentialsDetectorV2())
	// Using enhanced V2 detector for Infinite Loops with constant condition detection,
	// recursion analysis, multi-language support, and false positive reduction
	// Coverage: LangChain CVE-2024-2965, CrewAI, AutoGen, Flowise, Dify DoS scenarios
	registry.Register(detectors.NewInfiniteLoopDetectorV2())
	registry.Register(detectors.NewUnsafeEnvAccessDetector())

	// TIER 2: Compliance Critical Patterns
	// Will be added in Phase 2

	// TIER 3: Data Protection Patterns
	// Will be added in Phase 3

	return registry
}
