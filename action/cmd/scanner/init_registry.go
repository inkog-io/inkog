package main

import (
	"github.com/inkog-io/inkog/action/pkg/patterns"
	"github.com/inkog-io/inkog/action/pkg/patterns/detectors"
)

// InitializeRegistry creates and populates the pattern registry with all available detectors
func InitializeRegistry() *patterns.Registry {
	registry := patterns.NewRegistry()

	// DEBUG: Test detector - REMOVE AFTER DEBUGGING
	registry.Register(detectors.NewDebugDetector())

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
	// Using AST-aware V2 detector for Unsafe Environment Access with Tree-sitter based semantic analysis
	// Features: Import alias tracking, nested attribute chain analysis, dynamic function detection
	// Dangerous code execution detection, environment variable access tracking, obfuscation detection
	// Coverage: LangChain CVE-2023-44467, CVE-2024-36480, CVE-2025-46059; CrewAI, AutoGen, Flowise, Dify
	// AST Advantage: Catches evasion like "import os as x; x.system()" that regex-only detectors miss
	registry.Register(detectors.NewUnsafeEnvAccessDetectorV2())

	// TIER 2: Resource Exhaustion Patterns
	// Clean, production-grade V2 detectors with proper API usage and zero tech debt
	// Token Bombing: Detects unbounded input/output to LLM APIs causing DoS or runaway costs
	// Covers: OpenAI, Anthropic, Google, LLaMA - detects missing token limits, unbounded loops
	// Real CVE mapping: LangChain $12k bill, Dify ReDoS, Flowise CustomMCP RCE
	registry.Register(detectors.NewTokenBombingDetectorV2Clean())
	// Recursive Tool Calling: Detects infinite recursion and agent delegation loops
	// Features: Direct recursion, mutual recursion, agent delegation loops, unbounded while loops
	// Framework support: LangChain agents, CrewAI delegation, AutoGen conversations
	// Real CVE: CVE-2024-2965 (LangChain SitemapLoader infinite recursion)
	registry.Register(detectors.NewRecursiveToolCallingDetectorV2Clean())

	// TIER 3: Data Protection Patterns
	// Will be added in Phase 3

	return registry
}
