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
	registry.Register(detectors.NewPromptInjectionDetector())
	registry.Register(detectors.NewHardcodedCredentialsDetector())
	registry.Register(detectors.NewInfiniteLoopDetector())
	registry.Register(detectors.NewUnsafeEnvAccessDetector())

	// TIER 2: Compliance Critical Patterns
	// Will be added in Phase 2

	// TIER 3: Data Protection Patterns
	// Will be added in Phase 3

	return registry
}
