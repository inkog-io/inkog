package detectors

import (
	"encoding/json"
	"io/ioutil"
)

// SimplePatternConfig contains basic per-pattern configuration
// Simplified from complex config to just the essentials for MVP
type SimplePatternConfig struct {
	Enabled              bool    `json:"enabled"`               // Is this pattern enabled?
	ConfidenceThreshold  float32 `json:"confidence_threshold"`  // Min confidence to report (0-1.0)
	FilterTestCode       bool    `json:"filter_test_code"`      // Filter findings in test files?
	FilterComments       bool    `json:"filter_comments"`       // Filter findings in comments?
	FilterStrings        bool    `json:"filter_strings"`        // Filter findings in strings?
}

// SimpleEnterpriseConfig contains basic configuration for Inkog
// Simplified for MVP - just pattern thresholds and filters
type SimpleEnterpriseConfig struct {
	Version  string                       `json:"version"`
	Patterns map[string]*SimplePatternConfig `json:"patterns"`
}

// NewSimpleEnterpriseConfig creates default configuration
func NewSimpleEnterpriseConfig() *SimpleEnterpriseConfig {
	return &SimpleEnterpriseConfig{
		Version: "1.0.0",
		Patterns: map[string]*SimplePatternConfig{
			"hardcoded_credentials": {
				Enabled:             true,
				ConfidenceThreshold: 0.7,
				FilterTestCode:      true,
				FilterComments:      true,
				FilterStrings:       false, // Important: don't filter strings for creds
			},
			"prompt_injection": {
				Enabled:             true,
				ConfidenceThreshold: 0.7,
				FilterTestCode:      true,
				FilterComments:      true,
				FilterStrings:       true,
			},
			"infinite_loops": {
				Enabled:             true,
				ConfidenceThreshold: 0.8,
				FilterTestCode:      true,
				FilterComments:      true,
				FilterStrings:       true,
			},
			"unsafe_env_access": {
				Enabled:             true,
				ConfidenceThreshold: 0.7,
				FilterTestCode:      true,
				FilterComments:      true,
				FilterStrings:       true,
			},
			"token_bombing": {
				Enabled:             true,
				ConfidenceThreshold: 0.75,
				FilterTestCode:      true,
				FilterComments:      true,
				FilterStrings:       true,
			},
			"recursive_tool_calling": {
				Enabled:             true,
				ConfidenceThreshold: 0.7,
				FilterTestCode:      true,
				FilterComments:      true,
				FilterStrings:       true,
			},
			"rag_over_fetching": {
				Enabled:             true,
				ConfidenceThreshold: 0.70,
				FilterTestCode:      true,
				FilterComments:      true,
				FilterStrings:       true,
			},
			"missing_rate_limits": {
				Enabled:             true,
				ConfidenceThreshold: 0.70,
				FilterTestCode:      true,
				FilterComments:      true,
				FilterStrings:       true,
			},
			"unvalidated_exec_eval": {
				Enabled:             true,
				ConfidenceThreshold: 0.75,
				FilterTestCode:      false, // Don't filter test code - eval in tests is still dangerous
				FilterComments:      true,
				FilterStrings:       true,
			},
			"sql_injection_via_llm": {
				Enabled:             true,
				ConfidenceThreshold: 0.70, // Higher threshold - SQL injection requires context
				FilterTestCode:      false, // Don't filter - SQL injection in tests is still dangerous
				FilterComments:      true,
				FilterStrings:       true,
			},
			"context_window_accumulation": {
				Enabled:             true,
				ConfidenceThreshold: 0.50, // Lower threshold - catch more patterns (Pattern 11 is detection-focused)
				FilterTestCode:      true,  // Can filter test code for accumulation patterns
				FilterComments:      true,
				FilterStrings:       true,
			},
			"logging_sensitive_data": {
				Enabled:             true,
				ConfidenceThreshold: 0.70, // Higher threshold - logging patterns prone to false positives (Pattern 12)
				FilterTestCode:      true,  // Can filter test code but flag if found
				FilterComments:      true,
				FilterStrings:       true,
			},
			"missing_human_oversight": {
				Enabled:             true,
				ConfidenceThreshold: 0.65, // Medium threshold - oversight patterns can be context-dependent (Pattern 13)
				FilterTestCode:      true,  // Tests often have unsafe patterns intentionally
				FilterComments:      true,
				FilterStrings:       true,
			},
		},
	}
}

// GetPatternConfig retrieves config for a specific pattern
func (sec *SimpleEnterpriseConfig) GetPatternConfig(patternID string) *SimplePatternConfig {
	if cfg, ok := sec.Patterns[patternID]; ok {
		return cfg
	}
	// Return default if pattern not configured
	return &SimplePatternConfig{
		Enabled:             true,
		ConfidenceThreshold: 0.7,
		FilterTestCode:      true,
		FilterComments:      true,
		FilterStrings:       true,
	}
}

// SetConfidenceThreshold sets the minimum confidence for a pattern
func (sec *SimpleEnterpriseConfig) SetConfidenceThreshold(patternID string, threshold float32) {
	cfg := sec.GetPatternConfig(patternID)
	if threshold < 0 {
		threshold = 0
	}
	if threshold > 1 {
		threshold = 1
	}
	cfg.ConfidenceThreshold = threshold
	sec.Patterns[patternID] = cfg
}

// IsPatternEnabled checks if a pattern is enabled
func (sec *SimpleEnterpriseConfig) IsPatternEnabled(patternID string) bool {
	cfg := sec.GetPatternConfig(patternID)
	return cfg.Enabled
}

// LoadFromFile loads configuration from JSON file
func (sec *SimpleEnterpriseConfig) LoadFromFile(filename string) error {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, sec)
}

// SaveToFile saves configuration to JSON file
func (sec *SimpleEnterpriseConfig) SaveToFile(filename string) error {
	data, err := json.MarshalIndent(sec, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filename, data, 0644)
}
