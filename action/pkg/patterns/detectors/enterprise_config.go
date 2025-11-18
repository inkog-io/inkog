package detectors

import (
	"encoding/json"
	"fmt"
	"os"
)

// EnterpriseConfig manages enterprise-level configuration for pattern detection
// Allows organizations to tune detection parameters for their specific needs
type EnterpriseConfig struct {
	Version      string                    `json:"version"`
	Organization string                    `json:"organization"`
	Environment  string                    `json:"environment"`
	Patterns     map[string]*PatternConfig `json:"patterns"`
	Global       *GlobalConfig             `json:"global"`
	Learning     *LearningConfig           `json:"learning"`
}

// PatternConfig contains per-pattern configuration
type PatternConfig struct {
	Enabled                  bool              `json:"enabled"`
	ConfidenceThreshold      float32           `json:"confidence_threshold"`
	FalsePositiveSensitivity float32           `json:"false_positive_sensitivity"` // 0=aggressive, 1=conservative
	FactorWeights            map[string]float32 `json:"factor_weights"`
	CustomRules              []string          `json:"custom_rules"`
	FilterTestCode           bool              `json:"filter_test_code"`
	FilterComments           bool              `json:"filter_comments"`
	FilterStrings            bool              `json:"filter_strings"`
	Description              string            `json:"description"`
}

// GlobalConfig contains global settings
type GlobalConfig struct {
	LogLevel             string `json:"log_level"`
	MaxConcurrency       int    `json:"max_concurrency"`
	DebugMode            bool   `json:"debug_mode"`
	PerformanceOptimized bool   `json:"performance_optimized"`
	StrictMode           bool   `json:"strict_mode"` // Fail on any issues
}

// LearningConfig controls the learning system
type LearningConfig struct {
	Enabled                bool   `json:"enabled"`
	StorageDir             string `json:"storage_dir"`
	AutoRecalibrate        bool   `json:"auto_recalibrate"`
	RecalibrationInterval  string `json:"recalibration_interval"`
	SharedLearning         bool   `json:"shared_learning"` // Share learnings across team
	CollectMetrics         bool   `json:"collect_metrics"`
}

// NewEnterpriseConfig creates default enterprise configuration
func NewEnterpriseConfig() *EnterpriseConfig {
	return &EnterpriseConfig{
		Version:      "1.0.0",
		Organization: "Default Organization",
		Environment:  "production",
		Patterns:     make(map[string]*PatternConfig),
		Global: &GlobalConfig{
			LogLevel:             "info",
			MaxConcurrency:       4,
			DebugMode:            false,
			PerformanceOptimized: true,
			StrictMode:           false,
		},
		Learning: &LearningConfig{
			Enabled:               true,
			StorageDir:            ".inkog/feedback",
			AutoRecalibrate:       true,
			RecalibrationInterval: "weekly",
			SharedLearning:        true,
			CollectMetrics:        true,
		},
	}
}

// GetPatternConfig gets config for a specific pattern
func (ec *EnterpriseConfig) GetPatternConfig(patternID string) *PatternConfig {
	if cfg, ok := ec.Patterns[patternID]; ok {
		return cfg
	}

	// Return default config if not configured
	return &PatternConfig{
		Enabled:                    true,
		ConfidenceThreshold:        0.7,
		FalsePositiveSensitivity:   0.5, // Balanced
		FactorWeights:              make(map[string]float32),
		FilterTestCode:             true,
		FilterComments:             true,
		FilterStrings:              false,
	}
}

// SetPatternConfig sets configuration for a pattern
func (ec *EnterpriseConfig) SetPatternConfig(patternID string, cfg *PatternConfig) {
	ec.Patterns[patternID] = cfg
}

// LoadFromFile loads configuration from JSON file
func (ec *EnterpriseConfig) LoadFromFile(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	if err := json.Unmarshal(data, ec); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	return nil
}

// SaveToFile saves configuration to JSON file
func (ec *EnterpriseConfig) SaveToFile(filePath string) error {
	data, err := json.MarshalIndent(ec, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// CreateDefaultConfigs creates default configs for all patterns
func (ec *EnterpriseConfig) CreateDefaultConfigs() {
	patterns := map[string]string{
		"token_bombing":           "Detects unbounded LLM API calls that could lead to token exhaustion",
		"recursive_tool_calling":  "Detects recursive tool calls that could exhaust resources",
		"rag_over_fetching":       "Detects RAG systems fetching excessive data",
		"exec_in_loop":            "Detects dynamic code execution in loops",
		"oversight_disabled":      "Detects disabled oversight/approval mechanisms",
		"logging_disabled":        "Detects disabled security logging",
		"context_accumulation":    "Detects unbounded context accumulation in LLM conversations",
		"prompt_injection":        "Detects potential prompt injection vulnerabilities",
		"unsafe_env_access":       "Detects unsafe environment variable access",
		"hardcoded_credentials":   "Detects hardcoded credentials",
	}

	for patternID, description := range patterns {
		ec.Patterns[patternID] = &PatternConfig{
			Enabled:                    true,
			ConfidenceThreshold:        0.7,
			FalsePositiveSensitivity:   0.5,
			FactorWeights:              make(map[string]float32),
			FilterTestCode:             true,
			FilterComments:             true,
			FilterStrings:              false,
			Description:                description,
		}
	}
}

// ValidateConfig validates the configuration
func (ec *EnterpriseConfig) ValidateConfig() error {
	if ec.Global == nil {
		return fmt.Errorf("global config is required")
	}

	if ec.Learning == nil {
		return fmt.Errorf("learning config is required")
	}

	if ec.Global.MaxConcurrency < 1 {
		return fmt.Errorf("max_concurrency must be >= 1")
	}

	for patternID, cfg := range ec.Patterns {
		if cfg.ConfidenceThreshold < 0 || cfg.ConfidenceThreshold > 1 {
			return fmt.Errorf("confidence_threshold for %s must be between 0 and 1", patternID)
		}

		if cfg.FalsePositiveSensitivity < 0 || cfg.FalsePositiveSensitivity > 1 {
			return fmt.Errorf("false_positive_sensitivity for %s must be between 0 and 1", patternID)
		}
	}

	return nil
}

// GetConfigSummary returns a human-readable config summary
func (ec *EnterpriseConfig) GetConfigSummary() string {
	summary := fmt.Sprintf(`
Enterprise Configuration Summary
================================
Organization: %s
Environment:  %s
Version:      %s

Global Settings:
  Log Level:              %s
  Performance Optimized:  %v
  Strict Mode:            %v

Learning System:
  Enabled:                %v
  Auto-recalibrate:       %v
  Shared Learning:        %v

Patterns Configured: %d
  `, ec.Organization, ec.Environment, ec.Version,
		ec.Global.LogLevel, ec.Global.PerformanceOptimized, ec.Global.StrictMode,
		ec.Learning.Enabled, ec.Learning.AutoRecalibrate, ec.Learning.SharedLearning,
		len(ec.Patterns))

	for patternID, cfg := range ec.Patterns {
		status := "enabled"
		if !cfg.Enabled {
			status = "disabled"
		}
		summary += fmt.Sprintf("\n  - %s (%s, threshold: %.2f)", patternID, status, cfg.ConfidenceThreshold)
	}

	return summary
}
