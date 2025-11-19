package detectors

import (
	"regexp"
	"strings"
)

// PatternMatcher provides consistent, reusable pattern matching with normalization
// This utility prevents bugs caused by inconsistent case handling and pattern variations
type PatternMatcher struct {
	patterns      []string          // Base patterns
	regexPatterns []*regexp.Regexp  // Compiled regex patterns
	normalizeFn   func(string) string
}

// PatternMatcherConfig defines how patterns should be matched
type PatternMatcherConfig struct {
	// CaseInsensitive treats patterns case-insensitively
	CaseInsensitive bool
	// WhitespaceInsensitive ignores whitespace in matching
	WhitespaceInsensitive bool
	// UseRegex treats patterns as regular expressions
	UseRegex bool
}

// NewPatternMatcher creates a new pattern matcher with consistent normalization
func NewPatternMatcher(patterns []string, config PatternMatcherConfig) *PatternMatcher {
	pm := &PatternMatcher{
		patterns: patterns,
	}

	// Set normalization function based on config
	if config.CaseInsensitive && config.WhitespaceInsensitive {
		pm.normalizeFn = func(s string) string {
			s = strings.ToLower(s)
			fields := strings.Fields(strings.TrimSpace(s))
			return strings.Join(fields, " ")
		}
	} else if config.CaseInsensitive {
		pm.normalizeFn = strings.ToLower
	} else if config.WhitespaceInsensitive {
		pm.normalizeFn = func(s string) string {
			fields := strings.Fields(strings.TrimSpace(s))
			return strings.Join(fields, " ")
		}
	} else {
		pm.normalizeFn = func(s string) string { return s }
	}

	// Normalize all patterns once, at creation time
	normalizedPatterns := make([]string, len(patterns))
	for i, pattern := range patterns {
		normalizedPatterns[i] = pm.normalizeFn(pattern)
	}
	pm.patterns = normalizedPatterns

	// Compile regex patterns if requested
	if config.UseRegex {
		for _, pattern := range pm.patterns {
			if re, err := regexp.Compile(pattern); err == nil {
				pm.regexPatterns = append(pm.regexPatterns, re)
			}
		}
	}

	return pm
}

// Match checks if text contains any of the patterns
// Returns: (matched, matchedPattern)
func (pm *PatternMatcher) Match(text string) (bool, string) {
	normalizedText := pm.normalizeFn(text)

	if len(pm.regexPatterns) > 0 {
		// Regex matching
		for _, re := range pm.regexPatterns {
			if re.MatchString(normalizedText) {
				return true, re.String()
			}
		}
		return false, ""
	}

	// String matching
	for _, pattern := range pm.patterns {
		if strings.Contains(normalizedText, pattern) {
			return true, pattern
		}
	}
	return false, ""
}

// MatchAny checks if text matches any pattern, returns all matches
func (pm *PatternMatcher) MatchAny(text string) []string {
	var matches []string
	normalizedText := pm.normalizeFn(text)

	if len(pm.regexPatterns) > 0 {
		for _, re := range pm.regexPatterns {
			if re.MatchString(normalizedText) {
				matches = append(matches, re.String())
			}
		}
		return matches
	}

	for _, pattern := range pm.patterns {
		if strings.Contains(normalizedText, pattern) {
			matches = append(matches, pattern)
		}
	}
	return matches
}

// MatchIndex returns the index of the first matching pattern
func (pm *PatternMatcher) MatchIndex(text string) int {
	normalizedText := pm.normalizeFn(text)

	if len(pm.regexPatterns) > 0 {
		for i, re := range pm.regexPatterns {
			if re.MatchString(normalizedText) {
				return i
			}
		}
		return -1
	}

	for i, pattern := range pm.patterns {
		if strings.Contains(normalizedText, pattern) {
			return i
		}
	}
	return -1
}

// AddPattern adds a new pattern dynamically
func (pm *PatternMatcher) AddPattern(pattern string) {
	normalized := pm.normalizeFn(pattern)
	pm.patterns = append(pm.patterns, normalized)

	if len(pm.regexPatterns) > 0 {
		if re, err := regexp.Compile(normalized); err == nil {
			pm.regexPatterns = append(pm.regexPatterns, re)
		}
	}
}

// RemovePattern removes a pattern
func (pm *PatternMatcher) RemovePattern(pattern string) {
	normalized := pm.normalizeFn(pattern)
	for i, p := range pm.patterns {
		if p == normalized {
			pm.patterns = append(pm.patterns[:i], pm.patterns[i+1:]...)
			if len(pm.regexPatterns) > i {
				pm.regexPatterns = append(pm.regexPatterns[:i], pm.regexPatterns[i+1:]...)
			}
			break
		}
	}
}

// Patterns returns the normalized patterns
func (pm *PatternMatcher) Patterns() []string {
	return pm.patterns
}

// Count returns the number of patterns
func (pm *PatternMatcher) Count() int {
	return len(pm.patterns)
}

// LLMProviderRegistry is a specialized PatternMatcher for LLM API detection
// Maintains a registry of provider-specific API call patterns
type LLMProviderRegistry struct {
	providers map[string]*PatternMatcher // provider -> matcher
	allMatcher *PatternMatcher            // matcher for all patterns
}

// NewLLMProviderRegistry creates a registry for LLM provider detection
func NewLLMProviderRegistry() *LLMProviderRegistry {
	registry := &LLMProviderRegistry{
		providers: make(map[string]*PatternMatcher),
	}

	// OpenAI patterns
	registry.providers["OpenAI"] = NewPatternMatcher([]string{
		"openai.ChatCompletion.create",
		"openai.completion.create",
		"openai.Completion.create",
		"client.ChatCompletion.create",
		"client.chat.completions.create",
		"openai.chat.completions.create",
		"openai.completion(",
		"openai.chat.completion(",
		"client.completion(",
		"client.chat(",
	}, PatternMatcherConfig{CaseInsensitive: true})

	// Anthropic patterns
	registry.providers["Anthropic"] = NewPatternMatcher([]string{
		"client.messages.create",
		"anthropic.messages.create",
		"claude.invoke",
		"claude.create",
		"messages.create(",
		"claude.messages",
	}, PatternMatcherConfig{CaseInsensitive: true})

	// Google patterns
	registry.providers["Google"] = NewPatternMatcher([]string{
		"genai.generate_text",
		"genai.GenerateText",
		"genai.generate",
		"palm.generate_text",
		"vertexai.predict",
	}, PatternMatcherConfig{CaseInsensitive: true})

	// LangChain patterns
	registry.providers["LangChain"] = NewPatternMatcher([]string{
		".invoke(",
		".run(",
		".call(",
		"chain.invoke",
		"agent.run",
	}, PatternMatcherConfig{CaseInsensitive: true})

	// Build combined matcher
	var allPatterns []string
	for _, matcher := range registry.providers {
		allPatterns = append(allPatterns, matcher.Patterns()...)
	}
	registry.allMatcher = NewPatternMatcher(allPatterns, PatternMatcherConfig{CaseInsensitive: true})

	return registry
}

// DetectProvider identifies which provider is being called
func (r *LLMProviderRegistry) DetectProvider(text string) string {
	for provider, matcher := range r.providers {
		if matched, _ := matcher.Match(text); matched {
			return provider
		}
	}
	return ""
}

// IsLLMCall checks if text contains any LLM API call
func (r *LLMProviderRegistry) IsLLMCall(text string) bool {
	matched, _ := r.allMatcher.Match(text)
	return matched
}

// FileClassifier provides consistent file type detection
type FileClassifier struct {
	testPatterns      *PatternMatcher
	configPatterns    *PatternMatcher
	documentPatterns  *PatternMatcher
	vendorPatterns    *PatternMatcher
}

// NewFileClassifier creates a new file classifier
func NewFileClassifier() *FileClassifier {
	return &FileClassifier{
		testPatterns: NewPatternMatcher([]string{
			"test_",
			"_test.",
			"tests/",
			"test/",
			"_test_",
			"spec_",
			"_spec.",
			".test.",
			".spec.",
		}, PatternMatcherConfig{CaseInsensitive: true}),

		configPatterns: NewPatternMatcher([]string{
			".config",
			".env",
			".yml",
			".yaml",
			".json",
			"config/",
			"settings/",
		}, PatternMatcherConfig{CaseInsensitive: true}),

		documentPatterns: NewPatternMatcher([]string{
			".md",
			".txt",
			".rst",
			".doc",
			"README",
			"CHANGELOG",
			"docs/",
		}, PatternMatcherConfig{CaseInsensitive: true}),

		vendorPatterns: NewPatternMatcher([]string{
			"vendor/",
			"node_modules/",
			".venv/",
			"venv/",
			"dist/",
			"build/",
		}, PatternMatcherConfig{CaseInsensitive: true}),
	}
}

// IsTestFile checks if a file is a test file
func (fc *FileClassifier) IsTestFile(filename string) bool {
	matched, _ := fc.testPatterns.Match(filename)
	return matched
}

// IsConfigFile checks if a file is a configuration file
func (fc *FileClassifier) IsConfigFile(filename string) bool {
	matched, _ := fc.configPatterns.Match(filename)
	return matched
}

// IsDocumentation checks if a file is documentation
func (fc *FileClassifier) IsDocumentation(filename string) bool {
	matched, _ := fc.documentPatterns.Match(filename)
	return matched
}

// IsVendor checks if a file is in vendor/dependency directory
func (fc *FileClassifier) IsVendor(filename string) bool {
	matched, _ := fc.vendorPatterns.Match(filename)
	return matched
}

// ClassifyFile returns all applicable classifications
func (fc *FileClassifier) ClassifyFile(filename string) map[string]bool {
	return map[string]bool{
		"test":        fc.IsTestFile(filename),
		"config":      fc.IsConfigFile(filename),
		"documentation": fc.IsDocumentation(filename),
		"vendor":      fc.IsVendor(filename),
	}
}

// UnboundedLoopDetector detects unbounded loop patterns
type UnboundedLoopDetector struct {
	matcher *PatternMatcher
}

// NewUnboundedLoopDetector creates a new loop detector
func NewUnboundedLoopDetector() *UnboundedLoopDetector {
	return &UnboundedLoopDetector{
		matcher: NewPatternMatcher([]string{
			"while true",
			"while(true)",
			"while true:",
			"while 1",
			"while(1)",
			"for(;;)",
			"for;;",
		}, PatternMatcherConfig{CaseInsensitive: true}),
	}
}

// IsUnboundedLoop checks if line contains unbounded loop pattern
func (uld *UnboundedLoopDetector) IsUnboundedLoop(line string) bool {
	matched, _ := uld.matcher.Match(line)
	return matched
}
