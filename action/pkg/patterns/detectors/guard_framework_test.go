package detectors

import (
	"testing"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// TestLLMPatternDetector - Tests for real LLM API call detection
func TestLLMPatternDetector(t *testing.T) {
	detector := NewLLMPatternDetector()

	tests := []struct {
		name        string
		line        string
		shouldMatch bool
		provider    string
	}{
		// Real OpenAI API calls (should match)
		{"OpenAI real call", "response = openai.ChatCompletion.create(", true, "OpenAI"},
		{"OpenAI client call", "client.ChatCompletion.create(", true, "OpenAI"},
		{"OpenAI completion", "openai.completion(", true, "OpenAI"},

		// Real Anthropic API calls (should match)
		{"Anthropic messages", "client.messages.create(", true, "Anthropic"},
		{"Anthropic claude", "claude.create(", true, "Anthropic"},

		// Real framework calls (should match)
		{"LangChain invoke", "llm.invoke(", true, "LangChain"},
		{"CrewAI execute", "agent.execute_task(", true, "CrewAI"},

		// Keyword-only (should NOT match as real calls)
		{"Keyword in string", `label: 'Anthropic Claude Model'`, false, ""},
		{"Keyword in config", `model = "openai"`, false, ""},
		{"Keyword in comment", `# Uses OpenAI API`, false, ""},

		// False positive cases (should NOT match)
		{"Just provider name", "anthropic_agent", false, ""},
		{"In documentation", "The OpenAI API allows", false, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			isReal, provider := detector.IsRealLLMCall(tc.line)
			if isReal != tc.shouldMatch {
				t.Errorf("Expected match=%v, got %v for line: %s", tc.shouldMatch, isReal, tc.line)
			}
			if tc.shouldMatch && provider != tc.provider {
				t.Errorf("Expected provider=%s, got %s", tc.provider, provider)
			}
		})
	}
}

// TestKeywordOnlyDetection - Tests for keyword-without-invocation detection
func TestKeywordOnlyDetection(t *testing.T) {
	detector := NewLLMPatternDetector()

	tests := []struct {
		name          string
		line          string
		shouldBeKeywordOnly bool
	}{
		// Config lines with keywords (should be detected as keyword-only)
		{"Config with anthropic", `model_name: "Anthropic Claude"`, true},
		{"Config with openai", `provider: "openai"`, true},
		{"Documentation string", `"Uses OpenAI for chat"`, true},

		// Real invocations (should NOT be keyword-only)
		{"Real openai call", `response = openai.ChatCompletion.create(model="gpt-4",`, false},
		{"Real anthropic call", `msg = client.messages.create(`, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := detector.ContainsLLMKeywordOnly(tc.line)
			if result != tc.shouldBeKeywordOnly {
				t.Errorf("Expected keyword_only=%v, got %v for line: %s", tc.shouldBeKeywordOnly, result, tc.line)
			}
		})
	}
}

// TestLoopPatternDetection - Tests for bounded vs unbounded loop detection
func TestLoopPatternDetection(t *testing.T) {
	detector := NewLoopPatternDetector()

	unboundedTests := []struct {
		name string
		line string
	}{
		{"while True Python", "while True:"},
		{"while(true) C-style", "while(true) {"},
		{"for empty loop", "for(;;) {"},
		{"while 1 C", "while(1) {"},
	}

	for _, tc := range unboundedTests {
		t.Run("unbounded: "+tc.name, func(t *testing.T) {
			if !detector.IsUnboundedLoop(tc.line) {
				t.Errorf("Expected unbounded loop detection for: %s", tc.line)
			}
		})
	}

	boundedTests := []struct {
		name string
		line string
	}{
		{"for range", "for i in range(10):"},
		{"for range len", "for i in range(len(items)):"},
		{"for collection", "for item in items:"},
		{"for C-style", "for(int i=0; i<10; i++) {"},
		{"foreach Go", "for i := range items {"},
	}

	for _, tc := range boundedTests {
		t.Run("bounded: "+tc.name, func(t *testing.T) {
			if !detector.IsBoundedLoop(tc.line) {
				t.Errorf("Expected bounded loop detection for: %s", tc.line)
			}
		})
	}
}

// TestContextFiltering - Tests for context awareness (string, comment, test code detection)
func TestContextFiltering(t *testing.T) {
	filter := NewContextFilterEngine()

	// Test string detection
	stringTests := []struct {
		name     string
		line     string
		isString bool
	}{
		{"Single quoted", `label = "openai"`, true},
		{"Double quoted", `name = 'Claude'`, true},
		{"Backtick quoted", "`invoke_model(`", true},
		{"Code only", `response = invoke_model()`, false},
	}

	for _, tc := range stringTests {
		t.Run("string: "+tc.name, func(t *testing.T) {
			result := filter.IsInString(tc.line)
			if result != tc.isString {
				t.Errorf("Expected is_string=%v, got %v for: %s", tc.isString, result, tc.line)
			}
		})
	}

	// Test comment detection
	commentTests := []struct {
		name      string
		line      string
		isComment bool
	}{
		{"Python comment", "# Uses OpenAI", true},
		{"C comment", "// invoke_model", true},
		{"Not comment", "response = invoke_model()", false},
	}

	for _, tc := range commentTests {
		t.Run("comment: "+tc.name, func(t *testing.T) {
			result := filter.IsInComment(tc.line)
			if result != tc.isComment {
				t.Errorf("Expected is_comment=%v, got %v for: %s", tc.isComment, result, tc.line)
			}
		})
	}

	// Test config detection
	configTests := []struct {
		name     string
		line     string
		isConfig bool
	}{
		{"YAML config", `model: "gpt-4"`, true},
		{"Key-value config", `api_key = "sk-..."`, true},
		{"JSON config", `"model": "claude"`, true},
		{"Code line", `response = model.invoke()`, false},
	}

	for _, tc := range configTests {
		t.Run("config: "+tc.name, func(t *testing.T) {
			result := filter.IsConfigContext(tc.line)
			if result != tc.isConfig {
				t.Errorf("Expected is_config=%v, got %v for: %s", tc.isConfig, result, tc.line)
			}
		})
	}

	// Test test code detection
	testTests := []struct {
		name     string
		line     string
		isTest   bool
	}{
		{"Describe block", "describe('API tests', () => {", true},
		{"It block", "it('should invoke model', () => {", true},
		{"Test function", "def test_invoke_model():", true},
		{"Setup function", "def setup():", true},
		{"Production code", "response = model.invoke()", false},
	}

	for _, tc := range testTests {
		t.Run("test: "+tc.name, func(t *testing.T) {
			result := filter.IsTestCode(tc.line)
			if result != tc.isTest {
				t.Errorf("Expected is_test=%v, got %v for: %s", tc.isTest, result, tc.line)
			}
		})
	}
}

// TestApplyGuards - Tests the complete guard application flow
func TestApplyGuards(t *testing.T) {
	gf := NewGuardFramework()

	findings := []patterns.Finding{
		{
			Line:      1,
			Pattern:   "Token Bombing Attack",
			PatternID: "token_bombing",
			Message:   "LLM API call (OpenAI) without token limits",
		},
		{
			Line:      2,
			Pattern:   "Token Bombing Attack",
			PatternID: "token_bombing",
			Message:   "LLM API call (Anthropic) without token limits",
		},
		{
			Line:      3,
			Pattern:   "Token Bombing Attack",
			PatternID: "token_bombing",
			Message:   "LLM API call (Unknown) without token limits",
		},
	}

	lines := []string{
		"response = openai.ChatCompletion.create(",  // Real call - keep
		`label = "Anthropic Claude Model"`,           // Config/keyword - filter
		"# Check LLM response",                       // Comment - filter
	}

	filtered := gf.ApplyGuards(findings, lines)

	// Should keep only the real API call
	if len(filtered) != 1 {
		t.Errorf("Expected 1 finding after filtering, got %d", len(filtered))
	}
	if len(filtered) > 0 && filtered[0].Line != 1 {
		t.Errorf("Expected finding from line 1, got line %d", filtered[0].Line)
	}
}

// TestFrameworkReusability - Tests that guard components can be reused by different patterns
func TestFrameworkReusability(t *testing.T) {
	gf1 := NewGuardFramework()
	gf2 := NewGuardFramework()

	// Both frameworks should have independent component instances
	if gf1.GetLLMDetector() == gf2.GetLLMDetector() {
		t.Error("Expected separate LLM detector instances")
	}

	if gf1.GetLoopDetector() == gf2.GetLoopDetector() {
		t.Error("Expected separate loop detector instances")
	}

	if gf1.GetContextFilter() == gf2.GetContextFilter() {
		t.Error("Expected separate context filter instances")
	}

	// But their behavior should be identical
	line := "while True:"
	if gf1.GetLoopDetector().IsUnboundedLoop(line) != gf2.GetLoopDetector().IsUnboundedLoop(line) {
		t.Error("Expected consistent behavior across guard instances")
	}
}

// BenchmarkLLMDetection - Benchmark real LLM call detection
func BenchmarkLLMDetection(b *testing.B) {
	detector := NewLLMPatternDetector()
	testLines := []string{
		"response = openai.ChatCompletion.create(",
		`label = "Anthropic Claude"`,
		"client.messages.create(",
		"# Using bedrock invoke_model",
		"for i in range(100):",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, line := range testLines {
			detector.IsRealLLMCall(line)
		}
	}
}

// BenchmarkLoopDetection - Benchmark loop detection
func BenchmarkLoopDetection(b *testing.B) {
	detector := NewLoopPatternDetector()
	testLines := []string{
		"while True:",
		"for i in range(10):",
		"for(;;) {",
		"foreach (var item in items)",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, line := range testLines {
			if detector.IsUnboundedLoop(line) {
				detector.IsBoundedLoop(line)
			}
		}
	}
}

// BenchmarkContextFiltering - Benchmark context filtering
func BenchmarkContextFiltering(b *testing.B) {
	filter := NewContextFilterEngine()
	testLines := []string{
		`label = "Model"`,
		"# Comment line",
		"response = invoke()",
		"def test_function():",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, line := range testLines {
			filter.IsInString(line)
			filter.IsInComment(line)
			filter.IsConfigContext(line)
			filter.IsTestCode(line)
		}
	}
}
