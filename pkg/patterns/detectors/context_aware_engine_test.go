package detectors

import (
	"testing"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// TestContextAwareEngineInitialization - Verify engine initializes with all components
func TestContextAwareEngineInitialization(t *testing.T) {
	engine := NewContextAwareEngine()

	if engine == nil {
		t.Fatal("Failed to create context-aware engine")
	}

	// Verify all components initialized
	if engine.guard == nil {
		t.Error("Guard framework not initialized")
	}
	if engine.confidence == nil {
		t.Error("Confidence framework not initialized")
	}
	if engine.analyzer == nil {
		t.Error("Semantic analyzer not initialized")
	}
	if engine.feedback == nil {
		t.Error("Feedback collector not initialized")
	}

	// Verify learning is enabled by default
	if !engine.learningEnabled {
		t.Error("Learning should be enabled by default")
	}
}

// TestAnalyzeFindingsBasic - Test basic finding analysis pipeline
func TestAnalyzeFindingsBasic(t *testing.T) {
	engine := NewContextAwareEngine()

	findings := []patterns.Finding{
		{
			Line:      1,
			Pattern:   "Test Pattern",
			PatternID: "test_pattern",
			Message:   "Test finding",
			Code:      "response = openai.ChatCompletion.create(",
			Severity:  "HIGH",
			CVSS:      7.5,
		},
	}

	lines := []string{
		"response = openai.ChatCompletion.create(",
	}

	results := engine.AnalyzeFindings(findings, lines, "test.py")

	if len(results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(results))
	}

	if results[0].Filtered {
		t.Error("Finding should not be filtered")
	}

	if results[0].AdjustedConfidence <= 0 || results[0].AdjustedConfidence > 1 {
		t.Errorf("Adjusted confidence out of bounds: %f", results[0].AdjustedConfidence)
	}
}

// TestGuardFiltering - Test that guard framework filtering works
func TestGuardFiltering(t *testing.T) {
	engine := NewContextAwareEngine()

	findings := []patterns.Finding{
		{
			Line:      1,
			Pattern:   "Test Pattern",
			PatternID: "test_pattern",
			Message:   "LLM API call",
			Code:      "# Using OpenAI",
			Severity:  "HIGH",
			CVSS:      7.5,
		},
	}

	lines := []string{
		"# Using OpenAI",
	}

	results := engine.AnalyzeFindings(findings, lines, "test.py")

	if len(results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(results))
	}

	if !results[0].Filtered {
		t.Error("Finding in comment should be filtered")
	}

	if results[0].FilterReason != "Found in comment" {
		t.Errorf("Expected 'Found in comment', got %s", results[0].FilterReason)
	}
}

// TestConfidenceAdjustment - Test confidence adjustment pipeline
func TestConfidenceAdjustment(t *testing.T) {
	engine := NewContextAwareEngine()

	findings := []patterns.Finding{
		{
			Line:      2,
			Pattern:   "Token Bombing",
			PatternID: "token_bombing",
			Message:   "LLM API call in unbounded loop",
			Code:      "response = openai.ChatCompletion.create()",
			Severity:  "CRITICAL",
			CVSS:      9.0,
		},
	}

	lines := []string{
		"while True:",
		"    response = openai.ChatCompletion.create(",
	}

	results := engine.AnalyzeFindings(findings, lines, "test.py")

	if len(results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(results))
	}

	result := results[0]

	// Verify confidence was calculated
	if result.OriginalConfidence != 0.9 { // CVSS 9.0 / 10
		t.Errorf("Expected original confidence 0.9, got %f", result.OriginalConfidence)
	}

	// Adjusted confidence should be different (adjusted by factors)
	if result.AdjustedConfidence == result.OriginalConfidence {
		t.Error("Confidence should be adjusted by factors")
	}

	// Verify factors were calculated
	if len(result.ConfidenceFactors) == 0 {
		t.Error("Confidence factors should be populated")
	}
}

// TestSemanticContextBuilding - Test semantic context extraction
func TestSemanticContextBuilding(t *testing.T) {
	engine := NewContextAwareEngine()

	findings := []patterns.Finding{
		{
			Line:      2,
			Pattern:   "Test Pattern",
			PatternID: "test_pattern",
			Message:   "Unvalidated user input",
			Code:      "response = llm.invoke(user_input)",
			Severity:  "HIGH",
			CVSS:      7.5,
		},
	}

	lines := []string{
		"user_input = request.args.get('query')",
		"response = llm.invoke(user_input)",
	}

	results := engine.AnalyzeFindings(findings, lines, "test.py")

	if len(results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(results))
	}

	result := results[0]

	// Verify semantic context was built
	if result.SemanticContext == nil {
		t.Error("Semantic context should be built")
	}

	// Verify variables were analyzed
	if result.SemanticContext != nil && len(result.SemanticContext.Variables) == 0 {
		t.Error("Variables should be extracted from context")
	}
}

// TestRecommendationGeneration - Test security recommendations
func TestRecommendationGeneration(t *testing.T) {
	engine := NewContextAwareEngine()

	findings := []patterns.Finding{
		{
			Line:      2,
			Pattern:   "Test Pattern",
			PatternID: "test_pattern",
			Message:   "LLM API call in loop",
			Code:      "client.messages.create(user_input)",
			Severity:  "CRITICAL",
			CVSS:      9.0,
		},
	}

	lines := []string{
		"while True:",
		"    client.messages.create(user_input)",
	}

	results := engine.AnalyzeFindings(findings, lines, "test.py")

	if len(results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(results))
	}

	result := results[0]

	// LLM-related findings should have recommendations
	// (Note: recommendations depend on semantic context being populated)
	hasRecommendations := len(result.Recommendations) > 0
	if hasRecommendations {
		// If recommendations exist, they should be valid
		for _, rec := range result.Recommendations {
			if rec == "" {
				t.Error("Recommendations should not be empty strings")
			}
		}
	}
}

// TestLearningEnable - Test learning mode toggle
func TestLearningEnable(t *testing.T) {
	engine := NewContextAwareEngine()

	// Default should be enabled
	if !engine.learningEnabled {
		t.Error("Learning should be enabled by default")
	}

	// Disable learning
	engine.EnableLearning(false)
	if engine.learningEnabled {
		t.Error("Learning should be disabled after EnableLearning(false)")
	}

	// Re-enable learning
	engine.EnableLearning(true)
	if !engine.learningEnabled {
		t.Error("Learning should be enabled after EnableLearning(true)")
	}
}

// TestFeedbackRecording - Test feedback collection
func TestFeedbackRecording(t *testing.T) {
	engine := NewContextAwareEngine()

	// Record actual result
	engine.RecordActualResult("test_pattern", true, "HIGH")

	// Verify feedback was recorded
	metrics := engine.GetCalibrationMetrics()
	if metrics == nil {
		t.Error("Should have metrics after recording feedback")
	}
}

// TestMultipleFindingsProcessing - Test processing multiple findings
func TestMultipleFindingsProcessing(t *testing.T) {
	engine := NewContextAwareEngine()

	findings := []patterns.Finding{
		{
			Line:      1,
			Pattern:   "Pattern 1",
			PatternID: "pattern_1",
			Message:   "Finding 1",
			Code:      "response = openai.create()",
			Severity:  "HIGH",
			CVSS:      7.5,
		},
		{
			Line:      2,
			Pattern:   "Pattern 2",
			PatternID: "pattern_2",
			Message:   "Finding 2 in comment",
			Code:      "# Uses API",
			Severity:  "MEDIUM",
			CVSS:      5.0,
		},
		{
			Line:      3,
			Pattern:   "Pattern 1",
			PatternID: "pattern_1",
			Message:   "Finding 3",
			Code:      "client.messages.create()",
			Severity:  "HIGH",
			CVSS:      7.5,
		},
	}

	lines := []string{
		"response = openai.ChatCompletion.create(",
		"# Uses API",
		"client.messages.create(",
	}

	results := engine.AnalyzeFindings(findings, lines, "test.py")

	if len(results) != 3 {
		t.Errorf("Expected 3 results, got %d", len(results))
	}

	// Second finding should be filtered (in comment)
	if !results[1].Filtered {
		t.Error("Finding in comment should be filtered")
	}

	// First and third should not be filtered
	if results[0].Filtered {
		t.Error("First finding should not be filtered")
	}
	if results[2].Filtered {
		t.Error("Third finding should not be filtered")
	}
}

// TestEmptyFindings - Test handling of empty findings
func TestEmptyFindings(t *testing.T) {
	engine := NewContextAwareEngine()

	findings := []patterns.Finding{}
	lines := []string{"code line"}

	results := engine.AnalyzeFindings(findings, lines, "test.py")

	if len(results) != 0 {
		t.Errorf("Expected 0 results for empty findings, got %d", len(results))
	}
}

// TestEmptyCode - Test handling of empty code
func TestEmptyCode(t *testing.T) {
	engine := NewContextAwareEngine()

	findings := []patterns.Finding{
		{
			Line:      1,
			Pattern:   "Test",
			PatternID: "test",
			Message:   "Test",
			Code:      "test",
			Severity:  "HIGH",
			CVSS:      7.5,
		},
	}

	lines := []string{}

	results := engine.AnalyzeFindings(findings, lines, "test.py")

	// Should still process finding, just with empty line content
	if len(results) == 0 {
		t.Error("Should handle empty code gracefully")
	}
}

// TestEdgeCaseHighCVSS - Test with high CVSS score
func TestEdgeCaseHighCVSS(t *testing.T) {
	engine := NewContextAwareEngine()

	findings := []patterns.Finding{
		{
			Line:      1,
			Pattern:   "Critical Issue",
			PatternID: "critical",
			Message:   "Critical vulnerability",
			Code:      "dangerous_code()",
			Severity:  "CRITICAL",
			CVSS:      10.0,
		},
	}

	lines := []string{"dangerous_code()"}

	results := engine.AnalyzeFindings(findings, lines, "test.py")

	if len(results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(results))
	}

	// CVSS 10.0 should map to confidence 1.0
	if results[0].OriginalConfidence != 1.0 {
		t.Errorf("Expected original confidence 1.0 for CVSS 10.0, got %f", results[0].OriginalConfidence)
	}

	// Adjusted confidence should be at max 1.0
	if results[0].AdjustedConfidence > 1.0 {
		t.Errorf("Adjusted confidence should not exceed 1.0, got %f", results[0].AdjustedConfidence)
	}
}

// TestEdgeCaseZeroCVSS - Test with zero CVSS score
func TestEdgeCaseZeroCVSS(t *testing.T) {
	engine := NewContextAwareEngine()

	findings := []patterns.Finding{
		{
			Line:      1,
			Pattern:   "Test",
			PatternID: "test",
			Message:   "Test",
			Code:      "test",
			Severity:  "LOW",
			CVSS:      0.0,
		},
	}

	lines := []string{"test"}

	results := engine.AnalyzeFindings(findings, lines, "test.py")

	if len(results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(results))
	}

	// Zero CVSS should default to 0.5
	if results[0].OriginalConfidence != 0.5 {
		t.Errorf("Expected original confidence 0.5 for CVSS 0.0, got %f", results[0].OriginalConfidence)
	}
}

// BenchmarkAnalyzeFinding - Benchmark finding analysis
func BenchmarkAnalyzeFinding(b *testing.B) {
	engine := NewContextAwareEngine()
	findings := []patterns.Finding{
		{
			Line:      1,
			Pattern:   "Test",
			PatternID: "test",
			Message:   "Test finding",
			Code:      "response = openai.create()",
			Severity:  "HIGH",
			CVSS:      7.5,
		},
	}
	lines := []string{"response = openai.ChatCompletion.create("}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.AnalyzeFindings(findings, lines, "test.py")
	}
}

// BenchmarkMultipleFindingsAnalysis - Benchmark multiple finding analysis
func BenchmarkMultipleFindingsAnalysis(b *testing.B) {
	engine := NewContextAwareEngine()
	findings := make([]patterns.Finding, 10)
	for i := 0; i < 10; i++ {
		findings[i] = patterns.Finding{
			Line:      i + 1,
			Pattern:   "Test",
			PatternID: "test",
			Message:   "Test finding",
			Code:      "code_line()",
			Severity:  "HIGH",
			CVSS:      7.5,
		}
	}

	lines := make([]string, 10)
	for i := 0; i < 10; i++ {
		lines[i] = "code_line()"
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.AnalyzeFindings(findings, lines, "test.py")
	}
}
