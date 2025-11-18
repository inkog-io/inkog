package detectors

import (
	"testing"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// TestConfidenceFrameworkInitialization - Verify framework initializes correctly
func TestConfidenceFrameworkInitialization(t *testing.T) {
	cf := NewConfidenceFramework()

	if cf == nil {
		t.Fatal("Failed to create confidence framework")
	}

	// Should have 7 factors
	factors := cf.GetConfidenceFactors()
	if len(factors) != 7 {
		t.Errorf("Expected 7 factors, got %d", len(factors))
	}

	expectedFactors := []string{
		"variable_classification",
		"data_flow_risk",
		"sanitization_presence",
		"execution_context",
		"pattern_specificity",
		"framework_detection",
		"severity_multiplier",
	}

	for i, expectedName := range expectedFactors {
		if i >= len(factors) {
			t.Errorf("Factor %d missing", i)
			continue
		}
		if factors[i].Name != expectedName {
			t.Errorf("Factor %d: expected %s, got %s", i, expectedName, factors[i].Name)
		}
	}

	// Verify weight distribution
	// Note: Total is 0.7 because sanitization factor is -0.15 (reduces confidence)
	totalWeight := float32(0)
	positiveWeight := float32(0)
	negativeWeight := float32(0)

	for _, factor := range factors {
		totalWeight += factor.Weight
		if factor.Weight > 0 {
			positiveWeight += factor.Weight
		} else {
			negativeWeight += factor.Weight
		}
	}

	// Positive weights should sum to 0.85 (all except sanitization)
	expectedPositive := float32(0.85)
	if positiveWeight < expectedPositive-0.01 || positiveWeight > expectedPositive+0.01 {
		t.Errorf("Positive weights should be ~%.2f, got %f", expectedPositive, positiveWeight)
	}

	// Negative weight should be -0.15 (sanitization)
	if negativeWeight > -0.14 || negativeWeight < -0.16 {
		t.Errorf("Negative weights should be ~-0.15, got %f", negativeWeight)
	}

	// Total should be 0.7 (1.0 - 0.15)
	expectedTotal := float32(0.70)
	if totalWeight < expectedTotal-0.01 || totalWeight > expectedTotal+0.01 {
		t.Errorf("Total weight should be ~%.2f, got %f", expectedTotal, totalWeight)
	}
}

// TestConfidenceCalculationBasic - Test basic confidence calculation
func TestConfidenceCalculationBasic(t *testing.T) {
	cf := NewConfidenceFramework()
	context := NewBasicCodeAnalysisContext("test.py", []string{"response = openai.ChatCompletion.create("}, 0)

	finding := &patterns.Finding{
		Line:     1,
		Message:  "LLM API call without token limits",
		Code:     "response = openai.ChatCompletion.create(",
		Severity: "HIGH",
		CVSS:     7.5,
	}

	// Test with various base confidences
	tests := []struct {
		baseConfidence float32
		minExpected    float32
		maxExpected    float32
	}{
		{0.5, 0.3, 0.7},   // Medium base should adjust
		{0.8, 0.6, 1.0},   // High base should stay high
		{0.2, 0.1, 0.5},   // Low base should adjust
	}

	for _, tc := range tests {
		result := cf.CalculateConfidence(tc.baseConfidence, context, finding)

		if result < tc.minExpected || result > tc.maxExpected {
			t.Errorf("Base=%.2f: expected result in [%.2f, %.2f], got %.2f",
				tc.baseConfidence, tc.minExpected, tc.maxExpected, result)
		}

		// Result should always be between 0 and 1
		if result < 0 || result > 1 {
			t.Errorf("Result out of bounds: %.2f", result)
		}
	}
}

// TestConfidenceWithDataFlowRisk - Test confidence calculation with data flow risk
func TestConfidenceWithDataFlowRisk(t *testing.T) {
	cf := NewConfidenceFramework()

	// High risk scenario - untrackedData
	highRiskContext := NewBasicCodeAnalysisContext(
		"test.py",
		[]string{
			"user_input = request.args.get('query')",
			"response = llm.invoke(user_input)",
		},
		1,
	)
	highRiskContext.DataFlow.UntrackedData = []string{"user_input"}
	highRiskContext.DataFlow.TaintedPaths = 5

	finding := &patterns.Finding{
		Line:     2,
		Message:  "Unvalidated user input in LLM call",
		Severity: "CRITICAL",
		CVSS:     9.0,
	}

	highRiskScore := cf.CalculateConfidence(0.8, highRiskContext, finding)

	// Low risk scenario - validated data
	lowRiskContext := NewBasicCodeAnalysisContext(
		"test.py",
		[]string{
			"user_input = request.args.get('query')",
			"validated = sanitize(user_input)",
			"response = llm.invoke(validated)",
		},
		2,
	)
	lowRiskContext.DataFlow.ValidatedData = []string{"validated"}
	lowRiskContext.DataFlow.TaintedPaths = 0

	lowRiskScore := cf.CalculateConfidence(0.8, lowRiskContext, finding)

	// High risk should result in higher confidence
	if highRiskScore <= lowRiskScore {
		t.Errorf("High risk (%.2f) should be higher than low risk (%.2f)",
			highRiskScore, lowRiskScore)
	}
}

// TestConfidenceWithSanitization - Test sanitization reduces confidence
func TestConfidenceWithSanitization(t *testing.T) {
	cf := NewConfidenceFramework()

	noSanitization := NewBasicCodeAnalysisContext(
		"test.py",
		[]string{
			"response = openai.ChatCompletion.create(messages=user_input)",
		},
		0,
	)

	withSanitization := NewBasicCodeAnalysisContext(
		"test.py",
		[]string{
			"safe_input = sanitize(user_input)",
			"response = openai.ChatCompletion.create(messages=safe_input)",
		},
		1,
	)

	finding := &patterns.Finding{
		Line:     1,
		Message:  "LLM call with user input",
		Severity: "HIGH",
		CVSS:     7.5,
	}

	scoreNoSanitization := cf.CalculateConfidence(0.8, noSanitization, finding)
	scoreWithSanitization := cf.CalculateConfidence(0.8, withSanitization, finding)

	// Sanitization should reduce confidence
	if scoreWithSanitization >= scoreNoSanitization {
		t.Errorf("Sanitization should reduce confidence: no_san=%.2f, with_san=%.2f",
			scoreNoSanitization, scoreWithSanitization)
	}
}

// TestConfidenceWithUnboundedLoop - Test unbounded loop increases confidence
func TestConfidenceWithUnboundedLoop(t *testing.T) {
	cf := NewConfidenceFramework()

	boundedLoopContext := NewBasicCodeAnalysisContext(
		"test.py",
		[]string{
			"for i in range(10):",
			"    response = openai.ChatCompletion.create()",
		},
		1,
	)
	boundedLoopContext.ControlFlow.IsUnboundedLoop = false
	boundedLoopContext.ControlFlow.HasBreakCondition = false

	unboundedLoopContext := NewBasicCodeAnalysisContext(
		"test.py",
		[]string{
			"while True:",
			"    response = openai.ChatCompletion.create()",
		},
		1,
	)
	unboundedLoopContext.ControlFlow.IsUnboundedLoop = true
	unboundedLoopContext.ControlFlow.HasBreakCondition = false

	finding := &patterns.Finding{
		Line:     2,
		Message:  "Token Bombing: LLM call in loop",
		Severity: "CRITICAL",
		CVSS:     7.5,
	}

	boundedScore := cf.CalculateConfidence(0.7, boundedLoopContext, finding)
	unboundedScore := cf.CalculateConfidence(0.7, unboundedLoopContext, finding)

	// Unbounded loop should have higher confidence
	if unboundedScore <= boundedScore {
		t.Errorf("Unbounded loop (%.2f) should have higher confidence than bounded (%.2f)",
			unboundedScore, boundedScore)
	}
}

// TestConfidenceWithFrameworkDetection - Test framework detection increases confidence
func TestConfidenceWithFrameworkDetection(t *testing.T) {
	cf := NewConfidenceFramework()
	context := NewBasicCodeAnalysisContext("test.py", []string{"response = agent.invoke()"}, 0)

	// Finding with framework mention
	withFramework := &patterns.Finding{
		Line:     1,
		Message:  "LangChain agent token bombing attack",
		Severity: "HIGH",
		CVSS:     7.5,
	}

	// Finding without framework mention
	withoutFramework := &patterns.Finding{
		Line:     1,
		Message:  "LLM token bombing attack",
		Severity: "HIGH",
		CVSS:     7.5,
	}

	scoreWith := cf.CalculateConfidence(0.7, context, withFramework)
	scoreWithout := cf.CalculateConfidence(0.7, context, withoutFramework)

	// Framework-specific should have higher confidence
	if scoreWith <= scoreWithout {
		t.Errorf("Framework-specific (%.2f) should be higher than generic (%.2f)",
			scoreWith, scoreWithout)
	}
}

// TestCodeAnalysisContextVariableAnalysis - Test variable classification
func TestCodeAnalysisContextVariableAnalysis(t *testing.T) {
	context := NewBasicCodeAnalysisContext("test.py", []string{
		"user_request = request.args.get('query')",
		"safe_config = config['api_key']",
		"computed_value = calculate(x)",
	}, 0)

	context.AnalyzeVariablesInLine(context.Lines[0])
	context.AnalyzeVariablesInLine(context.Lines[1])
	context.AnalyzeVariablesInLine(context.Lines[2])

	// Check user_request is high risk
	userReq, hasUserReq := context.Variables["user_request"]
	if !hasUserReq {
		t.Error("user_request should be analyzed")
	} else if userReq.RiskLevel != "high" {
		t.Errorf("user_request should be high risk, got %s", userReq.RiskLevel)
	}

	// Check safe_config
	safeConfig, hasSafeConfig := context.Variables["safe_config"]
	if !hasSafeConfig {
		t.Error("safe_config should be analyzed")
	} else if !safeConfig.Sanitized {
		t.Error("safe_config should be marked as sanitized")
	}
}

// TestCodeAnalysisContextControlFlow - Test control flow detection
func TestCodeAnalysisContextControlFlow(t *testing.T) {
	unboundedContext := NewBasicCodeAnalysisContext("test.py", []string{
		"while True:",
		"    print('looping')",
	}, 0)
	unboundedContext.DetectControlFlow()

	if !unboundedContext.ControlFlow.IsUnboundedLoop {
		t.Error("Should detect unbounded loop")
	}

	breakContext := NewBasicCodeAnalysisContext("test.py", []string{
		"while True:",
		"    if condition: break",
	}, 1)
	breakContext.DetectControlFlow()

	if !breakContext.ControlFlow.HasBreakCondition {
		t.Error("Should detect break condition")
	}
}

// TestConfidenceEdgeCases - Test edge cases in confidence calculation
func TestConfidenceEdgeCases(t *testing.T) {
	cf := NewConfidenceFramework()

	tests := []struct {
		name           string
		baseConfidence float32
		shouldPass     bool
	}{
		{"negative confidence", -0.5, true},  // Should be clamped to 0.5
		{"confidence above 1", 1.5, true},    // Should be clamped to 0.5
		{"zero confidence", 0.0, true},       // Should be replaced with 0.5
		{"valid low", 0.1, true},             // Valid
		{"valid mid", 0.5, true},             // Valid
		{"valid high", 0.95, true},           // Valid
	}

	finding := &patterns.Finding{
		Line:     1,
		Message:  "Test finding",
		Severity: "MEDIUM",
		CVSS:     5.0,
	}

	for _, tc := range tests {
		result := cf.CalculateConfidence(tc.baseConfidence, nil, finding)

		// Should always return valid confidence between 0 and 1
		if result < 0 || result > 1 {
			t.Errorf("%s: result out of bounds (%.2f)", tc.name, result)
		}
	}
}

// TestConfidenceRecalibration - Test framework can learn from actual accuracy
func TestConfidenceRecalibration(t *testing.T) {
	cf := NewConfidenceFramework()

	// Get initial weights
	initialFactors := cf.GetConfidenceFactors()
	initialWeights := make([]float32, len(initialFactors))
	for i, f := range initialFactors {
		initialWeights[i] = f.Weight
	}

	// Simulate that base confidence was too high
	cf.RecalibrateFromPattern("test_pattern", 0.8, 0.5)

	// Weights should have been reduced
	recalibratedFactors := cf.GetConfidenceFactors()
	weightsReduced := false
	for i, f := range recalibratedFactors {
		if f.Weight > 0 && f.Weight < initialWeights[i] {
			weightsReduced = true
			break
		}
	}

	if !weightsReduced {
		t.Error("Expected weights to be reduced during recalibration")
	}
}

// BenchmarkConfidenceCalculation - Benchmark confidence calculation performance
func BenchmarkConfidenceCalculation(b *testing.B) {
	cf := NewConfidenceFramework()
	context := NewBasicCodeAnalysisContext("test.py", []string{
		"user_input = request.args.get('query')",
		"response = llm.invoke(user_input)",
	}, 1)

	context.DataFlow.UntrackedData = []string{"user_input"}
	context.ControlFlow.IsUnboundedLoop = true

	finding := &patterns.Finding{
		Line:     2,
		Message:  "Unvalidated input in LLM call",
		Severity: "CRITICAL",
		CVSS:     9.0,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cf.CalculateConfidence(0.8, context, finding)
	}
}

// BenchmarkVariableAnalysis - Benchmark variable classification
func BenchmarkVariableAnalysis(b *testing.B) {
	context := NewBasicCodeAnalysisContext("test.py", []string{
		"user_input = request.args.get('query')",
	}, 0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		context.AnalyzeVariablesInLine(context.Lines[0])
	}
}

// BenchmarkControlFlowDetection - Benchmark control flow detection
func BenchmarkControlFlowDetection(b *testing.B) {
	testLines := []string{
		"while True:",
		"for i in range(10):",
		"if condition: break",
		"try: pass",
		"except: pass",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, line := range testLines {
			context := NewBasicCodeAnalysisContext("test.py", []string{line}, 0)
			context.DetectControlFlow()
		}
	}
}
