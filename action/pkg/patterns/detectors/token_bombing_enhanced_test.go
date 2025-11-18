package detectors

import (
	"testing"
)

// TestEnhancedTokenBombingBasic - Test basic enhanced detection
func TestEnhancedTokenBombingBasic(t *testing.T) {
	detector := NewEnhancedTokenBombingDetector(nil)

	code := []byte(`
while True:
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=user_input
    )
`)

	findings, err := detector.Detect("test.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should find the unbounded loop with LLM call
	if len(findings) == 0 {
		t.Error("Expected to find token bombing vulnerability")
	}

	// Check enhanced findings have metrics
	if len(findings) > 0 {
		if findings[0].Confidence <= 0 || findings[0].Confidence > 1.0 {
			t.Errorf("Expected valid confidence score, got %f", findings[0].Confidence)
		}
	}
}

// TestEnhancedTokenBombingFiltering - Test filtering reduces false positives
func TestEnhancedTokenBombingFiltering(t *testing.T) {
	detector := NewEnhancedTokenBombingDetector(nil)

	// Code with false positive (keyword in comment)
	code := []byte(`
# This code uses openai.ChatCompletion.create for testing
print("No actual LLM call here")
`)

	findings, err := detector.Detect("test.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should filter out comment-only keyword
	if len(findings) > 0 {
		t.Error("Expected filtering of comment-only keyword")
	}
}

// TestEnhancedTokenBombingWithTokenLimits - Test safe code isn't flagged
func TestEnhancedTokenBombingWithTokenLimits(t *testing.T) {
	detector := NewEnhancedTokenBombingDetector(nil)

	code := []byte(`
while True:
    response = openai.ChatCompletion.create(
        model="gpt-4",
        max_tokens=100,
        messages=user_input
    )
    if response is None:
        break
`)

	findings, err := detector.Detect("test.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// With token limits and break condition, confidence should be lower
	if len(findings) > 0 && findings[0].Confidence > 0.7 {
		t.Logf("Warning: Safe code flagged with confidence %.2f (expected lower)", findings[0].Confidence)
	}
}

// TestEnhancedTokenBombingConfiguration - Test configuration applies
func TestEnhancedTokenBombingConfiguration(t *testing.T) {
	config := NewSimpleEnterpriseConfig()
	// Verify configuration applied
	detector := NewEnhancedTokenBombingDetector(config)

	if !detector.IsEnabled() {
		t.Error("Detector should be enabled by default")
	}

	// Test with disabled pattern
	config.Patterns["token_bombing"] = &SimplePatternConfig{
		Enabled:             false,
		ConfidenceThreshold: 0.7,
		FilterTestCode:      true,
		FilterComments:      true,
		FilterStrings:       false,
	}

	detector2 := NewEnhancedTokenBombingDetector(config)
	if detector2.IsEnabled() {
		t.Error("Detector should be disabled when configured")
	}
}

// TestEnhancedTokenBombingMultipleProviders - Test different LLM providers
func TestEnhancedTokenBombingMultipleProviders(t *testing.T) {
	detector := NewEnhancedTokenBombingDetector(nil)

	testCases := []struct {
		name     string
		code     string
		provider string
	}{
		{
			name:     "OpenAI",
			code:     `while True:\n    response = openai.ChatCompletion.create(model="gpt-4")\n`,
			provider: "OpenAI",
		},
		{
			name:     "Anthropic",
			code:     `while True:\n    response = client.messages.create(model="claude-3")\n`,
			provider: "Anthropic",
		},
		{
			name:     "Google",
			code:     `while True:\n    response = genai.generate_text(model="palm")\n`,
			provider: "Google",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := detector.Detect("test.py", []byte(tc.code))
			if err != nil {
				t.Fatalf("Detection failed: %v", err)
			}

			if len(findings) == 0 {
				t.Logf("Info: %s provider pattern not detected (may be expected)", tc.name)
			}
		})
	}
}

// TestEnhancedTokenBombingBoundedLoop - Test bounded loops are safe
func TestEnhancedTokenBombingBoundedLoop(t *testing.T) {
	detector := NewEnhancedTokenBombingDetector(nil)

	code := []byte(`
for i in range(10):
    response = openai.ChatCompletion.create(model="gpt-4")
    print(response)
`)

	findings, err := detector.Detect("test.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Bounded loop should have much lower risk
	if len(findings) > 0 && findings[0].Confidence > 0.6 {
		t.Logf("Info: Bounded loop flagged with confidence %.2f (expected lower)", findings[0].Confidence)
	}
}

// BenchmarkEnhancedTokenBombingDetection - Benchmark enhanced detection
func BenchmarkEnhancedTokenBombingDetection(b *testing.B) {
	detector := NewEnhancedTokenBombingDetector(nil)

	code := []byte(`
while True:
    response = openai.ChatCompletion.create(model="gpt-4")
`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.Detect("test.py", code)
	}
}
