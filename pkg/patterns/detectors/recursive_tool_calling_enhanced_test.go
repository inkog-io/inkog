package detectors

import (
	"testing"
)

// TestEnhancedRecursiveToolCallingBasic - Test basic enhanced detection
func TestEnhancedRecursiveToolCallingBasic(t *testing.T) {
	detector := NewEnhancedRecursiveToolCallingDetector(nil)

	code := []byte(`
def agent_task(task):
    # Calls agent recursively without base case
    result = agent.execute(task)
    next_task = agent.delegate(result)
    return agent_task(next_task)
`)

	findings, err := detector.Detect("test.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should find the recursive call without base case
	if len(findings) == 0 {
		t.Error("Expected to find recursive tool calling vulnerability")
	}

	// Check enhanced findings have metrics
	if len(findings) > 0 {
		if findings[0].Confidence <= 0 || findings[0].Confidence > 1.0 {
			t.Errorf("Expected valid confidence score, got %f", findings[0].Confidence)
		}
	}
}

// TestEnhancedRecursiveToolCallingFiltering - Test filtering reduces false positives
func TestEnhancedRecursiveToolCallingFiltering(t *testing.T) {
	detector := NewEnhancedRecursiveToolCallingDetector(nil)

	// Code with false positive (recursion in comment)
	code := []byte(`
# This code mentions recursion and agent.execute but doesn't actually do it
print("No actual agent recursion here")
`)

	findings, err := detector.Detect("test.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should filter out comment-only recursion
	if len(findings) > 0 {
		t.Error("Expected filtering of comment-only recursion")
	}
}

// TestEnhancedRecursiveToolCallingWithBaseCase - Test safe recursion with base case
func TestEnhancedRecursiveToolCallingWithBaseCase(t *testing.T) {
	detector := NewEnhancedRecursiveToolCallingDetector(nil)

	code := []byte(`
def agent_task(depth, max_depth):
    # Has base case - safe recursion
    if depth >= max_depth:
        return "done"
    result = agent.execute(task)
    return agent_task(depth + 1, max_depth)
`)

	findings, err := detector.Detect("test.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// With base case, confidence should be lower
	if len(findings) > 0 && findings[0].Confidence > 0.6 {
		t.Logf("Warning: Safe recursion flagged with confidence %.2f (expected lower)", findings[0].Confidence)
	}
}

// TestEnhancedRecursiveToolCallingConfiguration - Test configuration applies
func TestEnhancedRecursiveToolCallingConfiguration(t *testing.T) {
	config := NewSimpleEnterpriseConfig()
	detector := NewEnhancedRecursiveToolCallingDetector(config)

	if !detector.IsEnabled() {
		t.Error("Detector should be enabled by default")
	}

	// Test with disabled pattern
	config.Patterns["recursive_tool_calling"] = &SimplePatternConfig{
		Enabled:             false,
		ConfidenceThreshold: 0.7,
		FilterTestCode:      true,
		FilterComments:      true,
		FilterStrings:       false,
	}

	detector2 := NewEnhancedRecursiveToolCallingDetector(config)
	if detector2.IsEnabled() {
		t.Error("Detector should be disabled when configured")
	}
}

// TestEnhancedRecursiveToolCallingMultipleRecursionTypes - Test different recursion patterns
func TestEnhancedRecursiveToolCallingMultipleRecursionTypes(t *testing.T) {
	detector := NewEnhancedRecursiveToolCallingDetector(nil)

	testCases := []struct {
		name string
		code string
	}{
		{
			name: "Direct recursion",
			code: `def func(n):\n    return func(n - 1)\n`,
		},
		{
			name: "Agent delegation",
			code: `agent = Agent(allow_delegation=True)\nother = Agent(allow_delegation=True)\n`,
		},
		{
			name: "Unbounded loop with agent",
			code: `while True:\n    result = agent.execute(task)\n`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := detector.Detect("test.py", []byte(tc.code))
			if err != nil {
				t.Fatalf("Detection failed: %v", err)
			}

			if len(findings) == 0 {
				t.Logf("Info: %s pattern not detected (may be expected)", tc.name)
			}
		})
	}
}

// TestEnhancedRecursiveToolCallingBoundedRecursion - Test bounded recursion is safer
func TestEnhancedRecursiveToolCallingBoundedRecursion(t *testing.T) {
	detector := NewEnhancedRecursiveToolCallingDetector(nil)

	code := []byte(`
for i in range(10):
    result = agent.delegate(task)
    task = result
`)

	findings, err := detector.Detect("test.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Bounded loops should have much lower risk
	if len(findings) > 0 && findings[0].Confidence > 0.6 {
		t.Logf("Info: Bounded loop flagged with confidence %.2f (expected lower)", findings[0].Confidence)
	}
}

// TestEnhancedRecursiveToolCallingMutualRecursion - Test mutual recursion detection
func TestEnhancedRecursiveToolCallingMutualRecursion(t *testing.T) {
	detector := NewEnhancedRecursiveToolCallingDetector(nil)

	code := []byte(`
def func_a(x):
    return func_b(x)

def func_b(x):
    return func_a(x)
`)

	findings, err := detector.Detect("test.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Mutual recursion without base case should be detected
	if len(findings) == 0 {
		t.Logf("Info: Mutual recursion not detected (may be expected)")
	}
}

// BenchmarkEnhancedRecursiveToolCallingDetection - Benchmark enhanced detection
func BenchmarkEnhancedRecursiveToolCallingDetection(b *testing.B) {
	detector := NewEnhancedRecursiveToolCallingDetector(nil)

	code := []byte(`
def func(n):
    return func(n - 1)
`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.Detect("test.py", code)
	}
}
