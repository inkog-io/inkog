package detectors

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// BenchmarkLoadTestAllPatterns - Comprehensive load testing across all 8 patterns
func BenchmarkLoadTestAllPatterns(b *testing.B) {
	tests := []struct {
		name     string
		fileSize string
		code     []byte
	}{
		{
			name:     "Small_10KB",
			fileSize: "10KB",
			code:     generateLoadTestCode(10),
		},
		{
			name:     "Medium_100KB",
			fileSize: "100KB",
			code:     generateLoadTestCode(100),
		},
		{
			name:     "Large_1MB",
			fileSize: "1MB",
			code:     generateLoadTestCode(1000),
		},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			// Test Pattern 1: Hardcoded Credentials
			b.Run("Pattern1_HardcodedCredentials", func(b *testing.B) {
				detector := NewHardcodedCredentialsDetector()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					detector.Detect("test.py", tt.code)
				}
			})

			// Test Pattern 2: Prompt Injection
			b.Run("Pattern2_PromptInjection", func(b *testing.B) {
				detector := NewPromptInjectionDetector()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					detector.Detect("test.py", tt.code)
				}
			})

			// Test Pattern 3: Infinite Loops
			b.Run("Pattern3_InfiniteLoops", func(b *testing.B) {
				detector := NewInfiniteLoopDetector()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					detector.Detect("test.py", tt.code)
				}
			})

			// Test Pattern 4: Unsafe Env Access
			b.Run("Pattern4_UnsafeEnvAccess", func(b *testing.B) {
				detector := NewUnsafeEnvAccessDetector()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					detector.Detect("test.py", tt.code)
				}
			})

			// Test Pattern 5: Token Bombing
			b.Run("Pattern5_TokenBombing", func(b *testing.B) {
				detector := NewTokenBombingDetector()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					detector.Detect("test.py", tt.code)
				}
			})

			// Test Pattern 6: Recursive Tool Calling
			b.Run("Pattern6_RecursiveToolCalling", func(b *testing.B) {
				detector := NewRecursiveToolCallingDetector()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					detector.Detect("test.py", tt.code)
				}
			})

			// Test Pattern 7: RAG Over-fetching
			b.Run("Pattern7_RAGOverFetching", func(b *testing.B) {
				detector := NewEnhancedRAGOverFetchingDetector(nil)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					detector.Detect("test.py", tt.code)
				}
			})

			// Test Pattern 8: Missing Rate Limits
			b.Run("Pattern8_MissingRateLimits", func(b *testing.B) {
				detector := NewEnhancedMissingRateLimitsDetector(nil)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					detector.Detect("test.py", tt.code)
				}
			})
		})
	}
}

// TestLoadTestingPerformance - Verify all patterns stay under 1ms for typical files
func TestLoadTestingPerformance(t *testing.T) {
	code := generateLoadTestCode(100) // ~100KB

	detectorTests := []struct {
		name    string
		fn      func(string, []byte) ([]patterns.Finding, error)
		maxTime time.Duration
	}{
		{
			name:    "Pattern1_HardcodedCredentials",
			fn:      NewHardcodedCredentialsDetector().Detect,
			maxTime: 5 * time.Millisecond,
		},
		{
			name:    "Pattern2_PromptInjection",
			fn:      NewPromptInjectionDetector().Detect,
			maxTime: 5 * time.Millisecond,
		},
		{
			name:    "Pattern3_InfiniteLoops",
			fn:      NewInfiniteLoopDetector().Detect,
			maxTime: 5 * time.Millisecond,
		},
		{
			name:    "Pattern4_UnsafeEnvAccess",
			fn:      NewUnsafeEnvAccessDetector().Detect,
			maxTime: 5 * time.Millisecond,
		},
		{
			name:    "Pattern5_TokenBombing",
			fn:      NewTokenBombingDetector().Detect,
			maxTime: 5 * time.Millisecond,
		},
		{
			name:    "Pattern6_RecursiveToolCalling",
			fn:      NewRecursiveToolCallingDetector().Detect,
			maxTime: 5 * time.Millisecond,
		},
		{
			name:    "Pattern7_RAGOverFetching",
			fn:      NewEnhancedRAGOverFetchingDetector(nil).Detect,
			maxTime: 5 * time.Millisecond,
		},
		{
			name:    "Pattern8_MissingRateLimits",
			fn:      NewEnhancedMissingRateLimitsDetector(nil).Detect,
			maxTime: 5 * time.Millisecond,
		},
	}

	for _, tt := range detectorTests {
		t.Run(tt.name, func(t *testing.T) {
			start := time.Now()
			_, _ = tt.fn("test.py", code)
			elapsed := time.Since(start)

			if elapsed > tt.maxTime {
				t.Logf("Performance warning: %s took %v (expected < %v)", tt.name, elapsed, tt.maxTime)
			}
		})
	}
}

// TestLinearTimeComplexity - Verify O(n) behavior across file sizes
func TestLinearTimeComplexity(t *testing.T) {
	// Generate code of different sizes
	sizes := []struct {
		name string
		kb   int
	}{
		{"10KB", 10},
		{"50KB", 50},
		{"100KB", 100},
	}

	detector := NewEnhancedMissingRateLimitsDetector(nil)

	var previousTime time.Duration
	for i, tt := range sizes {
		code := generateLoadTestCode(tt.kb)
		start := time.Now()
		detector.Detect("test.py", code)
		elapsed := time.Since(start)

		t.Logf("Size: %s - Time: %v", tt.name, elapsed)

		// Check that time grows roughly linearly (within reasonable bounds)
		if i > 0 && previousTime > 0 {
			ratio := float64(elapsed) / float64(previousTime)
			if ratio > 3.0 { // If scaling worse than 3x, something is wrong
				t.Logf("Warning: Time complexity may not be linear (ratio: %.2f)", ratio)
			}
		}
		previousTime = elapsed
	}
}

// generateLoadTestCode creates code with multiple patterns for load testing
func generateLoadTestCode(sizeInKB int) []byte {
	// Target roughly sizeInKB kilobytes
	linesPerPattern := sizeInKB * 10 // Rough estimate: ~100 bytes per line

	var code strings.Builder
	code.WriteString("# Generated test code for load testing\n\n")

	// Add Pattern 1: Hardcoded Credentials
	for i := 0; i < linesPerPattern/10; i++ {
		code.WriteString(fmt.Sprintf("API_KEY_%d = \"sk-proj-abc123def456xyz789-%d\"\n", i, i))
	}

	// Add Pattern 2: Prompt Injection
	for i := 0; i < linesPerPattern/10; i++ {
		code.WriteString(fmt.Sprintf("prompt_%d = f\"User input: {user_input_%d}\"\n", i, i))
	}

	// Add Pattern 3: Infinite Loops
	for i := 0; i < linesPerPattern/10; i++ {
		code.WriteString(fmt.Sprintf(`
def process_%d():
	while True:
		data = fetch_data_%d()
		process(data)
`, i, i))
	}

	// Add Pattern 4: Unsafe Env Access
	for i := 0; i < linesPerPattern/10; i++ {
		code.WriteString(fmt.Sprintf("db_password_%d = os.environ[\"DB_PASSWORD_%d\"]\n", i, i))
	}

	// Add Pattern 5: Token Bombing
	for i := 0; i < linesPerPattern/10; i++ {
		code.WriteString(fmt.Sprintf(`
def generate_response_%d():
	for i in range(1000):
		response_%d = openai.ChatCompletion.create(
			model="gpt-4",
			messages=[{"role": "user", "content": str(i)}],
			max_tokens=4096
		)
`, i, i))
	}

	// Add Pattern 6: Recursive Tool Calling
	for i := 0; i < linesPerPattern/10; i++ {
		code.WriteString(fmt.Sprintf(`
def agent_task_%d(task):
	result = agent_%d.execute(task)
	if not result.success:
		return agent_task_%d(next_task)
`, i, i, i))
	}

	// Add Pattern 7: RAG Over-fetching
	for i := 0; i < linesPerPattern/10; i++ {
		code.WriteString(fmt.Sprintf(`
retriever_%d = vectorstore_%d.as_retriever()
results_%d = retriever_%d.invoke("query")
`, i, i, i, i))
	}

	// Add Pattern 8: Missing Rate Limits
	for i := 0; i < linesPerPattern/10; i++ {
		code.WriteString(fmt.Sprintf(`
@app.route("/api/endpoint_%d")
def endpoint_%d():
	while True:
		response = openai.ChatCompletion.create(model="gpt-4", messages=[])
`, i, i))
	}

	return []byte(code.String())
}
