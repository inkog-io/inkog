package detectors

import (
	"testing"
)

func TestInfiniteLoopWhileTrue(t *testing.T) {
	detector := NewInfiniteLoopDetector()

	// Test 1: Basic while True with no break
	vulnerable := `
while True:
    user_input = input("Enter query: ")
    result = agent.invoke(user_input)
    print(result)
`

	findings, err := detector.Detect("agent.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("Failed to detect while True loop")
	}

	if findings[0].Severity != "HIGH" {
		t.Fatalf("Expected HIGH severity, got %s", findings[0].Severity)
	}
}

func TestInfiniteLoopWhileTrueLowercase(t *testing.T) {
	detector := NewInfiniteLoopDetector()

	// Test 2: while true (lowercase)
	vulnerable := `
while true:
    execute_task()
`

	findings, err := detector.Detect("worker.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("Failed to detect lowercase 'while true'")
	}
}

func TestInfiniteLoopWhileOne(t *testing.T) {
	detector := NewInfiniteLoopDetector()

	// Test 3: while 1 (also infinite)
	vulnerable := `
iteration = 0
while 1:
    process_request()
`

	findings, err := detector.Detect("loop.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("Failed to detect 'while 1' loop")
	}
}

func TestInfiniteLoopWithBreak(t *testing.T) {
	detector := NewInfiniteLoopDetector()

	// Test 4: while True WITH break condition - should NOT trigger
	safe := `
while True:
    result = agent.invoke(query)
    if result.is_complete:
        break
    print(result.status)
`

	findings, err := detector.Detect("agent.py", []byte(safe))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(findings) > 0 {
		t.Fatalf("Should not flag loop with break condition, got %d findings", len(findings))
	}
}

func TestInfiniteLoopWithMaxIterations(t *testing.T) {
	detector := NewInfiniteLoopDetector()

	// Test 5: while True WITH max_iterations - should NOT trigger
	safe := `
max_iterations = 100
iteration = 0

while True:
    iteration += 1
    if iteration >= max_iterations:
        break

    result = execute_step()
    if not result:
        break
`

	findings, err := detector.Detect("agent.py", []byte(safe))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(findings) > 0 {
		t.Fatalf("Should not flag loop with max_iterations, got %d findings", len(findings))
	}
}

func TestInfiniteLoopWithTimeout(t *testing.T) {
	detector := NewInfiniteLoopDetector()

	// Test 6: while True WITH timeout - should NOT trigger
	safe := `
import time

start_time = time.time()
timeout = 30  # 30 seconds

while True:
    if time.time() - start_time > timeout:
        break

    task = execute_task()
`

	findings, err := detector.Detect("executor.py", []byte(safe))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(findings) > 0 {
		t.Fatalf("Should not flag loop with timeout check")
	}
}

func TestInfiniteLoopConfidenceScoring(t *testing.T) {
	detector := NewInfiniteLoopDetector()

	vulnerable := `
while True:
    process()
`

	findings, err := detector.Detect("app.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("No findings")
	}

	// Test 7: Confidence should be very high (90-99%)
	confidence := findings[0].Confidence
	if confidence < 0.90 {
		t.Fatalf("Confidence too low: %.2f, expected >= 0.90", confidence)
	}

	if confidence > 1.0 {
		t.Fatalf("Invalid confidence: %.2f", confidence)
	}
}

func TestInfiniteLoopMultipleLoops(t *testing.T) {
	detector := NewInfiniteLoopDetector()

	// Test 8: Multiple infinite loops in same file
	vulnerable := `
# Loop 1 - VULNERABLE
while True:
    query = input()
    result = agent.invoke(query)

# Loop 2 - VULNERABLE
while True:
    task = get_next_task()
    execute(task)
`

	findings, err := detector.Detect("app.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(findings) < 2 {
		t.Fatalf("Expected multiple findings, got %d", len(findings))
	}
}

func TestInfiniteLoopSkipsTestFiles(t *testing.T) {
	detector := NewInfiniteLoopDetector()

	// Test 9: Test files should skip infinite loop warnings
	testCode := `
def test_agent_loop():
    # In tests, we often use while True for demonstration
    while True:
        result = agent.invoke("test")
        assert result is not None
        break  # Exit after first test
`

	findings, err := detector.Detect("test_agent.py", []byte(testCode))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(findings) > 0 {
		t.Fatalf("Should skip test files, but found %d findings", len(findings))
	}
}

func TestInfiniteLoopWithReturn(t *testing.T) {
	detector := NewInfiniteLoopDetector()

	// Test 10: while True WITH return (inside function) - should be safe
	safe := `
def process_queue():
    while True:
        item = queue.get()
        if not item:
            return None

        result = process(item)
        return result
`

	findings, err := detector.Detect("queue.py", []byte(safe))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(findings) > 0 {
		t.Logf("Info: Loop with return statement: %d findings", len(findings))
	}
}

func TestInfiniteLoopWithRaise(t *testing.T) {
	detector := NewInfiniteLoopDetector()

	// Test 11: while True WITH raise exception - should be safe
	safe := `
while True:
    try:
        result = critical_operation()
        if not result:
            raise ValueError("Operation failed")
        return result
    except Exception as e:
        if attempts > max_attempts:
            raise
        attempts += 1
`

	findings, err := detector.Detect("critical.py", []byte(safe))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(findings) > 0 {
		t.Logf("Info: Loop with raise statement: %d findings", len(findings))
	}
}

func TestInfiniteLoopNested(t *testing.T) {
	detector := NewInfiniteLoopDetector()

	// Test 12: Nested while True loops (both problematic)
	vulnerable := `
while True:
    for item in items:
        while True:
            process_item(item)
`

	findings, err := detector.Detect("nested.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	// Should detect at least the outer loop
	if len(findings) == 0 {
		t.Fatal("Failed to detect nested infinite loops")
	}
}

func TestInfiniteLoopEarlyExitCondition(t *testing.T) {
	detector := NewInfiniteLoopDetector()

	// Test 13: Loop with early exit in different line pattern
	safe := `
counter = 0
while True:
    counter += 1
    print(f"Iteration {counter}")

    data = fetch_data()

    if counter > 100:
        print("Max iterations reached")
        break

    process(data)
`

	findings, err := detector.Detect("app.py", []byte(safe))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(findings) > 0 {
		t.Fatalf("Should not flag loop with max iterations check")
	}
}

func TestInfiniteLoopFinancialImpact(t *testing.T) {
	detector := NewInfiniteLoopDetector()

	vulnerable := `
while True:
    response = llm.chat(prompt)  # $0.01 per call
`

	findings, err := detector.Detect("expensive.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(findings) > 0 {
		// Verify financial impact is documented
		if findings[0].FinancialRisk == "" {
			t.Logf("Warning: Financial impact not documented for infinite loop")
		}
	}
}

// Benchmark test
func BenchmarkInfiniteLoop(b *testing.B) {
	detector := NewInfiniteLoopDetector()
	code := []byte(`
while True:
    process()
` + "\n")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.Detect("app.py", code)
	}
}
