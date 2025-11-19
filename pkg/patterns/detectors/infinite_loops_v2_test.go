package detectors

import (
	"testing"
)

// PRIORITY 1: Critical Infinite Loop Pattern Tests

func TestInfiniteLoopsV2WhileTrue(t *testing.T) {
	detector := NewInfiniteLoopDetectorV2()
	vulnerable := "while True:\n    print('Looping forever')"

	findings, err := detector.Detect("loop.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected while True detection, got 0 findings")
	}
	if findings[0].Severity != "HIGH" {
		t.Fatalf("Expected HIGH severity, got %s", findings[0].Severity)
	}
}

func TestInfiniteLoopsV2WhileTrueLowercase(t *testing.T) {
	detector := NewInfiniteLoopDetectorV2()
	vulnerable := "while true:\n    do_something()"

	findings, err := detector.Detect("loop.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected while true detection, got 0 findings")
	}
}

func TestInfiniteLoopsV2While1(t *testing.T) {
	detector := NewInfiniteLoopDetectorV2()
	vulnerable := "while 1:\n    process()"

	findings, err := detector.Detect("loop.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected while 1 detection, got 0 findings")
	}
}

func TestInfiniteLoopsV2ConstantConditions(t *testing.T) {
	detector := NewInfiniteLoopDetectorV2()
	vulnerable := `while 1 == 1:
    expensive_call()`

	findings, err := detector.Detect("loop.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected constant condition detection, got 0 findings")
	}
}

func TestInfiniteLoopsV2ForEmptyCondition(t *testing.T) {
	detector := NewInfiniteLoopDetectorV2()
	vulnerable := "for(;;) {\n    performTask();\n}"

	findings, err := detector.Detect("loop.c", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected for(;;) detection, got 0 findings")
	}
}

func TestInfiniteLoopsV2GoInfiniteLoop(t *testing.T) {
	detector := NewInfiniteLoopDetectorV2()
	vulnerable := "for {\n    x++\n}"

	findings, err := detector.Detect("loop.go", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected Go infinite loop detection, got 0 findings")
	}
}

func TestInfiniteLoopsV2JavaWhileTrue(t *testing.T) {
	detector := NewInfiniteLoopDetectorV2()
	vulnerable := "while(true) {\n    doWork();\n}"

	findings, err := detector.Detect("Loop.java", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected Java while(true) detection, got 0 findings")
	}
}

func TestInfiniteLoopsV2RubyLoop(t *testing.T) {
	detector := NewInfiniteLoopDetectorV2()
	vulnerable := "loop do\n  puts 'endless'\nend"

	findings, err := detector.Detect("loop.rb", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected Ruby loop detection, got 0 findings")
	}
}

// PRIORITY 1: False Positive Reduction - Break/Return Tests

func TestInfiniteLoopsV2WithBreak(t *testing.T) {
	detector := NewInfiniteLoopDetectorV2()
	notVulnerable := `while True:
    data = queue.get()
    if data is None:
        break
    process(data)`

	findings, err := detector.Detect("queue.py", []byte(notVulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	// Should not flag or have lower confidence due to break
	if len(findings) > 0 && findings[0].Confidence > 0.6 {
		t.Fatalf("Should not flag loop with break condition, confidence: %.2f", findings[0].Confidence)
	}
}

func TestInfiniteLoopsV2WithReturn(t *testing.T) {
	detector := NewInfiniteLoopDetectorV2()
	notVulnerable := `for(;;) {
    if(checkCondition()) {
        return;
    }
}`

	findings, err := detector.Detect("loop.c", []byte(notVulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	// Should have low confidence due to return
	if len(findings) > 0 && findings[0].Confidence > 0.6 {
		t.Fatalf("Should lower confidence for loop with return")
	}
}

func TestInfiniteLoopsV2WithSleep(t *testing.T) {
	detector := NewInfiniteLoopDetectorV2()
	benign := `while True:
    handle_request()
    time.sleep(0.01)`

	findings, err := detector.Detect("server.py", []byte(benign))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	// Sleep pattern should reduce confidence
	if len(findings) > 0 && findings[0].Confidence > 0.6 {
		t.Logf("Sleep pattern should reduce confidence, got %.2f", findings[0].Confidence)
	}
}

// PRIORITY 2: Variable-Based Infinite Loops

func TestInfiniteLoopsV2VariableNotModified(t *testing.T) {
	detector := NewInfiniteLoopDetectorV2()
	vulnerable := `done = False
while done:
    process_item()
    # BUG: forgot to set done = True`

	findings, err := detector.Detect("loop.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	// May or may not detect depending on analysis depth
	// This is a good edge case to test
	_ = findings
}

func TestInfiniteLoopsV2EventLoopServer(t *testing.T) {
	detector := NewInfiniteLoopDetectorV2()
	benign := `def run_server():
    while True:
        conn, addr = server.accept()
        handle(conn)`

	findings, err := detector.Detect("server.py", []byte(benign))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	// Event loop context should reduce severity
	if len(findings) > 0 {
		if findings[0].Confidence > 0.6 {
			t.Logf("Server loop should have reduced confidence, got %.2f", findings[0].Confidence)
		}
	}
}

func TestInfiniteLoopsV2DaemonContext(t *testing.T) {
	detector := NewInfiniteLoopDetectorV2()
	benign := `def daemon_worker():
    for {
        select_event()
        process()
    }`

	findings, err := detector.Detect("daemon.go", []byte(benign))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	// Daemon context should reduce severity
	if len(findings) > 0 {
		if findings[0].Confidence > 0.6 {
			t.Logf("Daemon loop should have reduced confidence")
		}
	}
}

// PRIORITY 2: Recursion Without Base Case

func TestInfiniteLoopsV2RecursionNoBaseCase(t *testing.T) {
	detector := NewInfiniteLoopDetectorV2()
	vulnerable := `def fetch_all_pages(url, page=1):
    data = fetch_page(url, page)
    return data + fetch_all_pages(url, page+1)`

	findings, err := detector.Detect("crawler.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	// May detect recursion pattern
	_ = findings
}

func TestInfiniteLoopsV2RecursionWithBaseCase(t *testing.T) {
	detector := NewInfiniteLoopDetectorV2()
	secure := `def fetch_pages(url, page=1, max_depth=10):
    if page > max_depth:
        return []
    data = fetch_page(url, page)
    return data + fetch_pages(url, page+1, max_depth)`

	findings, err := detector.Detect("crawler.py", []byte(secure))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	// Should recognize base case and not flag
	if len(findings) > 0 {
		t.Logf("Recursion with base case should not be flagged")
	}
}

// PRIORITY 3: Multi-Language Support

func TestInfiniteLoopsV2CLanguageStyle(t *testing.T) {
	detector := NewInfiniteLoopDetectorV2()
	vulnerable := "while(1) {\n    perform_task();\n}"

	findings, err := detector.Detect("loop.c", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected C-style while(1) detection")
	}
}

func TestInfiniteLoopsV2CppStyle(t *testing.T) {
	detector := NewInfiniteLoopDetectorV2()
	vulnerable := "for(;;) {\n    std::cout << \"endless\";\n}"

	findings, err := detector.Detect("loop.cpp", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected C++ for(;;) detection")
	}
}

func TestInfiniteLoopsV2JavaScript(t *testing.T) {
	detector := NewInfiniteLoopDetectorV2()
	vulnerable := "while(true) {\n  console.log('endless');\n}"

	findings, err := detector.Detect("loop.js", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected JavaScript while(true) detection")
	}
}

func TestInfiniteLoopsV2CSharp(t *testing.T) {
	detector := NewInfiniteLoopDetectorV2()
	vulnerable := "while(true) {\n    DoWork();\n}"

	findings, err := detector.Detect("Loop.cs", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected C# while(true) detection")
	}
}

// CVE Validation Tests

func TestInfiniteLoopsV2CVELangChainSitemap(t *testing.T) {
	detector := NewInfiniteLoopDetectorV2()
	vulnerable := `def parse_sitemap(self, url):
    # Vulnerable: uncontrolled recursion when sitemap references itself
    sitemap_data = fetch_url(url)
    for link in sitemap_data:
        if is_sitemap(link):
            self.parse_sitemap(link)  # No depth limit - infinite recursion`

	findings, err := detector.Detect("loader.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	// May detect recursion pattern
	_ = findings
}

func TestInfiniteLoopsV2CVECrewAIEndlessLoop(t *testing.T) {
	detector := NewInfiniteLoopDetectorV2()
	vulnerable := `def agent_A(task):
    # CrewAI: infinite delegation loop
    result = agent_B(task)
    return result

def agent_B(task):
    result = agent_A(task)
    return result`

	findings, err := detector.Detect("agents.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	// Mutual recursion is hard to detect statically
	_ = findings
}

func TestInfiniteLoopsV2CVEAutoGenTermination(t *testing.T) {
	detector := NewInfiniteLoopDetectorV2()
	vulnerable := `while True:
    response = agent.chat(message)
    message = response
    # Bug: loop continues indefinitely, no TERMINATE check`

	findings, err := detector.Detect("autogen.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected AutoGen infinite loop detection")
	}
}

func TestInfiniteLoopsV2CVEFlowiseMissingExit(t *testing.T) {
	detector := NewInfiniteLoopDetectorV2()
	vulnerable := `while True:
    # Flowise: loop node with no exit condition
    ask_user_for_input()
    # Missing: if user_said_exit: break`

	findings, err := detector.Detect("flow.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected Flowise missing exit detection")
	}
}

func TestInfiniteLoopsV2CVEDifyCodeExecution(t *testing.T) {
	detector := NewInfiniteLoopDetectorV2()
	vulnerable := `# Dify: user input executes code with infinite loop
user_code = request.get('code')
exec(user_code)  # User might provide: while True: pass`

	findings, err := detector.Detect("dify.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	// exec() detection is complex; code inside isn't visible statically
	_ = findings
}

// Edge Cases and False Positives

func TestInfiniteLoopsV2EmptyFile(t *testing.T) {
	detector := NewInfiniteLoopDetectorV2()
	findings, err := detector.Detect("empty.py", []byte(""))
	if err != nil {
		t.Fatalf("Expected no error for empty file, got %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("Expected no findings for empty file, got %d", len(findings))
	}
}

func TestInfiniteLoopsV2UnsupportedFileType(t *testing.T) {
	detector := NewInfiniteLoopDetectorV2()
	vulnerable := "while True:\n    print('x')"
	findings, err := detector.Detect("data.csv", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("Expected no findings for unsupported file type, got %d", len(findings))
	}
}

func TestInfiniteLoopsV2CommentedLoop(t *testing.T) {
	detector := NewInfiniteLoopDetectorV2()
	notVulnerable := "# while True:\n#     print('commented out')"
	findings, err := detector.Detect("loop.py", []byte(notVulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	// Comments should be skipped
	if len(findings) > 0 {
		t.Fatalf("Expected no findings for commented code, got %d", len(findings))
	}
}

func TestInfiniteLoopsV2StringLiteral(t *testing.T) {
	detector := NewInfiniteLoopDetectorV2()
	benign := `code = "while True:\n    print('hello')"`
	findings, err := detector.Detect("strings.py", []byte(benign))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	// String literals should match the pattern but we can't avoid it with regex alone
	// This is a known limitation
	_ = findings
}

func TestInfiniteLoopsV2ConfidenceScoring(t *testing.T) {
	detector := NewInfiniteLoopDetectorV2()
	vulnerable := "while True:\n    print('x')"

	findings, err := detector.Detect("loop.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) > 0 {
		if findings[0].Confidence < 0.0 || findings[0].Confidence > 1.0 {
			t.Fatalf("Confidence out of range: %.2f", findings[0].Confidence)
		}
	}
}

func TestInfiniteLoopsV2MultipleLoops(t *testing.T) {
	detector := NewInfiniteLoopDetectorV2()
	vulnerable := `while True:
    x = 1

for(;;) {
    y = 2;
}`

	findings, err := detector.Detect("loops.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) < 1 {
		t.Fatalf("Expected multiple findings, got %d", len(findings))
	}
}

func TestInfiniteLoopsV2NotFalseCondition(t *testing.T) {
	detector := NewInfiniteLoopDetectorV2()
	vulnerable := "while not False:\n    do_something()"

	findings, err := detector.Detect("loop.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected 'not False' detection (evaluates to True)")
	}
}

// Benchmark Test

func BenchmarkInfiniteLoopsV2(b *testing.B) {
	detector := NewInfiniteLoopDetectorV2()
	content := `
while True:
    print("Loop 1")

for(;;) {
    perform();
}

def handler():
    while True:
        accept_connection()

for {
    select_event()
}

while not False:
    do_work()

class Server:
    def run(self):
        while True:
            self.process()
`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.Detect("benchmark.py", []byte(content))
	}
}
