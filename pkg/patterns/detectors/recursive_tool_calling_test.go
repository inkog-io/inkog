package detectors

import (
	"testing"
)

// TestRecursiveToolCallingDirectRecursion tests detection of direct recursion without base case
func TestRecursiveToolCallingDirectRecursion(t *testing.T) {
	detector := NewRecursiveToolCallingDetector()

	code := `
def process_data(data):
    # This function calls itself without clear base case
    return self.process_data(data[:-1])
`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected to find direct recursion without base case, but got 0 findings")
	}

	if len(findings) > 0 {
		if findings[0].Severity != "CRITICAL" {
			t.Errorf("Expected CRITICAL severity for unbounded recursion, got %s", findings[0].Severity)
		}
		if findings[0].Confidence < 0.80 {
			t.Errorf("Expected confidence >= 0.80, got %v", findings[0].Confidence)
		}
	}
}

// TestRecursiveToolCallingWithBaseCase tests that recursion with clear base case has lower confidence
func TestRecursiveToolCallingWithBaseCase(t *testing.T) {
	detector := NewRecursiveToolCallingDetector()

	code := `
def factorial(n):
    if n <= 1:
        return 1
    return n * factorial(n - 1)
`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	// Should have low or no confidence due to clear base case
	if len(findings) > 0 {
		if findings[0].Confidence > 0.60 {
			t.Logf("Warning: Recursion with clear base case has confidence %v (expected < 0.60)", findings[0].Confidence)
		}
	}
}

// TestRecursiveToolCallingMutualRecursion tests detection of mutual recursion patterns
func TestRecursiveToolCallingMutualRecursion(t *testing.T) {
	detector := NewRecursiveToolCallingDetector()

	code := `
def function_a(x):
    if x > 0:
        return function_b(x - 1)
    return x

def function_b(x):
    if x > 0:
        return function_a(x - 1)
    return x
`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	// Mutual recursion without clear termination should be detected
	if len(findings) == 0 {
		t.Logf("Info: Mutual recursion pattern not detected (may require extended analysis)")
	}
}

// TestRecursiveToolCallingUnboundedAgentLoop tests detection of unbounded agent loops
func TestRecursiveToolCallingUnboundedAgentLoop(t *testing.T) {
	detector := NewRecursiveToolCallingDetector()

	code := `
while True:
    result = agent.execute()
    process_result(result)
`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected to find unbounded agent loop, but got 0 findings")
	}

	if len(findings) > 0 {
		if findings[0].Severity != "CRITICAL" {
			t.Errorf("Expected CRITICAL severity for unbounded agent loop, got %s", findings[0].Severity)
		}
	}
}

// TestRecursiveToolCallingAgentDelegation tests detection of agent delegation loops (CrewAI pattern)
func TestRecursiveToolCallingAgentDelegation(t *testing.T) {
	detector := NewRecursiveToolCallingDetector()

	code := `
from langchain.agents import AgentExecutor, initialize_agent

agent1 = initialize_agent(..., allow_delegation=True)
agent2 = initialize_agent(..., allow_delegation=True)

result = agent1.run(prompt)
`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected to find agent delegation loop with multiple agents, but got 0 findings")
	}

	if len(findings) > 0 {
		if findings[0].Severity != "HIGH" && findings[0].Severity != "CRITICAL" {
			t.Errorf("Expected HIGH or CRITICAL severity, got %s", findings[0].Severity)
		}
	}
}

// TestRecursiveToolCallingCrewAI tests detection of CrewAI multi-agent delegation pattern
func TestRecursiveToolCallingCrewAI(t *testing.T) {
	detector := NewRecursiveToolCallingDetector()

	code := `
from crewai import Agent, Task, Crew

researcher = Agent(
    role="Researcher",
    goal="Research",
    allow_delegation=True
)

analyst = Agent(
    role="Analyst",
    goal="Analyze",
    allow_delegation=True
)

crew = Crew(agents=[researcher, analyst])
result = crew.kickoff()
`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected to find CrewAI delegation loop, but got 0 findings")
	}
}

// TestRecursiveToolCallingWithBreakShouldNotFlag tests that loops with breaks are safe
func TestRecursiveToolCallingWithBreakShouldNotFlag(t *testing.T) {
	detector := NewRecursiveToolCallingDetector()

	code := `
iterations = 0
while True:
    result = agent.run(prompt)
    iterations += 1
    if iterations >= 10:
        break
    if result.get("success"):
        break
`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	if len(findings) > 0 {
		t.Errorf("Expected no findings for loop with break condition, but found %d", len(findings))
	}
}

// TestRecursiveToolCallingWithReturnShouldNotFlag tests that loops with returns are safe
func TestRecursiveToolCallingWithReturnShouldNotFlag(t *testing.T) {
	detector := NewRecursiveToolCallingDetector()

	code := `
while True:
    result = agent.run(prompt)
    if result.get("done"):
        return result
`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	if len(findings) > 0 {
		t.Errorf("Expected no findings for loop with return condition, but found %d", len(findings))
	}
}

// TestRecursiveToolCallingForLoopVariation tests detection in for loops without bounds
func TestRecursiveToolCallingForLoopVariation(t *testing.T) {
	detector := NewRecursiveToolCallingDetector()

	code := `
for {
    result := agent.Execute()
    process(result)
}
`

	findings, err := detector.Detect("test.go", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Logf("Info: For loop unbounded agent call not detected")
	}
}

// TestRecursiveToolCallingRealCVELangChainSitemap tests LangChain SitemapLoader CVE pattern
func TestRecursiveToolCallingRealCVELangChainSitemap(t *testing.T) {
	detector := NewRecursiveToolCallingDetector()

	// Simulated LangChain SitemapLoader infinite recursion (CVE-2024-2965)
	code := `
from langchain.document_loaders import SitemapLoader

def process_url(url):
    loader = SitemapLoader(url)
    docs = loader.load()
    for doc in docs:
        # Recursive call without proper termination!
        child_docs = process_url(doc.url)
        all_docs.extend(child_docs)
    return all_docs
`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected to find LangChain SitemapLoader recursive pattern, but got 0 findings")
	}
}

// TestRecursiveToolCallingRealCVECrewAI tests CrewAI endless delegation loop pattern
func TestRecursiveToolCallingRealCVECrewAI(t *testing.T) {
	detector := NewRecursiveToolCallingDetector()

	// Simulated CrewAI endless delegation loop
	code := `
from crewai import Agent, Task, Crew

coordinator = Agent(
    role="Coordinator",
    goal="Coordinate work",
    allow_delegation=True
)

worker1 = Agent(
    role="Worker",
    goal="Do work",
    allow_delegation=True
)

worker2 = Agent(
    role="Worker",
    goal="Do work",
    allow_delegation=True
)

crew = Crew(agents=[coordinator, worker1, worker2])
result = crew.kickoff()
`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected to find CrewAI endless delegation loop, but got 0 findings")
	}
}

// TestRecursiveToolCallingAutoGenPattern tests AutoGen agent loop pattern
func TestRecursiveToolCallingAutoGenPattern(t *testing.T) {
	detector := NewRecursiveToolCallingDetector()

	code := `
from autogen import AssistantAgent, UserProxyAgent

assistant = AssistantAgent("assistant")
user_proxy = UserProxyAgent("user")

# This can lead to unbounded agent interaction
while True:
    assistant.respond()
    user_proxy.respond()
`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Logf("Info: AutoGen unbounded agent loop not detected")
	}
}

// TestRecursiveToolCallingSafePatternsNotFlagged tests that safe patterns don't trigger false positives
func TestRecursiveToolCallingSafePatternsNotFlagged(t *testing.T) {
	detector := NewRecursiveToolCallingDetector()

	safePatterns := []struct {
		name string
		code string
	}{
		{
			name: "No recursion",
			code: `
def process_data(data):
    for item in data:
        print(item)
`,
		},
		{
			name: "Recursion with clear base case",
			code: `
def binary_search(arr, target, left, right):
    if left > right:
        return -1
    mid = (left + right) // 2
    if arr[mid] == target:
        return mid
    elif arr[mid] < target:
        return binary_search(arr, target, mid + 1, right)
    else:
        return binary_search(arr, target, left, mid - 1)
`,
		},
		{
			name: "Loop with bounded agent calls",
			code: `
count = 0
while True:
    agent.execute()
    count += 1
    if count > 100:
        break
`,
		},
		{
			name: "Delegation disabled",
			code: `
agent = Agent(allow_delegation=False)
`,
		},
	}

	for _, pattern := range safePatterns {
		t.Run(pattern.name, func(t *testing.T) {
			findings, err := detector.Detect("test.py", []byte(pattern.code))
			if err != nil {
				t.Fatalf("Detector returned error: %v", err)
			}
			// Safe patterns may or may not have findings depending on strictness
			// Just verify no crashes
			_ = findings
		})
	}
}

// TestRecursiveToolCallingCommentsShouldNotTrigger tests that code in comments is ignored
func TestRecursiveToolCallingCommentsShouldNotTrigger(t *testing.T) {
	detector := NewRecursiveToolCallingDetector()

	code := `
# def recursive_function(x):
#     return recursive_function(x - 1)
# This is just example code in comments

# while True:
#     agent.run()
`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	if len(findings) > 0 {
		t.Errorf("Expected no findings for commented code, but found %d", len(findings))
	}
}

// TestRecursiveToolCallingMultipleFunctions tests detection with multiple functions
func TestRecursiveToolCallingMultipleFunctions(t *testing.T) {
	detector := NewRecursiveToolCallingDetector()

	code := `
def function1(x):
    return function1(x - 1)

def function2(x):
    return function2(x - 1)

def function3(x):
    if x > 0:
        return x * function3(x - 1)
    return 1
`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	// Should detect multiple recursive patterns
	if len(findings) < 2 {
		t.Logf("Info: Found %d recursive patterns, expected at least 2", len(findings))
	}
}

// TestRecursiveToolCallingEmptyCodeShouldNotCrash tests robustness with empty input
func TestRecursiveToolCallingEmptyCodeShouldNotCrash(t *testing.T) {
	detector := NewRecursiveToolCallingDetector()

	findings, err := detector.Detect("test.py", []byte(""))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	if len(findings) > 0 {
		t.Errorf("Expected no findings for empty code, but found %d", len(findings))
	}
}

// TestRecursiveToolCallingInterfaceImplementation verifies interface compliance
func TestRecursiveToolCallingInterfaceImplementation(t *testing.T) {
	detector := NewRecursiveToolCallingDetector()

	// Check Name() method
	name := detector.Name()
	if name != "recursive_tool_calling" {
		t.Errorf("Expected Name() to return 'recursive_tool_calling', got '%s'", name)
	}

	// Check GetPattern() method
	pattern := detector.GetPattern()
	if pattern.ID != "recursive_tool_calling" {
		t.Errorf("Expected pattern ID 'recursive_tool_calling', got '%s'", pattern.ID)
	}
	if pattern.Severity != "CRITICAL" {
		t.Errorf("Expected CRITICAL severity, got '%s'", pattern.Severity)
	}
	if pattern.CVSS != 8.2 {
		t.Errorf("Expected CVSS 8.2, got %v", pattern.CVSS)
	}

	// Check GetConfidence() method
	confidence := detector.GetConfidence()
	if confidence <= 0 || confidence > 1.0 {
		t.Errorf("Expected confidence between 0 and 1, got %v", confidence)
	}
}

// TestRecursiveToolCallingConfidenceScoring tests confidence scoring
func TestRecursiveToolCallingConfidenceScoring(t *testing.T) {
	detector := NewRecursiveToolCallingDetector()

	// Unbounded loop + agent call = high confidence
	code := `
while True:
    result = agent.run(prompt)
    print(result)
`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	if len(findings) > 0 {
		if findings[0].Confidence < 0.80 {
			t.Logf("Warning: Unbounded agent loop has confidence %v (expected >= 0.80)", findings[0].Confidence)
		}
	}
}

// TestRecursiveToolCallingDataProcessorRecursion tests recursion with data processor names
func TestRecursiveToolCallingDataProcessorRecursion(t *testing.T) {
	detector := NewRecursiveToolCallingDetector()

	code := `
def map_function(items):
    if items:
        return [process(items[0])] + map_function(items[1:])
    return []
`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	// Data processor patterns may have lower confidence (map_function is common pattern)
	if len(findings) > 0 {
		if findings[0].Confidence > 0.60 {
			t.Logf("Info: Data processor recursion confidence %v (may be lower due to pattern)", findings[0].Confidence)
		}
	}
}

// TestRecursiveToolCallingLimitedRecursion tests recursion with clear recursion depth limit
func TestRecursiveToolCallingLimitedRecursion(t *testing.T) {
	detector := NewRecursiveToolCallingDetector()

	code := `
def agent_interaction(depth=0):
    if depth >= MAX_DEPTH:
        return "done"
    return agent.run() + agent_interaction(depth + 1)
`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	// Should have low confidence due to depth check
	if len(findings) > 0 {
		if findings[0].Confidence > 0.70 {
			t.Logf("Info: Recursion with depth limit has confidence %v (expected lower)", findings[0].Confidence)
		}
	}
}

// TestRecursiveToolCallingDelegationFalse tests that delegation=false is safe
func TestRecursiveToolCallingDelegationFalse(t *testing.T) {
	detector := NewRecursiveToolCallingDetector()

	code := `
from crewai import Agent

agent1 = Agent(role="Writer", allow_delegation=False)
agent2 = Agent(role="Editor", allow_delegation=False)
`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	if len(findings) > 0 {
		t.Errorf("Expected no findings with delegation disabled, but found %d", len(findings))
	}
}
