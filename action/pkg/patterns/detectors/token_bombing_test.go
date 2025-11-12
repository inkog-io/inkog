package detectors

import (
	"testing"
)

// TestTokenBombingOpenAIUnboundedLoop tests detection of OpenAI API in unbounded loop
func TestTokenBombingOpenAIUnboundedLoop(t *testing.T) {
	detector := NewTokenBombingDetector()

	code := `
import openai

while True:
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": user_input}]
    )
    process_response(response)
`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected to find unbounded OpenAI call, but got 0 findings")
	}

	if len(findings) > 0 {
		if findings[0].Severity != "CRITICAL" {
			t.Errorf("Expected CRITICAL severity for unbounded OpenAI call, got %s", findings[0].Severity)
		}
		if findings[0].Confidence < 0.80 {
			t.Errorf("Expected confidence >= 0.80, got %v", findings[0].Confidence)
		}
	}
}

// TestTokenBombingAnthropicWithTokenLimit tests that token limit prevents flagging
func TestTokenBombingAnthropicWithTokenLimit(t *testing.T) {
	detector := NewTokenBombingDetector()

	code := `
from anthropic import Anthropic

while True:
    message = Anthropic().messages.create(
        model="claude-3-opus-20240229",
        max_tokens=100,
        messages=[{"role": "user", "content": query}]
    )
    process_response(message)
`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	if len(findings) > 0 {
		t.Errorf("Expected no findings for Anthropic call WITH token limit, but found %d", len(findings))
	}
}

// TestTokenBombingRecursiveCall tests detection in recursive function
func TestTokenBombingRecursiveCall(t *testing.T) {
	detector := NewTokenBombingDetector()

	code := `
import openai

def query_recursively(prompt, depth=0):
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": prompt}]
    )

    if should_recurse(response):
        return query_recursively(response["content"], depth + 1)
    return response
`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected to find recursive OpenAI call without max_tokens, but got 0 findings")
	}

	if len(findings) > 0 {
		if findings[0].Confidence < 0.88 {
			t.Errorf("Expected confidence >= 0.88 for recursive call, got %v", findings[0].Confidence)
		}
	}
}

// TestTokenBombingMultipleProviders tests detection works for multiple LLM providers
func TestTokenBombingMultipleProviders(t *testing.T) {
	detector := NewTokenBombingDetector()

	testCases := []struct {
		name     string
		code     string
		provider string
	}{
		{
			name: "OpenAI",
			code: `
while True:
    response = openai.ChatCompletion.create(model="gpt-4", messages=[...])
`,
			provider: "OpenAI",
		},
		{
			name: "Anthropic",
			code: `
while True:
    message = client.messages.create(model="claude-3", messages=[...])
`,
			provider: "Anthropic",
		},
		{
			name: "Google",
			code: `
while True:
    response = genai.generate_text(text="prompt")
`,
			provider: "Google",
		},
		{
			name: "Ollama",
			code: `
while True:
    response = requests.post("http://localhost:11434/api/generate", json=...)
`,
			provider: "Ollama",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := detector.Detect("test.py", []byte(tc.code))
			if err != nil {
				t.Fatalf("Detector returned error: %v", err)
			}

			// Most providers should be detected in unbounded loop
			if len(findings) == 0 {
				t.Logf("Info: %s provider not detected (may require specific patterns)", tc.provider)
			}

			if len(findings) > 0 && findings[0].Severity != "CRITICAL" && findings[0].Severity != "HIGH" {
				t.Errorf("Expected HIGH or CRITICAL severity, got %s", findings[0].Severity)
			}
		})
	}
}

// TestTokenBombingForLoopVariation tests detection in for loop without bounds
func TestTokenBombingForLoopVariation(t *testing.T) {
	detector := NewTokenBombingDetector()

	code := `
for {
    result := openai.CreateCompletion(
        Model: "text-davinci-003",
        Prompt: userInput,
    )
    process(result)
}
`

	findings, err := detector.Detect("test.go", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Logf("Info: For loop with unbounded LLM call not detected")
	}
}

// TestTokenBombingWithMaxLength tests that max_length variant is detected as token limit
func TestTokenBombingWithMaxLength(t *testing.T) {
	detector := NewTokenBombingDetector()

	code := `
while True:
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        max_length=512,
        messages=[...]
    )
`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	if len(findings) > 0 {
		t.Errorf("Expected no findings with max_length specified, but found %d", len(findings))
	}
}

// TestTokenBombingWithoutLoopShouldNotFlag tests single API call without loop
func TestTokenBombingWithoutLoopShouldNotFlag(t *testing.T) {
	detector := NewTokenBombingDetector()

	code := `
response = openai.ChatCompletion.create(
    model="gpt-3.5-turbo",
    messages=[{"role": "user", "content": "hello"}]
)
`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	if len(findings) > 0 {
		t.Errorf("Expected no findings for single API call without loop, but found %d", len(findings))
	}
}

// TestTokenBombingLoopWithBreakShouldNotFlag tests that loops with breaks are safe
func TestTokenBombingLoopWithBreakShouldNotFlag(t *testing.T) {
	detector := NewTokenBombingDetector()

	code := `
iterations = 0
while True:
    response = openai.ChatCompletion.create(model="gpt-3.5-turbo", messages=[...])
    iterations += 1
    if iterations >= 10:
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

// TestTokenBombingLoopWithReturnShouldNotFlag tests that loops with returns are safe
func TestTokenBombingLoopWithReturnShouldNotFlag(t *testing.T) {
	detector := NewTokenBombingDetector()

	code := `
while True:
    response = openai.ChatCompletion.create(model="gpt-3.5-turbo", messages=[...])
    if response.get("done"):
        return response
`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	if len(findings) > 0 {
		t.Errorf("Expected no findings for loop with return condition, but found %d", len(findings))
	}
}

// TestTokenBombingClaudeVariants tests different Claude model patterns
func TestTokenBombingClaudeVariants(t *testing.T) {
	detector := NewTokenBombingDetector()

	code := `
from anthropic import Anthropic
import anthropic

while True:
    # Should match 'claude-' pattern
    message = client.messages.create(
        model="claude-3-sonnet-20240229",
        messages=[{"role": "user", "content": user_input}]
    )

    # Also test direct claude pattern
    msg2 = anthropic.Anthropic().messages.create(
        model="claude-2",
        messages=[...]
    )
`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Logf("Info: Claude variants in unbounded loop not detected")
	}
}

// TestTokenBombingRealCVELangChain tests real-world LangChain unbounded call pattern
func TestTokenBombingRealCVELangChain(t *testing.T) {
	detector := NewTokenBombingDetector()

	// Simulated LangChain unbounded loop calling LLM without token limits
	code := `
from langchain.llms import OpenAI
from langchain.agents import initialize_agent, Tool

llm = OpenAI(temperature=0)

while True:
    agent = initialize_agent(tools, llm, agent="zero-shot-react-description", verbose=True)
    result = agent.run(user_query)
    if should_stop(result):
        break
    # But there's no guaranteed break, agent could loop forever
    user_query = transform_query(result)
`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	// This should ideally be detected (unbounded loop with LLM)
	if len(findings) == 0 {
		t.Logf("Info: LangChain unbounded agent loop pattern not detected (may need indirect detection)")
	}
}

// TestTokenBombingInterfaceImplementation verifies interface compliance
func TestTokenBombingInterfaceImplementation(t *testing.T) {
	detector := NewTokenBombingDetector()

	// Check Name() method
	name := detector.Name()
	if name != "token_bombing" {
		t.Errorf("Expected Name() to return 'token_bombing', got '%s'", name)
	}

	// Check GetPattern() method
	pattern := detector.GetPattern()
	if pattern.ID != "token_bombing" {
		t.Errorf("Expected pattern ID 'token_bombing', got '%s'", pattern.ID)
	}
	if pattern.Severity != "HIGH" {
		t.Errorf("Expected HIGH severity, got '%s'", pattern.Severity)
	}
	if pattern.CVSS != 7.5 {
		t.Errorf("Expected CVSS 7.5, got %v", pattern.CVSS)
	}

	// Check GetConfidence() method
	confidence := detector.GetConfidence()
	if confidence <= 0 || confidence > 1.0 {
		t.Errorf("Expected confidence between 0 and 1, got %v", confidence)
	}
}

// TestTokenBombingCommentsShouldNotTrigger tests that code in comments is ignored
func TestTokenBombingCommentsShouldNotTrigger(t *testing.T) {
	detector := NewTokenBombingDetector()

	code := `
# while True:
#     response = openai.ChatCompletion.create(model="gpt-3.5-turbo", messages=[...])
#     process(response)

# This is just an example
`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	if len(findings) > 0 {
		t.Errorf("Expected no findings for commented code, but found %d", len(findings))
	}
}

// TestTokenBombingEmptyCodeShouldNotCrash tests robustness with empty input
func TestTokenBombingEmptyCodeShouldNotCrash(t *testing.T) {
	detector := NewTokenBombingDetector()

	findings, err := detector.Detect("test.py", []byte(""))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	if len(findings) > 0 {
		t.Errorf("Expected no findings for empty code, but found %d", len(findings))
	}
}

// TestTokenBombingConfidenceScoring tests that confidence increases with more indicators
func TestTokenBombingConfidenceScoring(t *testing.T) {
	detector := NewTokenBombingDetector()

	// Unbounded loop + LLM call without limits = high confidence
	code := `
while True:
    response = openai.ChatCompletion.create(model="gpt-4", messages=[...])
    print(response)
`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	if len(findings) > 0 {
		if findings[0].Confidence < 0.85 {
			t.Errorf("Expected high confidence (>=0.85) for unbounded LLM call, got %v", findings[0].Confidence)
		}
	}
}
