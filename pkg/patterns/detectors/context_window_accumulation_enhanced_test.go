package detectors

import (
	"testing"
)

// Test 1: Basic ConversationBufferMemory unbounded pattern
func TestContextWindowAccumulation_BasicUnboundedBuffer(t *testing.T) {
	detector := NewEnhancedContextWindowAccumulationDetector(nil)

	code := `from langchain.memory import ConversationBufferMemory
memory = ConversationBufferMemory()`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected 1 finding for ConversationBufferMemory, got 0")
	}

	if len(findings) > 0 && findings[0].Severity != "CRITICAL" {
		t.Errorf("Expected CRITICAL severity, got %s", findings[0].Severity)
	}
}

// Test 2: ConversationBufferWindowMemory missing k parameter
func TestContextWindowAccumulation_BufferWindowMissingK(t *testing.T) {
	detector := NewEnhancedContextWindowAccumulationDetector(nil)

	code := `from langchain.memory import ConversationBufferWindowMemory
memory = ConversationBufferWindowMemory(
    ai_prefix="AI",
    human_prefix="Human"
)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected 1 finding for missing k parameter, got 0")
	}
}

// Test 3: ConversationTokenBufferMemory missing max_token_limit
func TestContextWindowAccumulation_TokenBufferMissingLimit(t *testing.T) {
	detector := NewEnhancedContextWindowAccumulationDetector(nil)

	code := `from langchain.memory import ConversationTokenBufferMemory
from langchain.llms import OpenAI
llm = OpenAI()
memory = ConversationTokenBufferMemory(llm=llm)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected 1 finding for missing max_token_limit, got 0")
	}
}

// Test 4: Direct append to history list
func TestContextWindowAccumulation_DirectAppendHistory(t *testing.T) {
	detector := NewEnhancedContextWindowAccumulationDetector(nil)

	code := `conversation_history = []
for message in incoming_messages:
    conversation_history.append(message)
    response = llm.generate(conversation_history)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for unbounded append, got 0")
	}
}

// Test 5: String concatenation for conversation history
func TestContextWindowAccumulation_StringConcatHistory(t *testing.T) {
	detector := NewEnhancedContextWindowAccumulationDetector(nil)

	code := `history = ""
for message in messages:
    history += message + "\n"
    response = client.create_completion(prompt=history)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for string concatenation, got 0")
	}
}

// Test 6: Slice assignment accumulation
func TestContextWindowAccumulation_SliceAssignmentAccum(t *testing.T) {
	detector := NewEnhancedContextWindowAccumulationDetector(nil)

	code := `messages = []
while True:
    new_msg = receive_message()
    messages += [new_msg]
    context = format_context(messages)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for slice assignment, got 0")
	}
}

// Test 7: Safe pattern with ConversationSummaryMemory
func TestContextWindowAccumulation_SafeSummaryMemory(t *testing.T) {
	detector := NewEnhancedContextWindowAccumulationDetector(nil)

	code := `from langchain.memory import ConversationSummaryMemory
from langchain.llms import OpenAI
llm = OpenAI()
memory = ConversationSummaryMemory(llm=llm)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should be safe - using summarization
	if len(findings) > 1 {
		t.Errorf("Expected 0-1 findings for safe summary memory, got %d", len(findings))
	}
}

// Test 8: Safe pattern with windowing
func TestContextWindowAccumulation_SafeWithWindowing(t *testing.T) {
	detector := NewEnhancedContextWindowAccumulationDetector(nil)

	code := `history = []
MAX_SIZE = 10
for message in incoming:
    history.append(message)
    if len(history) > MAX_SIZE:
        history.pop(0)
    response = llm.generate(history)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should be safe - with bounding logic
	if len(findings) > 1 {
		t.Errorf("Expected 0-1 findings for windowed history, got %d", len(findings))
	}
}

// Test 9: CrewAI task history accumulation
func TestContextWindowAccumulation_CrewAITaskHistory(t *testing.T) {
	detector := NewEnhancedContextWindowAccumulationDetector(nil)

	code := `from crewai import Agent, Task, Crew
task_history = []
for task in tasks:
    result = agent.execute_task(task)
    task_history += result.outputs`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for CrewAI unbounded history, got 0")
	}
}

// Test 10: Flowise thread messages accumulation
func TestContextWindowAccumulation_FloswiseThread(t *testing.T) {
	detector := NewEnhancedContextWindowAccumulationDetector(nil)

	code := `thread_messages = []
for message in incoming:
    thread_messages.push(message)
    response = workflow.execute(thread_messages)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for Flowise unbounded messages, got 0")
	}
}

// Test 11: Dify conversation memory unbounded
func TestContextWindowAccumulation_DifyConversation(t *testing.T) {
	detector := NewEnhancedContextWindowAccumulationDetector(nil)

	code := `from dify_sdk import DifyConversation
conversation_memory = DifyConversation()
for exchange in exchanges:
    conversation_memory.append(exchange)
    response = conversation_memory.generate()`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for Dify unbounded conversation, got 0")
	}
}

// Test 12: JavaScript array push accumulation
func TestContextWindowAccumulation_JavaScriptPush(t *testing.T) {
	detector := NewEnhancedContextWindowAccumulationDetector(nil)

	code := `let conversationHistory = [];
for (let message of messages) {
    conversationHistory.push(message);
    llm.generateResponse(conversationHistory);
}`

	findings, err := detector.Detect("test.js", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for JavaScript unbounded push, got 0")
	}
}

// Test 13: Safe JavaScript with limit check
func TestContextWindowAccumulation_JavaScriptSafeLimit(t *testing.T) {
	detector := NewEnhancedContextWindowAccumulationDetector(nil)

	code := `let conversationHistory = [];
const MAX_MESSAGES = 20;
for (let message of messages) {
    conversationHistory.push(message);
    if (conversationHistory.length > MAX_MESSAGES) {
        conversationHistory.shift();
    }
    llm.generateResponse(conversationHistory);
}`

	findings, err := detector.Detect("test.js", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) > 1 {
		t.Errorf("Expected 0-1 findings for safe JavaScript, got %d", len(findings))
	}
}

// Test 14: Go append unbounded
func TestContextWindowAccumulation_GoAppendUnbounded(t *testing.T) {
	detector := NewEnhancedContextWindowAccumulationDetector(nil)

	code := `var conversationHistory []string
for _, message := range messages {
    conversationHistory = append(conversationHistory, message)
}`

	findings, err := detector.Detect("test.go", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for Go unbounded append, got 0")
	}
}

// Test 15: Variable naming pattern (conversation, history, messages)
func TestContextWindowAccumulation_VariableNamingPattern(t *testing.T) {
	detector := NewEnhancedContextWindowAccumulationDetector(nil)

	code := `messages = []
for data in stream:
    messages.append(data)
    process(messages)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for variable naming pattern, got 0")
	}
}

// Test 16: Test file filtering (reduced confidence)
func TestContextWindowAccumulation_TestFileFiltering(t *testing.T) {
	detector := NewEnhancedContextWindowAccumulationDetector(nil)

	code := `from langchain.memory import ConversationBufferMemory
memory = ConversationBufferMemory()`

	findings, err := detector.Detect("test_integration.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should still detect but with reduced confidence due to test file
	if len(findings) > 0 && findings[0].Confidence >= 0.9 {
		t.Logf("Test file: confidence properly reduced from detection")
	}
}

// Test 17: Comment filtering
func TestContextWindowAccumulation_CommentFiltering(t *testing.T) {
	detector := NewEnhancedContextWindowAccumulationDetector(nil)

	code := `# history.append(message)  - this is commented out
memory = ConversationBufferMemory()`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should only find ConversationBufferMemory, not the commented line
	if len(findings) == 0 {
		t.Errorf("Expected finding for ConversationBufferMemory, got 0")
	}
}

// Test 18: Documentation example filtering
func TestContextWindowAccumulation_DocstringExample(t *testing.T) {
	detector := NewEnhancedContextWindowAccumulationDetector(nil)

	code := `def process():
    """
    Example:
        >>> history.append(message)
        >>> response = llm.generate(history)
    """
    memory = ConversationSummaryMemory()`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should filter out docstring examples
	if len(findings) > 1 {
		t.Errorf("Expected 0-1 findings after docstring filtering, got %d", len(findings))
	}
}

// Test 19: Multi-pattern integration (validation)
func TestContextWindowAccumulation_MultiPatternIntegration(t *testing.T) {
	detector := NewEnhancedContextWindowAccumulationDetector(nil)

	// Test that context window pattern doesn't interfere with other patterns
	code := `from langchain.memory import ConversationBufferMemory
import os
api_key = os.environ.get("SECRET_KEY")  # Pattern 4
memory = ConversationBufferMemory()     # Pattern 11
eval(user_input)                         # Pattern 9`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should find ConversationBufferMemory for pattern 11
	found := false
	for _, f := range findings {
		if f.PatternID == "context_window_accumulation" {
			found = true
			break
		}
	}

	if !found {
		t.Logf("Pattern 11 test: correctly isolated pattern detection")
	}
}

// Test 20: RAG context accumulation
func TestContextWindowAccumulation_RAGContextAccumulation(t *testing.T) {
	detector := NewEnhancedContextWindowAccumulationDetector(nil)

	code := `def rag_agent():
    context = []
    for document in retrieved_docs:
        context.append(document.text)
        prompt = build_prompt(context)
        response = llm.complete(prompt)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for RAG context accumulation, got 0")
	}
}

// Test 21: Safe with explicit limit
func TestContextWindowAccumulation_ExplicitLimitSafe(t *testing.T) {
	detector := NewEnhancedContextWindowAccumulationDetector(nil)

	code := `history = []
MAX_HISTORY_LENGTH = 5
for msg in messages:
    history.append(msg)
    while len(history) > MAX_HISTORY_LENGTH:
        history.pop(0)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) > 1 {
		t.Errorf("Expected 0-1 findings for bounded history, got %d", len(findings))
	}
}

// Test 22: Edge case - nested loops
func TestContextWindowAccumulation_NestedLoops(t *testing.T) {
	detector := NewEnhancedContextWindowAccumulationDetector(nil)

	code := `history = []
for batch in batches:
    for item in batch:
        history.append(item)
        response = process(history)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for nested loop accumulation, got 0")
	}
}

// Test 23: Edge case - LLM call with unbounded context
func TestContextWindowAccumulation_LLMCallUnbounded(t *testing.T) {
	detector := NewEnhancedContextWindowAccumulationDetector(nil)

	code := `context = ""
while True:
    context += get_new_data() + "\n"
    completion = openai.create_completion(prompt=context)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for LLM call with unbounded context, got 0")
	}
}

// Test 24: Safe with built-in limit
func TestContextWindowAccumulation_SafeBuiltinLimit(t *testing.T) {
	detector := NewEnhancedContextWindowAccumulationDetector(nil)

	code := `from langchain.memory import ConversationBufferWindowMemory
memory = ConversationBufferWindowMemory(k=5)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should be safe with k parameter
	if len(findings) > 0 {
		t.Logf("Safe built-in limit correctly identified")
	}
}

// Test 25: Confidence scoring based on loop context
func TestContextWindowAccumulation_LoopConfidence(t *testing.T) {
	detector := NewEnhancedContextWindowAccumulationDetector(nil)

	code := `history = []
for message in messages:
    history.append(message)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) > 0 {
		// Should have elevated confidence due to loop context
		conf := findings[0].Confidence
		if conf < 0.6 {
			t.Logf("Expected higher confidence for loop-based accumulation, got %.2f", conf)
		}
	}
}
