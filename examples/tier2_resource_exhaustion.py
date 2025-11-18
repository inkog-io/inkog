"""
TIER 2 - Resource Exhaustion Patterns
Combines Patterns 5-9: Token Bombing, Recursive Tools, Context Accumulation,
Missing Rate Limits, RAG Over-Fetching

CWE-400, CWE-770, CWE-674, CWE-835

Risk: Unbounded costs, DoS attacks, service degradation, resource exhaustion.
Impact: $100K+/year in runaway costs.
"""

from langchain.agents import initialize_agent, Tool
from langchain.llms import OpenAI
from anthropic import Anthropic
import time

# ======== PATTERN 5: TOKEN BOMBING ========

class TokenBombingAgent:
    """❌ VULNERABLE: Unbounded LLM API calls"""

    def __init__(self):
        self.llm = OpenAI(temperature=0)
        self.processed_items = 0

    def process_items_vulnerable(self, items):
        """No rate limiting or token budget"""
        results = []
        for item in items:
            # Every item makes unlimited API calls
            response = self.llm(f"Process: {item}")
            results.append(response)
        return results

    def batch_processing_vulnerable(self, batches):
        """Unbounded batches without limits"""
        all_results = []
        for batch in batches:
            for item in batch:
                # No rate limiting
                result = self.llm(f"Analyze {item}")
                all_results.append(result)

    def streaming_analysis_vulnerable(self, data_stream):
        """Infinite streaming without bounds"""
        while True:
            data = data_stream.get_next()
            if not data:
                continue
            # Unlimited API calls
            response = self.llm(f"Process stream: {data}")

# ======== PATTERN 6: RECURSIVE TOOL CALLING ========

class RecursiveToolAgent:
    """❌ VULNERABLE: Agent delegation loops"""

    def __init__(self):
        self.llm = OpenAI(temperature=0)
        self.tools = self.create_tools()

    def create_tools(self):
        """Tools that can delegate to each other"""
        return [
            Tool(
                name="analyze",
                func=self.analyze_tool,
                description="Analyze data and may delegate to other agents"
            ),
            Tool(
                name="process",
                func=self.process_tool,
                description="Process and may delegate back"
            ),
            Tool(
                name="delegate",
                func=self.delegate_tool,
                description="Delegate to another agent"
            ),
        ]

    def analyze_tool(self, data):
        # ❌ VULNERABLE: Can delegate back
        result = self.llm(f"Analyze: {data}")
        if "delegate" in result:
            return self.process_tool(result)  # Circular call
        return result

    def process_tool(self, data):
        # ❌ VULNERABLE: Can delegate back
        result = self.llm(f"Process: {data}")
        if "analyze" in result:
            return self.analyze_tool(result)  # Circular call
        return result

    def delegate_tool(self, task):
        # ❌ VULNERABLE: Self-delegation possible
        if task == "complex":
            return self.delegate_tool("even_more_complex")  # Infinite recursion
        return "done"

    def run_vulnerable(self, task):
        """No recursion depth limit"""
        agent = initialize_agent(
            self.tools,
            self.llm,
            agent="zero-shot-react-description",
            max_iterations=10  # Too high, allows deep recursion
        )
        return agent.run(task)

# ======== PATTERN 7: CONTEXT WINDOW ACCUMULATION ========

class ContextAccumulationAgent:
    """❌ VULNERABLE: Unbounded context growth"""

    def __init__(self):
        self.llm = OpenAI(temperature=0)
        self.conversation_history = []

    def add_to_context_vulnerable(self, message):
        """Unbounded context accumulation"""
        self.conversation_history.append({
            "role": "user",
            "content": message
        })
        # Context grows every turn

    def chat_session_vulnerable(self, num_turns):
        """Multi-turn without context management"""
        for i in range(num_turns):
            user_msg = f"Message {i}"
            self.add_to_context_vulnerable(user_msg)

            # Build entire context each turn
            context = "\n".join([
                f"{msg['role']}: {msg['content']}"
                for msg in self.conversation_history
            ])

            # Context window grows linearly
            response = self.llm(context)

    def long_running_conversation_vulnerable(self):
        """Never clears context"""
        while True:
            user_input = input("Enter message: ")
            self.add_to_context_vulnerable(user_input)
            # Context accumulates unbounded

    def memory_accumulation_vulnerable(self):
        """Stores all results without cleanup"""
        results = []
        for task in get_infinite_tasks():
            result = self.llm(f"Process: {task}")
            results.append(result)  # Never cleared

# ======== PATTERN 8: MISSING RATE LIMITS ========

class MissingRateLimitsAgent:
    """❌ VULNERABLE: Uncontrolled API exposure"""

    def __init__(self):
        self.llm = OpenAI(temperature=0)
        self.request_count = 0

    def process_without_limits_vulnerable(self, requests):
        """No rate limiting"""
        for request in requests:
            result = self.llm(request)
            self.request_count += 1
            # No delay, no limit check

    def concurrent_without_limits_vulnerable(self, tasks):
        """Concurrent requests without throttling"""
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=100) as executor:  # Too many workers
            futures = [
                executor.submit(self.llm, task)
                for task in tasks
            ]
            return [f.result() for f in futures]

    def webhook_handler_vulnerable(self, request):
        """No rate limit on external triggers"""
        # Uncontrolled external calls
        return self.llm(request.body)

# ======== PATTERN 9: RAG OVER-FETCHING ========

class RAGOverFetchingAgent:
    """❌ VULNERABLE: Excessive document retrieval"""

    def __init__(self):
        self.vector_store = MockVectorStore()
        self.llm = OpenAI(temperature=0)

    def fetch_documents_vulnerable(self, query):
        """Over-fetching documents"""
        # Fetch all matching documents without limit
        documents = self.vector_store.search(query, top_k=1000)  # Too many
        return documents

    def rag_query_vulnerable(self, question):
        """RAG without fetch limits"""
        # Fetch excessive documents
        docs = self.vector_store.search(question, top_k=500)  # Over-fetching

        # Include all in context
        context = "\n".join([doc.text for doc in docs])

        # Context becomes huge
        response = self.llm(f"Question: {question}\nContext: {context}")
        return response

    def chunking_without_limits_vulnerable(self, doc):
        """Split documents into too many chunks"""
        chunks = []
        for sentence in doc.split("."):
            # Create chunk for each sentence
            chunks.append(sentence)
        # Thousands of chunks for a single document

        # Fetch all chunks
        for chunk in chunks:
            result = self.vector_store.search(chunk, top_k=100)

    def retrieval_chain_vulnerable(self, query):
        """Multiple retrieval steps without limits"""
        # First retrieval
        docs1 = self.vector_store.search(query, top_k=100)

        # Second retrieval based on first
        for doc in docs1:
            docs2 = self.vector_store.search(doc.text, top_k=100)

        # Third retrieval
        for doc in docs2:
            docs3 = self.vector_store.search(doc.text, top_k=100)

        # Each step fetches 100 more documents

# ======== COMBINED RESOURCE EXHAUSTION ========

class ResourceExhaustionDemo:
    """Combines multiple resource exhaustion patterns"""

    def __init__(self):
        self.llm = OpenAI(temperature=0)
        self.history = []
        self.results = []

    def worst_case_vulnerable(self, num_iterations):
        """Combines all resource exhaustion patterns"""
        for i in range(num_iterations):
            # 1. Token bombing - unlimited API calls
            for batch in range(100):
                response = self.llm(f"Process batch {batch}")

                # 2. Context accumulation
                self.history.append(response)

                # 3. Unbounded results
                self.results.append(response)

                # 4. No rate limiting
                # No sleep, no throttle

                # 5. Recursive delegation
                if batch % 10 == 0:
                    response = self.recursive_process(response)

    def recursive_process(self, data):
        """Unbounded recursion"""
        result = self.llm(f"Recursive: {data}")
        if len(result) > 100:
            return self.recursive_process(result)  # No depth limit
        return result

# Mock helper
class MockVectorStore:
    def search(self, query, top_k=10):
        return [MockDocument() for _ in range(top_k)]

class MockDocument:
    text = "Sample document content"

def get_infinite_tasks():
    """Infinite task generator"""
    counter = 0
    while True:
        yield f"Task {counter}"
        counter += 1

if __name__ == "__main__":
    agent = TokenBombingAgent()
    print("Resource exhaustion patterns created")
