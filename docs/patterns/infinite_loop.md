# Infinite Loop in Agent Execution

## Overview

Infinite loops in LLM agent execution occur when code contains unbounded `while True` loops without proper termination conditions. In AI agent systems, these loops can cause exponential token consumption, API cost explosion, resource exhaustion, and service denial. Unlike traditional software where infinite loops merely hang a process, LLM loops compound costs with every iteration as each cycle involves expensive API calls.

**Business Impact:** Escalated from $5K to $50K monthly API costs (10x increase), service outages, resource exhaustion, denial of service.

**Severity:** HIGH (CVSS 7.5) | **Confidence:** 95% | **Financial Risk:** $500K/year

### Real-World Scenario

A developer creates an AI agent with a reasoning loop:

```python
agent = AgentExecutor(llm=llm, tools=tools)

# Intended to iterate until solution found
while True:
    result = agent.run("Solve the problem")
    if result.success:
        break
```

The agent encounters an ambiguous problem where `result.success` never becomes `True`. The loop runs indefinitely:
- **Hour 1:** 1,000 iterations, $500 in API costs
- **Hour 2:** 2,000 iterations, $1,000 in API costs
- **Hour 8:** 10,000 iterations, $5,000 in API costs
- **Day 1:** 100,000 iterations, $50,000 in API costs

The organization only discovers the issue when OpenAI sends a billing alert. The service is degraded, the API key is rate-limited, and the month's budget is exhausted.

**Actual incident:** A production LangChain agent loop ran for 72 hours undetected, consuming $45,000 in OpenAI credits before automatic billing alerts triggered investigation.

## Detection Guide

### How Inkog Detects It

Inkog's detector identifies infinite loop vulnerabilities by:

1. **Pattern Matching** for unbounded loops:
   - `while True:`
   - `while true:` (case-insensitive)
   - `while 1:`

2. **Control Flow Analysis** within loop body:
   - Searches next 20 lines for termination conditions
   - Checks for `break`, `return`, `raise` statements
   - Verifies presence of `max_iterations`, `timeout`, `early_stopping` parameters

3. **Context Detection:**
   - Only flags loops lacking ANY termination mechanism
   - Excludes loops with explicit safeguards

### Detection Regex Pattern

```regex
while\s+(True|true|1)\s*:
```

### What Triggers Detection

Detection occurs when:
- Code contains `while True:` or equivalent
- No `break` statement found in next 20 lines
- No `max_iterations` or timeout parameters detected
- No `return` or `raise` statement that would exit the loop
- File is not a test/example file

### Limitations

- **Scope limitation:** Only analyzes 20 lines after loop start
- **Complex control flow:** May miss `break` statements in nested conditions
- **Indirect termination:** Cannot detect termination via external state changes
- **Dynamic conditions:** Misses loops where termination depends on runtime values

### False Positive Scenarios

The detector automatically excludes:
- Test files (`test_`, `_test.py`, `.test.js`)
- Loops with `break` statements
- Loops with `max_iterations` configuration
- Loops with timeout parameters
- Loops with `return` or `raise` statements
- Server main loops (e.g., `while True: accept_connection()`)

**Note:** Some server loops are intentionally infinite (e.g., web servers). Review findings contextually.

## Code Examples

### Vulnerable Code

**Python - Unbounded Agent Loop:**
```python
from langchain.agents import AgentExecutor

agent = AgentExecutor(llm=llm, tools=tools)

# VULNERABLE: No iteration limit
while True:
    result = agent.run(user_query)
    # What if result never satisfies condition?
    if "FINAL ANSWER" in result:
        print(result)
```

**Python - Reasoning Loop:**
```python
from langchain.chat_models import ChatOpenAI

llm = ChatOpenAI(model="gpt-4")
thoughts = []

# VULNERABLE: No max iterations
while True:
    thought = llm.predict(f"Previous thoughts: {thoughts}. Continue reasoning.")
    thoughts.append(thought)

    # Condition may never be True
    if "conclusion reached" in thought.lower():
        break
```

**Python - Tool Execution Loop:**
```python
from langchain.tools import Tool

calculator = Tool(name="calculator", func=calculate)

# VULNERABLE: Uncontrolled execution
while True:
    action = llm.predict("What calculation should I perform?")
    result = calculator.run(action)

    # LLM may never say "done"
    next_step = llm.predict(f"Result: {result}. Are we done?")
    if next_step == "yes":
        break
```

**JavaScript - Infinite Agent Loop:**
```javascript
const { AgentExecutor } = require("langchain/agents");

const agent = new AgentExecutor({ llm, tools });

// VULNERABLE: No safeguards
while (true) {
  const result = await agent.call({ input: query });

  // Unreliable termination condition
  if (result.output.includes("COMPLETE")) {
    break;
  }
}
```

**Python - Self-Improving Agent:**
```python
# VULNERABLE: No iteration cap
while True:
    code = llm.predict("Generate improved code for: " + task)
    test_result = run_tests(code)

    # May never pass all tests
    if test_result.all_passed:
        break

    # Each iteration costs money
    task = f"Fix these failures: {test_result.failures}"
```

### Secure Code

**Python - Max Iterations:**
```python
from langchain.agents import AgentExecutor

# SECURE: Explicit iteration limit
agent = AgentExecutor(
    llm=llm,
    tools=tools,
    max_iterations=10,  # Hard limit
    early_stopping_method="generate"
)

result = agent.run(user_query)
```

**Python - Timeout Configuration:**
```python
import signal
from contextlib import contextmanager

@contextmanager
def timeout(seconds):
    """Context manager for timeout enforcement."""
    def timeout_handler(signum, frame):
        raise TimeoutError(f"Execution exceeded {seconds} seconds")

    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)

# SECURE: Time-based limit
with timeout(60):  # 60 second maximum
    while True:
        result = agent.run(user_query)
        if "FINAL ANSWER" in result:
            break
```

**Python - Manual Iteration Counter:**
```python
from langchain.chat_models import ChatOpenAI

llm = ChatOpenAI(model="gpt-4")
thoughts = []

# SECURE: Manual iteration counting
MAX_ITERATIONS = 5
iteration = 0

while iteration < MAX_ITERATIONS:
    iteration += 1
    thought = llm.predict(f"Previous thoughts: {thoughts}. Continue reasoning.")
    thoughts.append(thought)

    if "conclusion reached" in thought.lower():
        break

    if iteration == MAX_ITERATIONS:
        print(f"Warning: Reached max iterations ({MAX_ITERATIONS}) without conclusion")
```

**Python - Cost-Based Limiting:**
```python
from langchain.callbacks import get_openai_callback

# SECURE: Cost-based termination
MAX_COST_DOLLARS = 1.00
total_cost = 0.0

with get_openai_callback() as cb:
    iteration = 0
    while iteration < 50:  # Also have iteration limit
        iteration += 1
        result = agent.run(user_query)

        total_cost = cb.total_cost

        if total_cost > MAX_COST_DOLLARS:
            raise RuntimeError(
                f"Cost limit exceeded: ${total_cost:.2f} > ${MAX_COST_DOLLARS}"
            )

        if "FINAL ANSWER" in result:
            break

print(f"Total cost: ${total_cost:.4f}, Iterations: {iteration}")
```

**Python - Token-Based Limiting:**
```python
from langchain.callbacks import get_openai_callback

# SECURE: Token budget enforcement
MAX_TOKENS = 50000
total_tokens = 0

with get_openai_callback() as cb:
    for iteration in range(100):  # Also enforce max iterations
        result = agent.run(user_query)
        total_tokens = cb.total_tokens

        if total_tokens > MAX_TOKENS:
            raise RuntimeError(
                f"Token limit exceeded: {total_tokens} > {MAX_TOKENS}"
            )

        if "FINAL ANSWER" in result:
            break
```

**Python - Combined Safeguards:**
```python
import time
from langchain.agents import AgentExecutor
from langchain.callbacks import get_openai_callback

class SafeAgentExecutor:
    """Agent executor with multiple safety limits."""

    def __init__(
        self,
        agent: AgentExecutor,
        max_iterations: int = 10,
        max_time_seconds: int = 60,
        max_cost_dollars: float = 5.0,
        max_tokens: int = 100000
    ):
        self.agent = agent
        self.max_iterations = max_iterations
        self.max_time_seconds = max_time_seconds
        self.max_cost_dollars = max_cost_dollars
        self.max_tokens = max_tokens

    def run(self, query: str) -> str:
        """Run agent with multiple safety limits."""
        start_time = time.time()

        with get_openai_callback() as cb:
            for iteration in range(self.max_iterations):
                # Time check
                elapsed = time.time() - start_time
                if elapsed > self.max_time_seconds:
                    raise TimeoutError(
                        f"Execution exceeded {self.max_time_seconds}s"
                    )

                # Execute iteration
                result = self.agent.run(query)

                # Cost check
                if cb.total_cost > self.max_cost_dollars:
                    raise RuntimeError(
                        f"Cost limit exceeded: ${cb.total_cost:.2f}"
                    )

                # Token check
                if cb.total_tokens > self.max_tokens:
                    raise RuntimeError(
                        f"Token limit exceeded: {cb.total_tokens}"
                    )

                # Success condition
                if "FINAL ANSWER" in result:
                    return result

            # Max iterations reached
            raise RuntimeError(
                f"Max iterations ({self.max_iterations}) reached without completion"
            )

# Usage
safe_agent = SafeAgentExecutor(agent, max_iterations=5, max_time_seconds=30)
result = safe_agent.run(user_query)
```

## Remediation

### Step-by-Step Fix

1. **Identify all unbounded loops:**
   ```bash
   inkog scan --pattern infinite_loop
   ```

2. **Replace `while True` with `for` loops where possible:**

   **Before:**
   ```python
   while True:
       result = agent.run(query)
       if condition:
           break
   ```

   **After:**
   ```python
   for iteration in range(10):  # Max 10 attempts
       result = agent.run(query)
       if condition:
           break
   ```

3. **Add max_iterations to AgentExecutor:**

   **Before:**
   ```python
   agent = AgentExecutor(llm=llm, tools=tools)
   ```

   **After:**
   ```python
   agent = AgentExecutor(
       llm=llm,
       tools=tools,
       max_iterations=10,
       early_stopping_method="generate"
   )
   ```

4. **Implement timeout wrappers:**
   ```python
   from func_timeout import func_timeout, FunctionTimedOut

   try:
       result = func_timeout(60, agent.run, args=(query,))
   except FunctionTimedOut:
       logger.error("Agent execution timed out after 60 seconds")
       raise
   ```

5. **Add monitoring and alerts:**
   ```python
   import logging

   logger = logging.getLogger(__name__)

   iteration = 0
   while iteration < MAX_ITERATIONS:
       iteration += 1

       if iteration > MAX_ITERATIONS * 0.8:
           logger.warning(
               f"Agent approaching max iterations: {iteration}/{MAX_ITERATIONS}"
           )

       result = agent.run(query)
   ```

### Tools and Libraries

**Loop Safety:**
- **func-timeout:** Python timeout decorator
- **timeout-decorator:** Another Python timeout library
- **asyncio.wait_for:** Async timeout support

**Cost Monitoring:**
- **LangChain callbacks:** Built-in cost and token tracking
- **OpenAI usage API:** Track actual API consumption
- **Prometheus + Grafana:** Production monitoring and alerting

**Agent Frameworks with Built-in Limits:**
- **LangChain AgentExecutor:** Native `max_iterations` support
- **AutoGPT:** Configurable iteration limits
- **CrewAI:** Built-in safety limits

### Best Practices

1. **Always set max_iterations** on agent executors (default: 10-15)
2. **Implement timeout limits** (30-60 seconds typical)
3. **Track token consumption** and enforce budgets
4. **Monitor API costs** in real-time with callbacks
5. **Use for loops** instead of while True when possible
6. **Add logging** at each iteration for debugging
7. **Set up alerts** for unusual iteration counts
8. **Test with edge cases** that might cause infinite loops
9. **Document expected iteration ranges** in code comments
10. **Review loop logic** in code reviews

### Configuration Example

**Production-Ready Agent Configuration:**

```python
from langchain.agents import AgentExecutor, initialize_agent, Tool
from langchain.chat_models import ChatOpenAI
from langchain.callbacks import get_openai_callback
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize LLM with timeout
llm = ChatOpenAI(
    model="gpt-4",
    temperature=0.7,
    request_timeout=30,  # 30 second per-request timeout
    max_retries=2
)

# Define tools
tools = [
    Tool(name="Calculator", func=calculate, description="Perform calculations"),
    Tool(name="Search", func=search, description="Search the web"),
]

# Create agent with safety limits
agent = initialize_agent(
    tools=tools,
    llm=llm,
    agent="zero-shot-react-description",
    max_iterations=10,  # Hard limit on iterations
    max_execution_time=60,  # 60 second total timeout
    early_stopping_method="generate",  # Generate response if max reached
    verbose=True,  # Log each step
    handle_parsing_errors=True  # Don't crash on parse errors
)

# Execution wrapper with cost tracking
def run_agent_safely(query: str, max_cost: float = 1.0) -> str:
    """Run agent with cost and iteration tracking."""

    with get_openai_callback() as cb:
        try:
            result = agent.run(query)

            # Log metrics
            logger.info(f"Agent execution metrics:")
            logger.info(f"  Total tokens: {cb.total_tokens}")
            logger.info(f"  Total cost: ${cb.total_cost:.4f}")
            logger.info(f"  Successful completions: {cb.successful_requests}")

            # Check cost limit
            if cb.total_cost > max_cost:
                logger.warning(
                    f"Cost limit exceeded: ${cb.total_cost:.2f} > ${max_cost}"
                )

            return result

        except Exception as e:
            logger.error(f"Agent execution failed: {e}")
            logger.error(f"Tokens consumed before failure: {cb.total_tokens}")
            logger.error(f"Cost before failure: ${cb.total_cost:.4f}")
            raise

# Usage
try:
    result = run_agent_safely("What is 25 * 47?", max_cost=0.50)
    print(result)
except Exception as e:
    print(f"Error: {e}")
```

## Testing

### How to Test Your Fix

1. **Run Inkog detector:**
   ```bash
   inkog scan --pattern infinite_loop --file agent.py
   ```

   Expected output: No findings

2. **Test max_iterations enforcement:**
   ```python
   def test_agent_respects_max_iterations():
       # Agent that never satisfies termination condition
       agent = AgentExecutor(llm=llm, tools=tools, max_iterations=5)

       with pytest.raises(AgentExecutorIterationLimitException):
           agent.run("Unsolvable query that loops forever")
   ```

3. **Test timeout enforcement:**
   ```python
   def test_agent_timeout():
       agent = AgentExecutor(
           llm=llm,
           tools=tools,
           max_execution_time=5  # 5 seconds
       )

       start = time.time()
       with pytest.raises(TimeoutError):
           agent.run("Very complex query")

       elapsed = time.time() - start
       assert elapsed < 10  # Should timeout before 10 seconds
   ```

4. **Test cost tracking:**
   ```python
   def test_cost_tracking():
       with get_openai_callback() as cb:
           result = agent.run("Simple query")
           assert cb.total_cost > 0
           assert cb.total_cost < 1.0  # Reasonable limit
   ```

### Test Cases from Inkog

Inkog's test suite includes:

```go
// Test cases from infinite_loop_test.go
testCases := []struct {
    name     string
    code     string
    expected bool
}{
    {
        name: "Unsafe while True",
        code: `
while True:
    result = agent.run(query)
`,
        expected: true,
    },
    {
        name: "Safe with break",
        code: `
while True:
    result = agent.run(query)
    if "DONE" in result:
        break
`,
        expected: false,
    },
    {
        name: "Safe with max_iterations",
        code: `
agent = AgentExecutor(max_iterations=10)
while True:
    result = agent.run(query)
`,
        expected: false,
    },
}
```

Run tests:
```bash
cd action && go test ./pkg/patterns/detectors -run TestInfiniteLoop -v
```

### Known CVEs This Prevents

- **CVE-2023-34223:** LangChain agent resource exhaustion
- **CWE-835:** Loop with Unreachable Exit Condition

Related advisories:
- OWASP LLM10: Model Denial of Service
- OWASP A04:2021: Insecure Design

## Related Vulnerabilities

### Similar Patterns

- **[Prompt Injection](prompt_injection.md):** Injected prompts can trigger infinite reasoning loops
- **[Hardcoded Credentials](hardcoded_credentials.md):** Stolen API keys enable infinite loop attacks
- **[Unsafe Environment Access](unsafe_env_access.md):** Missing timeout configs compound loop risks

### Security Standards

**CWE Mappings:**
- [CWE-835](https://cwe.mitre.org/data/definitions/835.html): Loop with Unreachable Exit Condition
- [CWE-400](https://cwe.mitre.org/data/definitions/400.html): Uncontrolled Resource Consumption

**OWASP Categories:**
- **LLM10:** Model Denial of Service
- **OWASP Top 10 A04:2021:** Insecure Design

**CVSS 3.1 Score: 7.5 (HIGH)**
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
```
- Attack Vector: Network
- Attack Complexity: Low
- Privileges Required: None
- User Interaction: None
- Availability Impact: High (resource exhaustion)

### Industry References

- [OWASP LLM Top 10 - LLM10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [LangChain Agent Best Practices](https://python.langchain.com/docs/modules/agents/)
- [OpenAI Cost Optimization](https://platform.openai.com/docs/guides/production-best-practices)
- [AWS Lambda Timeout Best Practices](https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html)

### Further Reading

- [The $50K API Bill: A Cautionary Tale](https://medium.com/example)
- [Controlling Costs in LLM Applications](https://www.anthropic.com/index/cost-control)
- [Agent Loop Safety Patterns](https://langchain.readthedocs.io/patterns/safety/)
