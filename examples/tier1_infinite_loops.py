"""
TIER 1 - Pattern 3: Infinite Loops & Unbounded Recursion
CWE-835, CWE-674

Demonstrates: while(true), recursion without base cases, missing break conditions.
Risk: CPU exhaustion, API cost explosion, service downtime.
Impact: $270K/year average impact.
"""

from langchain.agents import initialize_agent
import time

# ❌ VULNERABLE: Infinite while loop
def process_forever_vulnerable():
    """Infinite loop without exit condition"""
    while True:
        # Process agent requests
        process_agent_request()
        # No break condition!

# ❌ VULNERABLE: while True loop with faulty break
def retry_forever_vulnerable():
    """Loop with condition that never becomes true"""
    attempts = 0
    while True:
        attempts += 1
        try:
            make_api_call()
            if attempts > 0:  # This is always true!
                break
        except:
            pass  # Silently retry forever

# ❌ VULNERABLE: Unbounded recursion without base case
def recursive_processor_vulnerable(data):
    """Recursion without proper base case"""
    result = process_item(data)
    # No base case!
    return recursive_processor_vulnerable(result)

# ❌ VULNERABLE: Recursion with faulty base case
def recursive_agent_vulnerable(depth):
    """Recursion with condition that never triggers"""
    if depth > 1000:  # Unreachable or extreme limit
        return None

    # Process recursively
    result = process_recursively(depth)
    return recursive_agent_vulnerable(depth + 1)  # Always increases

# ❌ VULNERABLE: Multiple nested infinite loops
class InfiniteLoopAgent:
    """Agent with nested infinite loops"""

    def process_forever(self):
        while True:  # Outer infinite loop
            while True:  # Inner infinite loop
                process_request()
                # No break from either loop

    def accumulate_results(self):
        results = []
        while True:  # Infinite accumulation
            new_results = fetch_results()
            results.extend(new_results)
            # Never stops accumulating

    def retry_logic_broken(self):
        while True:
            try:
                return make_request()
            except:
                # Infinite retries
                continue

# ❌ VULNERABLE: Unbounded list accumulation in loop
def accumulate_forever_vulnerable():
    """Accumulates data in infinite loop"""
    data = []
    while True:
        new_data = fetch_data()
        data.append(new_data)
        # Memory grows unbounded

# ❌ VULNERABLE: Agent delegating to itself
def self_delegating_agent_vulnerable():
    """Agent that delegates to itself"""
    def process_request(request):
        if complex_request(request):
            # Delegate to same agent
            return process_request(request)  # Recursion without end
        return request

    return process_request

# ❌ VULNERABLE: for loop with manual increment that breaks
def loop_with_escape_route_broken():
    """Loop where escape route never executes"""
    for i in range(10):
        while True:
            try:
                process_item(i)
                break
            except:
                # Retries forever
                continue

# ❌ VULNERABLE: Deep recursion without limit
def deeply_recursive_vulnerable(data, level=0):
    """Unbounded recursion"""
    if not data:
        return None

    # Process current level
    result = process_level(data)

    # Recurse without depth limit
    return deeply_recursive_vulnerable(
        result,
        level=level + 1  # No maximum level
    )

# ❌ VULNERABLE: Agent loop with tool calling
class ToolCallingAgent:
    """Agent with infinite tool calling loop"""

    def run_agent(self):
        while True:
            # Get next tool
            tool = self.select_tool()

            # Call tool
            result = self.call_tool(tool)

            # Tool returns another tool to call
            # Infinite chain possible
            self.run_agent()  # Recursive call

    def chain_tools_forever(self):
        """Chain tools with no termination"""
        current_tool = self.initial_tool
        while True:
            result = current_tool()
            # Get next tool from result
            current_tool = result.get('next_tool')
            # No check if next_tool is None/invalid

# ❌ VULNERABLE: Event loop that never exits
def event_processing_loop_vulnerable():
    """Process events in infinite loop"""
    while True:
        events = get_pending_events()
        for event in events:
            process_event(event)
            # No mechanism to stop

# ❌ VULNERABLE: Retry with exponential backoff but no limit
def retry_with_backoff_vulnerable(action):
    """Retries with backoff but no maximum attempts"""
    wait_time = 1
    while True:
        try:
            return action()
        except:
            time.sleep(wait_time)
            wait_time *= 2  # Eventually becomes very large, but never stops

# ❌ VULNERABLE: Generator that never terminates
def infinite_token_generator_vulnerable():
    """Generator that yields forever"""
    tokens = []
    while True:
        token = generate_token()
        tokens.append(token)
        yield token

# ❌ VULNERABLE: Background task without stop condition
class BackgroundWorker:
    """Worker that processes forever"""

    def __init__(self):
        self.running = True

    def start(self):
        while True:  # Infinite loop
            task = self.get_next_task()
            self.process_task(task)
            # self.running is never set to False

    def process_batch(self):
        batch = []
        while True:  # Infinite batch accumulation
            batch.append(self.get_item())

# Helper functions (stubs)
def process_agent_request(): pass
def make_api_call(): pass
def process_item(x): return x
def process_recursively(x): return x
def fetch_results(): return []
def make_request(): return None
def fetch_data(): return None
def complex_request(r): return False
def process_level(x): return x
def get_pending_events(): return []
def process_event(e): pass
def generate_token(): return "token"
def get_next_task(): return None
def process_task(t): pass
def get_item(): return None
def select_tool(): return None
def call_tool(t): return None
def initial_tool(): return {}

if __name__ == "__main__":
    # These will hang/freeze the program
    # process_forever_vulnerable()
    print("Examples of infinite loops created (not executed to avoid hang)")
