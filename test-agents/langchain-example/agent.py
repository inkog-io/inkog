"""
LangChain AI Agent Example
This agent demonstrates common security vulnerabilities found in AI agents.
"""

import os
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain.chat_models import ChatOpenAI
from langchain.tools import Tool
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder

# ❌ VULNERABILITY 1: Hardcoded API Key (CWE-798)
OPENAI_API_KEY = "sk-proj-1234567890abcdefghij1234567890ab"
STRIPE_API_KEY = "sk_live_abcdefghij1234567890abcdefghijkl"

def create_agent():
    """Create an LangChain agent with security vulnerabilities for testing."""

    # Initialize LLM
    llm = ChatOpenAI(
        model="gpt-4",
        api_key=OPENAI_API_KEY,  # ❌ Hardcoded credential
        temperature=0.7
    )

    # Define tools
    tools = [
        Tool(
            name="search",
            func=search_tool,
            description="Search the web for information"
        ),
        Tool(
            name="database",
            func=database_tool,
            description="Query the database"
        )
    ]

    # Create agent
    agent = create_openai_tools_agent(llm, tools, get_prompt())
    executor = AgentExecutor(agent=agent, tools=tools, verbose=True)

    return executor

def get_prompt():
    """Create agent prompt template."""
    return ChatPromptTemplate.from_messages([
        ("system", "You are a helpful AI assistant."),
        MessagesPlaceholder(variable_name="chat_history"),
        ("human", "{input}")
    ])

def search_tool(query: str) -> str:
    """Search tool implementation."""
    # ❌ VULNERABILITY 2: Prompt Injection (CWE-94)
    # User input directly interpolated into prompt
    prompt = f"""
    Please search for the following user query: {query}
    Remember to be helpful and honest.
    """

    # Simulated API call
    return f"Search results for: {query}"

def database_tool(user_input: str) -> str:
    """Database query tool."""
    # ❌ VULNERABILITY 3: Another Prompt Injection
    system_prompt = f"Execute this query from user: {user_input}"

    # Simulated database query
    return "Query executed"

def process_agent_request(user_query: str):
    """Process a request through the agent."""
    agent = create_agent()

    # ❌ VULNERABILITY 4: Unsafe environment variable access
    # Direct dictionary access without default - will crash if not set
    db_password = os.environ["DATABASE_PASSWORD"]

    # ❌ VULNERABILITY 5: Another hardcoded credential
    jwt_secret = "your-secret-key-12345-super-secret"

    result = agent.run(user_query)
    return result

def vulnerable_loop_example():
    """
    ❌ VULNERABILITY 6: Infinite loop without proper break conditions
    This demonstrates an unbounded loop pattern.
    """
    attempts = 0
    while True:
        print(f"Attempt {attempts}")
        attempts += 1

        # This break is conditional on external state - risky pattern
        if attempts > 1000:  # Arbitrary limit, should use proper conditions
            break

    return attempts

def recursive_agent(depth: int = 0):
    """
    ❌ VULNERABILITY 7: Unbounded recursion without proper base case
    """
    print(f"Recursion depth: {depth}")

    # Recursive call without clear base case
    if depth < 100:  # Arbitrary depth limit
        return recursive_agent(depth + 1)

    return depth

def another_prompt_injection(user_message: str):
    """
    ❌ VULNERABILITY 8: Template string with user input (another injection point)
    """
    instruction = f"User instruction: {user_message}"

    # This could be used as system prompt, leading to injection
    return instruction

def safe_prompt_example(user_input: str):
    """✅ GOOD: Safe way to handle user input"""
    # Use parameterized approach or sanitization
    from html import escape

    sanitized_input = escape(user_input)
    prompt = f"Please help with: {sanitized_input}"

    return prompt

def safe_env_access():
    """✅ GOOD: Safe environment variable access"""
    db_password = os.environ.get("DATABASE_PASSWORD", "default_password")
    if not db_password:
        raise ValueError("DATABASE_PASSWORD not configured")

    return db_password

if __name__ == "__main__":
    # Test the agent
    executor = create_agent()

    # Example usage
    result = executor.invoke({"input": "What is machine learning?"})
    print(result)
