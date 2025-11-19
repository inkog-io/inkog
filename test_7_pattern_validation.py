#!/usr/bin/env python3
"""
Multi-Pattern Validation Test for Inkog Scanner MVP with Pattern 7
Tests all 7 patterns working together with real-world vulnerability samples
"""

# ============================================================================
# PATTERN 1: Hardcoded Credentials
# ============================================================================

# Real example - hardcoded API keys
OPENAI_API_KEY = "sk-proj-1234567890abcdefghijklmnop"
ANTHROPIC_API_KEY = "sk-ant-abcdefghijklmnop"
DB_PASSWORD = "admin_password_123"

# ============================================================================
# PATTERN 2: Prompt Injection
# ============================================================================

def process_user_request(user_input):
    """Vulnerable: directly interpolates user input"""
    system_prompt = "You are a helpful assistant."
    user_message = f"User request: {user_input}"

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_message}
    ]

    response = client.messages.create(
        model="claude-3-sonnet",
        messages=messages
    )
    return response

# ============================================================================
# PATTERN 3: Infinite Loops
# ============================================================================

def retry_loop_unbounded(task):
    """Vulnerable: while True without proper break"""
    while True:
        try:
            response = client.messages.create(
                model="claude-3",
                messages=[{"role": "user", "content": task}]
            )
            # No break condition - VULNERABLE
            return response.content
        except Exception as e:
            print(f"Error: {e}")
            # Just keeps retrying forever

# ============================================================================
# PATTERN 4: Unsafe Environment Access
# ============================================================================

import os

# Vulnerable: No default values
database_url = os.getenv("DATABASE_URL")
api_key = os.environ["OPENAI_API_KEY"]  # Will throw KeyError if not set
secret = os.getenv("SECRET_KEY")

# ============================================================================
# PATTERN 5: Token Bombing
# ============================================================================

def unbounded_llm_loop(messages):
    """Vulnerable: while loop with unbounded LLM calls"""
    responses = []

    while True:  # VULNERABLE: No break condition
        # No max_tokens parameter
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=messages
        )

        responses.append(response)
        token_count = len(str(responses))

        if token_count > 1000000:  # Way too high
            break

    return responses

# ============================================================================
# PATTERN 6: Recursive Tool Calling
# ============================================================================

def agent_task_recursive(task):
    """Vulnerable: recursive agent call without depth limit"""
    result = agent.execute(task)

    if not result.success:
        # Recursive call without base case limit - VULNERABLE
        next_task = agent.delegate(result)
        return agent_task_recursive(next_task)

    return result

# ============================================================================
# PATTERN 7: RAG Over-fetching (NEW)
# ============================================================================

from langchain_community.vectorstores import Chroma

def create_vulnerable_rag_pipeline():
    """Vulnerable: RAG retrievers without k parameter limits"""

    # Vulnerable: as_retriever() without k parameter
    vectorstore = Chroma(...)
    retriever = vectorstore.as_retriever()  # VULNERABLE

    # Vulnerable: similarity_search without k
    results = vectorstore.similarity_search(query)  # VULNERABLE

    # Vulnerable: get_relevant_documents without limits
    docs = retriever.get_relevant_documents(user_query)  # VULNERABLE

    return retriever, results, docs

# ============================================================================
# MULTI-PATTERN VIOLATIONS: All vulnerabilities combined
# ============================================================================

def vulnerable_combined():
    """Violates ALL patterns together"""
    # Pattern 1 + 5: Hardcoded key + Token bombing
    api_key = "sk-proj-1234567890"  # HARDCODED

    while True:  # INFINITE LOOP / TOKEN BOMBING (Pattern 3 + 5)
        # Pattern 2: Unsanitized user input
        user_prompt = f"Analyze: {user_input}"  # VULNERABLE

        # LLM call without limits
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "user", "content": user_prompt}],
            # MISSING: max_tokens (Pattern 5)
        )

        # Pattern 6: Potential recursive delegation
        if response.get("recurse"):
            return vulnerable_combined()  # RECURSIVE (Pattern 6)

    # Pattern 4: Unsafe env access
    db_url = os.environ["DB_URL"]  # VULNERABLE

    # Pattern 7: RAG over-fetching
    retriever = vectorstore.as_retriever()  # VULNERABLE

# ============================================================================
# VALIDATION SUMMARY
# ============================================================================
"""
EXPECTED DETECTION RESULTS:

Pattern 1 (Hardcoded Credentials): 3 instances
  - OPENAI_API_KEY = "sk-proj-..."
  - ANTHROPIC_API_KEY = "sk-ant-..."
  - DB_PASSWORD = "admin_password_123"

Pattern 2 (Prompt Injection): 1 instance
  - f"User request: {user_input}"

Pattern 3 (Infinite Loops): 2 instances
  - while True: (in retry_loop_unbounded)
  - while True: (in vulnerable_combined)

Pattern 4 (Unsafe Environment Access): 3 instances
  - os.getenv("DATABASE_URL") without default
  - os.environ["OPENAI_API_KEY"] without default
  - os.environ["DB_URL"] without default

Pattern 5 (Token Bombing): 2 instances
  - while True: with openai.ChatCompletion.create (in unbounded_llm_loop)
  - while True: with openai.ChatCompletion.create (in vulnerable_combined)

Pattern 6 (Recursive Tool Calling): 2 instances
  - agent_task_recursive() calling itself
  - vulnerable_combined() calling itself

Pattern 7 (RAG Over-fetching): 3 instances
  - vectorstore.as_retriever() without k parameter
  - vectorstore.similarity_search(query) without k
  - retriever.get_relevant_documents() without limits

TOTAL EXPECTED FINDINGS: 16 vulnerabilities across 7 patterns

FALSE POSITIVE REDUCTION:
  ✓ Comments will be filtered
  ✓ Example code in docstrings will be filtered
  ✓ Test files will have reduced confidence
  ✓ Code with validation will have boosted confidence
"""
