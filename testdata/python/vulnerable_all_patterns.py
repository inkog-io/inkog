"""
VULNERABLE TEST DATA - All 4 TIER 1 Patterns
This file intentionally contains all 4 vulnerable patterns for testing
"""

import os

# ============================================================================
# PATTERN 1: PROMPT INJECTION
# ============================================================================

def vulnerable_prompt_injection_1():
    """Direct user input in prompt"""
    user_question = input("What would you like to know? ")

    # VULNERABLE: User input directly interpolated into prompt
    prompt = f"Answer this question: {user_question}"
    response = llm.chat(prompt)
    return response


def vulnerable_prompt_injection_2():
    """User input from request in LLM context"""
    from flask import request

    search_query = request.args.get("q")

    # VULNERABLE: User input in LLM function call
    system_prompt = f"Search the database for: {search_query}"
    response = agent.invoke(system_prompt)
    return response


def vulnerable_prompt_injection_3():
    """Triple-quote template injection"""
    user_data = get_user_input()

    # VULNERABLE: f-string in triple-quoted template
    prompt = f"""
    You are a helpful assistant.
    Process this user request: {user_data}
    Provide a detailed response.
    """

    response = chat_model.invoke(prompt)
    return response


# ============================================================================
# PATTERN 2: HARDCODED CREDENTIALS
# ============================================================================

# VULNERABLE: OpenAI API Key
OPENAI_API_KEY = "sk-proj-abc123def456xyz789abcdef"
openai.api_key = OPENAI_API_KEY

# VULNERABLE: Database password
DB_HOST = "postgres.example.com"
DB_USER = "admin"
DB_PASSWORD = "SuperSecurePass123!@#$%"
DB_NAME = "production_db"

# VULNERABLE: GitHub token
GITHUB_TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"

# VULNERABLE: AWS secrets
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# VULNERABLE: JWT secret
JWT_SECRET = "my-super-secret-jwt-key-that-should-never-be-hardcoded"


def get_database_connection():
    """Function using hardcoded credentials"""
    import psycopg2

    # VULNERABLE: Using hardcoded password
    connection = psycopg2.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME
    )
    return connection


def authenticate_github():
    """GitHub API client with hardcoded token"""
    from github import Github

    # VULNERABLE: Hardcoded token
    g = Github(GITHUB_TOKEN)
    user = g.get_user()
    return user


# ============================================================================
# PATTERN 3: INFINITE LOOP
# ============================================================================

def vulnerable_infinite_loop_1():
    """Simple infinite loop processing user requests"""

    # VULNERABLE: No break condition
    while True:
        user_input = input("Enter your query: ")
        result = agent.invoke(user_input)
        print(f"Result: {result}")
        # Loop continues infinitely - never breaks


def vulnerable_infinite_loop_2():
    """Task processing loop with no limits"""

    # VULNERABLE: Infinite task processing
    while True:
        task = get_next_task()
        if not task:
            continue  # Not a real exit

        process_task(task)
        # No max iterations, no timeout, no graceful exit


def vulnerable_infinite_loop_3():
    """Retry loop without limits"""

    # VULNERABLE: Retry loop that never exits
    while True:
        try:
            response = call_external_api()
            print(response)
        except Exception as e:
            print(f"Error: {e}")
            # Loop continues forever on errors


class VulnerableAgent:
    """Agent class with infinite execution loop"""

    def run(self):
        # VULNERABLE: No iteration limit or timeout
        while True:
            action = self.decide_action()
            result = self.execute_action(action)

            if result.is_terminal:
                # Even 'terminal' conditions might not be reached
                # This is still flagged as vulnerable pattern
                pass


# ============================================================================
# PATTERN 4: UNSAFE ENVIRONMENT ACCESS
# ============================================================================

# VULNERABLE: Direct environment access without defaults
DATABASE_URL = os.environ["DATABASE_URL"]  # Crashes if not set
API_KEY = os.environ["API_KEY"]  # Crashes if not set
SECRET_KEY = os.environ["SECRET_KEY"]  # Crashes if not set

# VULNERABLE: Environment access in function
def get_config():
    """Get configuration from environment"""

    # VULNERABLE: Direct access without defaults
    return {
        "host": os.environ["HOST"],
        "port": os.environ["PORT"],
        "username": os.environ["USERNAME"],
        "password": os.environ["PASSWORD"],
        "database": os.environ["DATABASE"],
    }


# VULNERABLE: Environment access in class
class AppConfig:
    def __init__(self):
        # VULNERABLE: Direct environ access
        self.db_url = os.environ["DATABASE_URL"]
        self.cache_url = os.environ["CACHE_URL"]
        self.api_key = os.environ["THIRD_PARTY_API_KEY"]


def vulnerable_startup():
    """Application startup that crashes if env vars missing"""

    # VULNERABLE: Multiple direct accesses
    config = {
        "db": os.environ["DATABASE_URL"],
        "cache": os.environ["REDIS_URL"],
        "auth": os.environ["AUTH_TOKEN"],
    }

    # If any env var is missing, app crashes here
    initialize_app(config)


# ============================================================================
# MIXED VULNERABILITIES
# ============================================================================

class VulnerableAgentSystem:
    """Agent system with multiple vulnerabilities"""

    def __init__(self):
        # PATTERN 4: Unsafe env access
        self.api_key = os.environ["OPENAI_API_KEY"]
        self.db_url = os.environ["DATABASE_URL"]

    def process_query(self):
        # PATTERN 3: Infinite loop
        while True:
            query = get_user_query()

            # PATTERN 1: Prompt injection
            prompt = f"Answer: {query}"

            # Uses PATTERN 2 credentials
            response = self.call_llm(prompt)

    def call_llm(self, prompt):
        import openai

        # PATTERN 2: Uses hardcoded API key
        openai.api_key = OPENAI_API_KEY
        return openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}]
        )


# ============================================================================
# TEST HARNESS
# ============================================================================

if __name__ == "__main__":
    print("This file contains intentional security vulnerabilities for testing.")
    print("DO NOT USE IN PRODUCTION")
    print("\nVulnerabilities detected by Inkog:")
    print("- Prompt Injection: 3 instances")
    print("- Hardcoded Credentials: 5 instances")
    print("- Infinite Loops: 4 instances")
    print("- Unsafe Env Access: 4+ instances")
