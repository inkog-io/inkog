"""
SECURE TEST DATA - Best Practices for All 4 TIER 1 Patterns
This file shows secure implementations of each pattern
"""

import os
from typing import Optional
from functools import wraps
import time

# ============================================================================
# PATTERN 1: PROMPT INJECTION - SECURE PATTERNS
# ============================================================================

from langchain.prompts import ChatPromptTemplate


def secure_prompt_injection_1():
    """Use LangChain templates with input variables"""
    from langchain.chat_models import ChatOpenAI

    user_question = input("What would you like to know? ")

    # SECURE: Using LangChain template with input variables
    template = ChatPromptTemplate.from_messages([
        ("system", "You are a helpful assistant."),
        ("user", "Answer this question: {question}")
    ])

    prompt = template.format_prompt(question=user_question)
    llm = ChatOpenAI(model="gpt-4")
    response = llm.invoke(prompt)
    return response


def secure_prompt_injection_2():
    """Separate data from code using templates"""
    from langchain.prompts import PromptTemplate

    search_query = get_user_input()

    # SECURE: Using PromptTemplate with explicit variable
    template = PromptTemplate(
        input_variables=["query"],
        template="Search the database for: {query}"
    )

    prompt = template.format(query=search_query)
    response = agent.invoke(prompt)
    return response


def secure_prompt_injection_3():
    """Validate and sanitize input before using in prompts"""

    user_data = get_user_input()

    # SECURE: Validate input
    if not validate_input(user_data):
        raise ValueError("Invalid input")

    # Use prompt template, not f-string
    prompt = ChatPromptTemplate.from_template(
        """You are a helpful assistant.
        Process this user request: {data}
        Provide a detailed response."""
    )

    response = chat_model.invoke(prompt.format(data=user_data))
    return response


def validate_input(user_input: str) -> bool:
    """Validate user input before using in prompts"""
    if not user_input:
        return False

    if len(user_input) > 1000:  # Reasonable limit
        return False

    # Check for suspicious patterns
    dangerous_patterns = ["</system>", "{{", "}}"]
    for pattern in dangerous_patterns:
        if pattern in user_input:
            return False

    return True


# ============================================================================
# PATTERN 2: HARDCODED CREDENTIALS - SECURE PATTERNS
# ============================================================================

from dotenv import load_dotenv
from pydantic_settings import BaseSettings


# Load environment variables from .env file
load_dotenv()


class Settings(BaseSettings):
    """Application settings using environment variables"""

    # Using Pydantic with environment variable validation
    openai_api_key: str = ""
    database_url: str = "postgresql://localhost/db"
    github_token: Optional[str] = None
    jwt_secret: str = ""

    class Config:
        env_file = ".env"
        case_sensitive = False

    def validate_required(self):
        """Validate required credentials are set"""
        if not self.openai_api_key:
            raise ValueError("OPENAI_API_KEY must be set")
        if not self.jwt_secret:
            raise ValueError("JWT_SECRET must be set")


# Initialize settings
settings = Settings()


def get_openai_client():
    """Get OpenAI client with credentials from environment"""
    import openai

    # SECURE: API key from environment variables
    openai.api_key = settings.openai_api_key
    return openai


def get_database_connection():
    """Get database connection using environment variables"""
    import psycopg2

    # SECURE: Using environment variables
    connection = psycopg2.connect(
        settings.database_url
    )
    return connection


def get_github_client():
    """Get GitHub client with token from environment"""
    from github import Github

    # SECURE: Token from environment, with validation
    if not settings.github_token:
        raise ValueError("GITHUB_TOKEN not configured")

    g = Github(settings.github_token)
    return g


class SecureVaultClient:
    """Use HashiCorp Vault for secrets management"""

    def __init__(self, vault_addr: str, vault_token: str):
        self.vault_addr = vault_addr
        self.vault_token = vault_token

    def get_secret(self, secret_path: str) -> dict:
        """Retrieve secret from Vault"""
        # SECURE: Secrets stored in external vault
        # Example using hvac library
        # import hvac
        # client = hvac.Client(url=self.vault_addr, token=self.vault_token)
        # return client.secrets.kv.read_secret_version(secret_path)
        pass


class AWSSecretsManagerClient:
    """Use AWS Secrets Manager for secrets"""

    def __init__(self, region_name: str = "us-east-1"):
        import boto3
        self.client = boto3.client("secretsmanager", region_name=region_name)

    def get_secret(self, secret_name: str) -> dict:
        """Retrieve secret from AWS Secrets Manager"""
        # SECURE: Secrets stored in AWS
        response = self.client.get_secret_value(SecretId=secret_name)
        if "SecretString" in response:
            import json
            return json.loads(response["SecretString"])
        return {}


# ============================================================================
# PATTERN 3: INFINITE LOOP - SECURE PATTERNS
# ============================================================================

def secure_agent_execution_1():
    """Agent execution with iteration limit"""

    max_iterations = 10
    iteration = 0

    # SECURE: Loop with max iterations
    while iteration < max_iterations:
        user_input = input("Enter your query: ")
        result = agent.invoke(user_input)
        print(f"Result: {result}")

        iteration += 1

    print(f"Max iterations ({max_iterations}) reached")


def secure_agent_execution_2():
    """Agent execution with timeout"""

    timeout_seconds = 30
    start_time = time.time()

    # SECURE: Loop with timeout
    while time.time() - start_time < timeout_seconds:
        task = get_next_task()
        if not task:
            break

        result = process_task(task)
        if result.is_terminal:
            break

    elapsed = time.time() - start_time
    print(f"Execution completed in {elapsed:.2f} seconds")


def secure_agent_execution_3():
    """Agent execution with multiple exit conditions"""

    max_iterations = 100
    timeout_seconds = 60
    start_time = time.time()
    iteration = 0

    # SECURE: Multiple exit conditions
    while iteration < max_iterations:
        # Check timeout
        if time.time() - start_time > timeout_seconds:
            print("Timeout reached")
            break

        # Get next action
        action = decide_action()
        if action is None:
            print("No more actions")
            break

        # Execute action
        try:
            result = execute_action(action)
            if result.is_terminal:
                print("Terminal state reached")
                break
        except Exception as e:
            print(f"Error: {e}")
            # Don't break, continue to next iteration

        iteration += 1

    print(f"Completed {iteration} iterations")


class SafeAgentExecutor:
    """Production-ready agent executor with safety limits"""

    def __init__(
        self,
        agent,
        max_iterations: int = 10,
        timeout_seconds: int = 60,
        max_retries: int = 3
    ):
        self.agent = agent
        self.max_iterations = max_iterations
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries

    def execute(self, initial_input: str) -> dict:
        """Execute agent with safety limits"""

        start_time = time.time()
        iteration = 0
        retry_count = 0

        while iteration < self.max_iterations:
            # Check timeout
            elapsed = time.time() - start_time
            if elapsed > self.timeout_seconds:
                return {
                    "status": "timeout",
                    "iterations": iteration,
                    "elapsed_seconds": elapsed,
                    "result": None
                }

            try:
                # Execute step
                result = self.agent.step(initial_input)

                # Check for terminal condition
                if result.get("terminal"):
                    return {
                        "status": "success",
                        "iterations": iteration,
                        "elapsed_seconds": time.time() - start_time,
                        "result": result
                    }

                iteration += 1
                retry_count = 0

            except Exception as e:
                retry_count += 1

                if retry_count > self.max_retries:
                    return {
                        "status": "error",
                        "iterations": iteration,
                        "elapsed_seconds": time.time() - start_time,
                        "error": str(e)
                    }

        return {
            "status": "max_iterations",
            "iterations": iteration,
            "elapsed_seconds": time.time() - start_time,
            "result": None
        }


# ============================================================================
# PATTERN 4: UNSAFE ENVIRONMENT ACCESS - SECURE PATTERNS
# ============================================================================

def secure_env_access_1():
    """Use .get() with defaults"""

    # SECURE: Using .get() with default values
    database_url = os.environ.get("DATABASE_URL", "postgresql://localhost/db")
    api_key = os.environ.get("API_KEY", "")
    debug_mode = os.environ.get("DEBUG", "false").lower() == "true"

    return {
        "database_url": database_url,
        "api_key": api_key,
        "debug_mode": debug_mode
    }


def secure_env_access_2():
    """Use python-dotenv for local development"""
    from dotenv import load_dotenv

    # SECURE: Load .env file in development
    load_dotenv()

    # Then use .get() for safe access
    database_url = os.environ.get("DATABASE_URL", "localhost:5432")
    return database_url


def secure_env_access_3():
    """Validate environment configuration"""

    class Config:
        def __init__(self):
            self.required_vars = [
                "DATABASE_URL",
                "API_KEY",
                "JWT_SECRET"
            ]
            self.config = {}
            self._load_and_validate()

        def _load_and_validate(self):
            """Load and validate required environment variables"""

            missing = []
            for var in self.required_vars:
                value = os.environ.get(var)
                if not value:
                    missing.append(var)
                self.config[var] = value

            if missing:
                raise ValueError(
                    f"Missing required environment variables: {', '.join(missing)}"
                )

        def get(self, key: str, default=None):
            """Get config value safely"""
            return self.config.get(key, default)

    # SECURE: Validate configuration at startup
    try:
        config = Config()
    except ValueError as e:
        print(f"Configuration error: {e}")
        raise


class EnvironmentValidator:
    """Validate and load environment with type conversion"""

    def __init__(self):
        self.config = {}

    def load_str(self, key: str, required: bool = False) -> Optional[str]:
        """Load string environment variable"""
        value = os.environ.get(key)
        if required and not value:
            raise ValueError(f"Required environment variable {key} not set")
        return value

    def load_int(self, key: str, default: int = 0) -> int:
        """Load integer environment variable"""
        value = os.environ.get(key, str(default))
        try:
            return int(value)
        except ValueError:
            raise ValueError(f"Invalid integer for {key}: {value}")

    def load_bool(self, key: str, default: bool = False) -> bool:
        """Load boolean environment variable"""
        value = os.environ.get(key, str(default)).lower()
        return value in ("true", "1", "yes", "on")


# ============================================================================
# INTEGRATION EXAMPLE
# ============================================================================

class SecureApplication:
    """Application using all secure patterns"""

    def __init__(self):
        # Pattern 2: Load credentials safely
        self.settings = Settings()
        self.settings.validate_required()

        # Pattern 4: Load config safely
        self.config = Config()

        # Pattern 3: Initialize agent executor with limits
        self.agent = create_agent()
        self.executor = SafeAgentExecutor(
            self.agent,
            max_iterations=10,
            timeout_seconds=60
        )

    def process_user_query(self, user_input: str) -> dict:
        """Process user query securely"""

        # Pattern 1: Validate and use template for prompts
        if not validate_input(user_input):
            return {"error": "Invalid input"}

        # Execute with Pattern 3 safety limits
        result = self.executor.execute(user_input)

        return result


# ============================================================================
# TEST HARNESS
# ============================================================================

if __name__ == "__main__":
    print("This file contains SECURE implementations of all patterns.")
    print("\nSecure patterns demonstrated:")
    print("✓ Prompt Injection: LangChain templates with input validation")
    print("✓ Hardcoded Credentials: Environment variables + Pydantic Settings")
    print("✓ Infinite Loops: SafeAgentExecutor with limits and timeout")
    print("✓ Unsafe Env Access: .get() with defaults + validation")
