"""
FALSE POSITIVE TEST DATA
This file contains code that LOOKS vulnerable but shouldn't trigger
because it's in a test file, uses dummy data, or is for demonstration
"""

import os


# ============================================================================
# TEST FILES: Should skip ALL patterns (false positive reduction)
# ============================================================================

def test_prompt_injection_vulnerability():
    """Test case for prompt injection - should NOT trigger"""

    # In test files, we often use f-strings for test data
    user_input = "test input"
    prompt = f"Test prompt: {user_input}"  # Should be skipped

    # Verify detection works
    assert "test" in prompt


def test_hardcoded_secrets():
    """Test case using test credentials - should NOT trigger"""

    # Test data - obviously not real
    TEST_API_KEY = "sk-test-123"  # Should be skipped
    TEST_PASSWORD = "test_password"  # Should be skipped
    TEST_TOKEN = "ghp_test_12345"  # Should be skipped

    # These are testing - should not trigger
    assert TEST_API_KEY.startswith("sk-test")


def test_infinite_loop_logic():
    """Test infinite loop detection - should NOT trigger"""

    # In tests, we use while True for demo purposes
    count = 0
    while True:  # Should be skipped in test file
        count += 1
        if count >= 1:
            break

    assert count == 1


def test_env_access_patterns():
    """Test environment access - should NOT trigger"""

    # In tests, unsafe access is often acceptable
    test_value = os.environ["TEST_VAR"]  # Should be skipped

    assert test_value is not None


# ============================================================================
# EXAMPLE FILES: Also should be skipped
# ============================================================================

class ExamplePromptInjectionFixed:
    """Example showing fixed code - should NOT trigger"""

    def get_user_prompt(self):
        # In examples, we sometimes show vulnerable patterns
        user_input = "example input"
        prompt = f"Example: {user_input}"  # Should be skipped

        return prompt


def example_with_credentials():
    """Example setup code - should NOT trigger"""

    # Examples often show dummy credentials
    API_KEY = "sk-example-key"  # Should be skipped
    PASSWORD = "example_password"  # Should be skipped

    return {
        "api_key": API_KEY,
        "password": PASSWORD
    }


# ============================================================================
# DEMO FILES: Should be skipped
# ============================================================================

def demo_agent_loop():
    """Demo/POC code - should NOT trigger"""

    # Demos often use simplified unsafe patterns for clarity
    demo_api_key = "sk-demo-12345"  # Should be skipped
    while True:  # Should be skipped in demo file
        # Demo purposes only
        print("Processing...")
        break


# ============================================================================
# PLACEHOLDER VALUES: Should NOT trigger (false positive reduction)
# ============================================================================

def placeholder_values():
    """Values with obvious placeholders - should NOT trigger"""

    # These are CLEARLY placeholders, not real credentials
    api_key = "your_api_key_here"  # Should be skipped
    password = "replace_with_password"  # Should be skipped
    secret = "xxx"  # Should be skipped
    token = "YOUR_TOKEN_HERE"  # Should be skipped

    return {
        "api_key": api_key,
        "password": password,
        "secret": secret,
        "token": token
    }


# ============================================================================
# COMMENTED CODE: Should be skipped
# ============================================================================

def commented_vulnerabilities():
    """Commented code with vulnerabilities - should NOT trigger"""

    # # OLD_API_KEY = "sk-proj-old-key"
    # # while True:
    # #     result = agent.invoke(input())

    # Instead use this:
    api_key = os.environ.get("API_KEY", "default")

    return api_key


# ============================================================================
# DOCUMENTATION/STRING EXAMPLES: Should be skipped
# ============================================================================

class DocstringExample:
    """
    Example of vulnerable code (do not use):

    # VULNERABLE: Prompt injection
    prompt = f"User: {user_input}"

    # VULNERABLE: Credentials
    API_KEY = "sk-proj-abc123"

    # VULNERABLE: Infinite loop
    while True:
        process()

    # VULNERABLE: Unsafe env
    db_url = os.environ["DATABASE_URL"]
    """

    def safe_method(self):
        """Use environment variables safely"""
        api_key = os.environ.get("API_KEY")
        return api_key


# ============================================================================
# VARIABLE NAMES: Detecting false "secrets"
# ============================================================================

def variable_names_false_positive():
    """Variable names containing 'key', 'secret' but not credentials"""

    # These are just variable NAMES, not actual secrets
    api_key = "https://api.example.com"  # Just a URL
    secret_config = {"debug": True}  # Just a dict
    secret_message = "This is not a secret"  # Just text

    return api_key, secret_config, secret_message


# ============================================================================
# LEGITIMATE PATTERNS THAT LOOK SUSPICIOUS
# ============================================================================

def legitimate_string_patterns():
    """Legitimate code that contains suspicious patterns"""

    # This is a regular while loop with condition
    items = [1, 2, 3]
    index = 0
    while index < len(items):  # Has exit condition
        process(items[index])
        index += 1

    # This is accessing a dict with "environ"key
    config = {
        "environ": {
            "DATABASE_URL": "postgres://localhost"
        }
    }
    value = config["environ"]["DATABASE_URL"]

    return value


def legitimate_template_patterns():
    """Legitimate use of f-strings that isn't injection"""

    # Static content - no injection risk
    name = "World"
    greeting = f"Hello {name}"

    # Debug logging - not in LLM context
    level = "ERROR"
    log_message = f"[{level}] Something went wrong"

    # Safe structured data
    record = {
        "prompt": f"Query for {name}",
        "timestamp": "2024-11-08"
    }

    return greeting, log_message, record


# ============================================================================
# INDIRECT PATTERNS: Should NOT match direct detection
# ============================================================================

def indirect_credential_usage():
    """Accessing credentials indirectly - may or may not trigger"""

    # Credentials are in a config object, not directly hardcoded
    config = get_config()
    api_key = config.api_key  # Not hardcoded
    db_url = config.database_url  # Not hardcoded

    return api_key, db_url


def environment_variable_conditionally():
    """Environment access with proper error handling"""

    try:
        # Technically unsafe but wrapped in try/except
        database_url = os.environ["DATABASE_URL"]
    except KeyError:
        database_url = "postgresql://localhost/db"

    return database_url


# ============================================================================
# SUMMARY
# ============================================================================

EXPECTED_FALSE_POSITIVES_SKIPPED = {
    "test_files": [
        "test_prompt_injection_vulnerability",
        "test_hardcoded_secrets",
        "test_infinite_loop_logic",
        "test_env_access_patterns"
    ],
    "example_files": [
        "ExamplePromptInjectionFixed",
        "example_with_credentials",
        "demo_agent_loop"
    ],
    "placeholder_values": [
        "your_api_key_here",
        "replace_with_password",
        "xxx",
        "YOUR_TOKEN_HERE"
    ],
    "commented_code": [
        "OLD_API_KEY",
        "sk-proj-old-key"
    ],
    "docstrings": [
        "Example of vulnerable code"
    ]
}

if __name__ == "__main__":
    print("This file tests FALSE POSITIVE REDUCTION")
    print(f"\nExpected to skip: {len(EXPECTED_FALSE_POSITIVES_SKIPPED['test_files'])} test patterns")
    print(f"Expected to skip: {len(EXPECTED_FALSE_POSITIVES_SKIPPED['example_files'])} example patterns")
    print(f"Expected to skip: {len(EXPECTED_FALSE_POSITIVES_SKIPPED['placeholder_values'])} placeholder values")
    print("\nScanners should report 0 findings for this file")
