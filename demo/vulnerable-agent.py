#!/usr/bin/env python3
"""
Inkog Demo Agent - Intentionally Vulnerable
This agent demonstrates the types of vulnerabilities Inkog detects.
"""

import os
from typing import Optional

# ❌ VULNERABILITY #1: Hardcoded API Key
OPENAI_API_KEY = "sk-proj-1234567890abcdefghij1234567890ab"
DATABASE_PASSWORD = "admin@123!SuperSecretPassword"

class SearchAgent:
    """Simple AI agent that searches for information."""

    def __init__(self, user_query: str):
        self.user_query = user_query
        self.results = []

    # ❌ VULNERABILITY #2: Prompt Injection (f-string with user input)
    def search(self) -> str:
        """Search using LLM - vulnerable to prompt injection."""
        # User input directly interpolated without sanitization
        prompt = f"Search results for: {self.user_query}"
        system_prompt = f"Execute this query from user: {self.user_input}"

        # This would be sent to LLM without safety checks
        return self._call_llm(prompt)

    # ❌ VULNERABILITY #3: Infinite Loop (while True without break)
    def retry_search(self) -> Optional[str]:
        """Retry search with exponential backoff - but this loops forever."""
        max_retries = 3
        attempt = 0

        while True:  # Infinite loop - missing break condition!
            attempt += 1
            try:
                result = self.search()
                if result:
                    return result
            except Exception as e:
                print(f"Attempt {attempt} failed: {e}")
                # BUG: Never breaks out of loop if all attempts fail
                # Missing: if attempt >= max_retries: break

        return None

    # ❌ VULNERABILITY #4: Unsafe Environment Access (no default value)
    def get_database_url(self) -> str:
        """Get database URL - crashes if env var not set."""
        # Direct access without .get() and no default value
        # Will crash with KeyError if DATABASE_URL not set
        db_url = os.environ["DATABASE_URL"]
        return db_url

    # ✅ SAFE: Proper environment access with default
    def get_api_key_safe(self) -> str:
        """Safe way to access environment variables."""
        return os.environ.get("OPENAI_API_KEY", "default-test-key")

    def _call_llm(self, prompt: str) -> str:
        """Call LLM API - vulnerable because keys are hardcoded."""
        # Uses hardcoded API key from line 9
        headers = {
            "Authorization": f"Bearer {OPENAI_API_KEY}"
        }
        # In real code, this would call the API with exposed credentials
        return "Mock response from LLM"


# ❌ VULNERABILITY #5: Another prompt injection variant
def analyze_user_input(user_message: str) -> str:
    """Analyze user message - vulnerable to injection."""
    instruction = f"Analyze this user message: {user_message}"
    # Direct template injection
    return instruction


# ❌ VULNERABILITY #6: JWT secret hardcoded
JWT_SECRET = "your-secret-key-12345-super-secret-key-exposed"

def create_token(user_id: str) -> str:
    """Create JWT token - using hardcoded secret."""
    # Would use JWT_SECRET to sign token
    # Secret is visible in source code
    return f"jwt.encode({{'user_id': '{user_id}'}}, JWT_SECRET)"


if __name__ == "__main__":
    # Demo usage
    agent = SearchAgent("What is prompt injection?")

    # This would trigger vulnerabilities:
    # 1. Hardcoded credentials on lines 9-10
    # 2. Prompt injection on lines 27-29
    # 3. Infinite loop on lines 35-48
    # 4. Unsafe env access on lines 51
    # 5. JWT secret on line 64

    print("Agent initialized with vulnerabilities")
    print(f"Risk Score: HIGH - Multiple security issues detected")
