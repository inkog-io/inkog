"""
TIER 1 - Pattern 1: Hardcoded Credentials
CWE-798, CWE-259

Demonstrates: API keys, tokens, and passwords hardcoded in source code.
Risk: Account compromise, unauthorized API usage, credential theft.
Impact: $50K+/month per exposed credential.
"""

import os
import openai
from anthropic import Anthropic
import stripe

# ❌ VULNERABLE: Hardcoded API Keys
OPENAI_API_KEY = "sk-proj-abc123def456ghi789jkl"
CLAUDE_API_KEY = "sk-ant-v1-xyz789abc456def123ghi"
STRIPE_SECRET_KEY = "sk_live_123456789abcdefghijklmnop"
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
DISCORD_BOT_TOKEN = "discord_bot_token_12345abc"

# ❌ VULNERABLE: Keys in configuration
config = {
    "openai_key": "sk-123456789",
    "anthropic_key": "sk-ant-987654321",
    "stripe_key": "sk_live_payment_key",
    "database_password": "super_secret_password_123",
    "jwt_secret": "my_secret_jwt_key_here",
    "api_token": "bearer_token_xyz123"
}

# ❌ VULNERABLE: Keys in environment initialization
def initialize_services():
    # Direct credential usage
    openai.api_key = "sk-proj-credentials-here"

    # Stripe initialization with hardcoded key
    stripe.api_key = "sk_live_hardcoded_stripe_key"

    # Anthropic client with hardcoded credentials
    client = Anthropic(api_key="sk-ant-hardcoded-key")

    return client

# ❌ VULNERABLE: Credentials passed to functions
def make_api_call(api_key="sk-123456789"):
    """Function with default hardcoded credential"""
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Hello"}],
        api_key=api_key
    )
    return response

# ❌ VULNERABLE: Database credentials hardcoded
DATABASE_CONFIG = {
    "host": "db.example.com",
    "port": 5432,
    "user": "admin",
    "password": "admin123456",  # Hardcoded password
    "database": "production_db"
}

# ❌ VULNERABLE: Connection strings with credentials
CONNECTION_STRINGS = {
    "postgres": "postgresql://user:password123@localhost/dbname",
    "mongodb": "mongodb+srv://admin:secretpassword@cluster.mongodb.net/dbname",
    "mysql": "mysql://root:rootpassword@localhost:3306/mydb"
}

# ❌ VULNERABLE: Credentials in comments or docstrings
"""
API Credentials for testing:
- OpenAI: sk-proj-test-key-12345
- Stripe: sk_test_payment_key_xyz
- AWS: AKIAIOSFODNN7EXAMPLE
- AWS Secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""

class AgentWithCredentials:
    """AI Agent with hardcoded credentials"""

    def __init__(self):
        # ❌ VULNERABLE: Credentials in instance variables
        self.openai_key = "sk-proj-instance-key-here"
        self.stripe_key = "sk_live_instance_key"
        self.database_url = "postgresql://user:hardcoded_pass@db:5432/prod"

    def initialize_llm(self):
        # ❌ VULNERABLE: Credentials in method
        self.client = Anthropic(api_key="sk-ant-class-method-key")
        return self.client

    def make_payment(self, amount):
        # ❌ VULNERABLE: API key in method
        stripe.api_key = "sk_live_payment_processing_key"
        charge = stripe.Charge.create(
            amount=int(amount * 100),
            currency="usd",
            source="tok_visa"
        )
        return charge

# ❌ VULNERABLE: Multiple hardcoded secrets
def process_agent_request(user_query):
    # Hardcoded API keys in function
    api_key = "sk-proj-abc123"
    secret_key = "secret-xyz789"
    auth_token = "bearer-token-12345"

    # Use credentials to process request
    openai.api_key = api_key
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": user_query}]
    )

    return response

# ❌ VULNERABLE: Credentials in exception handling
def authenticate():
    try:
        # Some authentication logic
        pass
    except Exception as e:
        # Logging credentials in error messages
        print(f"Auth failed with key: sk-proj-test-key-12345: {e}")
        return False

if __name__ == "__main__":
    # ❌ VULNERABLE: Credentials in main execution
    client = initialize_services()

    # Test with hardcoded credentials
    response = make_api_call(api_key="sk-1234567890")

    print("Agent initialized with hardcoded credentials")
