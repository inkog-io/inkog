# Unsafe Environment Variable Access

## Overview

Unsafe environment variable access occurs when code reads environment variables using direct dictionary access (`os.environ["KEY"]`) instead of the safer `.get()` method with default values. When the environment variable is missing, the application crashes with a `KeyError` at runtime instead of gracefully handling the missing configuration. This vulnerability causes production outages, service failures, and unpredictable application behavior.

**Business Impact:** Missing environment variable causes agent crash on first customer interaction, production downtime, degraded user experience.

**Severity:** MEDIUM (CVSS 6.5) | **Confidence:** 92% | **Financial Risk:** $10K-$100K/year

### Real-World Scenario

An AI agent is deployed to production with this configuration loading:

```python
import os
from langchain.chat_models import ChatOpenAI

# Deployed without ANTHROPIC_API_KEY set
OPENAI_API_KEY = os.environ["OPENAI_API_KEY"]  # Works
ANTHROPIC_API_KEY = os.environ["ANTHROPIC_API_KEY"]  # Crashes!

llm = ChatOpenAI(api_key=OPENAI_API_KEY)
```

The deployment works fine during initial testing because only OpenAI is used. However:

1. A feature flag enables Anthropic Claude integration
2. The first customer request triggers `os.environ["ANTHROPIC_API_KEY"]`
3. `KeyError: 'ANTHROPIC_API_KEY'` crashes the service
4. All customer requests fail until manual intervention
5. The team discovers the issue through customer complaints and error monitoring

**Impact:** 2 hours of downtime, 500+ failed customer requests, emergency hotfix deployment.

## Detection Guide

### How Inkog Detects It

Inkog's detector identifies unsafe environment access by:

1. **Pattern Matching** for dictionary-style access:
   - Regex: `os\.environ\s*\[\s*["']`
   - Matches: `os.environ["KEY"]`, `os.environ['KEY']`

2. **Safety Verification:**
   - Checks if the line contains `.get()`
   - If `.get()` is present, the pattern is considered safe
   - Only flags direct dictionary access without `.get()`

3. **Context Filtering:**
   - Excludes test files
   - Excludes comment lines
   - Only scans Python files (`.py`)

### Detection Regex Pattern

```regex
os\.environ\s*\[\s*["']
```

**Note:** This pattern specifically targets Python's `os.environ` usage. Similar patterns exist in other languages (e.g., `process.env` in JavaScript) but may have different safety characteristics.

### What Triggers Detection

Detection occurs when:
- Code contains `os.environ[` with quotes
- The line does NOT contain `.get()`
- The line is not a comment
- The file is not a test/example file

### Limitations

- **Python-specific:** Only detects Python `os.environ` patterns
- **Single-line analysis:** Cannot detect multi-line environment access
- **Validation timing:** Cannot detect if validation occurs after access
- **Wrapper functions:** Misses custom environment loading wrappers

### False Positive Scenarios

The detector automatically excludes:
- Test files (`test_`, `_test.py`, `/tests/`)
- Lines using `.get()`: `os.environ.get("KEY")`
- Comment lines
- Environment variable iteration: `for key in os.environ:`

## Code Examples

### Vulnerable Code

**Python - Direct Dictionary Access:**
```python
import os
from langchain.chat_models import ChatOpenAI

# VULNERABLE: Will crash if not set
OPENAI_API_KEY = os.environ["OPENAI_API_KEY"]
DATABASE_URL = os.environ["DATABASE_URL"]
REDIS_HOST = os.environ["REDIS_HOST"]

llm = ChatOpenAI(api_key=OPENAI_API_KEY)
```

**Python - Configuration Module:**
```python
import os

class Config:
    # VULNERABLE: No defaults
    API_KEY = os.environ["API_KEY"]
    MODEL_NAME = os.environ["MODEL_NAME"]
    MAX_TOKENS = int(os.environ["MAX_TOKENS"])
```

**Python - Multiple Services:**
```python
import os

# VULNERABLE: Any missing variable crashes startup
openai_key = os.environ["OPENAI_API_KEY"]
anthropic_key = os.environ["ANTHROPIC_API_KEY"]
cohere_key = os.environ["COHERE_API_KEY"]
pinecone_key = os.environ["PINECONE_API_KEY"]
```

**Python - Runtime Access:**
```python
def get_model():
    # VULNERABLE: Crashes at runtime when function is called
    model = os.environ["MODEL_NAME"]
    return ChatOpenAI(model=model)
```

### Secure Code

**Python - Using .get() with Defaults:**
```python
import os
from langchain.chat_models import ChatOpenAI

# SECURE: Safe access with defaults
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///local.db")
REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
MAX_TOKENS = int(os.environ.get("MAX_TOKENS", "1000"))

if not OPENAI_API_KEY:
    raise ValueError("OPENAI_API_KEY environment variable is required")

llm = ChatOpenAI(api_key=OPENAI_API_KEY)
```

**Python - Validation at Startup:**
```python
import os
import sys

def validate_environment():
    """Validate all required environment variables at startup."""
    required = [
        "OPENAI_API_KEY",
        "DATABASE_URL",
        "REDIS_HOST"
    ]

    missing = [var for var in required if not os.environ.get(var)]

    if missing:
        print(f"ERROR: Missing required environment variables: {missing}")
        print("Please set these variables before running the application")
        sys.exit(1)

# Validate before application starts
validate_environment()

# Now safe to use
OPENAI_API_KEY = os.environ["OPENAI_API_KEY"]
```

**Python - Configuration Class with Validation:**
```python
import os
from typing import Optional

class Config:
    """Application configuration with safe environment access."""

    def __init__(self):
        # Required variables (validate at init)
        self.openai_api_key = self._require_env("OPENAI_API_KEY")
        self.database_url = self._require_env("DATABASE_URL")

        # Optional variables with defaults
        self.model_name = os.environ.get("MODEL_NAME", "gpt-4")
        self.max_tokens = int(os.environ.get("MAX_TOKENS", "1000"))
        self.temperature = float(os.environ.get("TEMPERATURE", "0.7"))
        self.redis_host = os.environ.get("REDIS_HOST", "localhost")
        self.redis_port = int(os.environ.get("REDIS_PORT", "6379"))

    def _require_env(self, key: str) -> str:
        """Get required environment variable or raise clear error."""
        value = os.environ.get(key)
        if not value:
            raise EnvironmentError(
                f"Required environment variable '{key}' is not set. "
                f"Please set it in your .env file or export it in your shell."
            )
        return value

# Usage - fails fast at initialization if config is invalid
config = Config()
llm = ChatOpenAI(api_key=config.openai_api_key, model=config.model_name)
```

**Python - python-dotenv with Validation:**
```python
import os
from dotenv import load_dotenv
from pathlib import Path

# Load .env file
env_path = Path('.') / '.env'
load_dotenv(dotenv_path=env_path)

# SECURE: Validate and provide helpful errors
def get_env(key: str, default: Optional[str] = None, required: bool = False) -> str:
    """Safely get environment variable with validation."""
    value = os.environ.get(key, default)

    if required and not value:
        raise ValueError(
            f"Environment variable '{key}' is required but not set.\n"
            f"Please add '{key}=your_value' to your .env file."
        )

    return value

# Usage
OPENAI_API_KEY = get_env("OPENAI_API_KEY", required=True)
MODEL_NAME = get_env("MODEL_NAME", default="gpt-4")
MAX_TOKENS = int(get_env("MAX_TOKENS", default="1000"))
```

**Python - Pydantic Settings:**
```python
from pydantic import BaseSettings, Field

class Settings(BaseSettings):
    """Type-safe settings with automatic validation."""

    # Required settings
    openai_api_key: str = Field(..., env="OPENAI_API_KEY")
    database_url: str = Field(..., env="DATABASE_URL")

    # Optional with defaults
    model_name: str = Field("gpt-4", env="MODEL_NAME")
    max_tokens: int = Field(1000, env="MAX_TOKENS")
    temperature: float = Field(0.7, env="TEMPERATURE")

    class Config:
        env_file = '.env'
        env_file_encoding = 'utf-8'
        case_sensitive = False

# Usage - automatically validates and loads from .env
try:
    settings = Settings()
    print(f"Loaded settings: model={settings.model_name}")
except Exception as e:
    print(f"Configuration error: {e}")
    sys.exit(1)
```

**Python - Graceful Degradation:**
```python
import os
import logging

logger = logging.getLogger(__name__)

# SECURE: Feature flagging based on available config
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")

def get_llm():
    """Return available LLM based on configured credentials."""
    if OPENAI_API_KEY:
        logger.info("Using OpenAI")
        return ChatOpenAI(api_key=OPENAI_API_KEY)
    elif ANTHROPIC_API_KEY:
        logger.info("Using Anthropic")
        return ChatAnthropic(api_key=ANTHROPIC_API_KEY)
    else:
        logger.error("No LLM API keys configured")
        raise ValueError(
            "At least one LLM API key must be set: "
            "OPENAI_API_KEY or ANTHROPIC_API_KEY"
        )
```

## Remediation

### Step-by-Step Fix

1. **Identify all unsafe environment access:**
   ```bash
   inkog scan --pattern unsafe_env_access
   ```

2. **Replace direct access with .get():**

   **Before:**
   ```python
   API_KEY = os.environ["API_KEY"]
   ```

   **After:**
   ```python
   API_KEY = os.environ.get("API_KEY")
   if not API_KEY:
       raise ValueError("API_KEY environment variable required")
   ```

3. **Add default values for optional config:**

   **Before:**
   ```python
   MAX_TOKENS = int(os.environ["MAX_TOKENS"])
   ```

   **After:**
   ```python
   MAX_TOKENS = int(os.environ.get("MAX_TOKENS", "1000"))
   ```

4. **Create a config validation function:**
   ```python
   def validate_config():
       """Validate environment configuration at startup."""
       required = ["API_KEY", "DATABASE_URL"]
       missing = [key for key in required if not os.environ.get(key)]

       if missing:
           raise EnvironmentError(
               f"Missing required environment variables: {missing}\n"
               "Please check your .env file or environment setup."
           )

   # Call at application startup
   validate_config()
   ```

5. **Use a configuration class:**
   ```python
   from pydantic import BaseSettings

   class Config(BaseSettings):
       api_key: str
       database_url: str
       max_tokens: int = 1000  # Default value

       class Config:
           env_file = '.env'

   config = Config()  # Validates automatically
   ```

### Tools and Libraries

**Configuration Management:**
- **python-dotenv:** Load environment variables from `.env` files
- **pydantic-settings:** Type-safe configuration with validation
- **environs:** Enhanced environment variable parsing
- **python-decouple:** Strict separation of config from code
- **dynaconf:** Multi-environment configuration management

**Validation Libraries:**
- **Pydantic:** Schema validation for configuration
- **Cerberus:** Lightweight data validation
- **marshmallow:** Object serialization and validation

**Development Tools:**
- **direnv:** Automatic environment loading per directory
- **docker-compose:** Environment variable injection
- **dotenv-cli:** Run commands with .env loaded

### Best Practices

1. **Always use .get()** for environment variable access
2. **Provide defaults** for optional configuration
3. **Validate at startup** before application runs
4. **Use type-safe configs** (Pydantic Settings)
5. **Document required variables** in README
6. **Provide .env.example** template file
7. **Fail fast** with clear error messages
8. **Log configuration** at startup (without secrets)
9. **Use different configs** for dev/staging/prod
10. **Never commit .env** files to version control

### Configuration Example

**Complete Safe Configuration Setup:**

```python
# config.py
import os
import sys
import logging
from typing import Optional
from dotenv import load_dotenv
from pathlib import Path

logger = logging.getLogger(__name__)

class ConfigurationError(Exception):
    """Raised when configuration is invalid."""
    pass

class AppConfig:
    """Application configuration with validation."""

    def __init__(self, env_file: str = ".env"):
        # Load .env file if it exists
        env_path = Path(env_file)
        if env_path.exists():
            load_dotenv(dotenv_path=env_path)
            logger.info(f"Loaded environment from {env_file}")

        # Load and validate configuration
        self._load_config()
        self._validate_config()

    def _load_config(self):
        """Load all configuration values."""
        # Required settings
        self.openai_api_key = os.environ.get("OPENAI_API_KEY")
        self.database_url = os.environ.get("DATABASE_URL")

        # Optional with defaults
        self.environment = os.environ.get("ENVIRONMENT", "development")
        self.model_name = os.environ.get("MODEL_NAME", "gpt-4")
        self.max_tokens = int(os.environ.get("MAX_TOKENS", "1000"))
        self.temperature = float(os.environ.get("TEMPERATURE", "0.7"))
        self.log_level = os.environ.get("LOG_LEVEL", "INFO")

        # Feature flags
        self.enable_caching = os.environ.get("ENABLE_CACHING", "true").lower() == "true"
        self.enable_monitoring = os.environ.get("ENABLE_MONITORING", "false").lower() == "true"

    def _validate_config(self):
        """Validate configuration and raise errors if invalid."""
        errors = []

        # Check required variables
        if not self.openai_api_key:
            errors.append("OPENAI_API_KEY is required")

        if not self.database_url:
            errors.append("DATABASE_URL is required")

        # Validate ranges
        if self.max_tokens < 1 or self.max_tokens > 100000:
            errors.append(f"MAX_TOKENS must be between 1 and 100000, got {self.max_tokens}")

        if self.temperature < 0 or self.temperature > 2:
            errors.append(f"TEMPERATURE must be between 0 and 2, got {self.temperature}")

        # Validate environment
        valid_environments = ["development", "staging", "production"]
        if self.environment not in valid_environments:
            errors.append(f"ENVIRONMENT must be one of {valid_environments}, got {self.environment}")

        # Report all errors
        if errors:
            error_msg = "\n".join(f"  - {error}" for error in errors)
            raise ConfigurationError(
                f"Configuration validation failed:\n{error_msg}\n\n"
                f"Please check your .env file or environment variables."
            )

    def __repr__(self):
        """String representation (without secrets)."""
        return (
            f"AppConfig(\n"
            f"  environment={self.environment}\n"
            f"  model_name={self.model_name}\n"
            f"  max_tokens={self.max_tokens}\n"
            f"  temperature={self.temperature}\n"
            f"  api_key={'***' + self.openai_api_key[-4:] if self.openai_api_key else 'NOT_SET'}\n"
            f")"
        )

# Load configuration at module import
try:
    config = AppConfig()
    logger.info(f"Configuration loaded successfully:\n{config}")
except ConfigurationError as e:
    logger.error(f"Configuration error: {e}")
    sys.exit(1)
```

**.env.example (committed to git):**
```bash
# Copy to .env and fill in your values
# DO NOT commit .env to git!

# Required
OPENAI_API_KEY=sk-proj-your-key-here
DATABASE_URL=postgresql://user:pass@localhost/db

# Optional (defaults shown)
ENVIRONMENT=development
MODEL_NAME=gpt-4
MAX_TOKENS=1000
TEMPERATURE=0.7
LOG_LEVEL=INFO

# Feature flags
ENABLE_CACHING=true
ENABLE_MONITORING=false
```

## Testing

### How to Test Your Fix

1. **Run Inkog detector:**
   ```bash
   inkog scan --pattern unsafe_env_access --file config.py
   ```

   Expected output: No findings

2. **Test missing required variable:**
   ```python
   def test_missing_required_variable(monkeypatch):
       monkeypatch.delenv("OPENAI_API_KEY", raising=False)

       with pytest.raises(ValueError, match="OPENAI_API_KEY.*required"):
           config = Config()
   ```

3. **Test default values:**
   ```python
   def test_default_values(monkeypatch):
       monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
       monkeypatch.setenv("DATABASE_URL", "sqlite:///test.db")
       monkeypatch.delenv("MAX_TOKENS", raising=False)

       config = Config()
       assert config.max_tokens == 1000  # Default value
   ```

4. **Test .get() returns None safely:**
   ```python
   def test_safe_get(monkeypatch):
       monkeypatch.delenv("OPTIONAL_VAR", raising=False)

       # Should not raise KeyError
       value = os.environ.get("OPTIONAL_VAR")
       assert value is None

       # With default
       value = os.environ.get("OPTIONAL_VAR", "default")
       assert value == "default"
   ```

5. **Integration test with actual environment:**
   ```python
   def test_load_from_env_file():
       """Test loading from .env.test file."""
       from dotenv import load_dotenv

       load_dotenv(".env.test")
       config = Config()

       assert config.openai_api_key is not None
       assert config.database_url is not None
   ```

### Test Cases from Inkog

Inkog's test suite includes:

```go
// Test cases from unsafe_env_access_test.go
testCases := []struct {
    name     string
    code     string
    expected bool
}{
    {
        name:     "Unsafe dict access",
        code:     `api_key = os.environ["API_KEY"]`,
        expected: true,
    },
    {
        name:     "Safe .get() access",
        code:     `api_key = os.environ.get("API_KEY")`,
        expected: false,
    },
    {
        name:     "Safe .get() with default",
        code:     `api_key = os.environ.get("API_KEY", "default")`,
        expected: false,
    },
}
```

Run tests:
```bash
cd action && go test ./pkg/patterns/detectors -run TestUnsafeEnvAccess -v
```

### Known CVEs This Prevents

- **CWE-665:** Improper Initialization (missing configuration)
- General class of configuration-related runtime failures

Related advisories:
- OWASP A05:2021 - Security Misconfiguration
- Twelve-Factor App: Config (store config in the environment)

## Related Vulnerabilities

### Similar Patterns

- **[Hardcoded Credentials](hardcoded_credentials.md):** Unsafe env access often appears alongside hardcoded fallbacks
- **[Infinite Loop](infinite_loop.md):** Missing timeout configs compound with unsafe env access
- **[Prompt Injection](prompt_injection.md):** Missing input validation configs increase injection risk

### Security Standards

**CWE Mappings:**
- [CWE-665](https://cwe.mitre.org/data/definitions/665.html): Improper Initialization

**OWASP Categories:**
- **LLM02:** Insecure Output Handling (configuration-dependent)
- **OWASP Top 10 A05:2021:** Security Misconfiguration

**CVSS 3.1 Score: 6.5 (MEDIUM)**
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
```
- Attack Vector: Network
- Attack Complexity: Low
- Privileges Required: None
- User Interaction: None
- Availability Impact: High (service crash)

### Industry References

- [The Twelve-Factor App: Config](https://12factor.net/config)
- [OWASP Configuration Management](https://cheatsheetseries.owasp.org/cheatsheets/Configuration_Management_Cheat_Sheet.html)
- [Python Environment Variables Best Practices](https://docs.python.org/3/library/os.html#os.environ)
- [Pydantic Settings Documentation](https://pydantic-docs.helpmanual.io/usage/settings/)

### Further Reading

- [Managing Application Configuration](https://www.redhat.com/en/topics/automation/what-is-configuration-management)
- [Environment Variables in Production](https://blog.doppler.com/environment-variables-in-production)
- [Python Configuration Best Practices](https://tech.preferred.jp/en/blog/working-with-configuration-in-python/)
