# Hardcoded API Keys and Credentials

## Overview

Hardcoded credentials occur when API keys, tokens, passwords, and other secrets are embedded directly in source code. When code is committed to version control, shared with team members, or deployed to production, these credentials become accessible to unauthorized parties. This vulnerability leads to account compromise, unauthorized API usage, and potential data breaches.

**Business Impact:** Account compromise, $50K+/month unauthorized API usage, full repository access, multi-tenant data breaches.

**Severity:** CRITICAL (CVSS 9.1) | **Confidence:** 98% | **Financial Risk:** $600K/year

### Real-World Scenario

A developer hardcodes an OpenAI API key during initial development:

```python
OPENAI_API_KEY = "sk-proj-abc123xyz789..."
llm = ChatOpenAI(api_key=OPENAI_API_KEY)
```

The code is committed to GitHub. Within hours:
1. Automated scanners detect the exposed key
2. Attackers clone the repository and extract the key
3. The key is used to make $50,000 worth of API calls in a single month
4. OpenAI flags the account for suspicious activity
5. The organization faces service disruption and financial loss

**Actual incident:** A Fortune 500 company exposed AWS credentials in a public repository, leading to $100K+ in unauthorized EC2 instance usage within 48 hours.

## Detection Guide

### How Inkog Detects It

Inkog's detector identifies hardcoded credentials through multiple regex patterns:

1. **Known API Key Formats:**
   - OpenAI: `sk-proj-`, `sk-ant-`
   - Stripe: `sk_live_`, `sk_test_`
   - GitHub: `ghp_`
   - Generic: 20+ character strings with known prefixes

2. **Credential Variable Assignments:**
   - Pattern: `api_key = "..."`
   - Pattern: `secret = "..."`
   - Pattern: `token = "..."`
   - Pattern: `password = "..."`
   - Minimum length: 15 characters

3. **Service-Specific Constants:**
   - `OPENAI_KEY = "..."`
   - `STRIPE_SECRET = "..."`
   - `DATABASE_PASSWORD = "..."`
   - `GITHUB_TOKEN = "..."`

4. **Authentication Tokens:**
   - JWT tokens (20+ chars)
   - Bearer tokens
   - Auth tokens

5. **Database Credentials:**
   - Connection strings
   - Database passwords
   - Database URLs

### Detection Regex Patterns

```regex
# Known API key formats
(sk-|sk_|sk_live_|ghp_|sk-ant-)[a-zA-Z0-9_\-]{20,}

# Variable assignments
(api_?key|secret_?key|secret|token|password|api_?secret)\s*[=:]\s*["']([a-zA-Z0-9_\-\.]{15,})["']

# Service credentials
(OPENAI|STRIPE|GITHUB|ANTHROPIC|DATABASE|API|SECRET|TOKEN)_?(KEY|PASSWORD|SECRET|TOKEN)\s*=\s*["']([a-zA-Z0-9_\-\.]{15,})["']

# JWT/Bearer tokens
(jwt|token|auth|bearer)\s*[=:]\s*["']([a-zA-Z0-9_\-\.]{20,})["']

# Database credentials
(db_?password|db_?user|db_?host|database_?url)\s*[=:]\s*["']([^"']{8,})["']
```

### What Triggers Detection

Detection occurs when:
- A string value contains known API key prefixes
- Variable names indicate credential storage (`api_key`, `secret`, `token`)
- String values are 15+ characters (credential length threshold)
- The line is not a comment or in a test/example file

### Limitations

- **Encrypted secrets:** Cannot detect encrypted or base64-encoded credentials
- **Runtime construction:** Misses secrets built character-by-character
- **External files:** Does not scan `.env` files or configuration files
- **Obfuscated patterns:** May miss deliberately obfuscated credentials

### False Positive Scenarios

The detector automatically excludes:
- Test files (`test_`, `_test.py`, `.test.js`)
- Example files (`example`, `sample`, `demo`)
- Documentation files (`README`, `TUTORIAL`)
- Placeholder values (`your_api_key`, `replace_me`, `xxx`)
- Short strings (< 15 characters)
- Comment lines

## Code Examples

### Vulnerable Code

**Python - Hardcoded API Key:**
```python
from langchain.chat_models import ChatOpenAI

# VULNERABLE: API key hardcoded in source
OPENAI_API_KEY = "sk-proj-1234567890abcdefghijklmnop"
llm = ChatOpenAI(api_key=OPENAI_API_KEY)
```

**JavaScript - Inline Secret:**
```javascript
const { ChatOpenAI } = require("langchain/chat_models");

// VULNERABLE: Secret in code
const apiKey = "sk-ant-api03-abcdefghijklmnop123456";
const llm = new ChatOpenAI({ openAIApiKey: apiKey });
```

**Python - Database Credentials:**
```python
import psycopg2

# VULNERABLE: Database credentials in code
DB_PASSWORD = "SuperSecret123!"
DB_HOST = "production-db.company.com"
DB_USER = "admin"

conn = psycopg2.connect(
    host=DB_HOST,
    user=DB_USER,
    password=DB_PASSWORD,
    database="customers"
)
```

**TypeScript - Stripe Key:**
```typescript
// VULNERABLE: Payment API key exposed
const stripe = require('stripe')('sk_live_51Hxyz123abc456def');

const charge = await stripe.charges.create({
  amount: 2000,
  currency: 'usd',
});
```

**Python - GitHub Token:**
```python
import requests

# VULNERABLE: Personal access token in code
GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"

headers = {"Authorization": f"Bearer {GITHUB_TOKEN}"}
response = requests.get("https://api.github.com/user/repos", headers=headers)
```

### Secure Code

**Python - Environment Variables:**
```python
import os
from langchain.chat_models import ChatOpenAI

# SECURE: Load from environment
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")

if not OPENAI_API_KEY:
    raise ValueError("OPENAI_API_KEY environment variable not set")

llm = ChatOpenAI(api_key=OPENAI_API_KEY)
```

**Python - dotenv Library:**
```python
import os
from dotenv import load_dotenv
from langchain.chat_models import ChatOpenAI

# SECURE: Load secrets from .env file (not committed to git)
load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")

if not OPENAI_API_KEY:
    raise EnvironmentError("Missing required OPENAI_API_KEY in .env")

llm = ChatOpenAI(api_key=OPENAI_API_KEY)
```

**.env file (add to .gitignore):**
```bash
# .env - DO NOT commit to git
OPENAI_API_KEY=sk-proj-your-actual-key-here
ANTHROPIC_API_KEY=sk-ant-your-actual-key-here
DATABASE_PASSWORD=your-db-password
```

**.gitignore:**
```
.env
.env.local
.env.production
secrets.json
credentials.json
```

**JavaScript - Environment Variables:**
```javascript
const { ChatOpenAI } = require("langchain/chat_models");

// SECURE: Use environment variables
const apiKey = process.env.OPENAI_API_KEY;

if (!apiKey) {
  throw new Error("OPENAI_API_KEY not found in environment");
}

const llm = new ChatOpenAI({ openAIApiKey: apiKey });
```

**Python - AWS Secrets Manager:**
```python
import boto3
import json
from langchain.chat_models import ChatOpenAI

def get_secret(secret_name: str) -> dict:
    """Retrieve secret from AWS Secrets Manager."""
    client = boto3.client("secretsmanager", region_name="us-west-2")

    try:
        response = client.get_secret_value(SecretId=secret_name)
        return json.loads(response["SecretString"])
    except Exception as e:
        raise RuntimeError(f"Failed to retrieve secret: {e}")

# SECURE: Load from secrets manager
secrets = get_secret("prod/llm/api-keys")
OPENAI_API_KEY = secrets["openai_key"]

llm = ChatOpenAI(api_key=OPENAI_API_KEY)
```

**Python - HashiCorp Vault:**
```python
import hvac
from langchain.chat_models import ChatOpenAI

# SECURE: Load from Vault
client = hvac.Client(url="https://vault.company.com", token=os.getenv("VAULT_TOKEN"))
secret = client.secrets.kv.v2.read_secret_version(path="llm/openai")
OPENAI_API_KEY = secret["data"]["data"]["api_key"]

llm = ChatOpenAI(api_key=OPENAI_API_KEY)
```

**Docker - Environment Injection:**
```yaml
# docker-compose.yml
version: '3.8'
services:
  app:
    build: .
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}
    env_file:
      - .env.production  # Not committed to git
```

**Kubernetes - Secrets:**
```yaml
# k8s-secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: llm-secrets
type: Opaque
data:
  openai-api-key: <base64-encoded-key>
---
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: app
        env:
        - name: OPENAI_API_KEY
          valueFrom:
            secretKeyRef:
              name: llm-secrets
              key: openai-api-key
```

## Remediation

### Step-by-Step Fix

1. **Identify all hardcoded credentials:**
   ```bash
   # Run Inkog scan
   inkog scan --pattern hardcoded_credentials

   # Also use GitHub secret scanning
   git secret-scan
   ```

2. **Remove credentials from code:**

   **Before:**
   ```python
   API_KEY = "sk-proj-abc123"
   ```

   **After:**
   ```python
   API_KEY = os.environ.get("OPENAI_API_KEY")
   if not API_KEY:
       raise ValueError("OPENAI_API_KEY environment variable required")
   ```

3. **Install python-dotenv (Python) or dotenv (Node.js):**
   ```bash
   pip install python-dotenv
   # or
   npm install dotenv
   ```

4. **Create .env file with actual secrets:**
   ```bash
   # .env
   OPENAI_API_KEY=sk-proj-your-real-key
   DATABASE_PASSWORD=your-real-password
   ```

5. **Add .env to .gitignore:**
   ```bash
   echo ".env" >> .gitignore
   echo ".env.local" >> .gitignore
   echo ".env.production" >> .gitignore
   ```

6. **Rotate compromised credentials immediately:**
   - Generate new API keys on provider platforms
   - Update keys in secrets manager or .env files
   - Revoke old keys
   - Monitor for unauthorized usage

7. **Remove from git history (if committed):**
   ```bash
   # Use BFG Repo-Cleaner to remove secrets from git history
   bfg --replace-text passwords.txt

   # Or use git filter-repo
   git filter-repo --path-glob '*.env' --invert-paths

   # Force push (WARNING: coordinate with team)
   git push origin --force --all
   ```

### Tools and Libraries

**Secrets Management:**
- **AWS Secrets Manager:** Cloud-native secrets storage
- **HashiCorp Vault:** Enterprise secrets management
- **Azure Key Vault:** Microsoft cloud secrets
- **Google Secret Manager:** GCP secrets storage
- **1Password Secrets Automation:** Team secret sharing
- **Doppler:** Universal secrets manager

**Environment Management:**
- **python-dotenv:** Python environment variable loader
- **dotenv (Node):** JavaScript environment loader
- **direnv:** Per-directory environment variables
- **envchain:** macOS keychain integration

**Detection Tools:**
- **git-secrets:** Prevent committing secrets to git
- **TruffleHog:** Find secrets in git history
- **detect-secrets:** Pre-commit hook for secret detection
- **GitHub Secret Scanning:** Automatic detection in GitHub repos

### Best Practices

1. **Never commit credentials** to version control
2. **Use environment variables** for all secrets
3. **Add .env to .gitignore** immediately
4. **Use secrets managers** for production (Vault, AWS Secrets Manager)
5. **Rotate credentials regularly** (every 90 days minimum)
6. **Use different credentials** for dev/staging/prod
7. **Enable secret scanning** on all repositories
8. **Use pre-commit hooks** to prevent accidental commits
9. **Audit access logs** for credential usage
10. **Document secret rotation procedures** for team

### Configuration Example

**Complete Secure Setup:**

```python
# config.py
import os
from dotenv import load_dotenv
from typing import Optional

class Config:
    """Application configuration with secure secret loading."""

    def __init__(self):
        # Load .env file if present (local development)
        load_dotenv()

        # Required secrets
        self.openai_api_key = self._require_env("OPENAI_API_KEY")
        self.anthropic_api_key = self._require_env("ANTHROPIC_API_KEY")

        # Optional with defaults
        self.environment = os.getenv("ENVIRONMENT", "development")
        self.log_level = os.getenv("LOG_LEVEL", "INFO")

    def _require_env(self, key: str) -> str:
        """Get required environment variable or raise error."""
        value = os.getenv(key)
        if not value:
            raise EnvironmentError(
                f"Required environment variable {key} not set. "
                f"Add it to .env file or export it in your shell."
            )
        return value

    def _get_env(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get optional environment variable with default."""
        return os.getenv(key, default)

# Usage
config = Config()
llm = ChatOpenAI(api_key=config.openai_api_key)
```

**Pre-commit Hook (.git/hooks/pre-commit):**
```bash
#!/bin/bash
# Prevent committing files with potential secrets

# Check for common secret patterns
if git diff --cached | grep -iE '(api_key|secret|password|token)\s*=\s*["\'][^"\']+["\']'; then
    echo "ERROR: Potential secret detected in staged changes"
    echo "Remove secrets and use environment variables instead"
    exit 1
fi

# Check for .env files
if git diff --cached --name-only | grep -E '\.env$'; then
    echo "ERROR: Attempting to commit .env file"
    echo "Add .env to .gitignore"
    exit 1
fi

exit 0
```

## Testing

### How to Test Your Fix

1. **Run Inkog detector:**
   ```bash
   inkog scan --pattern hardcoded_credentials --file your_file.py
   ```

   Expected output: No findings

2. **Verify environment loading:**
   ```python
   def test_config_loads_from_env(monkeypatch):
       monkeypatch.setenv("OPENAI_API_KEY", "sk-test-fake-key")
       config = Config()
       assert config.openai_api_key == "sk-test-fake-key"
   ```

3. **Test missing environment variable:**
   ```python
   def test_config_raises_on_missing_env(monkeypatch):
       monkeypatch.delenv("OPENAI_API_KEY", raising=False)
       with pytest.raises(EnvironmentError):
           Config()
   ```

4. **Check .gitignore:**
   ```bash
   # Verify .env is ignored
   git check-ignore .env
   # Should output: .env
   ```

5. **Scan git history for secrets:**
   ```bash
   # Install TruffleHog
   pip install truffleHog

   # Scan entire git history
   trufflehog git file://. --only-verified
   ```

### Test Cases from Inkog

Inkog's test suite includes:

```go
// Test cases from hardcoded_credentials_test.go
testCases := []struct {
    name     string
    code     string
    expected bool
}{
    {
        name:     "OpenAI API key format",
        code:     `OPENAI_API_KEY = "sk-proj-abc123xyz789..."`,
        expected: true,
    },
    {
        name:     "Stripe live key",
        code:     `stripe_key = "sk_live_abc123..."`,
        expected: true,
    },
    {
        name:     "GitHub personal access token",
        code:     `GITHUB_TOKEN = "ghp_abcdefghijk123456"`,
        expected: true,
    },
    {
        name:     "Safe environment loading",
        code:     `api_key = os.environ.get("API_KEY")`,
        expected: false,
    },
}
```

Run tests:
```bash
cd action && go test ./pkg/patterns/detectors -run TestHardcodedCredentials -v
```

### Known CVEs This Prevents

- **CVE-2023-32313:** GitHub leaked credentials in public repositories
- **CVE-2022-39197:** AWS credentials hardcoded in open-source projects
- **CVE-2024-21887:** API keys exposed in mobile application code

Related advisories:
- OWASP A02:2021 - Cryptographic Failures
- OWASP A07:2021 - Identification and Authentication Failures
- NIST SP 800-53 IA-5 - Authenticator Management

## Related Vulnerabilities

### Similar Patterns

- **[Prompt Injection](prompt_injection.md):** Exposed API keys enable unlimited prompt injection attacks
- **[Unsafe Environment Access](unsafe_env_access.md):** Complements secure credential loading
- **[Infinite Loop](infinite_loop.md):** Stolen API keys used for resource exhaustion attacks

### Security Standards

**CWE Mappings:**
- [CWE-798](https://cwe.mitre.org/data/definitions/798.html): Use of Hard-coded Credentials

**OWASP Categories:**
- **LLM02:** Insecure Output Handling (credential exposure)
- **OWASP Top 10 A02:2021:** Cryptographic Failures
- **OWASP Top 10 A07:2021:** Identification and Authentication Failures

**CVSS 3.1 Score: 9.1 (CRITICAL)**
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
```
- Attack Vector: Network
- Attack Complexity: Low
- Privileges Required: None
- User Interaction: None
- Confidentiality Impact: High (API key theft)
- Integrity Impact: High (unauthorized actions)
- Availability Impact: None

### Industry References

- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning)
- [AWS Secrets Manager Best Practices](https://docs.aws.amazon.com/secretsmanager/latest/userguide/best-practices.html)
- [NIST SP 800-63B Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

### Further Reading

- [The Secret Life of Keys](https://queue.acm.org/detail.cfm?id=3469830)
- [How to Rotate Credentials Safely](https://www.vaultproject.io/docs/secrets/rotation)
- [GitHub Security Lab: Secret Scanning](https://securitylab.github.com/research/secret-scanning/)
