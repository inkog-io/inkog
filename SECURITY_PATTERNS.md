# Inkog Security Patterns & Standards

This document details all security patterns detected by Inkog, with their corresponding security standard mappings (CWE, CVSS, OWASP Top 10, SANS Top 25).

## Overview

Inkog detects 5 core patterns in the Go scanner and 4 patterns in the interactive demo analyzer.

### Scanner Coverage
- **Go Scanner**: 5 patterns
- **Demo Custom Code Analyzer**: 4 patterns (missing JWT/Token detection)
- **Demo Pre-defined Examples**: All vulnerabilities with full metadata

---

## Pattern Details

### 1. Hardcoded Credentials (Secrets Exposure)

**Description**: API keys, passwords, database credentials, JWT tokens, and other secrets hardcoded directly in source code.

**Detection Method**:
- Regex patterns for common secret formats
- API key prefixes (sk-, ghp-, etc.)
- Assignment patterns for PASSWORD, SECRET, API_KEY, JWT_SECRET variables

**Severity**: HIGH

**CWE Mapping**:
- **CWE-798**: Use of Hard-Coded Credentials
  - https://cwe.mitre.org/data/definitions/798.html
  - "The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data."

**CVSS Score**: 9.1 (High)
- Attack Vector: Network
- Attack Complexity: Low
- Privileges Required: None
- User Interaction: None
- Scope: Unchanged
- Confidentiality Impact: High
- Integrity Impact: High
- Availability Impact: High

**OWASP Top 10 (2021)**: A02:2021 – Cryptographic Failures
- Previously "Sensitive Data Exposure"
- Credentials exposed in code = cryptographic/configuration failures

**SANS Top 25**: CWE-798 (rank varies by year)
- Common in misconfiguration and resource management categories

**Example Patterns Detected**:
```python
OPENAI_API_KEY = "sk-proj-abcdefghij1234567890xyz"
DATABASE_PASSWORD = "admin@SecurePass123"
JWT_SECRET = "super-secret-key-12345"
ANTHROPIC_API_KEY = "sk-ant-1234567890abcdefghij"
```

**Remediation**:
- Use environment variables: `api_key = os.environ.get('OPENAI_API_KEY')`
- Use secrets management: HashiCorp Vault, AWS Secrets Manager, Azure Key Vault
- Use .env files (development only, never commit to git)
- Use CI/CD secrets injection

---

### 2. Prompt Injection

**Description**: Unvalidated user input directly interpolated into prompts sent to LLMs, allowing attackers to inject arbitrary instructions.

**Detection Method**:
- F-string patterns with variable interpolation
- Format string usage with user-controlled variables
- Prompt = f"..." patterns with {} containing variables

**Severity**: HIGH

**CWE Mapping**:
- **CWE-94**: Improper Control of Generation of Code ('Code Injection')
  - https://cwe.mitre.org/data/definitions/94.html
  - "The software generates dynamic code or commands, but does not neutralize or incorrectly neutralizes special elements that could modify the intended logic of the generated code."

- **CWE-95**: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')
  - Related: LLM prompts are "dynamically evaluated" by the language model

**CVSS Score**: 8.8 (High)
- Attack Vector: Network
- Attack Complexity: Low
- Privileges Required: None
- User Interaction: None
- Scope: Unchanged
- Confidentiality Impact: High
- Integrity Impact: High
- Availability Impact: High

**OWASP Top 10 (2021)**: A03:2021 – Injection
- Directly relevant: "Injection flaws occur when an application sends untrusted data to an interpreter"

**OWASP LLM Top 10**: LLM04:2024 – Prompt Injection

**SANS Top 25**: CWE-94 (rank varies)
- Dangerous and Widespread

**Example Patterns Detected**:
```python
prompt = f"Search for: {user_query}"
instruction = f"Process: {user_input}"
goal = f"Research topic: {self.topic}"
description = f"Execute user request: {self.user_input}"
```

**Remediation**:
- Separate instructions from data using prompt templating libraries
- Use structured inputs with validation
- Implement sandboxing for agent outputs
- Use retrieval-augmented generation (RAG) to limit tool scope
- Monitor and log prompt content
- Example: Use LangChain's `PromptTemplate` with safe input handling

```python
from langchain.prompts import PromptTemplate

template = PromptTemplate(
    input_variables=["search_term"],
    template="Search the database for items matching: {search_term}"
)
# search_term is safely handled, not eval'd
```

---

### 3. Infinite Loops

**Description**: Loop constructs (while True) without proper break conditions, causing resource exhaustion and DoS.

**Detection Method**:
- `while True:` or `while 1:` patterns
- Missing break conditions in loop bodies
- Unchecked retries without termination logic

**Severity**: HIGH

**CWE Mapping**:
- **CWE-835**: Loop with Unreachable Exit Condition ('Infinite Loop')
  - https://cwe.mitre.org/data/definitions/835.html
  - "The software contains a loop with an exit condition that can never be reached, such as a time-out, or a logical condition that determines whether an exit will occur."

**CVSS Score**: 7.5 (High)
- Attack Vector: Network
- Attack Complexity: Low
- Privileges Required: None
- User Interaction: None
- Scope: Unchanged
- Confidentiality Impact: None
- Integrity Impact: None
- Availability Impact: High (resource exhaustion)

**OWASP Top 10 (2021)**: A01:2021 – Broken Access Control (Availability)
- More broadly: Contributes to denial of service (A04)

**SANS Top 25**: CWE-835
- Performance issues and resource management

**Example Patterns Detected**:
```python
while True:
    attempt += 1
    # ... no break condition

while True:
    try:
        return self.search()
    except:
        pass  # Infinite retries
```

**Remediation**:
- Add explicit break conditions or max retry limits
- Use timeouts/circuit breakers
- Implement exponential backoff
- Add logging to detect infinite loops in production

```python
MAX_RETRIES = 3
for attempt in range(MAX_RETRIES):
    try:
        return self.search()
    except Exception as e:
        if attempt == MAX_RETRIES - 1:
            raise
        time.sleep(2 ** attempt)  # Exponential backoff
```

---

### 4. Unsafe Environment Access

**Description**: Accessing environment variables without default values, causing runtime failures and potential info disclosure.

**Detection Method**:
- `os.environ["KEY"]` patterns without `.get()` fallback
- Missing default value in environment variable access
- No error handling for missing environment variables

**Severity**: MEDIUM

**CWE Mapping**:
- **CWE-665**: Improper Initialization
  - https://cwe.mitre.org/data/definitions/665.html
  - "The software does not initialize or incorrectly initializes a resource, which might lead to unexpected states or behaviors."

- **CWE-1104**: Use of Unmaintained Third Party Components
  - Related: Reliance on runtime state without validation

**CVSS Score**: 6.5 (Medium)
- Attack Vector: Network
- Attack Complexity: Low
- Privileges Required: None
- User Interaction: None
- Scope: Unchanged
- Confidentiality Impact: Low
- Integrity Impact: Low
- Availability Impact: High (crash if env var missing)

**OWASP Top 10 (2021)**: A05:2021 – Broken Access Control / A07:2021 – Identification and Authentication Failures
- Environment vars often contain authentication/config data

**SANS Top 25**: CWE-665
- Dangerous and Widespread (initialization issues)

**Example Patterns Detected**:
```python
db_url = os.environ["DATABASE_URL"]  # Crashes if missing
api_key = os.environ["API_KEY"]

# Better approach:
db_url = os.environ.get("DATABASE_URL", "default_url")
api_key = os.environ.get("API_KEY") or raise_configuration_error()
```

**Remediation**:
- Always use `.get()` with default values
- Validate environment variables on startup
- Use config management libraries
- Log missing required env vars clearly

```python
def get_required_env(key, description=""):
    value = os.environ.get(key)
    if not value:
        raise RuntimeError(f"Missing required env var: {key}. {description}")
    return value

db_url = get_required_env("DATABASE_URL", "Should be postgres://...")
```

---

### 5. JWT/Token Detection (Go Scanner Only)

**Description**: Hardcoded JWT tokens, API tokens, or authentication credentials in source code.

**Severity**: HIGH

**CWE Mapping**: CWE-798 (same as Hardcoded Credentials)

**CVSS Score**: 9.1 (High)

**Example Patterns Detected**:
```python
JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
BEARER_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGc..."
```

**Note**: This pattern is detected in the Go scanner (5 patterns) but not yet in the demo custom code analyzer (4 patterns). Can be added if needed.

---

## Summary Table

| Pattern | CWE | CVSS | Severity | OWASP | SANS |
|---------|-----|------|----------|-------|------|
| Hardcoded Credentials | CWE-798 | 9.1 | HIGH | A02:2021 | CWE-798 |
| Prompt Injection | CWE-94 | 8.8 | HIGH | A03:2021 | CWE-94 |
| Infinite Loops | CWE-835 | 7.5 | HIGH | A01/A04 | CWE-835 |
| Unsafe Env Access | CWE-665 | 6.5 | MEDIUM | A05/A07 | CWE-665 |
| JWT/Token Detection | CWE-798 | 9.1 | HIGH | A02:2021 | CWE-798 |

---

## Security Standards References

### OWASP Top 10 (2021)
- https://owasp.org/Top10/
- **A02:2021 – Cryptographic Failures**: Hardcoded credentials
- **A03:2021 – Injection**: Prompt injection, code injection
- **A05:2021 – Access Control**: Environment variable misuse

### SANS Top 25 (2023)
- https://www.sans.org/top25-software-errors/
- **CWE-798**: Use of Hard-Coded Credentials
- **CWE-94**: Code Injection
- **CWE-665**: Improper Initialization

### CWE References
- CWE-798: https://cwe.mitre.org/data/definitions/798.html
- CWE-94: https://cwe.mitre.org/data/definitions/94.html
- CWE-835: https://cwe.mitre.org/data/definitions/835.html
- CWE-665: https://cwe.mitre.org/data/definitions/665.html

### CVSS Scoring
- https://www.first.org/cvss/
- Scoring methodology for security vulnerabilities
- Includes attack vector, complexity, privileges, user interaction, scope, and impact

---

## Verification Checklist

When reviewing these mappings with your security team, verify:

- [ ] CWE identifiers are current and correct
- [ ] CVSS scores reflect realistic attack scenarios for AI agents
- [ ] OWASP Top 10 mappings align with your organization's compliance needs
- [ ] SANS Top 25 rankings are appropriate for your threat model
- [ ] Severity levels (HIGH/MEDIUM) match your risk assessment
- [ ] Example patterns cover realistic agent implementations

---

## Future Enhancements

1. **Add JWT/Token Detection to Demo**: Include CWE-798 variant for token detection in custom code analyzer
2. **Add Prompt Template Detection**: Detect unsafe prompt template usage beyond f-strings
3. **Add Tool Chain Analysis**: Detect unsafe tool definitions in agent frameworks
4. **Add Sensitive Data Leakage**: Detect logging of sensitive information
5. **Add Race Condition Detection**: Detect concurrent access issues in agents

---

## Notes for Integration

- All findings in demo include: `pattern`, `severity`, `line`, `message`, `cwe`, `cvss`
- Standard compliance statement: "Complies with OWASP Top 10, SANS Top 25"
- Can be expanded to show full CVSS vector on demand
- CWE/CVSS values are easily updatable in demo.html for future refinement
