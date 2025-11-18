# Inkog Security Pattern Examples

This directory contains vulnerable code samples demonstrating each of Inkog's 15 security patterns. These examples are designed to help developers understand common AI agent security vulnerabilities.

> **⚠️ WARNING:** These examples intentionally contain security vulnerabilities for educational purposes. Do NOT use this code in production.

## Pattern Categories

### TIER 1 - Foundation Patterns (4)

1. **Hardcoded Credentials** (CWE-798, CWE-259)
   - File: `tier1_hardcoded_credentials.py`
   - Issue: API keys and secrets hardcoded in source code
   - Impact: Account compromise, unauthorized API usage

2. **Prompt Injection** (CWE-94, CWE-95)
   - File: `tier1_prompt_injection.py`
   - Issue: Unvalidated user input directly in LLM prompts
   - Impact: LLM jailbreaks, prompt hijacking attacks

3. **Infinite Loops & Unbounded Recursion** (CWE-835, CWE-674)
   - File: `tier1_infinite_loops.py`
   - Issue: Loops without exit conditions or recursion without base cases
   - Impact: CPU exhaustion, API cost explosion, service downtime

4. **Unsafe Environment Variable Access** (CWE-665)
   - File: `tier1_unsafe_env.py`
   - Issue: Environment variables accessed without defaults or validation
   - Impact: Runtime crashes, missing configuration errors

### TIER 2 - Resource Exhaustion (5)

5. **Token Bombing / Unbounded API Calls** (CWE-400, CWE-770)
   - File: `tier2_token_bombing.py`
   - Issue: LLM API calls without rate limiting or token budgets
   - Impact: Uncontrolled costs, DoS attacks

6. **Recursive Tool Calling / Agent Delegation Loops** (CWE-674, CWE-835)
   - File: `tier2_recursive_tools.py`
   - Issue: Agents delegating to each other in loops
   - Impact: Infinite loops, resource exhaustion

7. **Context Window Accumulation** (CWE-770, CWE-400)
   - File: `tier2_context_accumulation.py`
   - Issue: Unbounded conversation history growth
   - Impact: Memory exhaustion, slower responses

8. **Missing Rate Limits** (CWE-400, CWE-770)
   - File: `tier2_missing_rate_limits.py`
   - Issue: Uncontrolled API rate exposure
   - Impact: DoS attacks, service degradation

9. **RAG Over-Fetching** (CWE-770, CWE-400)
   - File: `tier2_rag_over_fetching.py`
   - Issue: Excessive document retrieval in RAG systems
   - Impact: Performance degradation, cost explosion

### TIER 3 - Data & Execution (6)

10. **Logging Sensitive Data** (CWE-532, CWE-209)
    - File: `tier3_logging_sensitive.py`
    - Issue: PII and credentials logged to files/stdout
    - Impact: Data breach, credential exposure

11. **Output Validation Failures** (CWE-74, CWE-95)
    - File: `tier3_output_validation.py`
    - Issue: Unvalidated LLM output used directly
    - Impact: Code injection, command injection

12. **SQL Injection via LLM** (CWE-89, CWE-94)
    - File: `tier3_sql_injection.py`
    - Issue: LLM-generated SQL without sanitization
    - Impact: Database breach, data manipulation

13. **Unvalidated Code Execution** (CWE-95, CWE-94)
    - File: `tier3_unvalidated_exec.py`
    - Issue: exec/eval on unvalidated LLM output
    - Impact: Remote code execution

14. **Missing Human Oversight** (CWE-99, CWE-674)
    - File: `tier3_missing_oversight.py`
    - Issue: Autonomous agent actions without approval gates
    - Impact: Uncontrolled damage, irreversible actions

15. **Cross-Tenant Data Leakage** (CWE-284, CWE-862)
    - File: `tier3_cross_tenant.py`
    - Issue: Multi-tenant isolation failures
    - Impact: Data leakage between customers

## Quick Scan

Run Inkog on all examples:

```bash
# Scan entire examples directory
inkog-scanner --path examples/

# Generate JSON report
inkog-scanner --path examples/ --json-report examples-report.json

# Scan specific pattern
inkog-scanner --path examples/tier1_hardcoded_credentials.py
```

## Expected Results

Running Inkog on these examples should detect:
- 50+ total findings
- All 15 pattern types represented
- Risk score: 95-100/100
- Multiple CRITICAL and HIGH severity issues

## Learning Guide

### For Security Teams
1. Review each file to understand vulnerability patterns
2. Use as test cases for security tooling
3. Share with developers as security training material

### For Developers
1. Identify which patterns appear in your code
2. Apply the "Safe" remediation examples
3. Follow the OWASP LLM Top 10 guidelines

### For AI Agent Frameworks
1. Use as validation test suite
2. Benchmark detection capabilities
3. Verify pattern matching accuracy

## Safe Alternatives

Each vulnerable example can be remediated. Common patterns:

### Credentials
```python
# ❌ Vulnerable
api_key = "sk-123456..."

# ✅ Safe
api_key = os.environ.get('OPENAI_API_KEY')
if not api_key:
    raise ValueError("OPENAI_API_KEY not set")
```

### Prompts
```python
# ❌ Vulnerable
prompt = f"Execute this: {user_input}"

# ✅ Safe
from langchain.prompts import PromptTemplate
template = PromptTemplate(
    input_variables=["user_input"],
    template="Execute this: {user_input}"
)
```

### Loops
```python
# ❌ Vulnerable
while True:
    process_agent(data)

# ✅ Safe
for attempt in range(max_retries):
    result = process_agent(data)
    if result:
        break
```

## File Structure

```
examples/
├── README.md (this file)
├── tier1_hardcoded_credentials.py
├── tier1_prompt_injection.py
├── tier1_infinite_loops.py
├── tier1_unsafe_env.py
├── tier2_token_bombing.py
├── tier2_recursive_tools.py
├── tier2_context_accumulation.py
├── tier2_missing_rate_limits.py
├── tier2_rag_over_fetching.py
├── tier3_logging_sensitive.py
├── tier3_output_validation.py
├── tier3_sql_injection.py
├── tier3_unvalidated_exec.py
├── tier3_missing_oversight.py
├── tier3_cross_tenant.py
└── langchain/ (framework-specific examples)
    ├── vulnerable_agent.py
    └── safe_agent.py
```

## Contributing

To add more examples:
1. Create a new file with a clear vulnerability pattern
2. Add comments explaining the vulnerability
3. Update this README with the new example
4. Test with `inkog-scanner` to verify detection

## Additional Resources

- [CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Inkog Documentation](https://docs.inkog.ai)
- [GitHub Security Best Practices](https://docs.github.com/en/code-security)
