# Pattern 2: Hardcoded Credentials - Gap Analysis

## Current V1 vs. Specification Requirements

### Detection Coverage Comparison

| Aspect | V1 Current | Specification Requires | Gap | Priority |
|--------|-----------|----------------------|-----|----------|
| **Credential Patterns** | 5 patterns | 30+ patterns | -500% | P1 |
| **Provider Support** | Generic | AWS, Azure, GCP, Stripe, GitHub, SendGrid, Slack, Twilio, JWT, private keys | -90% | P1 |
| **Encoding Detection** | None | Base64, Hex, UTF-8, obfuscation | -100% | P2 |
| **Entropy Analysis** | None | High-entropy detection for unknown formats | -100% | P2 |
| **Confidence Scoring** | Fixed 0.98 | Dynamic algorithm (0.0-1.0) | Missing | P1 |
| **String Handling** | Single line | Concatenation, multi-line literals, adjacent strings | -80% | P2 |
| **Multi-Language** | Regex only | Language-specific patterns, multiple syntaxes | -60% | P3 |
| **Private Keys** | Not detected | PEM format detection | -100% | P1 |
| **False Positive Reduction** | Basic (5 words) | Advanced (30+ patterns, entropy, context, severity levels) | -80% | P2 |
| **Obfuscation Handling** | None | Char codes, loops, encoding variations | -100% | P3 |
| **Real CVE Coverage** | Not tested | LangChain AgentSmith, Uber, Flowise, Dify, CrewAI scenarios | -100% | P1 |

---

## Detailed Gap Analysis

### PRIORITY 1: Critical Gaps

#### 1. **Credential Format Detection (30+ formats missing)**

**Current V1:**
- 5 patterns: generic keys, service-specific, tokens, database

**Missing 25+ patterns:**

**AWS (4 patterns)**
- Access Key ID: `AKIA[0-9A-Z]{16}`
- Secret Access Key: 40-char base64
- Session token: Longer format
- IAM user format

**Azure (4 patterns)**
- Storage account keys
- Connection strings
- Service principal credentials
- ARM templates with secrets

**Google Cloud (3 patterns)**
- API keys: `AIza[0-9A-Za-z\-_]{35}`
- Service account JSON keys
- OAuth tokens: `ya29\.`

**Third-Party APIs (10+ patterns)**
- Stripe: `sk_live_`, `sk_test_`, `rk_live_`
- GitHub: `ghp_`, `gho_`, `ghu_`
- SendGrid: `SG\.`
- Slack: `xoxb-`, `xoxp-`
- Twilio: `ACxxxxxxxxxxxxx`
- PagerDuty: `u+`
- DigitalOcean: `dop_v1_`
- NPM tokens
- PyPI tokens

**JWT & Authentication (3+ patterns)**
- JWT format: `[A-Za-z0-9-_]{20,}\.[A-Za-z0-9-_]{20,}\.[A-Za-z0-9-_]{20,}`
- Bearer tokens
- Basic auth credentials in URLs

**Encryption & Private Keys (5+ patterns)**
- RSA private keys: `-----BEGIN RSA PRIVATE KEY-----`
- EC private keys: `-----BEGIN EC PRIVATE KEY-----`
- OpenSSH keys: `-----BEGIN OPENSSH PRIVATE KEY-----`
- PGP keys
- Certificate files with embedded secrets

**CWE Alignment:**
- CWE-798: Use of Hard-coded Credentials (primary)
- CWE-259: Hard-coded Password
- CWE-321: Hard-coded Cryptographic Key
- CWE-798 is currently covered, but missing 259 and 321 for comprehensive detection

#### 2. **Confidence Scoring Algorithm (Missing)**

**V1:** Fixed `confidence = 0.98` for all findings

**V2 Requirement:**
```
Base Score: 0.5

INCREASE (+points):
+ 0.20 if variable name matches credential keywords
+ 0.15 if value matches known secret format (regex)
+ 0.20 if value has high entropy (>4.0 bits/char)
+ 0.10 if located in production code (not test/example)
+ 0.15 if private key format detected

DECREASE (-points):
- 0.30 if contains placeholder words (example, test, dummy)
- 0.20 if appears in test file
- 0.15 if appears in documentation file
- 0.20 if short (<8 chars, likely not real secret)
- 0.25 if public key detected (ssh-rsa, BEGIN PUBLIC KEY)

Range: [0.0, 1.0]
Report if confidence >= 0.5
Alert if confidence >= 0.7
Critical if confidence >= 0.9
```

**Impact:** Reduces false positives from unknown levels to <5%

#### 3. **Private Key Detection (100% missing)**

**V1:** No detection for PEM-formatted private keys

**V2 Requirement:**
- Detect all private key formats:
  - RSA: `-----BEGIN RSA PRIVATE KEY-----`
  - EC: `-----BEGIN EC PRIVATE KEY-----`
  - DSA: `-----BEGIN DSA PRIVATE KEY-----`
  - OpenSSH: `-----BEGIN OPENSSH PRIVATE KEY-----`
  - PKCS8: `-----BEGIN PRIVATE KEY-----`
  - PGP: `-----BEGIN PGP PRIVATE KEY BLOCK-----`

**Severity:** CRITICAL (highest impact - full system compromise)

#### 4. **Real-World CVE Coverage (0% tested)**

**Missing validation against:**
- LangChain AgentSmith: Agent stealing API keys via proxy
- Uber 2022: PowerShell scripts with admin credentials
- Flowise: Lack of auth + stored API keys
- Dify: Code execution leading to secret exposure
- CrewAI: Environment variable recommendations (testing)

### PRIORITY 2: Advanced Gaps

#### 5. **Encoding & Obfuscation Detection (100% missing)**

**Missing patterns:**
- Base64-encoded secrets: `[A-Za-z0-9+/]{40,}={0,2}`
- Hex-encoded content: `\x[0-9a-fA-F]{2}`, `0x[0-9a-fA-F]+`
- URL encoding: `%[0-9A-F]{2}`
- Character array construction (char codes)
- Adjacent string literal concatenation

**Entropy Analysis:**
- High-entropy strings not matching known patterns
- Calculation: `entropy = -Σ(p_i * log2(p_i))` where p_i is char frequency
- Threshold: >4.0 bits/char indicates likely secret

#### 6. **String Handling Improvements (80% missing)**

**Current:** Only processes single lines

**Missing:**
- String concatenation: `"abc" + "def"` → `"abcdef"`
- Multi-line continuations: `"long\n" + "secret"`
- Python implicit: `"abc" "def"` → `"abcdef"`
- Template literals: `` `secret_${var}` ``
- F-string analysis for constant expressions

#### 7. **Advanced False Positive Reduction (80% missing)**

**Current:** 5 placeholder words

**Missing (25+ patterns):**
- Common defaults: `password123`, `admin`, `123456`, `changeme`, `test`, `demo`
- Standard dummy formats: `YOUR_API_KEY`, `REPLACE_WITH_`, `INSERT_`
- SSH public key detection: `ssh-rsa`, `ssh-ed25519`, `BEGIN PUBLIC KEY`
- Hashed passwords: SHA/MD5 format detection
- License/certificate content (high entropy but not secrets)
- Session IDs and UUIDs (high entropy but not credentials)
- Binary/encoded data that's not text
- Environment variable references: `${ENV_VAR}`, `$ENV_VAR`

### PRIORITY 3: Comprehensive Gaps

#### 8. **Multi-Language Support Gaps (60% missing)**

**Current:** Regex-based, all languages

**Missing language-specific detection:**
- Python: Function parameter defaults, decorators
- Go: struct tags with secrets, interface{} values
- Java: Annotations, static initializers
- JavaScript/TypeScript: Object literals, `process.env` fallbacks
- C#: Configuration sections, app.settings
- Ruby: Rails credentials format

#### 9. **Obfuscation Techniques (100% missing)**

**Missing detection for:**
- Character array construction loops
- Base64 decoding in code (indicates encoded secret)
- Hex escape sequences
- Unicode codepoint arrays
- Reflection-based string assembly
- Environment variable obfuscation with defaults

#### 10. **Context-Aware Severity (Missing)**

**V1:** All findings CRITICAL

**V2 Should Differentiate:**
- Admin/root credentials: CRITICAL (highest risk)
- API keys: CRITICAL (account compromise)
- Database passwords: CRITICAL (multi-tenant data breach)
- Bot tokens: HIGH (account takeover)
- OAuth tokens: HIGH (unauthorized access)
- Encryption keys: CRITICAL (full compromise)
- Default credentials: MEDIUM (often intentional in tests)
- SSH public keys: LOW (not sensitive)

---

## Impact Assessment

### False Positive Rate

**V1 Estimated:** Unknown (likely 10-20% based on generic patterns)
**V2 Target:** <5% with confidence scoring

### Detection Accuracy

**V1 Estimated:** 60-70% (misses obfuscation, encoding, many formats)
**V2 Target:** >95% (comprehensive patterns + scoring)

### Real-World Incident Coverage

**V1:** 0/5 major scenarios (not tested against actual CVEs)
**V2:** Should detect all 5 (LangChain, Uber, Flowise, Dify, CrewAI)

---

## Implementation Strategy

Following Pattern 1 methodology:

### Phase 1: Priority 1 Implementation
- 30+ credential format patterns
- Private key detection (PEM, OpenSSH, PGP)
- Confidence scoring algorithm
- Enhanced false positive reduction

### Phase 2: Priority 2 Implementation
- Base64/Hex encoding detection
- Entropy analysis
- String concatenation handling
- Multi-line literal support

### Phase 3: Priority 3 Implementation
- Multi-language patterns
- Obfuscation detection
- Context-aware severity

---

## Files to Create/Modify

**New Files:**
- `hardcoded_credentials_v2.go` (800+ LOC)
- `hardcoded_credentials_v2_test.go` (1000+ LOC)
- `docs/HARDCODED_CREDENTIALS_V2_ANALYSIS.md`

**Updated Files:**
- `cmd/scanner/init_registry.go` (use V2 detector)

---

## Timeline & Effort Estimate

- **Phase 1:** 2-3 hours (30+ patterns, confidence scoring, testing)
- **Phase 2:** 2-3 hours (encoding, entropy, string handling)
- **Phase 3:** 1-2 hours (multi-language, obfuscation)
- **Total:** 5-8 hours
- **Testing:** 30+ test cases across all scenarios
- **Documentation:** Comprehensive analysis + examples

---

## Success Criteria

✅ Detect all 5 real-world CVE scenarios
✅ 30+ credential format patterns
✅ False positive rate <5%
✅ Detection accuracy >95%
✅ 100% test pass rate
✅ Performance: <1s for typical projects
✅ Full documentation with examples
