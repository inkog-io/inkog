# Inkog Pattern Development Framework

**Version:** 1.0
**Date:** November 12, 2025
**Status:** Production Ready

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Pattern Interface](#pattern-interface)
4. [Development Workflow](#development-workflow)
5. [Best Practices](#best-practices)
6. [Testing Strategy](#testing-strategy)
7. [Real-World Validation](#real-world-validation)
8. [Deployment](#deployment)

---

## Overview

The Inkog Pattern Development Framework provides a standardized, production-ready approach to implementing security detection patterns for AI agent code vulnerabilities.

### Core Principles

1. **No Band-Aids** - Complete implementations, not workarounds
2. **Test-Driven** - Tests written first, code implements to pass
3. **Enterprise-Grade** - Production quality from day one
4. **Modular & Pluggable** - Patterns are independent, composable
5. **Honest Assessment** - Unbiased evaluation before declaring ready
6. **Real CVE Validation** - Detect actual known vulnerabilities

### Pattern Tiers

**Tier 1: Financial Impact** (Critical threats to cost/revenue)
- Hardcoded Credentials (API keys, tokens)
- Prompt Injection (user input in prompts)
- Infinite Loops (cost explosion, DoS)
- Unsafe Environment Access (credential exposure)

**Tier 2: Resource Exhaustion** (System stability threats)
- Token Bombing (unbounded LLM consumption)
- Recursive Tool Calling (agent loops, delegation chains)

**Tier 3: Data Protection** (Confidentiality/integrity threats)
- To be implemented in future releases

---

## Architecture

### Component Diagram

```
┌─────────────────────────────────────────────────┐
│           Scanner (cmd/scanner)                 │
│  - File discovery, concurrent execution         │
│  - Results aggregation and reporting            │
└──────────────────┬──────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────┐
│        Registry (pkg/patterns)                  │
│  - Auto-discovery of detectors                  │
│  - Plugin management                            │
└──────────────────┬──────────────────────────────┘
                   │
        ┌──────────┴──────────┬────────────┐
        │                     │            │
┌───────▼──────┐  ┌──────────▼───┐  ┌────▼─────────┐
│ Detector 1   │  │  Detector 2  │  │  Detector N  │
│ Interface    │  │  Interface   │  │  Interface   │
│ Implementation│  │Implementation│  │Implementation│
└──────────────┘  └──────────────┘  └──────────────┘
```

### File Structure

```
pkg/patterns/
├── detector.go           # Detector interface definition
├── pattern.go            # Pattern metadata structure
├── registry.go           # Registry for pattern discovery
└── detectors/
    ├── hardcoded_credentials.go      # Pattern 1
    ├── hardcoded_credentials_test.go
    ├── prompt_injection.go            # Pattern 2
    ├── prompt_injection_test.go
    ├── infinite_loop.go               # Pattern 3
    ├── infinite_loop_test.go
    ├── unsafe_env_access.go           # Pattern 4
    ├── unsafe_env_access_test.go
    ├── token_bombing.go               # Pattern 5
    ├── token_bombing_test.go
    ├── recursive_tool_calling.go      # Pattern 6
    ├── recursive_tool_calling_test.go
    └── [patterns_7_through_15].go     # Future patterns

cmd/scanner/
├── main.go               # CLI entry point
├── scanner.go            # Scanning engine
├── init_registry.go      # Pattern registration
└── inkog-scanner         # Compiled binary
```

---

## Pattern Interface

Every detector must implement the `Detector` interface:

```go
type Detector interface {
    // Name returns the detector identifier (e.g., "prompt_injection")
    Name() string

    // Detect analyzes source code and returns findings
    Detect(filePath string, src []byte) ([]Finding, error)

    // GetPattern returns metadata about this pattern
    GetPattern() Pattern

    // GetConfidence returns default confidence score (0.0-1.0)
    GetConfidence() float32
}
```

### Pattern Metadata Structure

```go
type Pattern struct {
    ID          string   // Unique identifier: "pattern_name"
    Name        string   // Display name: "Pattern Display Name"
    Version     string   // Semantic version: "1.0"
    Category    string   // Tier: "financial_impact", "resource_exhaustion", etc.
    Severity    string   // Base severity: "CRITICAL", "HIGH", "MEDIUM"
    CVSS        float32  // CVSS score (0.0-10.0)
    CWEIDs      []string // CWE identifiers: ["CWE-89", "CWE-90"]
    OWASP       string   // OWASP mapping: "A01:2021"
    Description string   // What this pattern detects
}
```

### Finding Structure

```go
type Finding struct {
    ID         string  // Unique finding ID
    PatternID  string  // Pattern that detected this
    Pattern    string  // Display name of pattern
    File       string  // File path
    Line       int     // Line number (1-indexed)
    Column     int     // Column number (1-indexed)
    Severity   string  // "CRITICAL", "HIGH", "MEDIUM", "LOW"
    Confidence float32 // Confidence 0.0-1.0
    Message    string  // Human-readable description
    Code       string  // The actual vulnerable code line
    CWE        string  // CWE of this specific finding
    CVSS       float32 // CVSS score of this finding
    OWASP      string  // OWASP mapping of this finding
}
```

---

## Development Workflow

### Step 1: Design Phase

**Define the Vulnerability**
1. Identify real-world vulnerability (CVE, best practice violation)
2. Determine detection scope (language, framework)
3. Define severity and confidence scoring

**Example: Pattern 5 (Token Bombing)**
- **Vulnerability**: LLM API calls without token limits in unbounded contexts
- **Scope**: Python/Go code with LLM SDK calls
- **Severity**: CRITICAL (unbounded loops), HIGH (recursive)
- **Confidence**: 0.88-0.95 depending on context

**Acceptance Criteria**
- [ ] Real CVEs or known vulnerabilities can be detected
- [ ] Safe patterns (with token limits, with breaks) are not flagged
- [ ] Confidence scores match severity assessment
- [ ] No false positives on test suite code

### Step 2: Test-Driven Implementation

**Write Tests First**
```
1. Create pattern_name_test.go
2. Write 50+ unit tests covering:
   - Basic vulnerable patterns
   - Variations (language, framework)
   - Safe patterns (false negative prevention)
   - Edge cases and boundaries
   - Real CVE patterns
   - Interface compliance
```

**Example Test Structure**
```go
func TestPatternBasicVulnerability(t *testing.T) {
    detector := NewPatternDetector()

    code := `vulnerable code here`
    findings, err := detector.Detect("test.py", []byte(code))

    if err != nil {
        t.Fatalf("Detector error: %v", err)
    }

    if len(findings) == 0 {
        t.Errorf("Expected to find vulnerability, got 0 findings")
    }

    if findings[0].Severity != "CRITICAL" {
        t.Errorf("Expected CRITICAL, got %s", findings[0].Severity)
    }
}

func TestPatternSafePatternNotFlagged(t *testing.T) {
    detector := NewPatternDetector()

    code := `safe code here`
    findings, err := detector.Detect("test.py", []byte(code))

    if len(findings) > 0 {
        t.Errorf("Expected no findings for safe pattern, got %d", len(findings))
    }
}
```

### Step 3: Implementation

**Create Detector**
```
1. Create pattern_name.go
2. Implement Detector interface
3. Implement detection logic:
   - Pattern matching (regex, string matching)
   - Context analysis (surrounding lines, indentation)
   - Confidence scoring
   - Severity assignment
4. Handle edge cases:
   - Comments (skip them)
   - Empty files
   - Different language syntaxes
```

**Key Implementation Patterns**

**A. Multi-Line Context Detection**
```go
// Check surrounding lines for related tokens
startCheck := lineNum - 2
if startCheck < 0 {
    startCheck = 0
}
endCheck := lineNum + 3
if endCheck > len(lines) {
    endCheck = len(lines)
}

for i := startCheck; i < endCheck; i++ {
    if strings.Contains(lines[i], "token_limit") {
        hasTokenLimit = true
        break
    }
}
```

**B. Indentation-Based Scope Tracking**
```go
// Determine scope by indentation level
currentIndent := len(line) - len(strings.TrimLeft(line, " \t"))
loopIndent := len(loopLine) - len(strings.TrimLeft(loopLine, " \t"))

// If indentation same or less than loop level, we've exited the loop
if currentIndent <= loopIndent {
    break
}
```

**C. Safe Pattern Filtering**
```go
// Skip patterns that indicate safe code
if strings.Contains(line, "if ") {
    hasGuardCondition = true
}

if hasGuardCondition && strings.Contains(line, "return") {
    if !strings.Contains(line, "recursive_call(") {
        hasBaseCase = true
    }
}
```

### Step 4: Test Validation

**Run Unit Tests**
```bash
go test ./pkg/patterns/detectors -v
```

**Validation Checklist**
- [ ] All unit tests pass (hard assertions, not info logs)
- [ ] No unused variables or dead code
- [ ] Confidence scores are correct
- [ ] Safe patterns excluded
- [ ] Real CVE patterns detected
- [ ] Multiple language support verified
- [ ] Edge cases handled

### Step 5: Integration

**Register Pattern**
```go
// In cmd/scanner/init_registry.go
registry.Register(detectors.NewPatternDetector())
```

**Rebuild Scanner**
```bash
go build -o inkog-scanner ./cmd/scanner/
```

**Run End-to-End Test**
```bash
./inkog-scanner /path/to/test/code
```

### Step 6: Documentation

**Document the Pattern**
- Update PATTERN_REFERENCE.md
- Add examples to extension template
- Document any language-specific requirements

---

## Best Practices

### 1. **Detection Logic**

✅ **DO:**
- Check surrounding context (multi-line analysis)
- Use language-specific patterns (def vs func)
- Handle edge cases explicitly
- Test on real vulnerable code
- Start with broad patterns, refine if needed

❌ **DON'T:**
- Rely on single-line matches
- Ignore indentation/scope
- Leave edge cases untested
- Test only on synthetic examples
- Over-engineer pattern matching

### 2. **Testing**

✅ **DO:**
- Write 50+ tests per pattern
- Use hard assertions (t.Errorf)
- Test both vulnerable and safe patterns
- Include real CVE examples
- Test edge cases and boundaries

❌ **DON'T:**
- Write only 10-20 tests
- Use info-level logs instead of assertions
- Test only vulnerable patterns
- Use only synthetic examples
- Skip edge cases

### 3. **Confidence Scoring**

✅ **DO:**
- Base confidence on evidence (loop + call = high)
- Adjust for context (recursive vs unbounded)
- Match confidence to severity
- Document scoring logic

❌ **DON'T:**
- Use fixed confidence for all findings
- Ignore context strength
- Have low confidence on CRITICAL findings
- Leave scoring logic undocumented

### 4. **Code Quality**

✅ **DO:**
- Remove debug code before commit
- Clean up old implementations
- Use consistent naming
- Add comments for complex logic
- Keep functions focused

❌ **DON'T:**
- Leave TODO or DEBUG comments
- Have multiple versions of detectors
- Use inconsistent naming (v2, v2clean, final)
- Write 200+ line functions
- Have circular dependencies

### 5. **Honest Assessment**

✅ **DO:**
- Pause before declaring "done"
- Review for band-aids and workarounds
- Test on real code, not just examples
- Document limitations
- Be willing to rebuild if needed

❌ **DON'T:**
- Lower test expectations to pass
- Call something production-ready without proof
- Ignore known limitations
- Test only happy path
- Commit before honest review

---

## Testing Strategy

### Unit Test Structure

**File:** `pattern_name_test.go`

**Sections:**
1. **Basic Vulnerability Tests** (10-15 tests)
   - Direct detection of primary vulnerability
   - Different code variations
   - Confidence scoring

2. **Safe Pattern Tests** (10-15 tests)
   - Patterns that should NOT be flagged
   - False negative prevention
   - Valid use cases

3. **Real CVE Tests** (5-10 tests)
   - Known vulnerabilities from CVE database
   - Framework-specific patterns
   - Complex code examples

4. **Edge Cases** (5-10 tests)
   - Empty files
   - Comments
   - Different languages
   - Boundary conditions

5. **Interface Tests** (2-3 tests)
   - Name() returns correct value
   - GetPattern() returns valid metadata
   - GetConfidence() returns 0.0-1.0

### Test Execution

```bash
# Run specific pattern tests
go test ./pkg/patterns/detectors -run PatternName -v

# Run all detector tests
go test ./pkg/patterns/detectors -v

# Run with coverage
go test ./pkg/patterns/detectors -cover
```

### Validation Criteria

✅ **Required:**
- 100% test pass rate
- No hardcoded values in detector
- No debug code
- All tests use hard assertions
- Real CVE patterns tested

⚠️ **Recommended:**
- 90%+ code coverage
- 50+ unit tests
- Documentation of limitations
- Performance benchmarks

---

## Real-World Validation

### Before Production Deployment

**1. Create Real Vulnerable Code**
```python
# test_vulnerable_code.py
import openai

def process_unbounded():
    """Real token bombing vulnerability"""
    while True:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": user_input}]
        )
        # No token limit, no break = VULNERABLE
        print(response)
```

**2. Scan with Detector**
```bash
./inkog-scanner test_vulnerable_code.py
```

**3. Verify Detection**
- Detector finds the vulnerability
- Severity is correct (CRITICAL)
- Confidence is appropriate (0.88+)
- Message is clear and actionable

**4. Test False Positives**
```python
# test_safe_code.py
import openai

def process_safely():
    """This should NOT be flagged"""
    for i in range(10):  # Bounded loop
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            max_tokens=100,  # Token limit
            messages=[{"role": "user", "content": "hello"}]
        )
        print(response)
```

**5. Verify No False Positives**
- Detector does NOT flag safe code
- Real vulnerabilities are still detected

---

## Deployment

### Pre-Deployment Checklist

- [ ] All tests passing (100% pass rate)
- [ ] No debug code or TODO comments
- [ ] Old implementations removed
- [ ] Real CVE validation successful
- [ ] False positive rate acceptable
- [ ] Documentation complete
- [ ] Honest review conducted
- [ ] Team sign-off obtained

### Deployment Steps

**1. Merge to Main**
```bash
git add pattern_name.go pattern_name_test.go
git commit -m "Add Pattern X with comprehensive tests"
git push origin main
```

**2. Rebuild Scanner**
```bash
go build -o inkog-scanner ./cmd/scanner/
```

**3. Run Full Test Suite**
```bash
go test ./pkg/patterns/detectors -v
```

**4. Deploy Binary**
```bash
# Copy to deployment location
cp inkog-scanner /usr/local/bin/

# Verify installation
inkog-scanner --version
```

**5. Run Acceptance Tests**
```bash
# Test on known vulnerable code
./inkog-scanner /path/to/test/code --strict

# Verify findings are correct
# Verify no false positives
```

---

## Pattern Development Checklist

Use this checklist for each new pattern:

```
DESIGN PHASE
☐ Vulnerability identified and documented
☐ Real CVEs or known patterns found
☐ Detection scope defined (languages, frameworks)
☐ Severity levels determined
☐ Acceptance criteria written

TEST PHASE
☐ Test file created with 50+ tests
☐ Basic vulnerability tests written
☐ Safe pattern tests written
☐ Real CVE tests written
☐ Edge case tests written
☐ All tests use hard assertions (not logs)

IMPLEMENTATION PHASE
☐ Detector interface implemented
☐ Detection logic coded
☐ Multi-line context handled
☐ Edge cases handled
☐ Confidence scoring correct
☐ No debug code

VALIDATION PHASE
☐ All unit tests passing
☐ Scanner builds successfully
☐ Real vulnerable code detected
☐ Safe patterns not flagged
☐ Confidence scores correct

INTEGRATION PHASE
☐ Pattern registered in init_registry.go
☐ Full test suite passes
☐ End-to-end scanning works
☐ Documentation updated

DEPLOYMENT PHASE
☐ Honest review completed
☐ No band-aids or workarounds found
☐ Code quality standards met
☐ Team sign-off obtained
☐ Deployed to production
```

---

## Summary

This framework provides a proven approach to implementing production-ready security patterns:

1. **Design** - Understand the vulnerability deeply
2. **Test-Drive** - Write tests, then code
3. **Implement** - Build with context awareness
4. **Validate** - Prove it works on real code
5. **Review** - Honestly assess before shipping
6. **Deploy** - Release with confidence

Following this framework ensures patterns are:
- ✅ Truly production-ready
- ✅ Well-tested and documented
- ✅ Free of band-aids and workarounds
- ✅ Capable of detecting real vulnerabilities
- ✅ Maintainable for future enhancement

---

**Version:** 1.0
**Last Updated:** November 12, 2025
**Status:** Approved for Production
