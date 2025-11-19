# Inkog Testing Best Practices

**Version:** 1.0
**Date:** November 12, 2025
**Audience:** Pattern Developers

---

## Overview

This guide establishes testing standards for Inkog security patterns. Following these practices ensures detectors are production-ready and free of false positives.

---

## Core Testing Principles

### 1. Test-Driven Development (TDD)

**Process:**
1. Write tests FIRST (before implementation)
2. Implement code to PASS tests
3. Refactor for clarity and efficiency

**Benefits:**
- Tests define requirements clearly
- Code is designed for testability
- Prevents over-engineering
- Creates living documentation

### 2. Comprehensive Coverage

**Minimum Test Count: 50 tests per pattern**

- 10-15 vulnerable pattern tests
- 10-15 safe pattern tests
- 5-10 real CVE tests
- 5-10 edge case tests
- 2-3 interface compliance tests

### 3. Hard Assertions

**ALWAYS use hard assertions** (t.Errorf, t.Fatalf)

```go
// ✅ CORRECT: Hard assertion will fail the test
if len(findings) == 0 {
    t.Errorf("Expected finding, but got 0 - test FAILS")
}

// ❌ WRONG: Info log doesn't fail the test
if len(findings) == 0 {
    t.Logf("Info: No findings - test still PASSES")
}
```

### 4. Real-World Examples

**Every pattern needs real CVE tests**

- Test actual known vulnerabilities
- Use code from CVE databases (NVD, Snyk)
- Test framework-specific patterns
- Document the CVE reference

---

## Test File Structure

### Template

```go
package detectors

import (
	"testing"
)

// ============================================================================
// SECTION 1: BASIC VULNERABILITY DETECTION
// ============================================================================

// TestPatternBasicVulnerability tests core vulnerability detection
func TestPatternBasicVulnerability(t *testing.T) {
	detector := NewPatternDetector()

	code := `vulnerable_code_here`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected to find vulnerability, but got 0 findings")
	}

	if len(findings) > 0 {
		if findings[0].Severity != "CRITICAL" {
			t.Errorf("Expected CRITICAL, got %s", findings[0].Severity)
		}
	}
}

// ============================================================================
// SECTION 2: SAFE PATTERN EXCLUSION (FALSE NEGATIVE PREVENTION)
// ============================================================================

// TestPatternSafePatternNotFlagged tests that safe patterns are excluded
func TestPatternSafePatternNotFlagged(t *testing.T) {
	detector := NewPatternDetector()

	code := `safe_code_here`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	if len(findings) > 0 {
		t.Errorf("Expected no findings for safe pattern, but found %d", len(findings))
	}
}

// ============================================================================
// SECTION 3: REAL CVE DETECTION
// ============================================================================

// TestPatternRealCVE tests detection of actual known vulnerability
func TestPatternRealCVE(t *testing.T) {
	detector := NewPatternDetector()

	// Real vulnerable code from CVE database
	code := `real_cve_pattern_here`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected to find real CVE pattern, but got 0 findings")
	}
}

// ============================================================================
// SECTION 4: EDGE CASES & BOUNDARIES
// ============================================================================

// TestPatternEdgeCases tests boundary conditions
func TestPatternEdgeCases(t *testing.T) {
	detector := NewPatternDetector()

	tests := []struct {
		name     string
		code     string
		expected int // Expected number of findings
	}{
		{
			name:     "EmptyFile",
			code:     "",
			expected: 0,
		},
		{
			name: "CommentsOnly",
			code: `
# This looks vulnerable in comments
# But shouldn't be detected
`,
			expected: 0,
		},
		{
			name: "StringLiteralsOnly",
			code: `
text = "vulnerable_pattern_but_in_string"
`,
			expected: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := detector.Detect("test.py", []byte(tc.code))
			if err != nil {
				t.Fatalf("Detector crashed: %v", err)
			}

			if len(findings) != tc.expected {
				t.Errorf("Expected %d findings, got %d", tc.expected, len(findings))
			}
		})
	}
}

// ============================================================================
// SECTION 5: INTERFACE COMPLIANCE
// ============================================================================

// TestPatternInterfaceImplementation verifies Detector interface
func TestPatternInterfaceImplementation(t *testing.T) {
	detector := NewPatternDetector()

	// Verify Name()
	name := detector.Name()
	if name != "pattern_id" {
		t.Errorf("Expected Name() = 'pattern_id', got '%s'", name)
	}

	// Verify GetPattern()
	pattern := detector.GetPattern()
	if pattern.ID != "pattern_id" {
		t.Errorf("Expected pattern.ID = 'pattern_id', got '%s'", pattern.ID)
	}
	if pattern.Severity != "HIGH" && pattern.Severity != "CRITICAL" {
		t.Errorf("Expected HIGH or CRITICAL severity, got %s", pattern.Severity)
	}

	// Verify GetConfidence()
	confidence := detector.GetConfidence()
	if confidence <= 0 || confidence > 1.0 {
		t.Errorf("Expected confidence 0.0-1.0, got %v", confidence)
	}
}
```

---

## Test Categories

### Category 1: Vulnerable Pattern Tests (10-15 tests)

**Purpose:** Verify detector finds real vulnerabilities

```go
func TestTokenBombingOpenAIUnboundedLoop(t *testing.T) {
	detector := NewTokenBombingDetector()

	code := `
import openai

while True:
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[...]
    )
    # No token limit, no break = VULNERABLE
`

	findings, err := detector.Detect("test.py", []byte(code))
	if len(findings) == 0 {
		t.Errorf("Expected to find token bombing vulnerability")
	}
	if findings[0].Severity != "CRITICAL" {
		t.Errorf("Expected CRITICAL, got %s", findings[0].Severity)
	}
	if findings[0].Confidence < 0.85 {
		t.Errorf("Expected high confidence, got %v", findings[0].Confidence)
	}
}
```

**Testing Variations:**
- Different syntax (while vs for, Python vs Go)
- Different frameworks (OpenAI, Anthropic, Google)
- Different vulnerability indicators
- Confidence scoring

### Category 2: Safe Pattern Tests (10-15 tests)

**Purpose:** Prevent false positives

```go
func TestTokenBombingWithTokenLimitIsSafe(t *testing.T) {
	detector := NewTokenBombingDetector()

	code := `
import openai

while True:
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        max_tokens=100,  # TOKEN LIMIT - SAFE
        messages=[...]
    )
    if done:
        break  # BREAK CONDITION - SAFE
`

	findings, err := detector.Detect("test.py", []byte(code))
	if len(findings) > 0 {
		t.Errorf("Expected no findings for safe pattern with token limit")
	}
}
```

**Safe Pattern Examples:**
- Loops with break conditions
- Loops with return statements
- Token/context limits specified
- Time-based limits
- Explicit safety checks

### Category 3: Real CVE Tests (5-10 tests)

**Purpose:** Verify detection of actual known vulnerabilities

```go
func TestLangChainSitemapLoaderRecursion(t *testing.T) {
	// CVE: Infinite recursion in LangChain SitemapLoader
	// Reference: https://github.com/langchain-ai/langchain/issues/XXXX

	detector := NewRecursiveToolCallingDetector()

	code := `
from langchain.document_loaders import SitemapLoader

def process_url(url):
    loader = SitemapLoader(url)
    docs = loader.load()
    for doc in docs:
        # VULNERABLE: Recursive call without proper termination
        child_docs = process_url(doc.url)
        all_docs.extend(child_docs)
    return all_docs
`

	findings, err := detector.Detect("test.py", []byte(code))
	if len(findings) == 0 {
		t.Errorf("Failed to detect LangChain SitemapLoader recursion CVE")
	}
	if findings[0].Severity != "CRITICAL" {
		t.Errorf("Expected CRITICAL for unpatched CVE")
	}
}
```

**CVE Sources:**
- NVD (National Vulnerability Database)
- Snyk Vulnerability Database
- GitHub Security Advisories
- CVE.org
- Framework-specific security announcements

### Category 4: Edge Case Tests (5-10 tests)

**Purpose:** Handle boundary conditions gracefully

```go
func TestPatternEdgeCases(t *testing.T) {
	detector := NewPatternDetector()

	tests := []struct {
		name string
		code string
	}{
		{"EmptyFile", ""},
		{"OnlyWhitespace", "   \n  \n  "},
		{"OnlyComments", "# comment\n# another\n# comment"},
		{"VeryLongFile", strings.Repeat("code\n", 10000)},
		{"MixedLanguages", "def python():\n    pass\nfunc go() {}"},
		{"UnicodeCharacters", "# 你好 مرحبا Привет\ncode_here"},
		{"SpecialCharacters", "code = \"!@#$%^&*(){}[]\"\nmore_code()"},
		{"DeepNesting", "if a:\n  if b:\n    if c:\n      vulnerable_here()"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := detector.Detect("test.py", []byte(tc.code))
			if err != nil {
				t.Fatalf("%s: Detector crashed: %v", tc.name, err)
			}
			// Should not crash and should return valid findings
			_ = findings
		})
	}
}
```

**Edge Cases to Test:**
- Empty files
- Very large files
- Comments-only files
- Mixed language code
- Unicode and special characters
- Deeply nested code
- Malformed code (invalid syntax)

### Category 5: Interface Tests (2-3 tests)

**Purpose:** Verify Detector interface compliance

```go
func TestPatternInterfaceCompliance(t *testing.T) {
	detector := NewPatternDetector()

	// All methods must exist and return valid values
	if detector.Name() == "" {
		t.Errorf("Name() returned empty string")
	}

	pattern := detector.GetPattern()
	if pattern.ID == "" || pattern.Name == "" {
		t.Errorf("GetPattern() returned incomplete data")
	}

	confidence := detector.GetConfidence()
	if confidence < 0 || confidence > 1.0 {
		t.Errorf("GetConfidence() returned invalid value: %v", confidence)
	}
}
```

---

## Common Testing Mistakes

### ❌ Mistake 1: Using Info Logs Instead of Assertions

```go
// WRONG: Test passes even when finding is 0
if len(findings) == 0 {
    t.Logf("Info: No findings detected")  // ❌ Doesn't fail test
}

// CORRECT: Test fails if finding is 0
if len(findings) == 0 {
    t.Errorf("Expected finding but got 0")  // ✅ Fails test
}
```

### ❌ Mistake 2: Testing Only Happy Path

```go
// WRONG: Only tests vulnerable code
func TestVulnerability(t *testing.T) {
    findings, _ := detector.Detect("test.py", vulnerable_code)
    if len(findings) == 0 {
        t.Errorf("Should detect vulnerability")
    }
}

// CORRECT: Test both vulnerable AND safe patterns
func TestVulnerability(t *testing.T) {
    findings, _ := detector.Detect("test.py", vulnerable_code)
    if len(findings) == 0 {
        t.Errorf("Should detect vulnerability")
    }
}

func TestSafePattern(t *testing.T) {
    findings, _ := detector.Detect("test.py", safe_code)
    if len(findings) > 0 {
        t.Errorf("Should not flag safe pattern")
    }
}
```

### ❌ Mistake 3: Ignoring Edge Cases

```go
// WRONG: Assuming valid input
func TestDetector(t *testing.T) {
    findings, _ := detector.Detect("test.py", code)
    // What happens if code is empty? Very large? Malformed?
}

// CORRECT: Test edge cases
func TestDetectorEdgeCases(t *testing.T) {
    // Empty file
    findings, _ := detector.Detect("test.py", "")

    // Very large file
    huge := strings.Repeat("code\n", 10000)
    findings, _ = detector.Detect("test.py", huge)

    // Malformed code
    findings, _ = detector.Detect("test.py", "def break syntax)")
}
```

### ❌ Mistake 4: Not Testing Real CVEs

```go
// WRONG: Only synthetic examples
code := `
while True:
    llm.call()
`

// CORRECT: Real CVE examples
code := `
# LangChain CVE-2024-XXXX: SitemapLoader infinite recursion
from langchain.document_loaders import SitemapLoader

def process_url(url):
    loader = SitemapLoader(url)
    for doc in loader.load():
        child_docs = process_url(doc.url)  # Vulnerable!
`
```

---

## Test Execution

### Run Specific Pattern Tests

```bash
# Test only Token Bombing pattern
go test ./pkg/patterns/detectors -run TokenBombing -v

# Test only Recursive Calling pattern
go test ./pkg/patterns/detectors -run RecursiveToolCalling -v

# Test specific test function
go test ./pkg/patterns/detectors -run TestTokenBombingOpenAIUnboundedLoop -v
```

### Run All Detector Tests

```bash
# Run all tests with verbose output
go test ./pkg/patterns/detectors -v

# Run all tests with coverage
go test ./pkg/patterns/detectors -v -cover

# Run with coverage report
go test ./pkg/patterns/detectors -v -coverprofile=coverage.out
go tool cover -html=coverage.out
```

### Test Output Interpretation

```
=== RUN   TestTokenBombingOpenAIUnboundedLoop
--- PASS: TestTokenBombingOpenAIUnboundedLoop (0.00s)
✅ Test PASSED

=== RUN   TestTokenBombingWithTokenLimitSafe
--- FAIL: TestTokenBombingWithTokenLimitSafe (0.00s)
    token_bombing_test.go:63: Expected no findings for safe pattern, but found 1
❌ Test FAILED - detector is incorrectly flagging safe code
```

---

## Test Quality Metrics

### Required Metrics

| Metric | Requirement | How to Measure |
|--------|-------------|-----------------|
| Test Pass Rate | 100% | `go test ./pkg/patterns/detectors` |
| Unit Tests | 50+ per pattern | Count test functions |
| Code Coverage | >80% | `go test -cover` |
| Real CVE Tests | 5+ per pattern | Review test file for CVE comments |
| Safe Pattern Tests | 10+ per pattern | Count negative test cases |
| Hard Assertions | 100% | Grep for `t.Errorf`, `t.Fatalf` |

### Recommended Metrics

| Metric | Recommendation |
|--------|-----------------|
| Code Coverage | >90% |
| Performance | <100ms per pattern |
| Test Clarity | Comments on complex tests |
| Documentation | Examples in test names |

---

## Validation Checklist

Before marking tests COMPLETE:

```
✅ Test Quantity
- [ ] 50+ total tests per pattern
- [ ] 10+ vulnerable pattern tests
- [ ] 10+ safe pattern tests
- [ ] 5+ real CVE tests
- [ ] 5+ edge case tests

✅ Test Quality
- [ ] All tests passing (100%)
- [ ] No compiler warnings
- [ ] Hard assertions used throughout
- [ ] Clear test names and purposes
- [ ] Comments on complex logic

✅ Coverage
- [ ] All code paths tested
- [ ] All conditions tested (true/false)
- [ ] All exception paths tested
- [ ] >80% code coverage

✅ Real-World Validation
- [ ] Real CVE patterns detected
- [ ] Safe patterns not flagged
- [ ] Confidence scores correct
- [ ] Severity levels appropriate
- [ ] Messages clear and actionable
```

---

## Summary

Effective testing for Inkog patterns requires:

1. **Comprehensive Coverage** - 50+ tests covering all scenarios
2. **Hard Assertions** - Test failures must fail the build
3. **Real CVE Examples** - Detect actual known vulnerabilities
4. **Safe Pattern Testing** - Prevent false positives
5. **Edge Case Handling** - Graceful handling of boundaries
6. **Interface Compliance** - Proper Detector implementation
7. **Clear Documentation** - Comments explaining test purpose

Following these practices ensures production-ready detectors with minimal false positives and maximum real-world vulnerability detection.

---

**Version:** 1.0
**Last Updated:** November 12, 2025
**Status:** Approved
