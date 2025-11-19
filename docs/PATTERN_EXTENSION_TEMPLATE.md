# Inkog Pattern Extension Template

**Version:** 1.0
**Purpose:** Template for implementing Patterns 7-15
**Date:** November 12, 2025

---

## Overview

This document provides the complete template for extending Inkog with new security patterns (7-15). Follow the sections in order for each new pattern.

---

## Patterns 7-15: Data Protection Tier

### Planned Data Protection Patterns

**Pattern 7: Sensitive Data in Prompts**
- Detects PII, secrets, or sensitive data passed to LLM
- Risk: Exposure of confidential information to LLM provider

**Pattern 8: Prompt Data Leakage**
- Detects user data logged, stored, or sent unencrypted
- Risk: Data interception, unauthorized access

**Pattern 9: Unsafe Deserialization**
- Detects pickle, eval, or unsafe unmarshaling
- Risk: Code injection through crafted serialized data

**Pattern 10: Unbounded Context Window**
- Detects accumulating context without clearing
- Risk: Token cost explosion, memory exhaustion

**Pattern 11: Agent Tool Injection**
- Detects dynamically constructed tool definitions
- Risk: Agent executing unintended tool calls

**Pattern 12: Missing Output Validation**
- Detects LLM output used without sanitization
- Risk: XSS, injection attacks on downstream systems

**Pattern 13: Unsafe File Operations**
- Detects agents with file access without safeguards
- Risk: Arbitrary file read/write/delete

**Pattern 14: Unbounded Model Switching**
- Detects code that switches models without authorization
- Risk: Cost explosion, use of inappropriate models

**Pattern 15: Missing Rate Limiting**
- Detects agent endpoints without rate/quota limits
- Risk: DoS, cost explosion, API abuse

---

## Pattern Implementation Template

Use this template for each new pattern (7-15). Replace `PATTERN_NAME` with actual name.

### Step 1: Create Test File

**File:** `pkg/patterns/detectors/PATTERN_NAME_test.go`

```go
package detectors

import (
	"testing"
)

// TestPATTERN_NAMEBasicVulnerability tests basic vulnerability detection
func TestPATTERN_NAMEBasicVulnerability(t *testing.T) {
	detector := NewPATTERN_NAMEDetector()

	code := `
// Insert vulnerable code example here
// Should demonstrate the core vulnerability
`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected to find vulnerability, but got 0 findings")
	}

	if len(findings) > 0 {
		if findings[0].Severity != "HIGH" && findings[0].Severity != "CRITICAL" {
			t.Errorf("Expected HIGH or CRITICAL severity, got %s", findings[0].Severity)
		}
	}
}

// TestPATTERN_NAMESafePatternNotFlagged tests that safe patterns don't trigger false positives
func TestPATTERN_NAMESafePatternNotFlagged(t *testing.T) {
	detector := NewPATTERN_NAMEDetector()

	code := `
// Insert safe code example here
// This should NOT be flagged as vulnerable
`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	if len(findings) > 0 {
		t.Errorf("Expected no findings for safe pattern, but found %d", len(findings))
	}
}

// TestPATTERN_NAMEInterfaceImplementation verifies interface compliance
func TestPATTERN_NAMEInterfaceImplementation(t *testing.T) {
	detector := NewPATTERN_NAMEDetector()

	// Check Name() method
	name := detector.Name()
	if name != "PATTERN_ID" {
		t.Errorf("Expected Name() to return 'PATTERN_ID', got '%s'", name)
	}

	// Check GetPattern() method
	pattern := detector.GetPattern()
	if pattern.ID != "PATTERN_ID" {
		t.Errorf("Expected pattern ID 'PATTERN_ID', got '%s'", pattern.ID)
	}

	// Check GetConfidence() method
	confidence := detector.GetConfidence()
	if confidence <= 0 || confidence > 1.0 {
		t.Errorf("Expected confidence between 0 and 1, got %v", confidence)
	}
}

// TestPATTERN_NAMERealCVEPattern tests detection of real CVE or known vulnerability
func TestPATTERN_NAMERealCVEPattern(t *testing.T) {
	detector := NewPATTERN_NAMEDetector()

	// Insert code that reproduces a real CVE or known vulnerability pattern
	code := `
// Real vulnerability example from CVE database or security research
`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected to find real CVE pattern, but got 0 findings")
	}
}

// TestPATTERN_NAMEEdgeCases tests boundary conditions
func TestPATTERN_NAMEEdgeCases(t *testing.T) {
	detector := NewPATTERN_NAMEDetector()

	// Test 1: Empty file
	findings, err := detector.Detect("test.py", []byte(""))
	if err != nil {
		t.Fatalf("Detector crashed on empty file: %v", err)
	}

	// Test 2: Comments only
	code := `
# This is just a comment with vulnerable-looking code
# But it shouldn't be detected
`
	findings, err = detector.Detect("test.py", []byte(code))
	if len(findings) > 0 {
		t.Errorf("Expected no findings for comments, but found %d", len(findings))
	}

	// Test 3: String literals
	code = `
code = "vulnerable_pattern_here_but_in_string"
`
	findings, err = detector.Detect("test.py", []byte(code))
	if len(findings) > 0 {
		t.Errorf("Expected no findings for string literals, but found %d", len(findings))
	}
}

// TestPATTERN_NAMEConfidenceScoring tests confidence assignment
func TestPATTERN_NAMEConfidenceScoring(t *testing.T) {
	detector := NewPATTERN_NAMEDetector()

	code := `
// Code with high-confidence vulnerability indicators
`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detector returned error: %v", err)
	}

	if len(findings) > 0 {
		if findings[0].Confidence < 0.75 {
			t.Logf("Warning: Expected confidence >= 0.75, got %v", findings[0].Confidence)
		}
	}
}

// Add 40+ more tests covering:
// - Different language/framework variations
// - Complex code patterns
// - Multiple vulnerability types
// - Context sensitivity
// - Partial patterns
// - False negative prevention
// - Performance edge cases
```

### Step 2: Create Detector Implementation

**File:** `pkg/patterns/detectors/PATTERN_NAME.go`

```go
package detectors

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// PATTERN_NAMEDetector detects [specific vulnerability]
// This pattern identifies [what makes it vulnerable]
type PATTERN_NAMEDetector struct {
	pattern patterns.Pattern
}

func NewPATTERN_NAMEDetector() patterns.Detector {
	return &PATTERN_NAMEDetector{
		pattern: patterns.Pattern{
			ID:          "PATTERN_ID",
			Name:        "Pattern Display Name",
			Version:     "1.0",
			Category:    "data_protection",
			Severity:    "HIGH",
			CVSS:        7.5,
			CWEIDs:      []string{"CWE-XXX"},
			OWASP:       "A04:2021",
			Description: "Detects [vulnerability description]",
		},
	}
}

func (d *PATTERN_NAMEDetector) Name() string {
	return "PATTERN_ID"
}

// Detect finds [vulnerability type] vulnerabilities
func (d *PATTERN_NAMEDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	findings := []patterns.Finding{}
	sourceStr := string(src)
	lines := strings.Split(sourceStr, "\n")

	// IMPLEMENT DETECTION LOGIC HERE
	//
	// Pattern for detecting the vulnerability:
	// 1. Identify vulnerable code patterns (regex, string matching)
	// 2. Check context (surrounding lines, indentation, scope)
	// 3. Exclude safe patterns (false negative prevention)
	// 4. Assign confidence based on evidence strength
	// 5. Create findings with appropriate severity

	// Example pattern matching
	vulnerabilityRegex := regexp.MustCompile(`PATTERN_HERE`)

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}

		// Check for vulnerability pattern
		if vulnerabilityRegex.MatchString(line) {
			// Check context to determine if truly vulnerable
			hasContextIndicator := d.checkContext(lines, i)

			if hasContextIndicator {
				finding := patterns.Finding{
					ID:         fmt.Sprintf("PATTERN_ID_%d", i+1),
					PatternID:  d.pattern.ID,
					Pattern:    d.pattern.Name,
					File:       filePath,
					Line:       i + 1,
					Column:     1,
					Severity:   "HIGH",
					Confidence: 0.85,
					Message:    fmt.Sprintf("Vulnerability description for line %d", i+1),
					Code:       strings.TrimSpace(line),
					CWE:        "CWE-XXX",
					CVSS:       7.5,
					OWASP:      "A04:2021",
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// checkContext determines if vulnerability pattern is truly vulnerable
func (d *PATTERN_NAMEDetector) checkContext(lines []string, currentLine int) bool {
	// Implement context checking logic
	// Return true if pattern is vulnerable, false if safe

	// Example: Check surrounding lines for safety indicators
	for i := currentLine - 2; i <= currentLine+2 && i >= 0 && i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])

		// If we find a safety check, not vulnerable
		if strings.Contains(line, "validation") || strings.Contains(line, "check") {
			return false
		}
	}

	return true
}

func (d *PATTERN_NAMEDetector) GetPattern() patterns.Pattern {
	return d.pattern
}

func (d *PATTERN_NAMEDetector) GetConfidence() float32 {
	return 0.85
}
```

### Step 3: Register Pattern

**File:** `cmd/scanner/init_registry.go`

Add to the InitializeRegistry function:

```go
// Pattern 7: [Pattern Name] - [Description]
registry.Register(detectors.NewPATTERN_NAMEDetector())
```

### Step 4: Run Tests and Validate

```bash
# Build detector tests
go test ./pkg/patterns/detectors -run PATTERN_NAME -v

# Ensure all tests pass
go test ./pkg/patterns/detectors -v

# Rebuild scanner
go build -o inkog-scanner ./cmd/scanner/

# Test end-to-end
./inkog-scanner /path/to/test/code
```

---

## Development Checklist for Each Pattern

```markdown
## Pattern [N]: [Name]

### Design Phase
- [ ] Vulnerability documented with real CVE reference
- [ ] Detection scope defined (languages, frameworks)
- [ ] Severity level determined (CRITICAL/HIGH/MEDIUM)
- [ ] Acceptance criteria written
- [ ] Real examples found

### Test Phase
- [ ] Test file created (pattern_name_test.go)
- [ ] 50+ unit tests written
- [ ] Basic vulnerability tests (10-15)
- [ ] Safe pattern tests (10-15)
- [ ] Real CVE tests (5-10)
- [ ] Edge case tests (5-10)
- [ ] Interface tests (2-3)
- [ ] All tests use hard assertions

### Implementation Phase
- [ ] Detector file created (pattern_name.go)
- [ ] Detector interface implemented
- [ ] Detection logic coded
- [ ] Context analysis implemented
- [ ] Confidence scoring correct
- [ ] No debug code

### Validation Phase
- [ ] All unit tests passing (100%)
- [ ] No compiler warnings
- [ ] Real vulnerable code detected
- [ ] Safe patterns not flagged
- [ ] Confidence scores correct
- [ ] Scanner builds successfully

### Integration Phase
- [ ] Pattern registered in init_registry.go
- [ ] Full test suite passes
- [ ] End-to-end scanning works
- [ ] Documentation updated
- [ ] Old code removed

### Review Phase
- [ ] Honest assessment completed
- [ ] No band-aids found
- [ ] Code quality approved
- [ ] Team sign-off obtained
- [ ] Ready for deployment
```

---

## Real-World CVE Examples for Testing

### Pattern 7: Sensitive Data in Prompts

**CVE Reference:** [Document similar CVEs]
```python
# VULNERABLE: PII in prompt
user_data = database.get_user_info(user_id)
response = llm.ask(f"Process user data: {user_data}")  # Leaks PII

# SAFE: Sanitize before prompt
summary = extract_safe_fields(user_data)
response = llm.ask(f"Process summary: {summary}")
```

### Pattern 8: Prompt Data Leakage

**CVE Reference:** [Document similar CVEs]
```python
# VULNERABLE: User input logged
prompt = user_input  # No validation
logger.info(f"User prompt: {prompt}")  # Logs to files
llm_response = llm.ask(prompt)

# SAFE: Sanitize before logging
prompt = sanitize_input(user_input)
logger.info(f"Prompt: [REDACTED]")
llm_response = llm.ask(prompt)
```

[Continue for patterns 9-15...]

---

## Testing Best Practices

### For Each Pattern

1. **Write 50+ Tests**
   - 10-15 vulnerable patterns
   - 10-15 safe patterns
   - 5-10 real CVEs
   - 5-10 edge cases
   - 2-3 interface tests

2. **Use Hard Assertions**
   ```go
   // ✅ CORRECT: Hard assertion
   if len(findings) == 0 {
       t.Errorf("Expected finding, got 0")
   }

   // ❌ WRONG: Info-level log
   if len(findings) == 0 {
       t.Logf("Info: No findings")
   }
   ```

3. **Test Real CVEs**
   ```go
   // ✅ Test actual known vulnerabilities
   func TestRealCVE(t *testing.T) {
       code := `// Code from CVE database`
       findings, _ := detector.Detect("test.py", []byte(code))
       if len(findings) == 0 {
           t.Errorf("Failed to detect real CVE")
       }
   }
   ```

4. **Prevent False Positives**
   ```go
   // ✅ Explicitly test safe patterns
   func TestSafePattern(t *testing.T) {
       code := `// Safe code`
       findings, _ := detector.Detect("test.py", []byte(code))
       if len(findings) > 0 {
           t.Errorf("False positive: flagged safe pattern")
       }
   }
   ```

---

## Deployment Timeline

**Week 1: Patterns 7-9**
- Design: 4 hours
- Tests: 8 hours
- Implementation: 8 hours
- Validation: 4 hours

**Week 2: Patterns 10-12**
- Design: 4 hours
- Tests: 8 hours
- Implementation: 8 hours
- Validation: 4 hours

**Week 3: Patterns 13-15**
- Design: 4 hours
- Tests: 8 hours
- Implementation: 8 hours
- Validation: 4 hours

**Week 4: Integration & Release**
- Full test suite: 8 hours
- Documentation: 8 hours
- Review & approval: 4 hours
- Deployment: 4 hours

**Total: 120 hours (~3 weeks)**

---

## Quality Gates

Before each pattern is marked DONE:

✅ **Mandatory**
- [ ] 100% test pass rate
- [ ] Real CVE detected
- [ ] No false positives on test cases
- [ ] Code builds without warnings
- [ ] Documentation complete

⚠️ **Recommended**
- [ ] 50+ unit tests
- [ ] 90%+ code coverage
- [ ] Performance benchmarked
- [ ] Security review passed
- [ ] Team approval obtained

---

## Success Metrics

For each pattern implementation:

**Detection Accuracy**
- True Positive Rate: >90%
- False Positive Rate: <5%
- Real CVE Coverage: 100%

**Code Quality**
- Test Pass Rate: 100%
- Code Coverage: >85%
- No compiler warnings
- Clean code review

**Documentation**
- Pattern documented
- Examples provided
- Limitations noted
- Test cases shown

---

## Support & Questions

Refer to:
- `PATTERN_DEVELOPMENT_FRAMEWORK.md` - Development workflow
- `PATTERN_REFERENCE.md` - Pattern documentation (to be created)
- `PHASE2_FIX_COMPLETE.md` - Reference implementation (patterns 5-6)

---

**Template Version:** 1.0
**Last Updated:** November 12, 2025
**Status:** Ready for Extension
