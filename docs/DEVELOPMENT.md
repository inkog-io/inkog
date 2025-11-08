# Inkog Pattern Development Guide

**How to add new security patterns to Inkog**

---

## Quick Start: Add a Pattern (7 Steps - Including Testing)

### ⚠️ IMPORTANT: Testing is Part of Development

Every pattern must be tested BEFORE committing. Tests validate:
- Correct vulnerability detection
- False positive reduction
- Confidence scoring accuracy
- Performance metrics

### 1. Create Pattern File

Create a new file in `action/pkg/patterns/detectors/` named after your pattern:

```bash
# Example: action/pkg/patterns/detectors/token_bombing.go
```

### 2. Implement Detector Interface

Every pattern must implement the `Detector` interface:

```go
package detectors

import "github.com/inkog-io/inkog/action/pkg/patterns"

type MyPatternDetector struct {
    pattern    patterns.Pattern
    confidence float32
    // Your regex, parser, etc.
}

// Required methods
func (d *MyPatternDetector) Name() string { return "my_pattern" }
func (d *MyPatternDetector) GetPattern() patterns.Pattern { return d.pattern }
func (d *MyPatternDetector) GetConfidence() float32 { return d.confidence }
func (d *MyPatternDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
    // Your detection logic
    var findings []patterns.Finding
    // ... populate findings ...
    return findings, nil
}
```

### 3. Create Constructor

```go
func NewMyPatternDetector() *MyPatternDetector {
    pattern := patterns.Pattern{
        ID:       "my_pattern",
        Name:     "My Pattern Name",
        Version:  "1.0",
        Category: "category",
        Severity: "HIGH",
        CVSS:     8.5,
        CWEIDs:   []string{"CWE-123"},
        OWASP:    "LLM01",
        Description: "Description of vulnerability...",
        Remediation: "How to fix it...",
        FinancialImpact: struct {
            Severity    string
            Description string
            RiskPerYear float32
        }{
            Severity:    "HIGH",
            Description: "...",
            RiskPerYear: 100000,
        },
    }

    return &MyPatternDetector{
        pattern:    pattern,
        confidence: 0.95, // 95% confidence
    }
}
```

### 4. Register in Registry

Edit `action/pkg/patterns/init.go` and add:

```go
func InitializeRegistry() *Registry {
    registry := NewRegistry()

    // ... existing patterns ...

    // Add your pattern
    registry.Register(detectors.NewMyPatternDetector())

    return registry
}
```

### 5. Create Unit Tests (REQUIRED)

Create `my_pattern_test.go` with 6+ test cases:

```go
package detectors

import "testing"

// Test 1: Basic detection (positive case)
func TestMyPatternDetection(t *testing.T) {
    detector := NewMyPatternDetector()
    vulnerable := `[vulnerable code example]`

    findings, err := detector.Detect("app.py", []byte(vulnerable))
    if err != nil {
        t.Fatalf("Error: %v", err)
    }

    if len(findings) != 1 {
        t.Fatalf("Expected 1 finding, got %d", len(findings))
    }
}

// Test 2: False positive reduction (test files)
func TestMyPatternSkipsTestFiles(t *testing.T) {
    detector := NewMyPatternDetector()
    code := `[same vulnerable code]`

    findings, _ := detector.Detect("test_app.py", []byte(code))
    if len(findings) > 0 {
        t.Fatalf("Should skip test files")
    }
}

// Test 3: Known CVE/real scenario
func TestMyPatternKnownVulnerability(t *testing.T) {
    // Reference actual CVE or documented case
}

// Test 4: Confidence scoring
func TestMyPatternConfidence(t *testing.T) {
    // Verify confidence is within expected range
}

// Test 5: Multiple findings
func TestMyPatternMultipleFindings(t *testing.T) {
    // Test file with multiple vulnerabilities
}

// Test 6: Secure code
func TestMyPatternSecureCode(t *testing.T) {
    // Verify secure code doesn't trigger
}

// Bonus: Benchmark test
func BenchmarkMyPattern(b *testing.B) {
    detector := NewMyPatternDetector()
    code := []byte(`[vulnerable code]`)

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        detector.Detect("app.py", code)
    }
}
```

**Test Requirements:**
- ✅ All tests must pass
- ✅ Confidence must be 0.0-1.0
- ✅ < 5% false positive rate
- ✅ > 90% accuracy on known vulnerabilities
- ✅ Performance < 2ms per file

### 6. Create Test Data (REQUIRED)

Add test files to `testdata/`:

```
testdata/
├── vulnerable_my_pattern.py      # Examples of vulnerable code
├── secure_my_pattern.py          # Examples of secure code
└── false_positives_my_pattern.py # Code that shouldn't trigger
```

**Example test data:**

```python
# testdata/vulnerable_my_pattern.py
# VULNERABLE: Clear example of what you're detecting

# testdata/secure_my_pattern.py
# SECURE: Example of correct implementation

# testdata/false_positives_my_pattern.py
# In test file - should skip
# Placeholder values - should skip
# Commented code - should skip
```

### 7. Run Tests & Validate

```bash
cd action

# Run unit tests for your pattern
go test ./pkg/patterns/detectors -run MyPattern -v

# Run all tests with coverage
go test ./pkg/patterns/detectors -cover -v

# Generate coverage report
go test ./pkg/patterns/detectors -coverprofile=coverage.out
go tool cover -html=coverage.out

# Test against real code
./inkog --path ../testdata --json-report results.json

# Verify findings
jq '.findings[] | .pattern' results.json
```

**Expected Results:**
- ✅ All 6+ unit tests pass
- ✅ Code coverage > 80%
- ✅ Detects vulnerabilities in testdata/
- ✅ Skips test files correctly
- ✅ Confidence scores are reasonable

### 8. Document & Commit

Create documentation in `docs/patterns/my_pattern.md`:

```markdown
# My Pattern Name

## Overview
[What vulnerability does it detect?]

## Detection Method
[How does it detect it?]

## Code Examples

### Vulnerable
[Show bad code]

### Secure
[Show good code]

## Remediation
[How to fix it]

## Related
[Links to similar patterns]
```

Commit with comprehensive message:

```bash
git add action/pkg/patterns/detectors/my_pattern*.go
git add docs/patterns/my_pattern.md
git add testdata/
git commit -m "feat: Add my_pattern detector with full test coverage"
```

---

## Full Example: Token Bombing Pattern

This example shows how to implement a complete pattern detector.

### File: `action/pkg/patterns/detectors/token_bombing.go`

```go
package detectors

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// TokenBombingDetector detects repeated token patterns that cause timeouts
type TokenBombingDetector struct {
	pattern    patterns.Pattern
	confidence float32
	regexes    []struct {
		pattern string
		name    string
	}
}

// NewTokenBombingDetector creates a new token bombing detector
func NewTokenBombingDetector() *TokenBombingDetector {
	pattern := patterns.Pattern{
		ID:       "token_bombing",
		Name:     "Token Bombing Attack Pattern",
		Version:  "1.0",
		Category: "denial_of_service",
		Severity: "HIGH",
		CVSS:     7.5,
		CWEIDs:   []string{"CWE-400"},
		OWASP:    "LLM10",
		Description: "Repeated token patterns cause models to timeout, consuming CPU/GPU resources and costing $2.40-$7.68 per attack",
		Remediation: "Add input validation, implement token limits, add request timeouts",
		FinancialImpact: struct{
			Severity string
			Description string
			RiskPerYear float32
		}{
			Severity: "HIGH",
			Description: "$7.68 per timeout × 100 attacks/day = $280K/year",
			RiskPerYear: 280000,
		},
	}

	return &TokenBombingDetector{
		pattern:    pattern,
		confidence: 0.85, // Medium confidence (false positives possible)
		regexes: []struct {
			pattern string
			name    string
		}{
			{
				// Single token repeated 50+ times: "dog" × 50
				pattern: `(\w+)\s+(\1\s+){50,}`,
				name:    "Single token repetition",
			},
			{
				// Bigram repeated 50+ times: "poem secret" × 50
				pattern: `([\w\s]+)\s+(\1\s+){50,}`,
				name:    "Multi-token repetition",
			},
		},
	}
}

func (d *TokenBombingDetector) Name() string {
	return "token_bombing"
}

func (d *TokenBombingDetector) GetPattern() patterns.Pattern {
	return d.pattern
}

func (d *TokenBombingDetector) GetConfidence() float32 {
	return d.confidence
}

func (d *TokenBombingDetector) Detect(filePath string, src []byte) ([]Finding, error) {
	var findings []Finding

	if !isSupportedFile(filePath) || isTestFile(filePath) {
		return findings, nil
	}

	lines := strings.Split(string(src), "\n")

	for i, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") {
			continue
		}

		for _, regexPattern := range d.regexes {
			re := regexp.MustCompile(regexPattern.pattern)
			if re.MatchString(line) {
				finding := Finding{
					ID:            fmt.Sprintf("token_bombing_%d_%s", i, filePath),
					PatternID:     d.pattern.ID,
					Pattern:       d.pattern.Name,
					File:          filePath,
					Line:          i + 1,
					Column:        1,
					Message:       fmt.Sprintf("Token bombing pattern detected: %s", regexPattern.name),
					Code:          line,
					Severity:      d.pattern.Severity,
					Confidence:    d.confidence,
					CWE:           "CWE-400",
					CVSS:          d.pattern.CVSS,
					OWASP:         d.pattern.OWASP,
					FinancialRisk: "$7.68 per timeout attack, DoS risk",
				}

				findings = append(findings, finding)
				break
			}
		}
	}

	return findings, nil
}
```

---

## Pattern Structure Checklist

Every pattern MUST have:

- [ ] **ID**: Lowercase with underscores (e.g., `token_bombing`)
- [ ] **Name**: User-friendly (e.g., `Token Bombing Attack Pattern`)
- [ ] **Severity**: CRITICAL, HIGH, MEDIUM, or LOW
- [ ] **CVSS**: Score 0.0-10.0
- [ ] **CWE**: At least one CWE ID (e.g., `CWE-400`)
- [ ] **Confidence**: 0.0-1.0 (how accurate the detector is)
- [ ] **Description**: What vulnerability it detects
- [ ] **Remediation**: How to fix it
- [ ] **False Positive Reduction**:
  - Skip test files
  - Skip example files
  - Validate context (e.g., is it in an LLM function call?)

---

## Testing Your Pattern

### Unit Test Template

Create `action/pkg/patterns/detectors/token_bombing_test.go`:

```go
package detectors

import (
	"testing"
)

func TestTokenBombingDetector(t *testing.T) {
	detector := NewTokenBombingDetector()

	// Test case 1: Should detect repeated tokens
	vulnerable := `
prompt = "dog " * 50  # Token bombing
`

	findings, err := detector.Detect("test.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("Expected 1 finding, got %d", len(findings))
	}

	// Test case 2: Should NOT detect in test files
	findings, _ = detector.Detect("test_example.py", []byte(vulnerable))
	if len(findings) > 0 {
		t.Fatalf("Should skip test files, got %d findings", len(findings))
	}
}
```

### Known CVE Test

Test against real vulnerabilities:

```go
func TestTokenBombingKnownVulnerability(t *testing.T) {
	// Real Dropbox Security Team finding (Jan 2024)
	dropboxBombingExample := `
# Token bombing attack that caused 10-minute timeout
repeated_tokens = "jq_THREADS " * 2048  # Causes gibberish generation
response = llm.chat(repeated_tokens)  # 10-minute timeout = $7.68 cost
`

	detector := NewTokenBombingDetector()
	findings, _ := detector.Detect("vulnerable.py", []byte(dropboxBombingExample))

	if len(findings) == 0 {
		t.Fatal("Should detect known token bombing vulnerability")
	}
}
```

### Run Tests

```bash
cd action
go test ./pkg/patterns/detectors -v
```

---

## Financial Impact Scoring

Each pattern should include financial impact data:

```go
FinancialImpact: struct{
    Severity    string      // CRITICAL, HIGH, MEDIUM, LOW
    Description string      // What happens if exploited
    RiskPerYear float32     // Annual cost if undetected
}{
    Severity:    "CRITICAL",
    Description: "Stolen API key enables $50K/month unauthorized usage",
    RiskPerYear: 600000,    // $50K × 12 months
},
```

### Financial Severity Tiers

- **CRITICAL**: $500K+/year (e.g., hardcoded secrets, RCE)
- **HIGH**: $100K-$500K/year (e.g., prompt injection, SQL injection)
- **MEDIUM**: $10K-$100K/year (e.g., infinite loops, logging PII)
- **LOW**: <$10K/year (e.g., unsafe env access, missing timeouts)

---

## Pattern Lifecycle

### Phase 1: Core Patterns (TIER 1) ✅ COMPLETE
- Prompt Injection
- Hardcoded Credentials
- Infinite Loop
- Unsafe Environment Access

### Phase 2: Compliance Critical (TIER 2) 🔄 IN PROGRESS
- Token Bombing
- Recursive Tool Calling
- RAG Over-fetching
- Unvalidated exec/eval
- Missing Human Oversight
- Insufficient Audit Logging
- Context Window Accumulation

### Phase 3: Data Protection (TIER 3) 📅 PLANNED
- Logging Sensitive Data
- Cross-tenant Vector Store
- SQL Injection via LLM
- Uncontrolled API Rate Limits
- Missing Error Boundaries

---

## Common Patterns

### Pattern Type 1: Regex-Based (Simple)

Use for straightforward text matching:

```go
func NewMyRegexDetector() *MyDetector {
    regex := regexp.MustCompile(`pattern_to_match`)
    // ...
}
```

**Best for**: Credentials, obvious code patterns

### Pattern Type 2: Context-Aware (Medium)

Add context checking to reduce false positives:

```go
func (d *Detector) isInLLMContext(line string) bool {
    llmFuncs := []string{"chat(", "invoke(", "predict("}
    for _, fn := range llmFuncs {
        if strings.Contains(line, fn) { return true }
    }
    return false
}
```

**Best for**: Prompt injection, code execution contexts

### Pattern Type 3: AST-Based (Advanced)

Use tree-sitter for semantic analysis:

```go
// Future enhancement - when we add tree-sitter support
func (d *Detector) Detect(filePath string, src []byte) ([]Finding, error) {
    parser := sitter.NewParser()
    tree, _ := parser.Parse(src)
    // Use tree-sitter queries
}
```

**Best for**: Complex control flow, infinite loops, recursion

---

## Security Checklist

Every pattern must be **secure**:

- [ ] **No Code Execution**: Never execute scanned code
- [ ] **No Data Storage**: Don't store customer code
- [ ] **Context Aware**: Reduce false positives with context
- [ ] **Confident**: Confidence > 0.7 (70%)
- [ ] **Documented**: Clear description and remediation
- [ ] **Tested**: Includes test cases
- [ ] **Reversible**: Easy to update/disable pattern

---

## Pattern Performance

Target metrics per pattern:

- **Speed**: < 2ms per file
- **Memory**: < 1MB per detector
- **Accuracy**: > 90% (confidence > 0.9)
- **False Positives**: < 5%

---

## Getting Help

**Questions?**
- Reference existing patterns in `detectors/`
- Check tests in `detectors/*_test.go`
- Review types in `types.go` and `detector.go`

**Contributing?**
- Create pattern file
- Implement interface
- Add tests
- Register in init.go
- Submit PR

---

## Future Ideas: Custom Pattern SDK

### 🚀 Planned Feature (Not for Current Release)

**Inkog Custom Pattern SDK** - Allow companies to write their own patterns without forking the codebase.

This would enable:
- Enterprise-specific vulnerability detection
- Industry-specific patterns (fintech, healthcare, etc.)
- Custom business logic patterns
- Plugin-based architecture

**Potential Design:**

```go
// Pattern plugin could be loaded as:
import "github.com/company/inkog-patterns"

// SDK would provide:
// - PatternSDK interface
// - Testing utilities
// - Documentation generators
// - Performance measurement tools
```

**When to Build:** After completing TIER 1-3 core patterns and validating plugin approach with internal patterns.

**Benefits:**
- ✅ Extensibility without core code changes
- ✅ Easier customer adoption (can add their own patterns)
- ✅ Better market positioning vs competitors
- ✅ Revenue opportunity (pattern marketplace)

**Current Status:** Design phase only. Focus on core 16 patterns first.

---

**Happy pattern building! 🔒**

*Last Updated: November 8, 2024*
