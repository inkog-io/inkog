# Pattern 5 Development Standard

**Based On:** TIER 1 Patterns (1-4) Lessons Learned
**Effective Date:** November 10, 2025
**Purpose:** Ensure consistency and quality for Pattern 5 and beyond

---

## Naming Convention (Locked Standard)

### Pattern ID Format
```
Format: {pattern-name}-v2
Example: deserialization-unsafe-v2, ssrf-injection-v2

Rules:
- Lowercase
- Use hyphens (NOT underscores)
- Include version suffix (-v2)
- Max 40 characters
- Must be unique in registry
```

### File Naming Format
```
Detector File: {pattern_name_v2}.go
Test File: {pattern_name_v2}_test.go
Example: insecure_deserialization_v2.go, insecure_deserialization_v2_test.go

Rules:
- Lowercase
- Use underscores (NOT hyphens)
- Include version (v2)
- Must match exact pattern
```

### Function Naming Format
```
Constructor: New{PatternNameV2}()
Example: NewInsecureDeserializationDetectorV2()

Test Functions: Test{PatternName}V2{TestCase}
Example: TestInsecureDeserializationV2BasicPickle()

Rules:
- PascalCase for functions
- Include V2 suffix
- Append specific test case name
```

### Pattern Metadata Format
```go
pattern := patterns.Pattern{
    ID:       "pattern-name-v2",           // Kebab case
    Name:     "Pattern Name V2",           // Title case with V2
    Version:  "2.0",                       // Always 2.0
    Category: "pattern_category",          // Snake case
    Severity: "HIGH/CRITICAL",             // Must match above
    CVSS:     8.5,                         // Float, 0.0-10.0
    CWEIDs:   []string{"CWE-123", ...},    // Array of CWE strings
    OWASP:    "A01:2021 - ...",            // Full OWASP reference
    Description: "...",                    // 150-300 chars
    ...
}
```

---

## Metadata Requirements (Mandatory)

### Pattern Registration Fields
```go
type Pattern struct {
    ID                 string      // MANDATORY: unique identifier
    Name               string      // MANDATORY: display name
    Version            string      // MANDATORY: "2.0"
    Category           string      // MANDATORY: detection category
    Severity           string      // MANDATORY: HIGH/CRITICAL
    CVSS               float32     // MANDATORY: 0.0-10.0
    CWEIDs             []string    // MANDATORY: minimum 2 CWE IDs
    OWASP              string      // MANDATORY: e.g., "A01:2021 - ..."
    Description        string      // MANDATORY: 150-300 chars
    Remediation        string      // MANDATORY: mitigation steps
    FinancialImpact    struct { ... } // OPTIONAL: only if quantifiable
}
```

### Description Field Requirements
- 150-300 characters
- Must mention 3+ attack vectors
- Must reference 2+ CVE IDs
- Must mention all supported languages
- Example from Pattern 1:
  > "Detects unvalidated user input in LLM prompts, dangerous execution sinks, string interpolation, evasion techniques, and indirect injection vectors. Maps to multiple CVEs including LangChain PALChain (CVE-2023-44467), GraphCypher (CVE-2024-8309), and Flowise (CVE-2025-59528)"

---

## Implementation Requirements

### Detector Structure
```go
type Pattern5DetectorV2 struct {
    pattern      patterns.Pattern
    confidence   float32
    astFramework *ASTAnalysisFramework        // Required: use shared framework

    // Regex patterns (15+ minimum)
    patternX *regexp.Regexp
    patternY *regexp.Regexp
    // ... more patterns
}
```

### Required Methods
```go
func (d *Pattern5DetectorV2) Name() string                           // Return pattern name
func (d *Pattern5DetectorV2) GetPattern() patterns.Pattern           // Return metadata
func (d *Pattern5DetectorV2) GetConfidence() float32                 // Return default confidence
func (d *Pattern5DetectorV2) Detect(filePath string, src []byte) ([]patterns.Finding, error) // Main detection
```

### Detect Method Structure
```go
func (d *Pattern5DetectorV2) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
    var findings []patterns.Finding

    // 1. File type/context checks
    if !isSupportedFile(filePath) {
        return findings, nil
    }
    if isTestFile(filePath) {
        return findings, nil
    }

    // 2. Parse code
    lines := strings.Split(string(src), "\n")

    // 3. PASS 1: AST Analysis
    analysis := d.astFramework.AnalyzeCode(filePath, lines)

    // 4. PASS 2: Semantic Analysis (using framework components)
    // Example: Find dangerous data flows
    dataFlowAnalyzer := d.astFramework.GetDataFlowAnalyzer()
    dangerousFlows := dataFlowAnalyzer.GetFlowsBySource(analysis.DataFlows, "user_input")

    // 5. PASS 3: Pattern Matching
    for i, line := range lines {
        // Pattern checks...
        if d.patternX.MatchString(line) {
            // Create finding
        }
    }

    return findings, nil
}
```

---

## Confidence Scoring Requirements

### Confidence Scoring Checklist
- [ ] Base score defined (recommend 0.50)
- [ ] 7-8 risk factors identified
- [ ] 4-5 mitigation factors identified
- [ ] Clamp logic implemented (0.0-1.0)
- [ ] AST-based context scoring integrated
- [ ] Multi-language variance accounted for

### Scoring Algorithm Template
```go
func (d *Pattern5DetectorV2) calculateConfidence(line, filePath string, lineNum int) float32 {
    confidence := float32(0.50) // Base score

    // Risk factors: +0.10 to +0.25 each
    if d.riskFactor1(line) {
        confidence += 0.15
    }
    if d.riskFactor2(line) {
        confidence += 0.15
    }
    // ... more factors

    // Mitigation factors: -0.15 to -0.30 each
    if d.mitigationFactor1(line) {
        confidence -= 0.25
    }
    // ... more factors

    // Clamp to valid range
    if confidence < 0.0 { confidence = 0.0 }
    if confidence > 1.0 { confidence = 1.0 }

    return confidence
}
```

---

## Testing Requirements

### Test File Structure
```go
package detectors

import (
    "testing"
    "github.com/inkog-io/inkog/action/pkg/patterns"
)

func TestPattern5V2BasicDetection(t *testing.T) {
    // Test basic vulnerability
}

func TestPattern5V2FalsePositiveReduction(t *testing.T) {
    // Test that safe code doesn't trigger
}

func TestPattern5V2CVE123456(t *testing.T) {
    // Test real CVE case
}
```

### Minimum Test Count: 25 tests
- 8-10 basic detection tests (one per attack vector)
- 5-7 false positive reduction tests
- 3-5 CVE validation tests
- 2-4 multi-language tests
- 2-3 edge case tests

### Test Coverage Requirements
- [ ] 25+ test functions
- [ ] 3+ CVE/incident validation tests
- [ ] >500 lines of test code
- [ ] All tests passing
- [ ] <5% false positive rate verified

---

## Documentation Requirements

### Documentation Files (Minimum 3)

#### 1. Main Pattern Documentation (`docs/patterns/pattern_5_name.md`)
```markdown
# Pattern 5 Name

## Overview
- What vulnerability is detected?
- When is it a problem?
- What's the risk?

## Detection Method
- How does Inkog detect this?
- What are the attack vectors?
- What's the technical approach?

## Examples
- 5-10 vulnerable code examples (with explanations)
- 5-10 secure code examples (with remediation)

## CVE Coverage
- List of real CVEs covered
- Framework-specific incidents

## Configuration
- Any tuning options?
- Language-specific settings?

## Performance
- Expected detection time
- False positive rate
- Remediation time estimate
```

**Target Length:** 1,500+ words

#### 2. Technical Analysis (`docs/PATTERN_5_NAME_V2_ANALYSIS.md`)
```markdown
# Pattern 5 Name - Technical Analysis

## Executive Summary
- Key findings
- Architecture approach
- Achieved accuracy

## Vulnerability Details
- Deep technical breakdown
- Attack chains
- Real-world impact

## Detection Algorithm
- Regex patterns used
- Semantic analysis approach
- Confidence scoring details

## Implementation Details
- Code structure
- Component responsibilities
- Multi-language considerations

## Test Coverage
- Test breakdown
- CVE validation methodology
- False positive reduction approach

## Performance Benchmarks
- Detection time per file
- Memory usage
- Accuracy metrics

## Lessons Learned
- Challenges encountered
- Solutions implemented
- Future improvements
```

**Target Length:** 2,000+ words

#### 3. Architecture Reference (Section in `docs/INKOG_AST_ARCHITECTURE.md`)
```markdown
### Pattern 5: Insecure Deserialization

**How It Uses Framework:**
1. VariableTracker for untrusted input identification
2. DataFlowAnalyzer for user_input → deserialization sink tracing
3. Additional semantic analysis for specific deserialization patterns

**Sample Detection:**
```python
# Code being analyzed...
```

**CVE Coverage:** X/X
- CVE-123456
- CVE-789012
```

---

## CVE Mapping Requirements

### CVE Documentation Standard
For each CVE:
1. **CVE ID:** Official identifier
2. **Framework:** Which LLM framework/tool affected
3. **Attack Vector:** How is it exploited?
4. **Detection Method:** How does Inkog detect it?
5. **Test Coverage:** Is there a test case?
6. **Status:** Passing/Failing

### Minimum CVE Coverage: 3 real-world cases
```markdown
| CVE ID | Framework | Attack Vector | Detection | Test |
|--------|-----------|---------------|-----------|------|
| CVE-XXX | LangChain | ... | Regex + AST | ✅ |
| ... | ... | ... | ... | ... |
```

---

## Multi-Language Support Requirements

### Supported Languages (Minimum 6)
1. Python (priority)
2. JavaScript/TypeScript
3. Go
4. Java
5. C#
6. PHP
7. Ruby (optional)
8. Kotlin (optional)

### Language Testing
- [ ] At least 2 examples per language
- [ ] Language-specific syntax handled
- [ ] False positive rate <5% per language
- [ ] Documentation includes language-specific examples

---

## False Positive Reduction Strategy

### Multi-Factor FP Reduction (Minimum 5 factors)
```go
// Example: Reduce false positives from test files
if isTestFile(filePath) {
    confidence -= 0.30
}

// Example: Reduce for safe context
if hasSanitization(line) {
    confidence -= 0.25
}

// Example: Reduce for validation
if hasValidation(line) {
    confidence -= 0.20
}
```

### FP Reduction Checklist
- [ ] Test file detection and penalization
- [ ] Example/documentation file detection
- [ ] Sanitization pattern detection
- [ ] Validation/whitelist pattern detection
- [ ] Safe function context detection
- [ ] Target: <5% false positive rate

---

## AST Framework Integration

### Required Framework Usage
At minimum, Pattern 5 must use:
1. **ASTAnalysisFramework** for semantic analysis
2. One or more of:
   - **VariableTracker** (for input source detection)
   - **DataFlowAnalyzer** (for source-to-sink tracing)
   - **CallGraphBuilder** (for function relationship analysis)
   - **ControlFlowAnalyzer** (for code path analysis)

### Framework Integration Example
```go
// Pass 1: Perform AST analysis
analysis := d.astFramework.AnalyzeCode(filePath, lines)

// Pass 2: Use framework components
dataFlowAnalyzer := d.astFramework.GetDataFlowAnalyzer()
userInputFlows := dataFlowAnalyzer.GetFlowsBySource(analysis.DataFlows, "user_input")

// Pass 3: Check for dangerous flows
for _, flow := range userInputFlows {
    if d.astFramework.IsDataFlowDangerous(flow) {
        // Dangerous flow found
    }
}

// Pass 4: Enhance confidence with semantic context
confidence := d.astFramework.EnhanceConfidenceScore(0.70, analysis, lineNum)
```

---

## Code Quality Checklist

- [ ] Follows Go conventions (golint, gofmt)
- [ ] Proper error handling
- [ ] No hardcoded values (use pattern metadata)
- [ ] Comprehensive comments
- [ ] Efficient regex patterns (compiled once)
- [ ] No race conditions
- [ ] Memory efficient
- [ ] <5ms per file performance

---

## Deployment Checklist

- [ ] All 25+ tests passing
- [ ] Code review completed
- [ ] Documentation complete (3,500+ words)
- [ ] CVE validation tests passing
- [ ] Performance benchmarks acceptable
- [ ] False positive rate <5%
- [ ] No security issues in detector itself
- [ ] Ready for production deployment

---

## Pattern 5 Registration (Final Step)

Once complete, register in `cmd/scanner/init_registry.go`:

```go
// TIER 2: Compliance Critical Patterns
registry.Register(detectors.NewPattern5DetectorV2())
```

Update comment with:
- Pattern description
- Key features
- CVE coverage
- AST components used

---

## Success Criteria Validation

Use this checklist before declaring Pattern 5 complete:

- [ ] ✅ Pattern ID follows standard: `pattern-name-v2`
- [ ] ✅ File names follow standard: `pattern_name_v2.go`
- [ ] ✅ 25+ tests developed and passing
- [ ] ✅ 3+ real CVE/incidents mapped and tested
- [ ] ✅ <5% false positive rate achieved
- [ ] ✅ <5ms performance per file
- [ ] ✅ 3,500+ words documentation
- [ ] ✅ 7-8 factor confidence scoring
- [ ] ✅ Multi-language support (6+ languages)
- [ ] ✅ AST framework integrated
- [ ] ✅ Multi-factor FP reduction implemented
- [ ] ✅ Code quality review passed
- [ ] ✅ Documentation review passed
- [ ] ✅ Ready for production registration

---

## Questions & Reference

### Key Contacts for Questions
- Pattern framework: See `docs/INKOG_AST_ARCHITECTURE.md`
- Test examples: Check `prompt_injection_v2_test.go` (simplest example)
- Advanced examples: See `infinite_loops_v2.go` (recursion), `hardcoded_credentials_v2.go` (entropy)
- Confidence scoring: All patterns have detailed implementation examples

### Reference Implementations
1. **Pattern 1 (Prompt Injection):** Simple data flow tracing
2. **Pattern 2 (Hardcoded Credentials):** Complex entropy analysis + variable tracking
3. **Pattern 3 (Infinite Loops):** Call graphs + control flow analysis
4. **Pattern 4 (Unsafe Env Access):** Import alias tracking + semantic analysis

### When Stuck
1. Review the corresponding TIER 1 pattern
2. Check `docs/INKOG_AST_ARCHITECTURE.md` for framework usage
3. Review `TIER1_COMPLETION_VERIFICATION.md` for accuracy metrics
4. Look at test files for testing patterns

---

**This document is the standard for Pattern 5 and all future patterns (5+).**

Deviation from this standard requires documented approval and RFC (Request for Change).

**Last Updated:** November 10, 2025
**Maintained By:** Inkog Development Team
**Version:** 1.0
