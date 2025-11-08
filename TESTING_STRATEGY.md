# Inkog Testing Strategy & Implementation Roadmap

**Last Updated:** November 8, 2024
**Status:** Enterprise-Grade, Production-Ready
**Goal:** 100% accuracy with <5% false positive rate

---

## Executive Summary

This document outlines a comprehensive, multi-tier testing strategy ensuring all 16 patterns (4 current + 12 planned) meet enterprise-grade security standards with:

- **Detection Accuracy**: > 90% true positive rate
- **False Positive Rate**: < 5%
- **Performance**: < 2ms per file per pattern
- **Scalability**: 1000+ files in < 5 seconds
- **Maintainability**: 100% test coverage

---

## Testing Pyramid

```
                     █ End-to-End Tests
                    ███ Integration Tests
                   █████ Unit Tests
                  █████████ Code Quality Tests
```

---

## Phase 1: Unit Tests (TIER 1 Patterns - This Week)

### Test Structure

Each pattern gets a `*_test.go` file with the following test cases:

```
action/pkg/patterns/detectors/
├── prompt_injection.go
├── prompt_injection_test.go      ← NEW
├── hardcoded_credentials.go
├── hardcoded_credentials_test.go  ← NEW
├── infinite_loop.go
├── infinite_loop_test.go          ← NEW
├── unsafe_env_access.go
└── unsafe_env_access_test.go      ← NEW
```

### Unit Test Template (Per Pattern)

```go
package detectors

import "testing"

// Test 1: Basic Detection (Positive Case)
func TestPromptInjectionDetection(t *testing.T) {
    detector := NewPromptInjectionDetector()

    vulnerable := `
prompt = f"User asked: {user_input}"  // VULNERABLE
response = llm.chat(prompt)
`

    findings, err := detector.Detect("app.py", []byte(vulnerable))
    if err != nil {
        t.Fatalf("Error: %v", err)
    }

    if len(findings) != 1 {
        t.Fatalf("Expected 1 finding, got %d", len(findings))
    }

    if findings[0].Severity != "HIGH" {
        t.Fatalf("Expected HIGH severity, got %s", findings[0].Severity)
    }
}

// Test 2: False Positive Reduction (Test Files)
func TestSkipsTestFiles(t *testing.T) {
    detector := NewPromptInjectionDetector()
    vulnerable := `prompt = f"test: {user_input}"`

    findings, _ := detector.Detect("test_app.py", []byte(vulnerable))
    if len(findings) > 0 {
        t.Fatalf("Should skip test files, got %d findings", len(findings))
    }
}

// Test 3: Known CVE (Real-World Scenario)
func TestKnownCVE(t *testing.T) {
    // Reference actual CVE or documented vulnerability
}

// Test 4: Confidence Scoring
func TestConfidenceScoring(t *testing.T) {
    detector := NewPromptInjectionDetector()
    findings, _ := detector.Detect("app.py", []byte(vulnerable))

    if findings[0].Confidence < 0.85 || findings[0].Confidence > 0.95 {
        t.Fatalf("Confidence out of range: %f", findings[0].Confidence)
    }
}

// Test 5: Multiple Findings
func TestMultipleFindings(t *testing.T) {
    // Test file with multiple vulnerabilities
}

// Test 6: Language Support
func TestLanguageSupport(t *testing.T) {
    // Test Python, JavaScript, TypeScript, Go
}
```

### TIER 1 Unit Test Cases (4 patterns × 6 tests = 24 total)

#### Pattern 1: Prompt Injection

| Test Case | Input | Expected | Priority |
|-----------|-------|----------|----------|
| Basic f-string injection | `f"User: {user_input}"` | 1 finding, HIGH | P0 |
| Triple-quote injection | `"""User: {user_input}"""` | 1 finding, HIGH | P0 |
| LLM context detection | Interpolation outside LLM calls | 0 findings | P0 |
| Test file skip | `test_app.py` with injection | 0 findings | P0 |
| Confidence score | Any injection | 0.85-0.95 confidence | P1 |
| Multiple findings | 3 injections in one file | 3 findings | P1 |

#### Pattern 2: Hardcoded Credentials

| Test Case | Input | Expected | Priority |
|-----------|-------|----------|----------|
| OpenAI API key | `sk-proj-abc123def456` | 1 finding, CRITICAL | P0 |
| GitHub token | `ghp_abc123def456` | 1 finding, CRITICAL | P0 |
| Database password | `password = "SecurePass123"` | 1 finding, CRITICAL | P0 |
| Placeholder value | `password = "your_password"` | 0 findings | P0 |
| Comment skip | `# api_key = "sk-123"` | 0 findings | P0 |
| Masked output | Secret is masked in output | Redacted as s...56 | P1 |

#### Pattern 3: Infinite Loop

| Test Case | Input | Expected | Priority |
|-----------|-------|----------|----------|
| while True | `while True:` no break | 1 finding, HIGH | P0 |
| while true (lowercase) | `while true:` | 1 finding, HIGH | P0 |
| while 1 | `while 1:` | 1 finding, HIGH | P0 |
| with break | `while True:\n  break` | 0 findings | P0 |
| with max_iterations | `while True:\n  max_iterations` | 0 findings | P0 |
| Test file skip | `test_agent.py` with loop | 0 findings | P0 |

#### Pattern 4: Unsafe Env Access

| Test Case | Input | Expected | Priority |
|-----------|-------|----------|----------|
| os.environ[] | `os.environ["KEY"]` | 1 finding, MEDIUM | P0 |
| Without .get() | Direct bracket access | 1 finding | P0 |
| With .get() | `os.environ.get("KEY")` | 0 findings | P0 |
| With default | `os.environ.get("KEY", "default")` | 0 findings | P0 |
| Test file skip | `test_config.py` with access | 0 findings | P0 |
| Confidence score | Any unsafe access | 0.90-0.95 confidence | P1 |

### Running Unit Tests

```bash
# Run all tests
cd /Users/tester/inkog2/action
go test ./pkg/patterns/detectors -v

# Run specific pattern tests
go test ./pkg/patterns/detectors -run TestPromptInjection -v

# With coverage
go test ./pkg/patterns/detectors -cover -v

# Generate coverage report
go test ./pkg/patterns/detectors -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html
```

---

## Phase 2: Integration Tests (This Week + Next)

### Scanner Integration Tests

Test file: `action/cmd/scanner/scanner_test.go`

```go
package main

func TestScannerLoadsAllPatterns(t *testing.T) {
    registry := patterns.InitializeRegistry()
    if registry.Count() != 4 {
        t.Fatalf("Expected 4 patterns, got %d", registry.Count())
    }
}

func TestScannerConcurrentScanning(t *testing.T) {
    // Test 4-way parallelization
}

func TestJSONReportGeneration(t *testing.T) {
    // Test valid JSON output
}

func TestRiskThresholdEnforcement(t *testing.T) {
    // Test exit codes based on severity
}
```

### CLI Integration Tests

Test file: `action/cmd/scanner/main_test.go`

```go
func TestListPatterns(t *testing.T) {
    // Run ./inkog --list-patterns
    // Verify output contains all 4 patterns
}

func TestScanPath(t *testing.T) {
    // Run ./inkog --path ./testdata
    // Verify findings are detected
}

func TestJSONReportFlag(t *testing.T) {
    // Run ./inkog --json-report output.json
    // Verify file created with valid JSON
}

func TestRiskThresholdFlag(t *testing.T) {
    // Test --risk-threshold high|medium|low|critical
    // Verify exit codes
}
```

---

## Phase 3: Functional Tests (Test Data)

### Test Data Structure

```
testdata/
├── python/
│   ├── prompt_injection.py
│   ├── hardcoded_credentials.py
│   ├── infinite_loop.py
│   ├── unsafe_env_access.py
│   └── mixed_vulnerabilities.py
├── javascript/
│   ├── prompt_injection.js
│   ├── hardcoded_credentials.js
│   └── ...
├── typescript/
│   └── ...
├── go/
│   └── ...
└── false_positives/
    ├── test_false_positives.py
    ├── example_legitimate.py
    └── ...
```

### Test Data Examples

#### `testdata/python/prompt_injection.py` (Vulnerable)

```python
# VULNERABLE: User input directly in prompt
user_input = input("What do you want to know? ")
prompt = f"Answer this question: {user_input}"
response = llm.chat(prompt)

# VULNERABLE: Indirect injection
query = request.args.get("q")
full_prompt = f"Search for: {query}"
result = agent.invoke(full_prompt)

# SECURE (should not trigger)
safe_query = sanitize_input(query)
prompt = f"Search for: {safe_query}"
```

#### `testdata/python/hardcoded_credentials.py` (Vulnerable)

```python
# VULNERABLE: Hardcoded API key
OPENAI_API_KEY = "sk-proj-abc123def456xyz"
openai.api_key = OPENAI_API_KEY

# VULNERABLE: Database password
DB_PASSWORD = "admin123!@#"
connection_string = f"postgresql://user:{DB_PASSWORD}@localhost"

# VULNERABLE: GitHub token
GITHUB_TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"

# SECURE (should not trigger)
api_key = os.environ.get("OPENAI_API_KEY")
db_pass = os.getenv("DB_PASSWORD", None)
```

#### `testdata/python/infinite_loop.py` (Vulnerable)

```python
# VULNERABLE: Infinite loop without break
while True:
    result = agent.invoke(input("Query: "))
    print(result)

# VULNERABLE: while 1 with no exit
iteration = 0
while 1:
    process_request()

# SECURE: With max_iterations
max_iterations = 100
iteration = 0
while True and iteration < max_iterations:
    result = process()
    iteration += 1

# SECURE: With break condition
while True:
    if should_stop():
        break
```

#### `testdata/python/unsafe_env_access.py` (Vulnerable)

```python
# VULNERABLE: Direct environ access
DATABASE_URL = os.environ["DATABASE_URL"]
API_KEY = os.environ["API_KEY"]

# SECURE: With .get()
DATABASE_URL = os.environ.get("DATABASE_URL", "localhost:5432")
API_KEY = os.environ.get("API_KEY", "")
```

#### `testdata/false_positives/test_false_positives.py`

```python
# These should NOT trigger findings (in test files)

# Test prompt injection
test_prompt = f"Test: {test_input}"

# Test credentials
TEST_API_KEY = "sk-test-12345"

# Test loops
while True:
    break

# Test env
test_env = os.environ["TEST"]
```

### Functional Test Execution

```bash
# Create test data
mkdir -p testdata/{python,javascript,typescript,go,false_positives}

# Run scanner against test data
cd /Users/tester/inkog2/action
./inkog --path ../testdata --json-report scan_results.json

# Verify results
jq '.findings_count' scan_results.json  # Should be > 0
jq '.findings[] | .pattern' scan_results.json  # Should show all 4 patterns

# Verify false positives not flagged
./inkog --path ../testdata/false_positives  # Should be 0 findings
```

---

## Phase 4: Performance Testing (Week 2)

### Performance Metrics

```
Target Performance Per Pattern:
├── Speed: < 2ms per file
├── Memory: < 1MB per detector
├── Accuracy: > 90%
└── False Positives: < 5%

Scanner Overall:
├── 100 files: < 500ms
├── 1000 files: < 5 seconds
├── 10000 files: < 50 seconds
└── Memory: < 100MB
```

### Benchmark Tests

```go
// action/pkg/patterns/detectors/benchmark_test.go

func BenchmarkPromptInjection(b *testing.B) {
    detector := NewPromptInjectionDetector()
    code := []byte(largeCodeSample)

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        detector.Detect("test.py", code)
    }
}

func BenchmarkScannerConcurrency(b *testing.B) {
    scanner := NewScanner(registry, 4, "high")

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        scanner.Scan("./testdata")
    }
}
```

### Load Testing

```bash
# Generate large test codebase
python3 -c "
import os
for i in range(100):
    with open(f'testdata/large/app_{i}.py', 'w') as f:
        f.write('''
VULNERABLE = 'sk-proj-test-key-{i}'
while True: pass
prompt = f'User: {input()}'
db = os.environ['DB_URL']
''')
"

# Run scanner with time measurement
time ./inkog --path testdata/large
```

---

## Phase 5: CI/CD Integration (Week 2)

### GitHub Actions Workflow

```yaml
# .github/workflows/security-tests.yml

name: Security Pattern Tests

on: [push, pull_request]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
      - run: go test ./action/pkg/patterns/detectors -v -cover

  integration-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
      - run: go test ./action/cmd/scanner -v

  scan-repo:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
      - run: |
          cd action
          go build -o inkog ./cmd/scanner
          ./inkog --path .. --json-report results.json
      - uses: actions/upload-artifact@v3
        with:
          name: scan-results
          path: results.json
```

---

## Quality Gates

### Merge Requirements

Before merging to main:

```
✓ All unit tests pass (100% for new code)
✓ All integration tests pass
✓ Code coverage > 80%
✓ No new high-risk findings introduced
✓ Scanner runs without errors
✓ Documentation updated
✓ Performance benchmarks within targets
```

---

## Test Coverage Goals

| Component | Current | Target | Timeline |
|-----------|---------|--------|----------|
| TIER 1 Patterns | 0% | 95%+ | This week |
| Scanner | 0% | 90%+ | This week |
| CLI | 0% | 85%+ | Next week |
| TIER 2 Patterns | N/A | 95%+ | Week 2 |
| TIER 3 Patterns | N/A | 95%+ | Week 3 |
| **Overall** | **0%** | **90%+** | **By end of month** |

---

## Known Test Scenarios

### Prompt Injection

- [x] Basic f-string injection
- [x] LLM context validation
- [x] Multiple injections per file
- [x] Test file skipping
- [ ] Encoded payloads (future: harder)
- [ ] Semantic injection (future: requires AST)

### Hardcoded Credentials

- [x] OpenAI API keys (sk-*)
- [x] GitHub tokens (ghp_*)
- [x] Database passwords
- [x] Placeholder detection
- [x] Comment skipping
- [ ] Encrypted secrets (future)
- [ ] Vault integrations (future)

### Infinite Loop

- [x] while True
- [x] while true (case-insensitive)
- [x] while 1
- [x] Break condition detection
- [x] max_iterations recognition
- [ ] Recursive functions (future)
- [ ] Generator expressions (future)

### Unsafe Env Access

- [x] os.environ[] direct access
- [x] .get() detection
- [x] Default value support
- [ ] python-dotenv integration (future)
- [ ] AWS Secrets Manager (future)

---

## Testing Tools & Libraries

### Go Testing
- `testing` package (built-in)
- `assert` or `require` libraries for cleaner assertions

### Code Coverage
- `go tool cover` for coverage reports
- Coverage badges in README

### Performance Testing
- `go test -bench` for benchmarks
- `pprof` for profiling

### Mocking (if needed)
- `github.com/stretchr/testify/mock`

---

## Continuous Improvement

### Quarterly Review

Every quarter, analyze:
1. False positive rate per pattern
2. Detection accuracy vs real-world vulns
3. Performance metrics
4. User feedback/issues
5. New CVEs/vulnerabilities discovered

### Annual Update

- Review all 16 patterns
- Update detection logic based on learnings
- Refactor for performance
- Add new patterns based on research

---

## Success Metrics

| Metric | Target | Current | Status |
|--------|--------|---------|--------|
| Unit Test Pass Rate | 100% | 0% | In Progress |
| Integration Test Pass Rate | 100% | 0% | In Progress |
| Code Coverage | > 85% | 0% | In Progress |
| False Positive Rate | < 5% | TBD | Measuring |
| Detection Accuracy | > 90% | TBD | Measuring |
| Performance (100 files) | < 500ms | TBD | Benchmarking |
| Documentation Coverage | 100% | 95% | ✅ |

---

## Testing Timeline

```
Week 1:
├── Mon-Tue: Unit tests for 4 TIER 1 patterns
├── Wed: Integration tests for scanner/CLI
├── Thu: Functional tests with test data
└── Fri: Fix failures, achieve 95%+ pass rate

Week 2:
├── Mon: Performance benchmarks
├── Tue: Load testing (1000+ files)
├── Wed: CI/CD pipeline setup
├── Thu-Fri: Pattern 5 implementation + tests

Week 3:
├── Mon-Tue: Patterns 6-7 + tests
├── Wed: TIER 1 complete + final testing
├── Thu-Fri: Start TIER 2 patterns

Week 4:
├── Continuous implementation of TIER 2
├── Monthly metrics review
└── Plan next month improvements
```

