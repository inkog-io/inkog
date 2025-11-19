# Strategic Rebuild Plan: Modular Security Scanner Foundation

**Date:** November 12, 2025
**Status:** Critical Analysis Complete
**Decision:** Complete Rebuild Required

---

## THE PROBLEM WE DISCOVERED

### Current State: NOT PRODUCTION READY ❌

1. **Patterns Don't Detect Findings**
   - All 6 patterns compile but return zero findings on obviously vulnerable code
   - Debug detector works (proves pipeline is OK)
   - Real detectors are broken

2. **Root Causes Identified**
   - Overly complex implementations with non-existent methods
   - Code uses features that aren't implemented (AST framework methods)
   - Regex patterns don't match test cases
   - No unit tests for individual detectors
   - No isolation - can't test pattern without full system

3. **Architecture Issues**
   - Tight coupling between patterns and AST framework
   - No clear contract/interface for what detectors must do
   - Hard to add new patterns - requires understanding 700+ lines of existing code
   - Not modular like Kubernetes - no clear plugin architecture

---

## THE KUBERNETES APPROACH WE NEED

### Core Principle: Start Simple, Scale Elegantly

**Kubernetes Model:**
- Started with simple container scheduling
- Clear interfaces (Pod, Service, Controller)
- Each component responsible for one thing
- Easy to extend (Custom Resources, Operators)
- Backward compatibility maintained

**Our Scanner Should Work Same Way:**
- Clear Detector interface (what does every detector need?)
- Simple base implementation (what's the minimum viable detector?)
- Pluggable architecture (any detector can be added without touching core)
- Auto-discovery (registry finds detectors automatically)
- Test each pattern in isolation

---

## STRATEGIC REBUILD PHASES

### PHASE 1: Core Foundation (Today - Next 2 Hours)
**Goal: Build the cleanest possible core that proves the pattern works end-to-end**

1. **Define Interface Clarity**
   - What methods MUST every detector have?
   - What fields are REQUIRED in findings?
   - What's the minimal viable detector?

2. **Build One Perfect Pattern**
   - Pick Pattern 1 (Hardcoded Credentials - simplest)
   - Implement from scratch, no copy-paste
   - Make it detect obvious vulnerabilities
   - Write unit tests FIRST (TDD)
   - Full end-to-end: code → scanner → finding

3. **Verify Pipeline**
   - Scanner engine works ✓ (proven)
   - One detector produces findings ✓
   - System is modular and testable

### PHASE 2: Build Remaining 5 Patterns (2-3 Hours Each)
**Goal: Each pattern is production-grade before moving to next**

For Each Pattern (2-6):
1. Implement from scratch (don't reuse broken v2)
2. Unit tests in isolation
3. Smoke test on real vulnerable code
4. Add to registry
5. Full system test
6. Document how to add pattern 7

### PHASE 3: Framework Documentation (1 Hour)
**Goal: Clear playbook for patterns 7-15**

Document:
- How patterns are discovered
- Where to add new patterns
- What interface they must implement
- How to test in isolation
- CI/CD integration checklist

### PHASE 4: Full Integration & Validation (2-3 Hours)
**Goal: All 6 patterns working perfectly together**

- Run full test suite
- All 14 hard gates pass
- Performance acceptable
- Ready for GitHub Action

---

## TECHNICAL DECISIONS

### 1. Detector Interface (Kubernetes-Style)
```go
type Detector interface {
    // Core detection
    Name() string
    Detect(filePath string, src []byte) ([]Finding, error)

    // Metadata
    GetPattern() Pattern
    GetConfidence() float32

    // Lifecycle
    Close() error
}
```

**Why:** Simple, clear, enforced by compiler

### 2. Finding Struct (Flat, Not Nested)
```go
type Finding struct {
    ID         string  // Unique ID
    PatternID  string  // Which pattern found it
    Pattern    string  // Pattern name
    File       string  // Path
    Line       int     // Line number
    Column     int     // Column number
    Severity   string  // CRITICAL, HIGH, MEDIUM, LOW
    Confidence float32 // 0.0-1.0
    Message    string  // Human readable
    Code       string  // Code snippet
    CWE        string  // CWE ID
    CVSS       float32 // CVSS score
    OWASP      string  // OWASP category
}
```

**Why:** No nested structs, JSON serializable, all fields optional but clear

### 3. Pattern Registry (Auto-Discovery)
```go
type Registry struct {
    detectors map[string]Detector
}

func (r *Registry) Register(d Detector) error {
    // Validate detector implements interface
    // Check for duplicate IDs
    // Log registration
}
```

**Why:** Register pattern once, it's auto-available everywhere

### 4. Scanner Engine (Delegation Pattern)
```go
func (s *Scanner) Scan(dirPath string) (*ScanResult, error) {
    // Walk files
    // For each file:
    //   - For each detector:
    //     - Call Detect()
    //     - Collect findings
    //   - Aggregate results
}
```

**Why:** Simple, testable, each detector isolated

### 5. Testing Strategy (TDD)
For EACH pattern:
```
test_cases/
  ├── vulnerable/
  │   ├── code1.py  (should find issue)
  │   ├── code2.py  (should find issue)
  │   └── ...
  └── safe/
      ├── code1.py  (should NOT find issue)
      └── ...

detector_test.go:
  - Test each vulnerable case
  - Test each safe case
  - Test edge cases
  - Run in isolation
```

---

## SUCCESS CRITERIA

### Per-Pattern Checklist:
- [ ] Detector implements interface correctly
- [ ] Unit tests pass (vulnerable cases found, safe cases ignored)
- [ ] No false positives on safe code
- [ ] Detects real vulnerabilities
- [ ] JSON output is valid
- [ ] Severity/Confidence are reasonable
- [ ] Documented how to extend

### Full System Checklist:
- [ ] All 6 patterns register
- [ ] All 6 patterns scan simultaneously
- [ ] Combined memory < 2GB
- [ ] Combined time < 15 seconds (large repo)
- [ ] JSON report is valid
- [ ] No panics or crashes
- [ ] Framework docs complete

---

## WHAT WE'RE NOT DOING

### ❌ Don't:
- Copy/paste broken code
- Add complex features (AST, call graphs) in V1
- Use non-existent methods
- Build without tests
- Promise "later we'll fix it"
- Deliver incomplete patterns

### ✅ Do:
- Start simple, scale later
- Test every pattern independently
- Document as we build
- Make code easy to understand
- Make code easy to extend
- Deliver production-ready

---

## TIMELINE ESTIMATE

| Phase | Duration | Output |
|-------|----------|--------|
| Phase 1: Core + Pattern 1 | 2-3 hours | Working detector + tests |
| Phase 2: Patterns 2-6 | 10-15 hours | All 6 detectors, each tested |
| Phase 3: Framework Docs | 1-2 hours | Clear playbook for 7-15 |
| Phase 4: Integration | 2-3 hours | Full system validation |
| **TOTAL** | **15-23 hours** | **Production-ready scanner** |

---

## SUCCESS VISION

When complete:
- Any developer can add Pattern 7 in < 30 minutes
- Clear file structure shows where everything goes
- Test cases show what it should detect
- No magic, no complex dependencies
- Scales to patterns 15+ naturally
- GitHub Action ready to ship

---

## NEXT ACTION

Ready to proceed with **Phase 1: Clean Core + Pattern 1** ?

This is how we build something groundbreaking - not with feature bloat, but with solid fundamentals.
