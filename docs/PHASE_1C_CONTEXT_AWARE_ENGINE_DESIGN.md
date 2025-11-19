# Phase 1C Design - Context-Aware Engine

**Week:** 3-4
**Purpose:** Orchestrate Guard + Confidence frameworks into unified detection system
**Files:** 2 (implementation + tests)
**Lines of Code:** ~300 implementation + ~250 tests

---

## Design Overview

The Context-Aware Engine is the orchestration layer that:
1. Coordinates false positive filtering (Guard Framework)
2. Applies confidence calibration (Confidence Framework)
3. Provides unified entry point for all patterns
4. Implements learning/feedback loop
5. Handles semantic context across analysis types

---

## Architecture

### High-Level Flow

```
Raw Findings
    ↓
    ├─→ [1] Guard Framework Filtering
    │       ├─ Context Detection (strings/comments/config)
    │       ├─ LLM Pattern Validation
    │       ├─ Loop Pattern Analysis
    │       └─ Output: Filtered findings
    ↓
    ├─→ [2] Semantic Analysis
    │       ├─ Variable Classification
    │       ├─ Data Flow Analysis
    │       ├─ Control Flow Analysis
    │       └─ Output: CodeAnalysisContext
    ↓
    ├─→ [3] Confidence Framework
    │       ├─ 7-Factor Calculation
    │       ├─ Evidence-Based Scoring
    │       └─ Output: Adjusted confidence
    ↓
    ├─→ [4] Learning/Feedback
    │       ├─ Store actual accuracy
    │       ├─ Recalibrate weights
    │       └─ Continuous improvement
    ↓
Final Findings with Adjusted Confidence
```

---

## Core Components

### 1. ContextAwareEngine (Main Orchestrator)

**Purpose:** Coordinates the complete detection pipeline

**Fields:**
```go
type ContextAwareEngine struct {
    guard       *GuardFramework
    confidence  *ConfidenceFramework
    analyzer    *SemanticAnalyzer
    feedback    *FeedbackCollector
}
```

**Key Methods:**
- `NewContextAwareEngine()` - Initialize with all components
- `AnalyzeFindings(findings, code, file)` - Main pipeline
- `EnableLearning(bool)` - Toggle learning mode
- `RecalibrateFromFeedback()` - Improve from actual results

### 2. SemanticAnalyzer (Context Extraction)

**Purpose:** Extract semantic information from code for confidence adjustment

**Methods:**
- `AnalyzeFile(filePath, lines)` - Whole-file analysis
- `AnalyzeLine(code, lineNum)` - Single-line analysis
- `ExtractVariables(code)` - Variable extraction
- `DetectFlows(lines)` - Data/control flow detection
- `BuildContext(lineNum, findings)` - Context construction

**Returns:** `CodeAnalysisContext` with semantic information

### 3. FeedbackCollector (Learning System)

**Purpose:** Implements learning from actual detection accuracy

**Fields:**
```go
type FeedbackCollector struct {
    predictions []PredictionRecord  // What we predicted
    actuals     []ActualRecord      // What really happened
    confidences []float32           // Predicted confidences
    calibration *CalibrationMetrics
}

type PredictionRecord struct {
    PatternID      string
    Finding        patterns.Finding
    PredictedConf  float32
    GuardFiltered  bool
    FactorScores   map[string]float32
}

type ActualRecord struct {
    PatternID      string
    IsTruePositive bool
    ActualSeverity string
    DateVerified   time.Time
}

type CalibrationMetrics struct {
    TotalPredictions int
    Accuracy         float32
    Precision        float32
    Recall           float32
    F1Score          float32
}
```

**Key Methods:**
- `RecordPrediction(pattern, finding, confidence)` - Log prediction
- `RecordActual(pattern, isTruePositive, severity)` - Log actual result
- `Calculate Metrics()` - Compute accuracy metrics
- `GenerateRecalibrationGuidance()` - Recommend weight changes

### 4. PatternResult (Standardized Output)

**Purpose:** Consistent result format for all patterns

```go
type PatternResult struct {
    Finding              patterns.Finding
    Filtered             bool                // Was it filtered by guard?
    FilterReason         string              // Why filtered (if applicable)
    OriginalConfidence   float32
    AdjustedConfidence   float32
    ConfidenceFactors    map[string]float32  // Individual factor scores
    SemanticContext      *CodeAnalysisContext
    Recommendations      []string            // E.g., "Sanitize user input"
}
```

---

## Integration Points

### How Patterns Will Use It

**Old Way (Direct Pattern):**
```go
findings := PatternDetector.Detect(code)
return findings  // No filtering, no confidence adjustment
```

**New Way (Context-Aware):**
```go
engine := NewContextAwareEngine()
findings := PatternDetector.Detect(code)
results := engine.AnalyzeFindings(findings, code, filePath)
return results  // Filtered, adjusted confidence, with context
```

### Minimal Pattern Changes

Patterns won't need major rewrites. They just:
1. Do what they already do (detect findings)
2. Pass findings to context-aware engine
3. Get back adjusted results

**Code Per Pattern:** ~20-30 lines of integration code

---

## Learning System Details

### How Learning Works

**1. Record Phase (During Detection):**
```
for each finding:
  - Record what we predicted (confidence score, factors)
  - Store guard filtering decision
  - Save semantic context
```

**2. Verification Phase (User/Manual Verification):**
```
User marks finding as:
  - TRUE POSITIVE (correct detection)
  - FALSE POSITIVE (wrong detection)
  - UNCERTAIN (needs human review)
```

**3. Analysis Phase (End of Scan):**
```
Calculate:
  - Accuracy: TP / (TP + FP)
  - Which patterns/factors were wrong
  - How much weight adjustment needed
```

**4. Recalibration Phase (Next Scan):**
```
Update:
  - Confidence factors weights
  - Guard filter thresholds
  - Pattern-specific settings
```

### Recalibration Algorithm

```
For each factor that was wrong:
  - If confidence was too high: reduce factor weight by 10%
  - If confidence was too low: increase factor weight by 10%
  - Cap weights to prevent extremes (0.05 to 0.35 per factor)
```

---

## Expected Test Coverage

### Unit Tests (15+ tests)

1. **Engine Initialization**
   - All components initialized correctly
   - Guard and Confidence frameworks accessible

2. **Pipeline Execution**
   - Findings flow through complete pipeline
   - Guard filtering applied
   - Confidence adjustment applied
   - Context built correctly

3. **Guard Integration**
   - Filtered findings excluded from confidence adjustment
   - Filter reasons captured
   - Provider/framework detection used

4. **Confidence Integration**
   - Context properly built
   - All 7 factors considered
   - Confidence adjusted in expected ranges

5. **Semantic Analysis**
   - Variables extracted and classified
   - Data flows detected
   - Control flows identified

6. **Feedback Collection**
   - Predictions recorded correctly
   - Actuals recorded correctly
   - Metrics calculated accurately

7. **Recalibration**
   - Weights adjusted based on feedback
   - Accuracy improves with feedback
   - Learning disabled when set to false

8. **Edge Cases**
   - Empty findings handled
   - Missing context handled gracefully
   - Invalid patterns handled
   - Feedback without predictions handled

### Integration Tests (5+ tests)

1. **End-to-End Detection**
   - Real pattern → guard filtering → confidence adjustment
   - All components working together

2. **Multi-Finding Processing**
   - Multiple findings processed correctly
   - Each gets appropriate treatment

3. **Large Codebase**
   - Performance with 1000+ findings
   - Memory usage acceptable

4. **Pattern Migration Example**
   - Using real pattern (e.g., Token Bombing)
   - Showing before/after with engine

---

## Performance Expectations

### Per Finding Processing

| Operation | Time | Memory |
|-----------|------|--------|
| Guard filtering | <1 μs | 0 B |
| Semantic analysis | 2-5 μs | <1 KB |
| Confidence calculation | 1 μs | 88 B |
| Feedback recording | <1 μs | <500 B |
| **Total per finding** | **~5 μs** | **<2 KB** |

### Bulk Processing

- **1,000 findings:** ~5 ms
- **10,000 findings:** ~50 ms
- **1,000,000 findings:** ~5 seconds

**Enterprise Grade:** Suitable for production scanning

---

## Implementation Steps

### Step 1: Define Interfaces & Types
- PatternResult structure
- FeedbackCollector types
- SemanticAnalyzer interface

### Step 2: Implement SemanticAnalyzer
- Variable extraction from code
- Data flow detection
- Control flow detection
- Context building

### Step 3: Implement FeedbackCollector
- Recording predictions
- Recording actuals
- Calculating metrics
- Generating recalibration guidance

### Step 4: Implement ContextAwareEngine
- Initialize components
- Orchestrate pipeline
- Call guard filtering
- Build context
- Apply confidence adjustment
- Record feedback

### Step 5: Comprehensive Testing
- Unit tests for each component
- Integration tests for pipeline
- Performance benchmarks
- Example pattern migration

---

## Deliverables

### Implementation Files
- `pkg/patterns/detectors/context_aware_engine.go` (~300 lines)
  - ContextAwareEngine struct
  - SemanticAnalyzer implementation
  - FeedbackCollector implementation
  - Pipeline orchestration

- `pkg/patterns/detectors/context_aware_engine_test.go` (~250 lines)
  - Unit tests (15+ tests)
  - Integration tests (5+ tests)
  - Example usage
  - Performance benchmarks

### Documentation
- Implementation report
- Usage guide for patterns
- Learning system documentation
- Migration template for each pattern

---

## Success Criteria

✅ All 20+ tests passing
✅ <5 μs per finding overhead
✅ Guard & Confidence integration working
✅ Learning system functional
✅ Ready for pattern migration
✅ Enterprise performance metrics met
✅ Complete documentation provided

---

## What Comes After

Once Phase 1C is complete:
- **Week 5:** Pattern migration 5-7 (20+ patterns)
- **Week 6:** Pattern migration 8-11 (20+ patterns)
- **Week 7-8:** Complete validation & documentation

All patterns will use the unified detection system with:
- Consistent false positive handling
- Evidence-based confidence scoring
- Continuous learning capability
- Enterprise-grade performance

---

## This Completes the Infrastructure

After Phase 1C, the infrastructure is COMPLETE:

```
✅ Phase 1A: Guard Framework (false positive filtering)
✅ Phase 1B: Confidence Framework (score calibration)
✅ Phase 1C: Context-Aware Engine (orchestration & learning)
```

Then patterns migrate to use this infrastructure, followed by comprehensive validation and documentation.

The foundation is solid, tested, and ready for enterprise production use.
