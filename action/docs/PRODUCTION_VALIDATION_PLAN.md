# TIER 1 Production Validation Plan

**Purpose:** Validate all 4 patterns against real vulnerable code from production frameworks
**Status:** READY TO EXECUTE (before Pattern 5)
**Estimated Time:** 4-6 hours

---

## Objective

Validate that Inkog's TIER 1 patterns:
1. ✅ Detect real CVEs in production frameworks (LangChain, CrewAI, Flowise)
2. ✅ Maintain <5% false positive rate on real code
3. ✅ Achieve acceptable performance (<5ms per file)
4. ✅ Don't miss critical vulnerabilities

---

## Setup: Vulnerability Zoo Creation

### Step 1: Clone Real Frameworks

```bash
# Create vulnerability zoo directory
mkdir -p /tmp/vulnerability-zoo
cd /tmp/vulnerability-zoo

# Clone real vulnerable frameworks
git clone https://github.com/langchain-ai/langchain.git --depth 1
git clone https://github.com/joaomdmoura/crewai.git --depth 1
git clone https://github.com/FlowiseAI/Flowise.git --depth 1

# Verify clones
ls -la
# Should show: langchain/, crewai/, flowise/
```

### Step 2: Document Known Vulnerabilities

**LangChain Known CVEs (for validation):**
- CVE-2023-44467 (PALChain - eval execution)
- CVE-2024-36480 (Tool execution - unsafe subprocess)
- CVE-2025-46059 (Nested eval in Gmail toolkit)

**CrewAI Known Issues:**
- Infinite recursion in agent loops (missing base case)
- Hardcoded API keys in example code
- Unsafe subprocess calls in tool execution

**Flowise Known Issues:**
- Hardcoded credentials in example flows
- Custom MCP code execution (CVE-2025-59528)
- Infinite loops in workflow execution

---

## Test Execution Plan

### Phase 1: Pattern 1 Validation (Prompt Injection)

**Target:** Find prompt injection vulnerabilities in real code

```bash
# Step 1: Scan LangChain for prompt injection
echo "=== Pattern 1: Scanning LangChain ==="
./inkog scan ./langchain --pattern prompt_injection --json > results/p1_langchain.json

# Verify output
jq '.findings | length' results/p1_langchain.json
# Expected: 3-5 findings (CVE-2023-44467, CVE-2024-8309, CVE-2025-59528)

# Step 2: Scan CrewAI
echo "=== Pattern 1: Scanning CrewAI ==="
./inkog scan ./crewai --pattern prompt_injection --json > results/p1_crewai.json

# Step 3: Scan Flowise
echo "=== Pattern 1: Scanning Flowise ==="
./inkog scan ./flowise --pattern prompt_injection --json > results/p1_flowise.json

# Validation checklist:
# [ ] Found CVE-2023-44467 (exec of LLM output) in LangChain
# [ ] Found CVE-2024-8309 (DB injection) in LangChain
# [ ] Found CVE-2025-59528 (Code execution) in Flowise
# [ ] Confidence scores > 0.80 for real vulnerabilities
# [ ] False positives < 5%
```

**Expected Findings:**
- LangChain: 3-5 prompt injection vulnerabilities
- CrewAI: 1-2 vulnerabilities
- Flowise: 2-3 vulnerabilities
- **Total: 6-10 real findings**

**Validation Criteria:**
- ✅ All 4 CVEs from Pattern 1 test suite detected
- ✅ Confidence scores 0.80-0.95
- ✅ No false positives on legitimate prompt template code

---

### Phase 2: Pattern 2 Validation (Hardcoded Credentials)

**Target:** Find hardcoded API keys, tokens, secrets

```bash
# Step 1: Scan LangChain
echo "=== Pattern 2: Scanning LangChain ==="
./inkog scan ./langchain --pattern hardcoded-credentials-v2 --json > results/p2_langchain.json

# Expected findings:
jq '.findings[] | select(.message | contains("API") or contains("key")) | .message' results/p2_langchain.json
# Should find: OpenAI keys, API keys in examples, test credentials

# Step 2: Scan CrewAI
echo "=== Pattern 2: Scanning CrewAI ==="
./inkog scan ./crewai --pattern hardcoded-credentials-v2 --json > results/p2_crewai.json

# Expected: Hardcoded service tokens, API keys in examples

# Step 3: Scan Flowise
echo "=== Pattern 2: Scanning Flowise ==="
./inkog scan ./flowise --pattern hardcoded-credentials-v2 --json > results/p2_flowise.json

# Expected: Database credentials, API keys in example flows

# Count findings
for file in results/p2_*.json; do
    echo "File: $file"
    jq '.findings | length' "$file"
done

# Validation checklist:
# [ ] Found real API keys (not just in tests/examples)
# [ ] Confidence > 0.85 for real credentials
# [ ] Placeholder/dummy value filtering working (<5% FP)
# [ ] Test file exclusion working
```

**Expected Findings:**
- LangChain: 10-20 credentials (mixed real + examples)
- CrewAI: 5-10 credentials
- Flowise: 15-25 credentials (example flows)
- **Total: 30-55 findings**

**Validation Criteria:**
- ✅ Real credentials detected (not just placeholders)
- ✅ Confidence 0.85-0.98 for real findings
- ✅ FP rate from examples/tests <10%
- ✅ All 5 incident types from tests detected

---

### Phase 3: Pattern 3 Validation (Infinite Loops)

**Target:** Find infinite loops and recursion without base cases

```bash
# Step 1: Scan LangChain
echo "=== Pattern 3: Scanning LangChain ==="
./inkog scan ./langchain --pattern infinite-loops-v2 --json > results/p3_langchain.json

# Look for sitemap infinite recursion
jq '.findings[] | select(.message | contains("recursion") or contains("loop")) | .file' results/p3_langchain.json

# Step 2: Scan CrewAI
echo "=== Pattern 3: Scanning CrewAI ==="
./inkog scan ./crewai --pattern infinite-loops-v2 --json > results/p3_crewai.json

# Look for agent loop issues
jq '.findings[] | .message' results/p3_crewai.json | grep -i "loop\|recursion"

# Step 3: Scan Flowise
echo "=== Pattern 3: Scanning Flowise ==="
./inkog scan ./flowise --pattern infinite-loops-v2 --json > results/p3_flowise.json

# Validation checklist:
# [ ] Found infinite loops in agent code
# [ ] Found recursion without base case
# [ ] Event loop context awareness working (low FP)
# [ ] Confidence 0.75-0.90 for real issues
```

**Expected Findings:**
- LangChain: 2-4 infinite loop/recursion issues
- CrewAI: 3-5 agent retry loop issues
- Flowise: 1-3 workflow loop issues
- **Total: 6-12 findings**

**Validation Criteria:**
- ✅ Sitemap cyclic recursion detected in LangChain
- ✅ Agent retry loops detected in CrewAI
- ✅ Workflow loops detected in Flowise
- ✅ FP rate <5% (event loop filtering working)

---

### Phase 4: Pattern 4 Validation (Unsafe Environment Access)

**Target:** Find dangerous code execution and environment access

```bash
# Step 1: Scan LangChain
echo "=== Pattern 4: Scanning LangChain ==="
./inkog scan ./langchain --pattern unsafe-env-access-v2 --json > results/p4_langchain.json

# Look for CVE patterns
jq '.findings[] | select(.confidence > 0.80) | .message' results/p4_langchain.json

# Step 2: Scan CrewAI
echo "=== Pattern 4: Scanning CrewAI ==="
./inkog scan ./crewai --pattern unsafe-env-access-v2 --json > results/p4_crewai.json

# Step 3: Scan Flowise
echo "=== Pattern 4: Scanning Flowise ==="
./inkog scan ./flowise --pattern unsafe-env-access-v2 --json > results/p4_flowise.json

# Validation checklist:
# [ ] Found os.system() calls with user input
# [ ] Found subprocess.run() with LLM output
# [ ] Found eval/exec patterns
# [ ] Confidence 0.80-0.95 for real issues
# [ ] Sanitization detection working
```

**Expected Findings:**
- LangChain: 2-3 unsafe code execution patterns
- CrewAI: 2-4 subprocess issues
- Flowise: 1-2 dynamic execution issues
- **Total: 5-9 findings**

**Validation Criteria:**
- ✅ CVE-2023-44467 patterns detected
- ✅ CVE-2024-36480 patterns detected
- ✅ os.system() and subprocess patterns caught
- ✅ Import alias evasion detection working

---

## Consolidated Results Analysis

### Run All Patterns at Once

```bash
# Full scan (all patterns)
echo "=== RUNNING FULL TIER 1 SCAN ==="
./inkog scan ./langchain --json > results/langchain_full.json
./inkog scan ./crewai --json > results/crewai_full.json
./inkog scan ./flowise --json > results/flowise_full.json

# Generate summary report
cat > analyze_results.sh << 'EOF'
#!/bin/bash

echo "=== INKOG TIER 1 PRODUCTION VALIDATION RESULTS ==="
echo ""

for framework in langchain crewai flowise; do
    echo "Framework: $framework"
    echo "=================="

    file="results/${framework}_full.json"

    # Total findings
    total=$(jq '.findings | length' "$file")
    echo "Total Findings: $total"

    # By severity
    echo "By Severity:"
    jq '.findings | group_by(.severity) | map({severity: .[0].severity, count: length})' "$file" | jq -r '.[] | "  \(.severity): \(.count)"'

    # By pattern
    echo "By Pattern:"
    jq '.findings | group_by(.pattern) | map({pattern: .[0].pattern, count: length})' "$file" | jq -r '.[] | "  \(.pattern): \(.count)"'

    # Confidence distribution
    echo "Confidence Distribution:"
    jq '.findings | map(.confidence) | [min, max, (add/length)]' "$file" | jq -r '"  Min: \(.[0]), Max: \(.[1]), Avg: \(.[2])"'

    echo ""
done
EOF

chmod +x analyze_results.sh
./analyze_results.sh
```

---

## Expected Overall Results

### Target Metrics

| Metric | Target | Success Criteria |
|--------|--------|------------------|
| **Total CVEs Found** | 22+ | Find all 4+5+5+6 CVEs from test suites |
| **LangChain Findings** | 8-10 | Min 3 patterns detecting real issues |
| **CrewAI Findings** | 5-8 | Min 3 patterns detecting real issues |
| **Flowise Findings** | 8-12 | Min 3 patterns detecting real issues |
| **False Positive Rate** | <5% | Measured from all findings |
| **Performance** | <5ms/file | Average across all frameworks |
| **Confidence Accuracy** | 0.80+ | Real issues have high confidence |

### Success Criteria (All Must Pass)

```
✅ PATTERN 1 (Prompt Injection):
   [ ] CVE-2023-44467 detected in LangChain
   [ ] CVE-2024-8309 detected in LangChain
   [ ] CVE-2025-59528 detected in Flowise
   [ ] Confidence 0.80-0.95
   [ ] FP rate <5%

✅ PATTERN 2 (Hardcoded Credentials):
   [ ] Real credentials detected (not just test values)
   [ ] AWS keys detected in examples
   [ ] API keys detected in code
   [ ] Confidence 0.85-0.98
   [ ] FP rate <10% (examples are OK false positives)

✅ PATTERN 3 (Infinite Loops):
   [ ] Agent loops detected in CrewAI
   [ ] Recursion detected in LangChain
   [ ] Workflow loops detected in Flowise
   [ ] Confidence 0.75-0.90
   [ ] FP rate <5%

✅ PATTERN 4 (Unsafe Environment Access):
   [ ] CVE-2023-44467 patterns detected
   [ ] subprocess patterns detected
   [ ] os.system patterns detected
   [ ] Confidence 0.80-0.95
   [ ] FP rate <5%

✅ OVERALL:
   [ ] All 22+ CVEs/issues from TIER 1 test suites detected
   [ ] Overall FP rate <5%
   [ ] Performance <5ms per file
   [ ] No critical vulnerabilities missed
```

---

## False Positive Analysis

### How to Measure Real FP Rate

```bash
# Get all findings
jq '.findings[] | {file: .file, message: .message, confidence: .confidence}' results/*_full.json > all_findings.txt

# Manual verification needed for each finding:
# 1. Is this a real vulnerability? (check code context)
# 2. Is this exploitable in production? (check if user-controlled)
# 3. Is this a legitimate pattern? (check for false positive reasons)

# Example FP analysis:
jq '.findings[] | select(.confidence > 0.80) | {pattern: .pattern, file: .file}' results/langchain_full.json | \
while read line; do
    # Manually verify each high-confidence finding
    # Count real vs false positives
done
```

---

## Performance Profiling

### Measure Execution Time

```bash
# Create performance test script
cat > profile_scan.sh << 'EOF'
#!/bin/bash

frameworks=("langchain" "crewai" "flowise")

for framework in "${frameworks[@]}"; do
    echo "Profiling: $framework"

    # Time the scan
    time ./inkog scan /tmp/vulnerability-zoo/$framework --json > /dev/null

    # Count files scanned
    files=$(find /tmp/vulnerability-zoo/$framework -type f \( -name "*.py" -o -name "*.js" -o -name "*.ts" -o -name "*.go" -o -name "*.java" \) | wc -l)
    echo "Files scanned: $files"
    echo ""
done
EOF

chmod +x profile_scan.sh
./profile_scan.sh
```

---

## Expected Output Example

```json
{
  "framework": "langchain",
  "scan_time_ms": 2847,
  "files_scanned": 427,
  "total_findings": 12,
  "by_pattern": {
    "prompt_injection": 4,
    "hardcoded-credentials-v2": 6,
    "infinite-loops-v2": 1,
    "unsafe-env-access-v2": 1
  },
  "by_severity": {
    "CRITICAL": 4,
    "HIGH": 8
  },
  "avg_confidence": 0.87,
  "false_positive_rate": 0.02
}
```

---

## Validation Checklist

Before declaring TIER 1 production-ready:

### Real CVE Detection
- [ ] Pattern 1: All 4 CVEs detected in real code
- [ ] Pattern 2: Real credentials found (not just examples)
- [ ] Pattern 3: Real infinite loops detected
- [ ] Pattern 4: All 6 CVEs detected in real code

### False Positive Rate
- [ ] Pattern 1: FP <5%
- [ ] Pattern 2: FP <10% (examples are acceptable)
- [ ] Pattern 3: FP <5%
- [ ] Pattern 4: FP <5%

### Performance
- [ ] LangChain scan: <1 second total
- [ ] CrewAI scan: <500ms total
- [ ] Flowise scan: <1 second total
- [ ] Average: <5ms per file

### Confidence Accuracy
- [ ] Real findings: confidence 0.75+
- [ ] False positives: confidence <0.65 (or filtered)
- [ ] No high-confidence (>0.90) false positives

### Multi-Framework Coverage
- [ ] LangChain: All patterns working
- [ ] CrewAI: All patterns working
- [ ] Flowise: All patterns working

---

## Risk Assessment

### If Validation Fails

**Scenario 1: Not finding known CVEs**
- Action: Debug pattern regex/AST logic
- Review: Test cases vs real code differences
- Remediate: Add pattern variants before Pattern 5

**Scenario 2: High false positive rate**
- Action: Strengthen FP reduction logic
- Review: Context detection and filtering
- Remediate: Improve confidence scoring before Pattern 5

**Scenario 3: Performance issues**
- Action: Profile and optimize hot paths
- Review: Regex complexity, AST traversal
- Remediate: Cache results, optimize patterns

**Scenario 4: Missing certain frameworks**
- Action: Extended testing on other frameworks
- Review: Coverage gaps
- Remediate: Add support if time permits

---

## Timeline

```
Step 1 (30 min):  Clone vulnerability zoo
Step 2 (30 min):  Configure scan environment
Step 3 (2 hours): Execute Phase 1-4 scans
Step 4 (1 hour):  Analyze results
Step 5 (1 hour):  Verify CVE detection
Step 6 (30 min):  FP rate analysis
Step 7 (30 min):  Performance profiling

Total: 6 hours
```

---

## Success Outcome

**Upon successful validation:**

✅ Confirm all TIER 1 patterns work on real vulnerable code
✅ Verify CVE detection in production frameworks
✅ Validate false positive rates
✅ Confirm performance targets
✅ **CLEARED TO PROCEED WITH PATTERN 5**

**If any metric fails:** Remediate before Pattern 5

---

## Next Steps (After Validation)

1. Document results in: `TIER1_PRODUCTION_VALIDATION_RESULTS.md`
2. Update ROADMAP.md with validation outcomes
3. Commit validation results
4. Begin Pattern 5 development (Insecure Deserialization)

---

**This production validation is a critical quality gate.**
**Do not skip. Do not compromise.**

The difference between a beta tool and an enterprise-grade security scanner is real-world validation against known vulnerabilities.

**Once this passes, Pattern 5 is cleared to start.**

---

**Document Version:** 1.0
**Status:** READY FOR EXECUTION
**Last Updated:** November 10, 2025
