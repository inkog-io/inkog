# Validation Execution Checklist

**Status:** Ready to Execute
**Date:** November 10, 2025
**Purpose:** Track progress through validation execution

---

## Pre-Validation Setup

- [ ] Read START_HERE.md (5 minutes)
- [ ] Read VALIDATION_READY.md (10 minutes)
- [ ] Verify vulnerability zoo exists: `ls /tmp/vulnerability-zoo/`
- [ ] Verify VALIDATION_SCRIPT.sh exists: `ls /tmp/vulnerability-zoo/VALIDATION_SCRIPT.sh`

---

## Step 1: Build Scanner (5 minutes)

```bash
cd /Users/tester/inkog2/action
go build -o inkog-scanner ./cmd/scanner
./inkog-scanner -list-patterns
```

- [ ] Scanner builds without errors
- [ ] `-list-patterns` shows 4 patterns
- [ ] All patterns registered (Prompt Injection, Credentials, Loops, Env Access)

---

## Step 2: Create Results Directory (1 minute)

```bash
mkdir -p /tmp/validation-results
cd /tmp/validation-results
```

- [ ] Directory created successfully
- [ ] Directory is empty and ready for results

---

## Step 3: Run Validation (30 minutes)

```bash
bash /tmp/vulnerability-zoo/VALIDATION_SCRIPT.sh \
  /Users/tester/inkog2/action/inkog-scanner \
  /tmp/validation-results
```

### Monitor Progress
- [ ] LangChain scan completes (should take ~10 seconds)
- [ ] CrewAI scan completes (should take ~15 seconds)
- [ ] Flowise scan completes (should take ~10 seconds)
- [ ] All JSON files created in /tmp/validation-results/

### Verify Output Files
- [ ] `p1_langchain.json` created and has findings
- [ ] `p1_crewai.json` created and has findings
- [ ] `p1_flowise.json` created and has findings
- [ ] `p2_langchain.json` created and has findings
- [ ] `p2_crewai.json` created and has findings
- [ ] `p2_flowise.json` created and has findings
- [ ] `p3_langchain.json` created and has findings
- [ ] `p3_crewai.json` created and has findings
- [ ] `p3_flowise.json` created and has findings
- [ ] `p4_langchain.json` created and has findings
- [ ] `p4_crewai.json` created and has findings
- [ ] `p4_flowise.json` created and has findings

---

## Step 4: Analyze Results (15 minutes)

### Overall Findings Count

```bash
jq -s '.[].Findings | length' /tmp/validation-results/*.json | awk '{sum+=$1} END {print sum}'
```

- [ ] Total findings: **Expected 36-72** (Actual: ___)

### By Framework

```bash
# LangChain total
jq '.Findings | length' /tmp/validation-results/p*_langchain.json | awk '{sum+=$1} END {print sum}'

# CrewAI total
jq '.Findings | length' /tmp/validation-results/p*_crewai.json | awk '{sum+=$1} END {print sum}'

# Flowise total
jq '.Findings | length' /tmp/validation-results/p*_flowise.json | awk '{sum+=$1} END {print sum}'
```

- [ ] LangChain: **Expected 14-27** (Actual: ___)
- [ ] CrewAI: **Expected 10-22** (Actual: ___)
- [ ] Flowise: **Expected 12-23** (Actual: ___)

### By Pattern

```bash
# Pattern 1
jq '.Findings | length' /tmp/validation-results/p1_*.json | awk '{sum+=$1} END {print sum}'

# Pattern 2
jq '.Findings | length' /tmp/validation-results/p2_*.json | awk '{sum+=$1} END {print sum}'

# Pattern 3
jq '.Findings | length' /tmp/validation-results/p3_*.json | awk '{sum+=$1} END {print sum}'

# Pattern 4
jq '.Findings | length' /tmp/validation-results/p4_*.json | awk '{sum+=$1} END {print sum}'
```

- [ ] Pattern 1: **Expected 6-12** (Actual: ___)
- [ ] Pattern 2: **Expected 21-40** (Actual: ___)
- [ ] Pattern 3: **Expected 5-11** (Actual: ___)
- [ ] Pattern 4: **Expected 4-9** (Actual: ___)

---

## Step 5: Validate CVE Detection

### Pattern 1: Prompt Injection

```bash
grep -r "CVE-2023-44467\|CVE-2024-8309\|CVE-2025-59528" /tmp/validation-results/p1_*.json
```

- [ ] CVE-2023-44467 detected
- [ ] CVE-2024-8309 detected
- [ ] CVE-2025-59528 detected

### Pattern 2: Hardcoded Credentials

```bash
jq '.Findings[] | select(.Pattern == "hardcoded-credentials-v2") | .Message' \
  /tmp/validation-results/p2_*.json | grep -i "api\|key\|secret" | head -5
```

- [ ] OpenAI keys found
- [ ] AWS/Azure credentials found
- [ ] Database credentials found

### Pattern 3: Infinite Loops

```bash
jq '.Findings[] | select(.Pattern == "infinite-loops-v2") | .Message' \
  /tmp/validation-results/p3_*.json | head -5
```

- [ ] Agent loops detected
- [ ] Recursion detected
- [ ] Workflow loops detected

### Pattern 4: Unsafe Environment Access

```bash
grep -r "eval\|exec\|subprocess\|os.system" /tmp/validation-results/p4_*.json | head -5
```

- [ ] eval/exec patterns detected
- [ ] subprocess patterns detected
- [ ] os.system patterns detected

---

## Step 6: Check Confidence Scores

```bash
# Get confidence distribution
jq -s '.[].Findings[].Confidence | [min, max, add/length]' /tmp/validation-results/*.json
```

**Results:**
- Min Confidence: **Expected 0.70+** (Actual: ___)
- Max Confidence: **Expected 0.95+** (Actual: ___)
- Avg Confidence: **Expected 0.80+** (Actual: ___)

---

## Step 7: False Positive Analysis

### Manual Review (Sample 10 High-Confidence Findings)

```bash
jq '.Findings[] | select(.Confidence > 0.85) | {File: .File, Message: .Message, Confidence: .Confidence}' \
  /tmp/validation-results/*.json | head -10
```

Review each finding manually:
1. Is this a real vulnerability? (Yes/No)
2. Is it exploitable? (Yes/No)
3. Is the confidence score appropriate? (Yes/No)

**False Positive Counts:**
- [ ] False positives found: ___ out of ___
- [ ] False positive rate: **Expected <5%** (Actual: ___)

---

## Step 8: Performance Analysis

### Scan Times

```bash
# Get scan duration from first result
jq '.ScanDuration' /tmp/validation-results/p1_langchain.json
```

- [ ] LangChain scan time: ___ ms
- [ ] CrewAI scan time: ___ ms
- [ ] Flowise scan time: ___ ms
- [ ] Average per file: **Expected <5ms** (Actual: ___ ms)

---

## Step 9: Pattern-Specific Validation

### Pattern 1: Prompt Injection
```bash
jq '.Findings[] | select(.Pattern == "prompt_injection")' /tmp/validation-results/p1_langchain.json | head -3
```

- [ ] String interpolation patterns detected
- [ ] Dangerous sinks identified (eval, exec, system)
- [ ] LLM context properly identified
- [ ] Confidence range 0.80-0.95: **PASS/FAIL**
- [ ] False positive rate <5%: **PASS/FAIL**

### Pattern 2: Hardcoded Credentials
```bash
jq '.Findings[] | select(.Pattern == "hardcoded-credentials-v2")' /tmp/validation-results/p2_langchain.json | head -3
```

- [ ] API keys detected
- [ ] Database credentials found
- [ ] Entropy analysis working
- [ ] Confidence range 0.85-0.98: **PASS/FAIL**
- [ ] False positive rate <10%: **PASS/FAIL**

### Pattern 3: Infinite Loops
```bash
jq '.Findings[] | select(.Pattern == "infinite-loops-v2")' /tmp/validation-results/p3_crewai.json | head -3
```

- [ ] Infinite loop conditions detected
- [ ] Recursion without base case found
- [ ] Event loop context awareness: **PASS/FAIL**
- [ ] Confidence range 0.75-0.90: **PASS/FAIL**
- [ ] False positive rate <5%: **PASS/FAIL**

### Pattern 4: Unsafe Environment Access
```bash
jq '.Findings[] | select(.Pattern == "unsafe-env-access-v2")' /tmp/validation-results/p4_langchain.json | head -3
```

- [ ] Code execution patterns detected
- [ ] Untrusted input tracking: **PASS/FAIL**
- [ ] Import alias evasion detected
- [ ] Confidence range 0.80-0.95: **PASS/FAIL**
- [ ] False positive rate <5%: **PASS/FAIL**

---

## Success Criteria Validation

### ✅ All Must Pass

#### Pattern 1: Prompt Injection
- [ ] 3-10 findings
- [ ] Confidence: 0.80-0.95
- [ ] FP rate: <5%
- [ ] CVEs: Found 3+

#### Pattern 2: Hardcoded Credentials
- [ ] 10-30 findings
- [ ] Confidence: 0.85-0.98
- [ ] FP rate: <10%
- [ ] Real credentials: Found

#### Pattern 3: Infinite Loops
- [ ] 2-8 findings
- [ ] Confidence: 0.75-0.90
- [ ] FP rate: <5%
- [ ] Loop types: Found 3+

#### Pattern 4: Unsafe Environment Access
- [ ] 2-8 findings
- [ ] Confidence: 0.80-0.95
- [ ] FP rate: <5%
- [ ] Code execution: Found

#### Overall Metrics
- [ ] Total findings: 36-72
- [ ] Overall FP rate: <5%
- [ ] Performance: <5ms per file
- [ ] All critical vulnerabilities detected

---

## Final Decision

### Validation Result

- [ ] **✅ PASS** - All criteria met, approve Pattern 5 development
- [ ] **⚠️  BORDERLINE** - Most criteria met, review exceptions
- [ ] **❌ FAIL** - Issues found, fix and re-validate

### If PASS ✅

1. [ ] Copy results to project:
   ```bash
   cp /tmp/validation-results/SUMMARY.md \
      /Users/tester/inkog2/action/docs/TIER1_PRODUCTION_VALIDATION_RESULTS.md
   ```

2. [ ] Update ROADMAP.md - Mark TIER 1 as "Production-Validated"

3. [ ] Commit results:
   ```bash
   cd /Users/tester/inkog2/action
   git add docs/TIER1_PRODUCTION_VALIDATION_RESULTS.md ROADMAP.md
   git commit -m "docs: Add TIER 1 production validation results"
   ```

4. [ ] Approve Pattern 5 development
   - Review: docs/PATTERN5_DEVELOPMENT_STANDARD.md
   - Estimated time: 15-20 hours
   - Next pattern: Insecure Deserialization (CWE-502)

### If FAIL ❌

1. [ ] Identify root cause(s):
   ```bash
   # Run specific pattern test
   go test ./pkg/patterns/detectors -v -run TestPromptInjectionV2
   ```

2. [ ] Fix pattern issue(s)

3. [ ] Re-validate:
   ```bash
   rm /tmp/validation-results/*.json
   bash /tmp/vulnerability-zoo/VALIDATION_SCRIPT.sh \
     /Users/tester/inkog2/action/inkog-scanner \
     /tmp/validation-results
   ```

4. [ ] Repeat from Step 4 until all criteria pass

---

## Documentation

- [ ] Create validation summary:
  ```bash
  cat > /tmp/validation-results/SUMMARY.md << 'EOF'
  # TIER 1 Production Validation Results

  Date: [date]
  Status: PASS/FAIL

  ## Results
  - Total findings: [number]
  - False positive rate: [percent]
  - Performance: [ms per file]
  - All criteria passed: YES/NO

  ## Decision
  [Go/No-go for Pattern 5]
  EOF
  ```

- [ ] Document issues (if any):
  ```bash
  cat > /tmp/validation-results/ISSUES_FOUND.md << 'EOF'
  # Issues Found During Validation

  ## Issue 1: [Description]
  - Root cause: [cause]
  - Fix: [solution]
  - Status: [Fixed/Pending]

  EOF
  ```

---

## Final Status

**Validation Complete:** YES / NO
**All Criteria Pass:** YES / NO / BORDERLINE
**Pattern 5 Approved:** YES / NO
**Ready to Proceed:** YES / NO

---

**When all checkboxes are complete, validation is done.**

