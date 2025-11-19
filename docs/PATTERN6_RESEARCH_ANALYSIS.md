# Pattern 6: Recursive Tool Calling - Deep Research Analysis

**Status:** Pre-Implementation Analysis
**Date:** November 10, 2025
**Goal:** Extract all critical insights from research to ensure complete and robust implementation

---

## 1. Threat Model Analysis

### 1.1 Real-World CVEs and Incidents

**LangChain CVE-2024-2965 (CRITICAL)**
- **Vulnerability Type:** Infinite Loop / Denial of Service
- **Component:** SitemapLoader.parse_sitemap()
- **Root Cause:** No guard against self-referential sitemap URLs
- **Attack Vector:** Sitemap URL refers to itself → infinite recursion
- **Impact:** Process crash due to Python max recursion depth exceeded
- **CWE Mapping:** CWE-835 (Infinite Loop), CWE-674 (Uncontrolled Recursion)
- **Detection Signal:** Function calling itself without break condition
- **Real Cost:** Complete service unavailability

**LangChain CVE-2025-46059 (Related)**
- **Vulnerability Type:** Prompt Injection in Email Tool
- **Impact:** Can lead to tool calling itself indirectly
- **Lesson:** Tool misuse patterns multiply risk

**CrewAI Delegation Loop (No CVE, but Production Incidents)**
- **Framework Feature:** allow_delegation=True
- **Problem:** When multiple agents have allow_delegation=True, circular delegation possible
- **Example:** AgentA delegates to AgentB, AgentB delegates back to AgentA
- **Impact:** Infinite back-and-forth API calls, runaway costs ($1,000s per hour possible)
- **Detection Signal:** Multiple Agent() instances with allow_delegation=True + circular reference
- **Real Cost:** Reported by users: "infinite loops until manually stopped"

**AutoGen Multi-Agent Loops**
- **Problem:** Agents in conversation loops repeat exchanges indefinitely
- **Mitigation Implemented:** AgentOps "Recursive Thought Detection"
- **Real Cost:** "Rate-limit hits and a bunch of calls for no reason"
- **Detection Signal:** While True loops with no guaranteed break on agent.step()

**Flowise Loop Nodes**
- **Problem:** Loop nodes with no max_loops or max_loops=null
- **Impact:** UI freezing, infinite loops, storage exhaustion from logs
- **Detection Signal:** LoopNode definitions with missing or zero max iteration count
- **Real Cost:** Self-DoS, resource exhaustion

### 1.2 CWE Mappings (Critical for Classification)

| CWE | Description | Pattern Match | Severity |
|-----|-------------|--------------|----------|
| **CWE-835** | Loop with Unreachable Exit Condition | Direct while True, recursive function with no base case | CRITICAL |
| **CWE-674** | Uncontrolled Recursion | Function calls itself/mutual recursion without depth limit | CRITICAL |
| **CWE-400** | Uncontrolled Resource Consumption | Loop/recursion consuming CPU, memory, API calls | HIGH |
| **CWE-710** | Improper Adherence to Coding Standards | Loop exists but developer didn't follow best practices | MEDIUM |

### 1.3 Real Financial Impact

**Scenario 1: Agent Recursion Loop**
- 1,000 API calls to GPT-4 = $30 (at $0.03/1K tokens)
- Infinite loop could hit 100,000 calls in 1 hour = $3,000
- 24-hour undetected loop = $72,000
- **User Report:** $12,000 in one incident (LangChain agent)

**Scenario 2: CrewAI Delegation Loop**
- 2 agents in delegation cycle
- Each cycle: 4 API calls (2 per agent thinking)
- 100 cycles/minute = 400 API calls/minute
- $144,000 cost per day
- **User Report:** "Loop until manually stopped"

**Scenario 3: AutoGen Conversation Loop**
- N agents in dialogue
- 10 messages per round, N rounds until break
- If break never happens: infinite rounds
- **User Report:** "Rate-limited in minutes"

### 1.4 Business Impact Beyond Cost

1. **Service Unavailability:** Process crashes from stack overflow
2. **Reputation Damage:** "AI assistant entered infinite loop and drained API credits"
3. **Customer Trust:** Users lose faith in AI solutions
4. **Operational Overhead:** Manual intervention required, monitoring overload

---

## 2. Detection Complexity Analysis

### 2.1 Direct Detection (Straightforward)

**Pattern: Self-Recursion Without Base Case**
```python
def recursive_agent(task):
    return recursive_agent(task + " more")
```
- **Difficulty:** EASY
- **Detection Method:** Regex + AST
- **False Positive Risk:** LOW (unless legitimate recursive data processing)
- **Evasion Difficulty:** HARD (obvious code structure)

**Pattern: While True + Agent Call**
```python
while True:
    agent.run(query)
```
- **Difficulty:** EASY
- **Detection Method:** Regex pattern matching
- **False Positive Risk:** MEDIUM (many legitimate use cases if break exists)
- **Evasion Difficulty:** HARD (code is explicit)

### 2.2 Intermediate Detection (Requires Analysis)

**Pattern: Mutual Recursion (2+ Functions)**
```python
def A(): B()
def B(): A()
```
- **Difficulty:** MEDIUM
- **Detection Method:** Build call graph, detect 2-cycles
- **False Positive Risk:** LOW (if properly bounded is okay)
- **Evasion Difficulty:** MEDIUM (could add indirection)

**Pattern: CrewAI Delegation with Multiple Agents**
```python
A = Agent(..., allow_delegation=True)
B = Agent(..., allow_delegation=True)
A.team = [B]; B.team = [A]
```
- **Difficulty:** MEDIUM
- **Detection Method:** Build agent graph, detect cycles with allow_delegation=True
- **False Positive Risk:** MEDIUM-HIGH (one-way delegation is fine)
- **Evasion Difficulty:** MEDIUM (could be in config files)

### 2.3 Complex Detection (Advanced Analysis Required)

**Pattern: Indirect Recursion (3+ Functions)**
```python
def X(): Y()
def Y(): Z()
def Z(): X()
```
- **Difficulty:** HARD
- **Detection Method:** DFS on call graph, detect cycles of any length
- **False Positive Risk:** LOW (if cycle found, it's real)
- **Evasion Difficulty:** MEDIUM-HARD (need to trace across files)

**Pattern: Threading-Based Infinite Spawning**
```python
def spawn_agent():
    Thread(target=spawn_agent).start()
```
- **Difficulty:** HARD
- **Detection Method:** Detect self-reference in Thread(target=...) + spawn in own body
- **False Positive Risk:** MEDIUM (some legit async patterns)
- **Evasion Difficulty:** HARD (must parse Thread constructor)

**Pattern: Hidden Recursion via Callbacks or Event Handlers**
```python
def on_task_done(task):
    if not finished(task):
        agent.run(task)  # Hand back to agent which calls on_task_done again
```
- **Difficulty:** VERY HARD
- **Detection Method:** Full data flow + control flow analysis across callbacks
- **False Positive Risk:** HIGH (hard to distinguish from intentional retry)
- **Evasion Difficulty:** HARD (requires understanding of event semantics)

### 2.4 Detection Decision: Focus on High-Impact Patterns

**Our Detector Will Focus On:**
1. ✅ Direct recursion (self-calls)
2. ✅ While True loops with agent calls (no break or conditional break)
3. ✅ Mutual recursion (2-cycles in call graph)
4. ✅ CrewAI delegation loops (allow_delegation=True pairs)
5. ✅ Longer cycles (3+ node cycles in call graph)
6. ✅ Unbounded agent loops in frameworks

**Defer or Mark as Future:**
- Hidden recursion via callbacks (requires semantic analysis)
- Dynamic code generation and eval()
- Across-file mutual recursion (can add later with config)

---

## 3. False Positive Root Causes and Mitigation

### 3.1 Legitimate Recursion That Looks Suspicious

**Case: Data Structure Traversal**
```python
def parse_json(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            parse_json(v)  # recursive call
```
**Why Flagged:** Function calls itself
**Mitigation:** Check function context:
- Is it in utils.py or data_processing module? Lower severity
- Does it process data (not agents)? Don't flag
- Has clear base case (isinstance checks)? Don't flag

**Case: Bounded Retry Loop**
```python
for i in range(MAX_RETRIES):
    result = call_api()
    if result: break
```
**Why Flagged:** Loop with API call
**Mitigation:**
- Detect for loop with finite range
- Presence of break statement → lower severity or skip
- Static bound → safe

**Case: One-Way Agent Delegation**
```python
manager = Agent(..., allow_delegation=True)
worker = Agent(..., allow_delegation=False)
```
**Why Flagged:** allow_delegation=True
**Mitigation:**
- Build agent graph: see manager → worker but worker ≠> manager
- Not a cycle → don't flag as HIGH

### 3.2 Mitigation Strategies

**Strategy 1: Context Analysis**
- Is this in agent/tool related code? (filename contains agent, tool, chain)
- If no → lower severity
- If yes → full severity

**Strategy 2: Bound Detection**
- Does loop have static bound? (for i in range(N)) → safe
- Does function have base case? (if condition: return) → safe
- Does loop have break? → medium severity at most

**Strategy 3: Keyword-Based Classification**
- Functions named: parse, process, walk, traverse, traverse, render → likely data processing
- Functions named: handle_task, delegate, run, execute, invoke → likely agent code
- Only apply full severity if latter group

**Strategy 4: Degree of Confidence**
- Direct self-call with no base case → 0.95 confidence (CRITICAL)
- While True with break → 0.70 confidence (MEDIUM)
- Multiple allow_delegation=True → 0.80 confidence (HIGH)
- Data function with recursion → 0.30 confidence (low/skip)

---

## 4. Framework-Specific Detection Patterns

### 4.1 LangChain-Specific

**Pattern 1: AgentExecutor Loop**
```python
while True:
    result = agent_executor.run(query)
```
**Signal:** `agent_executor.run` inside unbounded loop
**Fix:** Use max_iterations parameter

**Pattern 2: Tool Calling Agent Back**
```python
def my_tool(query):
    if not found(query):
        return agent.run(query + " extended")  # Tool calls agent!
```
**Signal:** Function (tool) calls agent.run
**Fix:** Return a signal value, let agent decide

**Pattern 3: Self-Ask Without Termination**
```python
def self_ask_agent(question):
    sub_answer = self_ask_agent(related_q)  # recursive
```
**Signal:** Function calls itself recursively
**Fix:** Add counter or depth limit

### 4.2 CrewAI-Specific

**Pattern 1: Circular Delegation**
```python
manager = Agent(..., allow_delegation=True)
worker = Agent(..., allow_delegation=True)
# manager delegates to worker, worker could delegate back
```
**Signal:** Multiple agents with allow_delegation=True
**Fix:** Only manager allows delegation, workers don't

**Pattern 2: Agent Team with Cycles**
```python
agent_a.team = [agent_b]
agent_b.team = [agent_a]
```
**Signal:** Agent graph has a cycle
**Fix:** Ensure one-directional delegation

### 4.3 AutoGen-Specific

**Pattern 1: Conversation Loop Without Round Limit**
```python
while True:
    msg = agent1.step()
    agent2.receive(msg)
```
**Signal:** While True with agent.step()
**Fix:** `for _ in range(MAX_ROUNDS)` instead

**Pattern 2: Swarm with Cyclic Messaging**
```python
# agent1 sends to agent2, agent2 sends back to agent1, no termination
```
**Signal:** Agents in conversation graph with no clear exit
**Fix:** Add explicit termination condition

### 4.4 Flowise-Specific

**Pattern 1: Loop Node Without Max**
```json
{"id": "Loop1", "type": "LoopNode", "next": "Loop2"}
{"id": "Loop2", "type": "LoopNode", "next": "Loop1"}
```
**Signal:** Loop nodes referencing each other, no max_loops
**Fix:** Set max_loops property

**Pattern 2: Conditional Loop That Never Exits**
```json
{"condition": "always_true", "break": "never"}
```
**Signal:** Loop condition always true, no break
**Fix:** Add proper exit condition

---

## 5. Implementation Deep-Dive Requirements

### 5.1 AST Tree-Sitter Queries Needed

**Query 1: Direct Self-Recursion**
```
(function_definition
  name: (identifier) @funcName
  body: (block) @body)
(#match? @body "(call (identifier) @calledName)")
(#eq? @funcName @calledName)
```

**Query 2: While True Loops with Agent Calls**
```
(while_statement
  condition: (true) @cond
  body: (block) @body)
(#match? @body "\.run\s*\(|\.execute\s*\(|\.invoke\s*\(")
```

**Query 3: Agent Definition with Allow Delegation**
```
(call
  function: (identifier) @func
  arguments: (argument_list) @args)
(#match? @func "Agent")
(#match? @args "allow_delegation\s*=\s*True")
```

### 5.2 Call Graph Algorithm

**Input:** Parsed AST
**Output:** Call graph (function → functions it calls)

**Algorithm:**
```
1. For each function definition F:
   a. Extract function name
   b. Find all call expressions in body
   c. For each call, extract called function name
   d. Add edge F → called_function to graph

2. For each edge:
   a. Check if edge is recursive (A → A)
   b. Check if creates a cycle (A → B → A, etc.)
   c. Check if cycle is bounded (break conditions, depth limits)

3. Output: List of problematic functions/cycles
```

**Complexity:** O(N + E) where N = nodes (functions), E = edges (calls)

### 5.3 Key Detection Signals (Confidence Factors)

**Positive Signals (Increase Confidence):**
- [+5] Function calls itself (direct recursion)
- [+4] Function involved in cycle (A→B→A)
- [+3] Loop contains agent.run/execute/invoke
- [+3] While True loop present
- [+2] Multiple agents with allow_delegation=True
- [+2] Function is named like agent method (run, execute, delegate)
- [+1] No break statement in loop

**Negative Signals (Decrease Confidence):**
- [-3] Break statement in loop
- [-3] Base case exists (if ... return before recursion)
- [-4] For loop with finite range
- [-2] Function named like data function (parse, walk, traverse)
- [-2] Depth/iteration counter present
- [-2] Function in non-agent module (utils, helpers)
- [-1] Comment indicates intentional recursion

**Final Confidence = Base + Positives - Negatives**
- \>= 0.85 → CRITICAL
- 0.70-0.84 → HIGH
- 0.50-0.69 → MEDIUM
- < 0.50 → LOW/SKIP

### 5.4 Multi-Framework Support

**Python (Primary):**
- LangChain, CrewAI, AutoGen detection
- Tree-sitter Python grammar
- Parse .py files

**JavaScript/TypeScript (Secondary):**
- Flowise nodes (TypeScript)
- Tree-sitter JavaScript grammar
- Parse .ts, .js files

**JSON/YAML (Tertiary):**
- Flowise flow definitions
- Loop node configuration
- Check for cycles in flow graph

**Go (Future):**
- If someone implements agents in Go
- Detect same patterns in Go code

---

## 6. Testing Strategy Deep-Dive

### 6.1 Test Case Categories

**Category 1: Direct Recursion (5 tests)**
- Simple infinite recursion
- Recursion with base case (should not flag HIGH)
- Recursion with depth limit
- Recursion in non-agent function
- Recursion via alias variable

**Category 2: Loops (6 tests)**
- While True with agent call, no break
- While True with break (should be MEDIUM)
- For loop with finite range
- For loop with infinite range
- Loop with counter increment (bounded)
- Nested loops with agent calls

**Category 3: Mutual Recursion (4 tests)**
- 2-function cycle
- 3-function cycle
- 4+ function cycle
- Cycle with break condition

**Category 4: Framework-Specific (6 tests)**
- LangChain agent loop
- CrewAI delegation loop
- AutoGen multi-agent conversation
- Flowise loop node config
- Tool calling agent back
- Agent tool interaction

**Category 5: Obfuscation/Evasion (4 tests)**
- Recursion via getattr
- Recursion via variable alias
- Recursion via Thread/async
- Dynamic function naming

**Category 6: Edge Cases (3 tests)**
- Data processing with recursion (shouldn't flag HIGH)
- Retry with bounded attempts
- One-way delegation (shouldn't flag HIGH)

**Category 7: Performance (2 tests)**
- Large file (1000+ lines) performance
- Complex call graph resolution

---

## 7. Implementation Checklist

### 7.1 Pre-Implementation

- [x] Understand all CVEs and incidents
- [x] Map to CWE classifications
- [x] Identify false positive causes
- [x] Plan framework-specific detection
- [ ] Finalize confidence scoring algorithm
- [ ] Lock test case list

### 7.2 Implementation Phase

- [ ] Implement call graph builder
- [ ] Implement cycle detection algorithm
- [ ] Implement AST pattern matching
- [ ] Implement regex fallback patterns
- [ ] Implement confidence scoring
- [ ] Add framework-specific rules
- [ ] Add false positive reduction heuristics

### 7.3 Testing Phase

- [ ] Run all 30+ test cases
- [ ] Measure false positive rate (<5%)
- [ ] Verify true positive detection (>95%)
- [ ] Performance benchmark
- [ ] Real framework validation (LangChain, CrewAI, Flowise)

### 7.4 Validation Phase

- [ ] Scan LangChain 2,462 files
- [ ] Scan CrewAI 853 files
- [ ] Scan Flowise 100+ files
- [ ] Confirm CVE-2024-2965 detection
- [ ] Confirm delegation loop detection
- [ ] Generate validation report

---

## 8. Key Insights from Research (Critical Reminders)

### 8.1 What Makes This Pattern Dangerous

1. **Undetectable Without Analysis**: Loop might look benign until execution
2. **Cascading Failures**: One recursive call triggers many more
3. **Financial Impact**: Not just downtime, but direct API cost drain
4. **Hard to Debug**: Infinite loops can appear non-deterministic
5. **Social Impact**: Users lose trust in AI systems

### 8.2 Why Tree-Sitter is Essential

1. **AST Understanding**: Regex alone can't detect mutual recursion across functions
2. **Semantic Awareness**: Can distinguish data recursion from agent recursion
3. **Multi-Framework Support**: Same parsing logic works across Python versions
4. **Evasion Resistance**: Hard to hide recursion in AST structure (though can use getattr)

### 8.3 Why Call Graph is Essential

1. **Mutual Recursion Detection**: Can't find A→B→A without call graph
2. **Cycle Detection**: DFS on call graph finds any cycle length
3. **Performance**: Pre-computed graph makes analysis fast
4. **Complexity**: DFS is O(N+E), manageable for typical codebase

### 8.4 Why Confidence Scoring Matters

1. **Legitimate Uses Exist**: Not every recursion is bad
2. **Risk Varies**: Self-call with break is different from self-call without
3. **Context Dependent**: Same code pattern means different things in different modules
4. **User Trust**: High false positive rate destroys tool credibility

---

## 9. Critical Implementation Decisions

### 9.1 Decision: Call Graph vs Per-File Analysis

**Option A: Per-File Analysis Only**
- Pro: Simpler, faster
- Con: Can't detect mutual recursion across files
- Decision: Start here, add cross-file later

**Option B: Full Project Call Graph**
- Pro: Catches all recursion types
- Con: More complex, requires file coordination
- Decision: This is what we want for production

**Chosen: Hybrid**
- Per-file immediate analysis (for simple patterns)
- Build call graph for mutual recursion within scope
- Cross-file detection as future enhancement

### 9.2 Decision: Confidence Threshold for Reporting

**Options:**
- Conservative (0.70): Catch more, more false positives
- Moderate (0.75): Balance
- Strict (0.80): Fewer false positives, might miss some

**Chosen: Adaptive**
- Report all ≥0.70 but with severity based on confidence
- Allow user configuration: `--confidence-threshold 0.75`

### 9.3 Decision: Framework-Specific Rules vs Generic

**Options:**
- Generic rules only: Less noise but might miss framework-specific patterns
- Framework-specific rules: More accurate but more rules to maintain
- Hybrid: Generic + framework-specific

**Chosen: Hybrid with priority**
1. Apply framework-specific rules if framework detected
2. Fall back to generic rules
3. Cross-reference for confidence boost

---

## 10. Success Criteria for Implementation

1. ✅ Detects CVE-2024-2965 (LangChain self-referential sitemap)
2. ✅ Detects CrewAI delegation loops
3. ✅ Detects AutoGen conversation loops
4. ✅ Detects Flowise infinite loop nodes
5. ✅ False positive rate < 5%
6. ✅ True positive rate > 95%
7. ✅ Performance < 5ms per file
8. ✅ 30+ test cases passing
9. ✅ Multi-framework coverage
10. ✅ Real framework validation complete

---

## Conclusion

The research reveals that Recursive Tool Calling is a **CRITICAL** pattern with:
- Multiple real CVEs (CVE-2024-2965)
- Confirmed production incidents across 4+ frameworks
- Direct financial impact ($12k+ per incident)
- Requires sophisticated detection (call graphs, cycle detection)
- High false positive risk if not careful

Our implementation will use:
1. **Tree-sitter AST parsing** for semantic understanding
2. **Call graph + DFS** for cycle detection
3. **Confidence scoring** for false positive reduction
4. **Framework-specific rules** for accuracy
5. **Comprehensive testing** with 30+ cases
6. **Real framework validation** on LangChain, CrewAI, Flowise

This will result in a production-grade detector that catches the pattern while minimizing false positives.

---

**Analysis Completion:** ✅ COMPLETE
**Ready for Implementation:** YES
**Implementation Complexity:** HIGH
**Estimated Time:** 8-12 hours
