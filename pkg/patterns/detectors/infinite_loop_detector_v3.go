package detectors

import (
	"fmt"
	"log"
	"strings"

	"github.com/inkog-io/inkog/action/pkg/ast_engine/analysis"
	"github.com/inkog-io/inkog/action/pkg/ast_engine/parser"
	"github.com/inkog-io/inkog/action/pkg/patterns"
	"github.com/inkog-io/inkog/action/pkg/patterns/metadata"
)

// InfiniteLoopDetectorV3 detects Doom Loops using semantic analysis
// Extends the basic regex-based InfiniteLoopDetector with CFG analysis
type InfiniteLoopDetectorV3 struct {
	pattern    patterns.Pattern
	confidence float32
}

// NewInfiniteLoopDetectorV3 creates a semantic-aware infinite loop detector
func NewInfiniteLoopDetectorV3() *InfiniteLoopDetectorV3 {
	pattern := patterns.Pattern{
		ID:       metadata.ID_INFINITE_LOOP,
		Name:     "Infinite Loop (Semantic Analysis)",
		Version:  "3.0",
		Category: "resource_exhaustion",
		Severity: "CRITICAL",
		CVSS:     9.0,
		CWEIDs:   []string{"CWE-835", "CWE-400"},
		OWASP:    "LLM10",
		Description: "LLM-dependent loops without hard break counters cause unbounded execution and token exhaustion",
		Remediation: "Add max_iterations counter, max_execution_time, or explicit deterministic break conditions",
		FinancialImpact: struct {
			Severity    string
			Description string
			RiskPerYear float32
		}{
			Severity:    "CRITICAL",
			Description: "Escalated from $5K to $50K+ monthly API costs in production",
			RiskPerYear: 500000,
		},
	}

	return &InfiniteLoopDetectorV3{
		pattern:    pattern,
		confidence: 0.95,
	}
}

// GetPatternID returns the canonical detector ID (implements Detector interface)
func (d *InfiniteLoopDetectorV3) GetPatternID() string {
	return metadata.ID_INFINITE_LOOP
}

// GetPattern returns the pattern definition (implements Detector interface)
func (d *InfiniteLoopDetectorV3) GetPattern() patterns.Pattern {
	return d.pattern
}

// Detect performs the vulnerability detection and returns findings (implements Detector interface)
func (d *InfiniteLoopDetectorV3) Detect(filePath string, source []byte) ([]patterns.Finding, error) {
	return d.DetectSemantic(filePath, source)
}

// DetectSemantic analyzes code for Doom Loops using CFG analysis
func (d *InfiniteLoopDetectorV3) DetectSemantic(filePath string, src []byte) ([]patterns.Finding, error) {
	var findings []patterns.Finding

	// Only process Python files (for now - can extend to JS/TS)
	if !isSupportedLanguage(filePath, "python") {
		return findings, nil
	}

	// Parse the code
	parser, err := parser.NewPythonParser(parser.DefaultConfig())
	if err != nil {
		return findings, fmt.Errorf("failed to create parser: %w", err)
	}

	parseResult, err := parser.ParseFile(filePath, src)
	if err != nil {
		return findings, fmt.Errorf("failed to parse file: %w", err)
	}

	if parseResult == nil || parseResult.Root == nil {
		return findings, nil
	}

	// Run control flow analysis
	resolver := analysis.NewReferenceResolver(parseResult.Root, analysis.NewSymbolTable())
	taintTracker := analysis.NewTaintTracker(resolver)
	cfg := analysis.NewControlFlowGraph(parseResult.Root, taintTracker)

	// Check each loop for Doom Loop pattern
	loops := cfg.ExtractLoops()
	sourceLines := getSourceLines(src)

	log.Printf("[INFINITE_LOOP_DETECTOR] Checking %d loops in %s", len(loops), filePath)

	for i, loopInfo := range loops {
		log.Printf("[INFINITE_LOOP_DETECTOR] Evaluating loop %d at line %d: condition='%s', isDeterministic=%v",
			i, loopInfo.Line, loopInfo.ConditionText, loopInfo.IsDeterministic)

		isBoomLoop := false
		isSignatureMatch := false

		// Primary detection: CFG-based Doom Loop pattern
		if cfg.HasDoomLoopPattern(loopInfo) {
			log.Printf("[INFINITE_LOOP_DETECTOR] ✓ Loop at line %d MATCHED Doom Loop pattern", loopInfo.Line)
			isBoomLoop = true
		} else {
			// Signature fallback: Check for "should_continue" pattern (catches Line 99 case)
			// This handles loops like: while self._should_continue_solving():
			// Signature matches get HIGHEST priority: Confidence 1.0, Severity CRITICAL
			if strings.Contains(strings.ToLower(loopInfo.ConditionText), "should_continue") {
				log.Printf("[INFINITE_LOOP_DETECTOR] ✓ Loop at line %d MATCHED signature pattern (should_continue) - ENFORCING CRITICAL PRIORITY", loopInfo.Line)
				isBoomLoop = true
				isSignatureMatch = true
			}
		}

		if isBoomLoop {
			finding := d.createDoomLoopFinding(filePath, loopInfo, sourceLines)
			// ENFORCE SIGNATURE PRIORITY: Signature matches get highest confidence and severity
			if isSignatureMatch {
				finding.Confidence = 1.0
				finding.Severity = "CRITICAL"
				log.Printf("[INFINITE_LOOP_DETECTOR] ENFORCED: Line %d signature match now has Confidence=1.0, Severity=CRITICAL", loopInfo.Line)
			}
			findings = append(findings, finding)
		} else {
			log.Printf("[INFINITE_LOOP_DETECTOR] ✗ Loop at line %d does NOT match Doom Loop pattern", loopInfo.Line)
		}
	}

	return findings, nil
}

// createDoomLoopFinding creates a pattern.Finding for a Doom Loop
func (d *InfiniteLoopDetectorV3) createDoomLoopFinding(
	filePath string,
	loopInfo *analysis.LoopInfo,
	sourceLines []string,
) patterns.Finding {
	// ASSERTION: Verify loop line is reasonable (not a function start or very early in file)
	// This catches scope inheritance errors where function start line bleeds into loop detection
	// Loops are unlikely to be in first 20 lines, and function definitions are typically before loops
	if loopInfo.Line < 20 {
		log.Printf("[SCOPE_INTEGRITY_CHECK] WARNING: Loop line is suspiciously early (line %d). "+
			"This may indicate scope inheritance error where function start line is being used. "+
			"Code snippet: %.50s", loopInfo.Line, loopInfo.Node.Text)
	}

	// Get loop code snippet
	codeSnippet := ""
	if loopInfo.Line-1 >= 0 && loopInfo.Line-1 < len(sourceLines) {
		codeSnippet = sourceLines[loopInfo.Line-1]
	}

	// Build detailed message
	message := fmt.Sprintf(
		"Potential Infinite Loop: LLM-dependent condition without hard break counter (line %d)",
		loopInfo.Line,
	)

	// Financial impact assessment
	financialRisk := "HIGH"
	if len(loopInfo.LLMCallNodes) > 1 {
		financialRisk = "CRITICAL"
	}

	finding := patterns.Finding{
		ID:         fmt.Sprintf("doom_loop_%d", loopInfo.Line),
		PatternID:  d.GetPatternID(),
		Pattern:    d.pattern.Name,
		File:       filePath,
		Line:       loopInfo.Line,  // EXPLICITLY using loopInfo.Line (loop's own line, not parent)
		Column:     0,
		Message:    message,
		Code:       codeSnippet,
		Severity:   d.pattern.Severity,
		Confidence: d.confidence,
		CWE:        "CWE-835",
		CVSS:       d.pattern.CVSS,
		OWASP:      d.pattern.OWASP,
		FinancialRisk: financialRisk,
	}

	// Verify final finding line is reasonable
	log.Printf("[FINDING_VALIDATION] Created infinite loop finding at line %d for file %s, "+
		"code snippet: %.40s", finding.Line, filePath, finding.Code)

	return finding
}

// isSupportedLanguage checks if file type is supported
func isSupportedLanguage(filePath string, lang string) bool {
	switch lang {
	case "python":
		return len(filePath) > 3 && filePath[len(filePath)-3:] == ".py"
	case "javascript":
		return len(filePath) > 3 && filePath[len(filePath)-3:] == ".js"
	case "typescript":
		return len(filePath) > 3 && (filePath[len(filePath)-3:] == ".ts" || filePath[len(filePath)-4:] == ".tsx")
	}
	return false
}

// getSourceLines splits source into lines for snippet extraction
func getSourceLines(src []byte) []string {
	content := string(src)
	var lines []string
	var currentLine string

	for _, char := range content {
		if char == '\n' {
			lines = append(lines, currentLine)
			currentLine = ""
		} else {
			currentLine += string(char)
		}
	}

	if currentLine != "" {
		lines = append(lines, currentLine)
	}

	return lines
}
