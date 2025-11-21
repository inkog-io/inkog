package detectors

import (
	"fmt"

	"github.com/inkog-io/inkog/action/pkg/ast_engine/analysis"
	"github.com/inkog-io/inkog/action/pkg/ast_engine/parser"
	"github.com/inkog-io/inkog/action/pkg/patterns"
	"github.com/inkog-io/inkog/action/pkg/patterns/metadata"
)

// ContextExhaustionDetectorV3 detects unbounded context/token growth in loops
type ContextExhaustionDetectorV3 struct {
	pattern    patterns.Pattern
	confidence float32
}

// NewContextExhaustionDetectorV3 creates a context exhaustion detector
func NewContextExhaustionDetectorV3() *ContextExhaustionDetectorV3 {
	pattern := patterns.Pattern{
		ID: metadata.ID_CONTEXT_EXHAUSTION,
		Name:     "Context Exhaustion (Semantic Analysis)",
		Version:  "3.0",
		Category: "resource_exhaustion",
		Severity: "HIGH",
		CVSS: 7.5,
		CWEIDs:   []string{"CWE-770"},
		OWASP:    "LLM10",
		Description: "Unbounded growth of message history, conversation context, or data structures in loops can exhaust LLM token limits",
		Remediation: "Use bounded collections (deque with maxlen), implement truncation logic, or periodically reset conversation history",
		FinancialImpact: struct {
			Severity    string
			Description string
			RiskPerYear float32
		}{
			Severity:    "HIGH",
			Description: "Slow API degradation, hitting rate limits, increased token usage by 100-1000x",
			RiskPerYear: 100000,
		},
	}

	return &ContextExhaustionDetectorV3{
		pattern:    pattern,
		confidence: 0.85,
	}
}

// GetPatternID returns the canonical detector ID (implements Detector interface)
func (d *ContextExhaustionDetectorV3) GetPatternID() string {
	return metadata.ID_CONTEXT_EXHAUSTION
}

// GetPattern returns the pattern definition (implements Detector interface)
func (d *ContextExhaustionDetectorV3) GetPattern() patterns.Pattern {
	return d.pattern
}

// Detect performs the vulnerability detection and returns findings (implements Detector interface)
func (d *ContextExhaustionDetectorV3) Detect(filePath string, source []byte) ([]patterns.Finding, error) {
	return d.DetectSemantic(filePath, source)
}

// DetectSemantic analyzes code for context exhaustion patterns
func (d *ContextExhaustionDetectorV3) DetectSemantic(filePath string, src []byte) ([]patterns.Finding, error) {
	var findings []patterns.Finding

	// Only process Python files (can extend to JS/TS)
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

	// Check each loop for context exhaustion pattern
	loops := cfg.ExtractLoops()
	sourceLines := getSourceLines(src)

	for _, loopInfo := range loops {
		if cfg.HasContextExhaustionPattern(loopInfo) {
			finding := d.createContextBombFinding(filePath, loopInfo, sourceLines)
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// createContextBombFinding creates a pattern.Finding for context exhaustion
func (d *ContextExhaustionDetectorV3) createContextBombFinding(
	filePath string,
	loopInfo *analysis.LoopInfo,
	sourceLines []string,
) patterns.Finding {
	// Get loop code snippet
	codeSnippet := ""
	if loopInfo.Line-1 >= 0 && loopInfo.Line-1 < len(sourceLines) {
		codeSnippet = sourceLines[loopInfo.Line-1]
	}

	// Build message with growing variables
	varList := ""
	for i, v := range loopInfo.DataGrowthVars {
		varList += v
		if i < len(loopInfo.DataGrowthVars)-1 {
			varList += ", "
		}
	}

	message := fmt.Sprintf(
		"Context Exhaustion: Unbounded growth of %s in loop (line %d)",
		varList,
		loopInfo.Line,
	)

	// Financial risk based on severity
	financialRisk := "MEDIUM"
	if len(loopInfo.DataGrowthVars) > 2 && loopInfo.HasLLMCallInBody {
		financialRisk = "HIGH"
	}

	return patterns.Finding{
		ID:         fmt.Sprintf("context_bomb_%d", loopInfo.Line),
		PatternID:  d.pattern.ID,
		Pattern:    d.pattern.Name,
		File:       filePath,
		Line:       loopInfo.Line,
		Column:     0,
		Message:    message,
		Code:       codeSnippet,
		Severity:   d.pattern.Severity,
		Confidence: d.confidence,
		CWE:        "CWE-770",
		CVSS:       d.pattern.CVSS,
		OWASP:      d.pattern.OWASP,
		FinancialRisk: financialRisk,
	}
}
