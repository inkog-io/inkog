package detectors

import (
	"regexp"
	"strings"
	"time"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// ContextAwareEngine orchestrates Guard Framework + Confidence Framework
// This is the unified entry point for all pattern detection with:
// - False positive filtering (Guard Framework)
// - Confidence calibration (Confidence Framework)
// - Semantic context awareness
// - Learning and recalibration capability
type ContextAwareEngine struct {
	guard       *GuardFramework
	confidence  *ConfidenceFramework
	analyzer    *SemanticAnalyzer
	feedback    *FeedbackCollector
	learningEnabled bool
}

// NewContextAwareEngine creates a new context-aware detection engine
func NewContextAwareEngine() *ContextAwareEngine {
	return &ContextAwareEngine{
		guard:           NewGuardFramework(),
		confidence:      NewConfidenceFramework(),
		analyzer:        NewSemanticAnalyzer(),
		feedback:        NewFeedbackCollector(),
		learningEnabled: true,
	}
}

// PatternResult represents the output of context-aware analysis
type PatternResult struct {
	Finding             patterns.Finding
	Filtered            bool                    // Was it filtered by guard?
	FilterReason        string                  // Why filtered (if applicable)
	OriginalConfidence  float32
	AdjustedConfidence  float32
	ConfidenceFactors   map[string]float32      // Individual factor scores
	SemanticContext     *CodeAnalysisContext
	Recommendations     []string
}

// AnalyzeFindings runs the complete context-aware analysis pipeline
// Input: Raw findings from a pattern detector
// Output: Filtered findings with adjusted confidence and context
func (e *ContextAwareEngine) AnalyzeFindings(
	findings []patterns.Finding,
	lines []string,
	filePath string,
) []PatternResult {
	var results []PatternResult

	// Build semantic context for the entire file once
	_ = e.analyzer.AnalyzeFile(filePath, lines)

	for _, finding := range findings {
		result := PatternResult{
			Finding:            finding,
			ConfidenceFactors:   make(map[string]float32),
			Recommendations:     []string{},
		}

		// Step 1: Apply Guard Framework filtering
		if e.guard.GetContextFilter().ShouldFilterFinding(finding, e.getLineContent(finding.Line-1, lines)) {
			result.Filtered = true
			result.FilterReason = e.determineFilterReason(finding, lines)
			results = append(results, result)
			continue
		}

		// For LLM-related patterns, verify real API call
		if e.isLLMRelated(finding.Message) {
			isReal, provider := e.guard.GetLLMDetector().IsRealLLMCall(e.getLineContent(finding.Line-1, lines))
			if !isReal && e.guard.GetLLMDetector().ContainsLLMKeywordOnly(e.getLineContent(finding.Line-1, lines)) {
				result.Filtered = true
				result.FilterReason = "Keyword-only (not real LLM call)"
				results = append(results, result)
				continue
			}
			if isReal && provider != "" {
				finding.Message = "LLM API call (" + provider + ") " + strings.TrimPrefix(finding.Message, "LLM API call ")
			}
		}

		// Step 2: Build semantic context for this specific finding
		lineContext := e.analyzer.AnalyzeLine(e.getLineContent(finding.Line-1, lines), finding.Line-1)
		result.SemanticContext = lineContext

		// Step 3: Calculate adjusted confidence
		originalConf := finding.CVSS / 10.0 // Use CVSS as base
		if originalConf <= 0 || originalConf > 1.0 {
			originalConf = 0.5
		}
		result.OriginalConfidence = originalConf

		adjustedConf := e.confidence.CalculateConfidence(originalConf, lineContext, &finding)
		result.AdjustedConfidence = adjustedConf

		// Store factor scores for analysis
		for _, factor := range e.confidence.GetConfidenceFactors() {
			score := factor.Calculate(lineContext, &finding)
			result.ConfidenceFactors[factor.Name] = score
		}

		// Step 4: Generate recommendations based on semantic analysis
		result.Recommendations = e.generateRecommendations(finding, lineContext)

		// Step 5: Record feedback if learning enabled
		if e.learningEnabled {
			e.feedback.RecordPrediction(
				finding.PatternID,
				&finding,
				adjustedConf,
				false, // Not filtered by guard
				result.ConfidenceFactors,
			)
		}

		results = append(results, result)
	}

	return results
}

// EnableLearning toggles the learning mode
func (e *ContextAwareEngine) EnableLearning(enabled bool) {
	e.learningEnabled = enabled
}

// RecordActualResult records whether a finding was truly positive or false positive
func (e *ContextAwareEngine) RecordActualResult(
	patternID string,
	isTruePositive bool,
	severity string,
) {
	e.feedback.RecordActual(patternID, isTruePositive, severity, time.Now())
}

// RecalibrateFromFeedback adjusts confidence factors based on actual results
func (e *ContextAwareEngine) RecalibrateFromFeedback() {
	guidance := e.feedback.GenerateRecalibrationGuidance()

	// Apply guidance to confidence framework
	for _, adjustments := range guidance.WeightAdjustments {
		for factorName, adjustment := range adjustments {
			// Update confidence framework weights based on feedback
			factors := e.confidence.GetConfidenceFactors()
			for i, factor := range factors {
				if factor.Name == factorName {
					factors[i].Weight *= adjustment
					// Clamp to reasonable bounds
					if factors[i].Weight > 0.35 {
						factors[i].Weight = 0.35
					}
					if factors[i].Weight < -0.35 && factors[i].Weight < 0 {
						factors[i].Weight = -0.35
					}
				}
			}
		}
	}
}

// GetCalibrationMetrics returns current accuracy metrics
func (e *ContextAwareEngine) GetCalibrationMetrics() *CalibrationMetrics {
	return e.feedback.GetMetrics()
}

// GetGuardFramework returns the guard framework for direct access if needed
func (e *ContextAwareEngine) GetGuardFramework() *GuardFramework {
	return e.guard
}

// GetConfidenceFramework returns the confidence framework for direct access if needed
func (e *ContextAwareEngine) GetConfidenceFramework() *ConfidenceFramework {
	return e.confidence
}

// SemanticAnalyzer extracts semantic information from code
type SemanticAnalyzer struct {
	variablePatterns []*regexp.Regexp
	dataFlowPatterns []*regexp.Regexp
}

// NewSemanticAnalyzer creates a new semantic analyzer
func NewSemanticAnalyzer() *SemanticAnalyzer {
	return &SemanticAnalyzer{
		variablePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?:^|\\s)(\\w+)\\s*[:=]`),
		},
		dataFlowPatterns: []*regexp.Regexp{
			regexp.MustCompile(`validate|sanitize|escape|clean|filter`),
			regexp.MustCompile(`request|input|param|user|args`),
		},
	}
}

// AnalyzeFile analyzes an entire file for semantic context
func (sa *SemanticAnalyzer) AnalyzeFile(filePath string, lines []string) *CodeAnalysisContext {
	ctx := NewBasicCodeAnalysisContext(filePath, lines, 0)

	for i, line := range lines {
		ctx.AnalyzeVariablesInLine(line)
		ctx.LineNum = i
		ctx.DetectControlFlow()
	}

	return ctx
}

// AnalyzeLine analyzes a single line for semantic context
func (sa *SemanticAnalyzer) AnalyzeLine(code string, lineNum int) *CodeAnalysisContext {
	ctx := NewBasicCodeAnalysisContext("", []string{code}, lineNum)
	ctx.AnalyzeVariablesInLine(code)
	ctx.DetectControlFlow()
	return ctx
}

// FeedbackCollector implements learning from detection results
type FeedbackCollector struct {
	predictions []PredictionRecord
	actuals     map[string]ActualRecord
	calibration *CalibrationMetrics
}

// PredictionRecord logs what we predicted
type PredictionRecord struct {
	PatternID     string
	FindingID     string // Can be derived from finding hash
	PredictedConf float32
	Filtered      bool
	FactorScores  map[string]float32
	Timestamp     time.Time
}

// ActualRecord logs what actually happened
type ActualRecord struct {
	PatternID      string
	FindingID      string
	IsTruePositive bool
	Severity       string
	DateVerified   time.Time
}

// CalibrationMetrics tracks detection accuracy
type CalibrationMetrics struct {
	TotalPredictions int
	Accuracy         float32
	Precision        float32
	Recall           float32
	F1Score          float32
	TruePositives    int
	FalsePositives   int
	TrueNegatives    int
	FalseNegatives   int
}

// RecalibrationGuidance provides recommendations for weight adjustments
type RecalibrationGuidance struct {
	WeightAdjustments map[string]map[string]float32 // patternID -> factorName -> multiplier
	OverallAccuracy   float32
	FactorContribution map[string]float32
}

// NewFeedbackCollector creates a new feedback collector
func NewFeedbackCollector() *FeedbackCollector {
	return &FeedbackCollector{
		predictions: []PredictionRecord{},
		actuals:     make(map[string]ActualRecord),
		calibration: &CalibrationMetrics{},
	}
}

// RecordPrediction logs a prediction
func (fc *FeedbackCollector) RecordPrediction(
	patternID string,
	finding *patterns.Finding,
	confidence float32,
	filtered bool,
	factorScores map[string]float32,
) {
	record := PredictionRecord{
		PatternID:     patternID,
		FindingID:     hashFinding(finding),
		PredictedConf: confidence,
		Filtered:      filtered,
		FactorScores:  factorScores,
		Timestamp:     time.Now(),
	}
	fc.predictions = append(fc.predictions, record)
}

// RecordActual logs the actual result
func (fc *FeedbackCollector) RecordActual(
	patternID string,
	isTruePositive bool,
	severity string,
	timestamp time.Time,
) {
	// This would be called after manual verification
	// For now, we just track the last result per pattern
	record := ActualRecord{
		PatternID:      patternID,
		IsTruePositive: isTruePositive,
		Severity:       severity,
		DateVerified:   timestamp,
	}
	// Use pattern as key for demo purposes
	fc.actuals[patternID] = record
}

// GetMetrics returns current calibration metrics
func (fc *FeedbackCollector) GetMetrics() *CalibrationMetrics {
	return fc.calibration
}

// GenerateRecalibrationGuidance analyzes feedback and recommends weight adjustments
func (fc *FeedbackCollector) GenerateRecalibrationGuidance() *RecalibrationGuidance {
	guidance := &RecalibrationGuidance{
		WeightAdjustments: make(map[string]map[string]float32),
		FactorContribution: make(map[string]float32),
	}

	// Simple heuristic: if we had false positives, reduce factor weights by 10%
	// if we had false negatives, increase factor weights by 10%
	if fc.calibration.FalsePositives > 0 {
		for patternID := range fc.actuals {
			if guidance.WeightAdjustments[patternID] == nil {
				guidance.WeightAdjustments[patternID] = make(map[string]float32)
			}
			// Reduce weights when we have false positives
			guidance.WeightAdjustments[patternID]["data_flow_risk"] = 0.9
			guidance.WeightAdjustments[patternID]["execution_context"] = 0.9
		}
	}

	if fc.calibration.FalseNegatives > 0 {
		for patternID := range fc.actuals {
			if guidance.WeightAdjustments[patternID] == nil {
				guidance.WeightAdjustments[patternID] = make(map[string]float32)
			}
			// Increase weights when we have false negatives
			guidance.WeightAdjustments[patternID]["data_flow_risk"] = 1.1
			guidance.WeightAdjustments[patternID]["severity_multiplier"] = 1.1
		}
	}

	guidance.OverallAccuracy = fc.calibration.Accuracy
	return guidance
}

// Helper functions

func (e *ContextAwareEngine) getLineContent(lineIndex int, lines []string) string {
	if lineIndex >= 0 && lineIndex < len(lines) {
		return lines[lineIndex]
	}
	return ""
}

func (e *ContextAwareEngine) determineFilterReason(finding patterns.Finding, lines []string) string {
	line := e.getLineContent(finding.Line-1, lines)
	filter := e.guard.GetContextFilter()

	if filter.IsInComment(line) {
		return "Found in comment"
	}
	if filter.IsInString(line) {
		return "Found in string literal"
	}
	if filter.IsConfigContext(line) {
		return "Found in configuration"
	}
	if filter.IsTestCode(line) {
		return "Found in test code"
	}
	return "Filtered by guard framework"
}

func (e *ContextAwareEngine) isLLMRelated(message string) bool {
	llmKeywords := []string{"LLM", "API call", "OpenAI", "Anthropic", "ChatCompletion", "invoke", "messages.create"}
	messageLower := strings.ToLower(message)

	for _, keyword := range llmKeywords {
		if strings.Contains(messageLower, strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}

func (e *ContextAwareEngine) generateRecommendations(finding patterns.Finding, ctx *CodeAnalysisContext) []string {
	recommendations := []string{}

	if ctx == nil {
		return recommendations
	}

	// Check for untrackedData
	if ctx.DataFlow != nil && len(ctx.DataFlow.UntrackedData) > 0 {
		recommendations = append(recommendations, "Validate or sanitize user input before use")
	}

	// Check for unbounded loops
	if ctx.ControlFlow != nil && ctx.ControlFlow.IsUnboundedLoop {
		recommendations = append(recommendations, "Add break/exit condition to prevent infinite loops")
	}

	// Check for recursive calls
	if ctx.ControlFlow != nil && ctx.ControlFlow.IsRecursive {
		recommendations = append(recommendations, "Consider adding recursion depth limit or base case validation")
	}

	// LLM-specific
	if e.isLLMRelated(finding.Message) {
		recommendations = append(recommendations, "Consider implementing token limits or cost controls for LLM calls")
		recommendations = append(recommendations, "Add rate limiting to prevent resource exhaustion")
	}

	return recommendations
}

func hashFinding(finding *patterns.Finding) string {
	// Simple hash for finding identification
	return finding.PatternID + "_" + strings.ReplaceAll(finding.Code, " ", "_")
}
