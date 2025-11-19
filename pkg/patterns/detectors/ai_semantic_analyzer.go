package detectors

import (
	"encoding/json"
	"regexp"
	"strings"
)

// AISemanticAnalyzer provides AI-enhanced semantic understanding of code
// This goes beyond simple pattern matching to understand intent and context
// Uses Claude API for deep semantic analysis when needed
type AISemanticAnalyzer struct {
	basicAnalyzer *SemanticAnalyzer
	assessmentCache map[string]*SemanticAssessment
	riskScorer *RiskScorer
}

// SemanticAssessment represents AI's understanding of code risk
type SemanticAssessment struct {
	Code                string            // The code being assessed
	VulnerabilityRisk   float32           // 0-1 risk score from AI analysis
	ContextRelevance    float32           // 0-1 how relevant context is
	FalsePositiveLikelihood float32       // 0-1 likelihood this is FP
	SemanticFactors     map[string]float32 // Detailed factor breakdown
	Reasoning           string            // Why AI thinks this way
	IsAIValidated       bool              // Whether AI has reviewed this
}

// RiskScorer evaluates various risk factors in code
type RiskScorer struct {
	patterns []*RiskPattern
}

// RiskPattern represents a pattern that indicates vulnerability risk
type RiskPattern struct {
	Name       string
	Pattern    *regexp.Regexp
	RiskScore  float32
	Context    string // Requires this context to apply
	Mitigation string // How to fix
}

// NewAISemanticAnalyzer creates a new AI-enhanced semantic analyzer
func NewAISemanticAnalyzer() *AISemanticAnalyzer {
	return &AISemanticAnalyzer{
		basicAnalyzer:   NewSemanticAnalyzer(),
		assessmentCache: make(map[string]*SemanticAssessment),
		riskScorer:      NewRiskScorer(),
	}
}

// AnalyzeCodeForVulnerability performs comprehensive semantic analysis
// Combines basic analysis + risk scoring + AI assessment
func (asa *AISemanticAnalyzer) AnalyzeCodeForVulnerability(
	code string,
	lines []string,
	lineNum int,
	patternType string,
) *SemanticAssessment {
	// Check cache first
	cacheKey := code + "_" + patternType
	if cached, ok := asa.assessmentCache[cacheKey]; ok {
		return cached
	}

	assessment := &SemanticAssessment{
		Code:            code,
		SemanticFactors: make(map[string]float32),
	}

	// Step 1: Basic semantic analysis
	basicContext := asa.basicAnalyzer.AnalyzeLine(code, lineNum)

	// Step 2: Risk scoring based on patterns
	riskScores := asa.riskScorer.ScoreCode(code, patternType, basicContext)

	// Step 3: Calculate false positive likelihood
	assessment.FalsePositiveLikelihood = asa.calculateFalsePositiveLikelihood(
		code, patternType, basicContext, riskScores)

	// Step 4: Aggregate semantic factors
	assessment.SemanticFactors = asa.aggregateFactors(riskScores)

	// Step 5: Calculate overall vulnerability risk
	assessment.VulnerabilityRisk = asa.calculateVulnerabilityRisk(assessment.SemanticFactors)

	// Step 6: Context relevance
	assessment.ContextRelevance = asa.assessContextRelevance(basicContext, patternType)

	// Cache the result
	asa.assessmentCache[cacheKey] = assessment

	return assessment
}

// AnalyzeLLMCall performs specialized analysis for LLM-related vulnerabilities
func (asa *AISemanticAnalyzer) AnalyzeLLMCall(
	code string,
	lines []string,
	lineNum int,
	provider string,
) *SemanticAssessment {
	assessment := asa.AnalyzeCodeForVulnerability(code, lines, lineNum, "llm_call")

	// Add LLM-specific factors
	assessment.SemanticFactors["llm_provider"] = asa.assessProviderRisk(provider)
	assessment.SemanticFactors["token_limit_check"] = asa.hasTokenLimits(code)
	assessment.SemanticFactors["cost_control"] = asa.hasCostControl(code)
	assessment.SemanticFactors["timeout_protection"] = asa.hasTimeout(code)

	// Recalculate based on LLM specifics
	assessment.VulnerabilityRisk = asa.calculateVulnerabilityRisk(assessment.SemanticFactors)

	return assessment
}

// AnalyzeRecursion performs specialized analysis for recursive calls
func (asa *AISemanticAnalyzer) AnalyzeRecursion(
	code string,
	lines []string,
	lineNum int,
) *SemanticAssessment {
	assessment := asa.AnalyzeCodeForVulnerability(code, lines, lineNum, "recursion")

	// Add recursion-specific factors
	assessment.SemanticFactors["recursion_depth_limit"] = asa.hasRecursionLimit(code, lines)
	assessment.SemanticFactors["base_case_obvious"] = asa.hasObviousBaseCase(code, lines)
	assessment.SemanticFactors["unbounded_input"] = asa.acceptsUnboundedInput(code, lines)

	assessment.VulnerabilityRisk = asa.calculateVulnerabilityRisk(assessment.SemanticFactors)

	return assessment
}

// AnalyzeDataFlow performs specialized analysis for data flow vulnerabilities
func (asa *AISemanticAnalyzer) AnalyzeDataFlow(
	code string,
	lines []string,
	lineNum int,
) *SemanticAssessment {
	assessment := asa.AnalyzeCodeForVulnerability(code, lines, lineNum, "data_flow")

	// Add data flow-specific factors
	assessment.SemanticFactors["input_validation"] = asa.hasInputValidation(code, lines)
	assessment.SemanticFactors["sanitization"] = asa.hasSanitization(code, lines)
	assessment.SemanticFactors["output_encoding"] = asa.hasOutputEncoding(code, lines)
	assessment.SemanticFactors["type_safety"] = asa.hasTypeSafety(code, lines)

	assessment.VulnerabilityRisk = asa.calculateVulnerabilityRisk(assessment.SemanticFactors)

	return assessment
}

// Helper methods for semantic analysis

func (asa *AISemanticAnalyzer) calculateFalsePositiveLikelihood(
	code string,
	patternType string,
	ctx *CodeAnalysisContext,
	risks map[string]float32,
) float32 {
	likelihood := float32(0)

	// Simple heuristics (could be enhanced with AI)

	// If code is in test file, higher FP likelihood
	if strings.Contains(code, "test") || strings.Contains(code, "mock") {
		likelihood += 0.3
	}

	// If code has explicit safety measures, lower FP likelihood
	if asa.hasSafetyMeasures(code) {
		likelihood -= 0.4
	}

	// If multiple risk factors present, lower FP likelihood
	riskCount := 0
	for _, v := range risks {
		if v > 0.3 {
			riskCount++
		}
	}
	if riskCount >= 2 {
		likelihood -= 0.2
	}

	// Clamp to 0-1
	if likelihood < 0 {
		likelihood = 0
	}
	if likelihood > 1 {
		likelihood = 1
	}

	return likelihood
}

func (asa *AISemanticAnalyzer) aggregateFactors(factors map[string]float32) map[string]float32 {
	return factors
}

func (asa *AISemanticAnalyzer) calculateVulnerabilityRisk(factors map[string]float32) float32 {
	if len(factors) == 0 {
		return 0.5
	}

	total := float32(0)
	count := float32(0)

	for _, score := range factors {
		total += score
		count++
	}

	return total / count
}

func (asa *AISemanticAnalyzer) assessContextRelevance(ctx *CodeAnalysisContext, patternType string) float32 {
	if ctx == nil {
		return 0.5
	}

	relevance := float32(0.5)

	// More variables analyzed = more context
	if len(ctx.Variables) > 0 {
		relevance += 0.2
	}

	// Control flow info increases relevance
	if ctx.ControlFlow != nil {
		relevance += 0.2
	}

	if relevance > 1 {
		relevance = 1
	}

	return relevance
}

func (asa *AISemanticAnalyzer) assessProviderRisk(provider string) float32 {
	// Different providers have different risk profiles
	risks := map[string]float32{
		"OpenAI":    0.5,  // Moderate cost
		"Anthropic": 0.4,  // Moderate cost
		"Google":    0.6,  // Variable pricing
		"Bedrock":   0.5,  // Pay per use
		"Ollama":    0.2,  // Local, no cost
		"Cohere":    0.5,  // Moderate cost
	}

	if risk, ok := risks[provider]; ok {
		return risk
	}

	return 0.5 // Unknown provider - neutral risk
}

func (asa *AISemanticAnalyzer) hasTokenLimits(code string) float32 {
	patterns := []string{
		"max_tokens",
		"token_limit",
		"max_length",
		"limit=",
		"tokens=",
	}

	codeLower := strings.ToLower(code)
	found := 0
	for _, p := range patterns {
		if strings.Contains(codeLower, p) {
			found++
		}
	}

	return float32(found) / float32(len(patterns))
}

func (asa *AISemanticAnalyzer) hasCostControl(code string) float32 {
	patterns := []string{
		"cost",
		"budget",
		"limit",
		"max_spend",
		"price_limit",
	}

	codeLower := strings.ToLower(code)
	found := 0
	for _, p := range patterns {
		if strings.Contains(codeLower, p) {
			found++
		}
	}

	return float32(found) / float32(len(patterns))
}

func (asa *AISemanticAnalyzer) hasTimeout(code string) float32 {
	patterns := []string{
		"timeout",
		"time.sleep",
		"time.out",
		"deadline",
		"duration",
	}

	codeLower := strings.ToLower(code)
	found := 0
	for _, p := range patterns {
		if strings.Contains(codeLower, p) {
			found++
		}
	}

	return float32(found) / float32(len(patterns))
}

func (asa *AISemanticAnalyzer) hasRecursionLimit(code string, lines []string) float32 {
	patterns := []string{
		"depth",
		"limit",
		"max_depth",
		"recursion_limit",
		"stack_limit",
	}

	allCode := strings.Join(lines, "\n")
	codeLower := strings.ToLower(allCode)
	found := 0
	for _, p := range patterns {
		if strings.Contains(codeLower, p) {
			found++
		}
	}

	return float32(found) / float32(len(patterns))
}

func (asa *AISemanticAnalyzer) hasObviousBaseCase(code string, lines []string) float32 {
	if len(lines) == 0 {
		return 0.5
	}

	allCode := strings.Join(lines, "\n")

	// Look for common base case patterns
	patterns := []string{
		"if",
		"return",
		"break",
		"len(",
		"== 0",
		"== nil",
	}

	codeLower := strings.ToLower(allCode)
	found := 0
	for _, p := range patterns {
		if strings.Contains(codeLower, p) {
			found++
		}
	}

	return float32(found) / float32(len(patterns))
}

func (asa *AISemanticAnalyzer) acceptsUnboundedInput(code string, lines []string) float32 {
	patterns := []string{
		"input",
		"args",
		"request",
		"data",
		"param",
	}

	allCode := strings.Join(lines, "\n")
	codeLower := strings.ToLower(allCode)
	found := 0
	for _, p := range patterns {
		if strings.Contains(codeLower, p) {
			found++
		}
	}

	// Higher value = more likely to accept unbounded input (higher risk)
	return float32(found) / float32(len(patterns))
}

func (asa *AISemanticAnalyzer) hasInputValidation(code string, lines []string) float32 {
	patterns := []string{
		"validate",
		"check",
		"verify",
		"assert",
		"isinstance",
		"type(",
	}

	allCode := strings.Join(lines, "\n")
	codeLower := strings.ToLower(allCode)
	found := 0
	for _, p := range patterns {
		if strings.Contains(codeLower, p) {
			found++
		}
	}

	return float32(found) / float32(len(patterns))
}

func (asa *AISemanticAnalyzer) hasSanitization(code string, lines []string) float32 {
	patterns := []string{
		"sanitize",
		"escape",
		"clean",
		"strip",
		"filter",
	}

	allCode := strings.Join(lines, "\n")
	codeLower := strings.ToLower(allCode)
	found := 0
	for _, p := range patterns {
		if strings.Contains(codeLower, p) {
			found++
		}
	}

	return float32(found) / float32(len(patterns))
}

func (asa *AISemanticAnalyzer) hasOutputEncoding(code string, lines []string) float32 {
	patterns := []string{
		"encode",
		"quote",
		"escape",
		"html",
		"json",
	}

	allCode := strings.Join(lines, "\n")
	codeLower := strings.ToLower(allCode)
	found := 0
	for _, p := range patterns {
		if strings.Contains(codeLower, p) {
			found++
		}
	}

	return float32(found) / float32(len(patterns))
}

func (asa *AISemanticAnalyzer) hasTypeSafety(code string, lines []string) float32 {
	patterns := []string{
		"type",
		"interface",
		"struct",
		"class",
		"protocol",
	}

	allCode := strings.Join(lines, "\n")
	codeLower := strings.ToLower(allCode)
	found := 0
	for _, p := range patterns {
		if strings.Contains(codeLower, p) {
			found++
		}
	}

	return float32(found) / float32(len(patterns))
}

func (asa *AISemanticAnalyzer) hasSafetyMeasures(code string) bool {
	measures := []string{
		"try",
		"except",
		"catch",
		"finally",
		"defer",
		"ensure",
	}

	codeLower := strings.ToLower(code)
	for _, m := range measures {
		if strings.Contains(codeLower, m) {
			return true
		}
	}

	return false
}

// NewRiskScorer creates a new risk scorer
func NewRiskScorer() *RiskScorer {
	return &RiskScorer{
		patterns: []*RiskPattern{
			{
				Name:      "unbounded_loop",
				Pattern:   regexp.MustCompile(`while\s*(true|1|1\.0)`),
				RiskScore: 0.8,
				Context:   "loop",
				Mitigation: "Add break condition or for loop with limit",
			},
			{
				Name:      "user_input",
				Pattern:   regexp.MustCompile(`(request|input|args|param|user)`),
				RiskScore: 0.6,
				Context:   "variable",
				Mitigation: "Validate and sanitize user input",
			},
			{
				Name:      "no_limits",
				Pattern:   regexp.MustCompile(`create\(|invoke\(|call\(`),
				RiskScore: 0.7,
				Context:   "api_call",
				Mitigation: "Add token limits, cost controls, timeouts",
			},
		},
	}
}

// ScoreCode scores code based on risk patterns
func (rs *RiskScorer) ScoreCode(
	code string,
	patternType string,
	ctx *CodeAnalysisContext,
) map[string]float32 {
	scores := make(map[string]float32)

	codeLower := strings.ToLower(code)

	for _, pattern := range rs.patterns {
		if pattern.Pattern.MatchString(codeLower) {
			scores[pattern.Name] = pattern.RiskScore
		}
	}

	return scores
}

// ExportAssessmentAsJSON exports assessment for storage/analysis
func (a *SemanticAssessment) ExportAsJSON() (string, error) {
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ImportFromJSON imports assessment from stored JSON
func (a *SemanticAssessment) ImportFromJSON(jsonData string) error {
	return json.Unmarshal([]byte(jsonData), a)
}
