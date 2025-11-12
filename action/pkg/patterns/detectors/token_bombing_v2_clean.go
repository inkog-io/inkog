package detectors

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

type TokenBombingDetectorV2Clean struct {
	pattern patterns.Pattern

	openaiPattern    *regexp.Regexp
	anthropicPattern *regexp.Regexp
	googlePattern    *regexp.Regexp
	llamaPattern     *regexp.Regexp
	readAllPattern   *regexp.Regexp
	readFullyPattern *regexp.Regexp
	whileLoopPattern *regexp.Regexp
	forLoopPattern   *regexp.Regexp
	maxTokensPattern *regexp.Regexp
}

func NewTokenBombingDetectorV2Clean() patterns.Detector {
	return &TokenBombingDetectorV2Clean{
		pattern: patterns.Pattern{
			ID:       "token_bombing_v2",
			Name:     "Token Bombing Attack",
			Version:  "2.0",
			Category: "Resource Exhaustion",
			Severity: "HIGH",
			CVSS:     7.5,
			CWEIDs:   []string{"CWE-770", "CWE-834"},
			OWASP:    "A01:2021",
			Description: "Detects unbounded token consumption in LLM APIs causing DoS or runaway costs",
		},
		openaiPattern:    regexp.MustCompile(`(openai|ChatGPT|gpt-[34]|text-davinci)\.(.*?)\(|openai\..*?complete|CreateChatCompletion`),
		anthropicPattern: regexp.MustCompile(`(anthropic|claude)\..*?(complete|message)|CreateMessage`),
		googlePattern:    regexp.MustCompile(`(google|palm|bard|generativeai)\..*?generate|GenerateContent`),
		llamaPattern:     regexp.MustCompile(`(llama|ollama|local.*?model)\..*?complete|localhost:11434`),
		readAllPattern:   regexp.MustCompile(`io\.ReadAll\s*\(|ioutil\.ReadAll\s*\(`),
		readFullyPattern: regexp.MustCompile(`ReadFully|ReadAll`),
		whileLoopPattern: regexp.MustCompile(`while\s*\(\s*(true|True|1)\s*\)|for\s+\{\s*$`),
		forLoopPattern:   regexp.MustCompile(`for\s*\{`),
		maxTokensPattern: regexp.MustCompile(`max_tokens|maxTokens|max_length`),
	}
}

func (d *TokenBombingDetectorV2Clean) Name() string {
	return "token_bombing_v2"
}

func (d *TokenBombingDetectorV2Clean) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	findings := []patterns.Finding{}
	sourceStr := string(src)
	lines := strings.Split(sourceStr, "\n")

	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}

		hasLLMCall := d.openaiPattern.MatchString(line) ||
			d.anthropicPattern.MatchString(line) ||
			d.googlePattern.MatchString(line) ||
			d.llamaPattern.MatchString(line)

		if !hasLLMCall {
			continue
		}

		hasTokenLimit := d.maxTokensPattern.MatchString(line)
		if hasTokenLimit {
			continue
		}

		inUnboundedLoop := d.checkInUnboundedLoop(lines, lineNum)
		isUnboundedInput := d.checkUnboundedInput(lines, lineNum)

		if inUnboundedLoop || isUnboundedInput {
			confidence := float32(0.85)
			if inUnboundedLoop && isUnboundedInput {
				confidence = 0.95
			}

			finding := patterns.Finding{
				ID:         fmt.Sprintf("token_bombing_%d_%s", lineNum+1, filePath),
				PatternID:  d.pattern.ID,
				Pattern:    d.pattern.Name,
				File:       filePath,
				Line:       lineNum + 1,
				Column:     1,
				Severity:   "CRITICAL",
				Confidence: confidence,
				Message:    "LLM API call without token limits in unbounded context",
				Code:       line,
				CWE:        "CWE-770",
				CVSS:       7.5,
				OWASP:      "A01:2021",
			}
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

func (d *TokenBombingDetectorV2Clean) checkInUnboundedLoop(lines []string, lineNum int) bool {
	for i := lineNum; i >= 0 && i > lineNum-10; i-- {
		if d.whileLoopPattern.MatchString(lines[i]) {
			for j := i + 1; j < lineNum; j++ {
				if strings.Contains(lines[j], "break") || strings.Contains(lines[j], "return") {
					return false
				}
			}
			return true
		}
	}
	return false
}

func (d *TokenBombingDetectorV2Clean) checkUnboundedInput(lines []string, lineNum int) bool {
	for i := lineNum; i >= 0 && i > lineNum-20; i-- {
		if d.readAllPattern.MatchString(lines[i]) {
			for j := i; j < lineNum && j < len(lines); j++ {
				if strings.Contains(lines[j], "MaxBytesReader") {
					return false
				}
			}
			return true
		}
	}
	return false
}

func (d *TokenBombingDetectorV2Clean) GetPattern() patterns.Pattern {
	return d.pattern
}

func (d *TokenBombingDetectorV2Clean) GetConfidence() float32 {
	return 0.85
}

func (d *TokenBombingDetectorV2Clean) Close() error {
	return nil
}
