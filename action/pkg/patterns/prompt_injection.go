package patterns

import (
	"fmt"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/inkog-io/inkog/action/pkg/models"
	"github.com/inkog-io/inkog/action/pkg/parser"
)

// PromptInjectionDetector detects prompt injection vulnerabilities
type PromptInjectionDetector struct{}

// Detect finds prompt injection vulnerabilities
func (p *PromptInjectionDetector) Detect(fileInfo *parser.FileInfo) []models.Finding {
	var findings []models.Finding

	if fileInfo.Tree == nil {
		return findings
	}

	// Walk the tree looking for suspicious patterns
	cursor := sitter.NewTreeCursor(fileInfo.Tree.RootNode())
	findings = append(findings, p.findVulnerableStrings(cursor, fileInfo)...)

	return findings
}

// findVulnerableStrings finds f-strings or template literals with user input
func (p *PromptInjectionDetector) findVulnerableStrings(cursor *sitter.TreeCursor, fileInfo *parser.FileInfo) []models.Finding {
	var findings []models.Finding

	node := cursor.Node()
	nodeType := node.Type()

	// Python f-strings: (f-string node type)
	if fileInfo.Language == parser.LanguagePython && nodeType == "f-string" {
		if isSuspiciousPromptInjection(node, fileInfo.Content) {
			finding := models.Finding{
				ID:              "prompt_injection_fstring",
				Pattern:         "Prompt Injection via F-String",
				Severity:        models.RiskLevelHigh,
				Confidence:      0.85,
				File:            fileInfo.Path,
				Line:            parser.GetNodeLine(node),
				Column:          parser.GetNodeColumn(node),
				Message:         "Potential prompt injection: User input directly interpolated in prompt string",
				Code:            truncateCode(parser.GetNodeText(node, fileInfo.Content), 100),
				Remediation:     "Use parameterized prompts or sanitize user input before interpolation",
				ReferenceLinks:  []string{"https://owasp.org/www-community/attacks/Prompt_Injection"},
				CWEIdentifiers:  []string{"CWE-94", "CWE-95"},
				DetectionMethod: "AST-based pattern matching on f-string interpolation",
			}
			findings = append(findings, finding)
		}
	}

	// JavaScript/TypeScript template literals
	if (fileInfo.Language == parser.LanguageJavaScript || fileInfo.Language == parser.LanguageTypeScript) &&
		nodeType == "template_string" {
		if isSuspiciousTemplateString(node, fileInfo.Content) {
			finding := models.Finding{
				ID:              "prompt_injection_template",
				Pattern:         "Prompt Injection via Template Literal",
				Severity:        models.RiskLevelHigh,
				Confidence:      0.80,
				File:            fileInfo.Path,
				Line:            parser.GetNodeLine(node),
				Column:          parser.GetNodeColumn(node),
				Message:         "Potential prompt injection: User input directly interpolated in template literal",
				Code:            truncateCode(parser.GetNodeText(node, fileInfo.Content), 100),
				Remediation:     "Use parameterized prompts or sanitize user input before interpolation",
				ReferenceLinks:  []string{"https://owasp.org/www-community/attacks/Prompt_Injection"},
				CWEIdentifiers:  []string{"CWE-94", "CWE-95"},
				DetectionMethod: "AST-based pattern matching on template string interpolation",
			}
			findings = append(findings, finding)
		}
	}

	// Recursively check children
	if cursor.GoToFirstChild() {
		findings = append(findings, p.findVulnerableStrings(cursor, fileInfo)...)
		for cursor.GoToNextSibling() {
			findings = append(findings, p.findVulnerableStrings(cursor, fileInfo)...)
		}
		cursor.GoToParent()
	}

	return findings
}

// isSuspiciousPromptInjection checks if an f-string contains suspicious patterns
func isSuspiciousPromptInjection(node *sitter.Node, content []byte) bool {
	text := string(content[node.StartByte():node.EndByte()])

	// Check for common prompt-related variable names with interpolation
	suspiciousPatterns := []string{
		"prompt", "query", "question", "user_input", "request",
		"message", "text", "instruction", "input",
	}

	lowerText := strings.ToLower(text)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(lowerText, pattern) && strings.Contains(text, "{") {
			return true
		}
	}

	return false
}

// isSuspiciousTemplateString checks if a template string contains suspicious patterns
func isSuspiciousTemplateString(node *sitter.Node, content []byte) bool {
	text := string(content[node.StartByte():node.EndByte()])

	// Check for common prompt-related variable names with interpolation
	suspiciousPatterns := []string{
		"prompt", "query", "question", "userInput", "user_input", "request",
		"message", "text", "instruction", "input",
	}

	lowerText := strings.ToLower(text)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(lowerText, pattern) && strings.Contains(text, "${") {
			return true
		}
	}

	return false
}

// truncateCode truncates code to a maximum length
func truncateCode(code string, maxLen int) string {
	if len(code) > maxLen {
		return code[:maxLen] + "..."
	}
	return code
}

func (p *PromptInjectionDetector) Name() string {
	return "Prompt Injection Detection"
}

func (p *PromptInjectionDetector) Version() string {
	return "1.0.0"
}
