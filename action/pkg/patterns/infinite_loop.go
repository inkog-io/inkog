package patterns

import (
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/inkog-io/inkog/action/pkg/models"
	"github.com/inkog-io/inkog/action/pkg/parser"
	"strings"
)

// InfiniteLoopDetector detects infinite loops and unbounded recursion
type InfiniteLoopDetector struct{}

// Detect finds infinite loop vulnerabilities
func (i *InfiniteLoopDetector) Detect(fileInfo *parser.FileInfo) []models.Finding {
	var findings []models.Finding

	if fileInfo.Tree == nil {
		return findings
	}

	cursor := sitter.NewTreeCursor(fileInfo.Tree.RootNode())
	findings = append(findings, i.findInfiniteLoops(cursor, fileInfo)...)
	findings = append(findings, i.findUnboundedRecursion(cursor, fileInfo)...)

	return findings
}

// findInfiniteLoops detects while True loops and similar patterns
func (i *InfiniteLoopDetector) findInfiniteLoops(cursor *sitter.TreeCursor, fileInfo *parser.FileInfo) []models.Finding {
	var findings []models.Finding

	node := cursor.Node()
	nodeType := node.Type()

	// Python while loops
	if fileInfo.Language == parser.LanguagePython && nodeType == "while_statement" {
		if isInfiniteWhileLoop(node, fileInfo.Content) {
			finding := models.Finding{
				ID:              "infinite_loop_while",
				Pattern:         "Infinite While Loop",
				Severity:        models.RiskLevelHigh,
				Confidence:      0.90,
				File:            fileInfo.Path,
				Line:            parser.GetNodeLine(node),
				Column:          parser.GetNodeColumn(node),
				Message:         "Infinite loop detected: 'while True' or 'while 1' without break condition",
				Code:            truncateCode(parser.GetNodeText(node, fileInfo.Content), 150),
				Remediation:     "Add break conditions or use a bounded loop (for loop with counter)",
				ReferenceLinks:  []string{"https://en.wikipedia.org/wiki/Infinite_loop"},
				CWEIdentifiers:  []string{"CWE-835"},
				DetectionMethod: "AST pattern matching on while statement conditions",
			}
			findings = append(findings, finding)
		}
	}

	// JavaScript/TypeScript while loops
	if (fileInfo.Language == parser.LanguageJavaScript || fileInfo.Language == parser.LanguageTypeScript) &&
		nodeType == "while_statement" {
		if isInfiniteWhileLoopJS(node, fileInfo.Content) {
			finding := models.Finding{
				ID:              "infinite_loop_while_js",
				Pattern:         "Infinite While Loop (JavaScript)",
				Severity:        models.RiskLevelHigh,
				Confidence:      0.90,
				File:            fileInfo.Path,
				Line:            parser.GetNodeLine(node),
				Column:          parser.GetNodeColumn(node),
				Message:         "Infinite loop detected: 'while(true)' without break condition",
				Code:            truncateCode(parser.GetNodeText(node, fileInfo.Content), 150),
				Remediation:     "Add break conditions or use a bounded loop",
				ReferenceLinks:  []string{"https://en.wikipedia.org/wiki/Infinite_loop"},
				CWEIdentifiers:  []string{"CWE-835"},
				DetectionMethod: "AST pattern matching on while statement conditions",
			}
			findings = append(findings, finding)
		}
	}

	// Recursively check children
	if cursor.GoToFirstChild() {
		findings = append(findings, i.findInfiniteLoops(cursor, fileInfo)...)
		for cursor.GoToNextSibling() {
			findings = append(findings, i.findInfiniteLoops(cursor, fileInfo)...)
		}
		cursor.GoToParent()
	}

	return findings
}

// findUnboundedRecursion detects recursive functions without base cases
func (i *InfiniteLoopDetector) findUnboundedRecursion(cursor *sitter.TreeCursor, fileInfo *parser.FileInfo) []models.Finding {
	var findings []models.Finding

	node := cursor.Node()
	nodeType := node.Type()

	// Python function definitions
	if fileInfo.Language == parser.LanguagePython && nodeType == "function_definition" {
		if hasUnboundedRecursion(node, fileInfo) {
			funcName := extractFunctionName(node, fileInfo.Content)
			finding := models.Finding{
				ID:              "unbounded_recursion",
				Pattern:         "Unbounded Recursion",
				Severity:        models.RiskLevelMedium,
				Confidence:      0.70,
				File:            fileInfo.Path,
				Line:            parser.GetNodeLine(node),
				Column:          parser.GetNodeColumn(node),
				Message:         "Function '" + funcName + "' may have unbounded recursion without proper base case",
				Code:            truncateCode(parser.GetNodeText(node, fileInfo.Content), 150),
				Remediation:     "Add base case condition before recursive call to prevent stack overflow",
				ReferenceLinks:  []string{"https://en.wikipedia.org/wiki/Recursion_(computer_science)"},
				CWEIdentifiers:  []string{"CWE-674"},
				DetectionMethod: "AST analysis of function recursion patterns",
			}
			findings = append(findings, finding)
		}
	}

	// Recursively check children
	if cursor.GoToFirstChild() {
		findings = append(findings, i.findUnboundedRecursion(cursor, fileInfo)...)
		for cursor.GoToNextSibling() {
			findings = append(findings, i.findUnboundedRecursion(cursor, fileInfo)...)
		}
		cursor.GoToParent()
	}

	return findings
}

// isInfiniteWhileLoop checks if a while loop is potentially infinite (Python)
func isInfiniteWhileLoop(node *sitter.Node, content []byte) bool {
	text := string(content[node.StartByte():node.EndByte()])

	// Check for while True or while 1 patterns
	if strings.Contains(text, "while True:") || strings.Contains(text, "while 1:") {
		// Check if there's a break statement in the loop body
		if !strings.Contains(text, "break") {
			return true
		}
		// Even if there's a break, it might be conditional - flagged as medium risk
		return false
	}

	return false
}

// isInfiniteWhileLoopJS checks if a while loop is potentially infinite (JavaScript)
func isInfiniteWhileLoopJS(node *sitter.Node, content []byte) bool {
	text := string(content[node.StartByte():node.EndByte()])

	// Check for while(true) patterns
	if strings.Contains(text, "while(true)") || strings.Contains(text, "while (true)") {
		// Check if there's a break statement in the loop body
		if !strings.Contains(text, "break") {
			return true
		}
		return false
	}

	return false
}

// hasUnboundedRecursion checks if a function has unbounded recursion
func hasUnboundedRecursion(node *sitter.Node, fileInfo *parser.FileInfo) bool {
	text := string(fileInfo.Content[node.StartByte():node.EndByte()])
	funcName := extractFunctionName(node, fileInfo.Content)

	// Check if function calls itself
	if !strings.Contains(text, funcName+"(") {
		return false
	}

	// Check if there's an if statement (likely base case)
	if !strings.Contains(text, "if ") && !strings.Contains(text, "return") {
		return false
	}

	// This is a heuristic - real detection requires more sophisticated analysis
	return strings.Count(text, funcName+"(") > 1 && !hasExitCondition(text)
}

// hasExitCondition checks if code has exit conditions
func hasExitCondition(text string) bool {
	conditions := []string{"return", "if ", "else", "break", "raise"}
	for _, cond := range conditions {
		if strings.Contains(text, cond) {
			return true
		}
	}
	return false
}

// extractFunctionName extracts the function name from a function definition
func extractFunctionName(node *sitter.Node, content []byte) string {
	// Navigate to find the function name (usually the first identifier after 'def')
	for i := 0; i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child.Type() == "identifier" {
			return string(content[child.StartByte():child.EndByte()])
		}
	}
	return "unknown"
}

func (i *InfiniteLoopDetector) Name() string {
	return "Infinite Loop Detection"
}

func (i *InfiniteLoopDetector) Version() string {
	return "1.0.0"
}
