package detectors

import (
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// EnhancedMissingHumanOversightDetector detects missing human oversight in AI agent actions
// Uses: Core detection + FileClassifier + SimpleConfidenceFramework + SimpleEnterpriseConfig
// Pattern: Eval/exec/dangerous tools without human approval, insecure defaults, over-scoped permissions
type EnhancedMissingHumanOversightDetector struct {
	baseDetector        *MissingHumanOversightDetector
	fileClassifier      *FileClassifier
	confidenceFramework *SimpleConfidenceFramework
	config              *SimpleEnterpriseConfig
}

// NewEnhancedMissingHumanOversightDetector creates a new enhanced missing human oversight detector
func NewEnhancedMissingHumanOversightDetector(
	config *SimpleEnterpriseConfig,
) *EnhancedMissingHumanOversightDetector {
	if config == nil {
		config = NewSimpleEnterpriseConfig()
	}

	return &EnhancedMissingHumanOversightDetector{
		baseDetector:        NewMissingHumanOversightDetector(),
		fileClassifier:      NewFileClassifier(),
		confidenceFramework: NewSimpleConfidenceFramework(0.65), // 0.65 threshold for oversight patterns (can be context-dependent)
		config:              config,
	}
}

// Detect performs missing human oversight detection with context-aware confidence
func (d *EnhancedMissingHumanOversightDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	// Step 1: Check if pattern is enabled
	patternConfig := d.config.GetPatternConfig("missing_human_oversight")
	if !patternConfig.Enabled {
		return []patterns.Finding{}, nil
	}

	// Step 2: Get base findings from original detector
	baseFindings, err := d.baseDetector.Detect(filePath, src)
	if err != nil {
		return nil, err
	}

	if len(baseFindings) == 0 {
		return []patterns.Finding{}, nil
	}

	sourceStr := string(src)
	lines := strings.Split(sourceStr, "\n")

	// Step 3: Apply context-aware filtering and confidence scoring
	var enhancedFindings []patterns.Finding

	for _, finding := range baseFindings {
		lineIdx := finding.Line - 1
		var lineContent string
		if lineIdx >= 0 && lineIdx < len(lines) {
			lineContent = lines[lineIdx]
		}

		// Check if finding is in test file
		isInTestFile := d.fileClassifier.IsTestFile(filePath)
		if isInTestFile && patternConfig.FilterTestCode {
			// Test code often has intentional unsafe patterns for demonstration
			finding.Confidence = finding.Confidence * 0.80
		}

		// Check if finding is in comment
		isInComment := strings.HasPrefix(strings.TrimSpace(lineContent), "//") ||
			strings.HasPrefix(strings.TrimSpace(lineContent), "#")
		if isInComment && patternConfig.FilterComments {
			continue // Skip findings in comments
		}

		// Check if finding is in string or docstring
		isInString := d.isDocstringExample(lineContent)
		if isInString && patternConfig.FilterStrings {
			continue // Skip findings in docstrings/examples
		}

		// Apply context-aware confidence adjustments
		// Check for mitigating factors (human oversight, safe defaults, etc.)
		hasSafeguard := d.hasSafeguard(sourceStr, lineContent, lineIdx, lines)

		adjusted := d.confidenceFramework.AdjustConfidence(
			finding.Confidence,
			isInTestFile,
			isInComment,
			isInString,
			hasSafeguard, // Presence of safeguards reduces confidence
		)

		// For missing human oversight, use 0.65 threshold
		if !d.confidenceFramework.ShouldReport(adjusted) {
			continue
		}

		// Update finding with adjusted confidence
		finding.Confidence = adjusted

		enhancedFindings = append(enhancedFindings, finding)
	}

	return enhancedFindings, nil
}

// hasSafeguard checks for human oversight mechanisms and safe patterns
func (d *EnhancedMissingHumanOversightDetector) hasSafeguard(sourceStr string, lineContent string, lineIdx int, lines []string) bool {
	// Check for human oversight tools and patterns
	safeguards := []string{
		"HumanInputRun",
		"HumanInput",
		"human_input",
		"approval",
		"approved",
		"requires_approval",
		"needs_confirmation",
		"ask_user",
		"user_consent",
		"human_in_the_loop",
		"human_agent",
		"interactive",
		"interactive_run",
		"get_confirmation",
		"request_permission",
		"confirm_action",
		"validate_action",
		"validate_permission",
		"check_permission",
		"require_approval",
	}

	for _, safeguard := range safeguards {
		if strings.Contains(strings.ToLower(lineContent), strings.ToLower(safeguard)) {
			return true
		}
	}

	// Check for safe defaults and configuration patterns
	safeDefaults := []string{
		"allow_dangerous_requests=False",
		"allow_dangerous_requests = False",
		"allow_dangerous=False",
		"allow_dangerous = False",
		"code_execution_config = False",
		"code_execution_config=False",
		"enable_code_exec=False",
		"enable_code_exec = False",
		"dangerous_mode=False",
		"allow_exec=False",
		"allow_eval=False",
		"sandbox",
		"restricted",
		"safe_mode",
	}

	for _, safeDefault := range safeDefaults {
		if strings.Contains(strings.ToLower(sourceStr), strings.ToLower(safeDefault)) {
			return true
		}
	}

	// Check for parameterized/validated queries (SQL safety)
	sqlSafeguards := []string{
		"parameterized",
		"prepared statement",
		"question mark",
		"positional",
		"execute_many",
		"executemany",
		"?",
		"$1",
		"values(",
	}

	for _, safeguard := range sqlSafeguards {
		if strings.Contains(strings.ToLower(lineContent), strings.ToLower(safeguard)) {
			return true
		}
	}

	// Check for path validation (file operation safety)
	pathSafeguards := []string{
		"os.path.abspath",
		"os.path.realpath",
		"pathlib.Path",
		"allowed_path",
		"base_path",
		"safe_path",
		"validate_path",
		"check_path",
		"join",
		"normalize",
		"resolve",
		"startswith",
		"contains(",
	}

	for _, safeguard := range pathSafeguards {
		if strings.Contains(strings.ToLower(lineContent), strings.ToLower(safeguard)) {
			return true
		}
	}

	// Check for input validation and sanitization
	validationPatterns := []string{
		"validate",
		"sanitize",
		"escape",
		"quote",
		"filter",
		"whitelist",
		"blacklist",
		"check",
		"verify",
		"assert",
		"if not",
		"if !",
		"raise error",
		"throw error",
		"return error",
	}

	for _, pattern := range validationPatterns {
		if strings.Contains(strings.ToLower(lineContent), strings.ToLower(pattern)) {
			return true
		}
	}

	// Check for role-based access control (RBAC)
	rbacPatterns := []string{
		"role",
		"permission",
		"rbac",
		"has_role",
		"check_role",
		"check_permission",
		"allowed_roles",
		"requires_role",
		"access_control",
		"authorization",
		"scope",
		"scoped",
	}

	for _, pattern := range rbacPatterns {
		if strings.Contains(strings.ToLower(lineContent), strings.ToLower(pattern)) {
			return true
		}
	}

	// Check surrounding lines for approval/validation logic
	if lineIdx > 0 && lineIdx < len(lines) {
		// Look at previous line for conditions
		prevLine := strings.ToLower(lines[lineIdx-1])
		if strings.Contains(prevLine, "if") || strings.Contains(prevLine, "check") ||
			strings.Contains(prevLine, "validate") || strings.Contains(prevLine, "assert") {
			return true
		}

		// Look at next line for safeguards
		if lineIdx+1 < len(lines) {
			nextLine := strings.ToLower(lines[lineIdx+1])
			if strings.Contains(nextLine, "human") || strings.Contains(nextLine, "approval") ||
				strings.Contains(nextLine, "validate") || strings.Contains(nextLine, "check") {
				return true
			}
		}
	}

	return false
}

// isDocstringExample checks if a line is within a docstring or example
func (d *EnhancedMissingHumanOversightDetector) isDocstringExample(line string) bool {
	trimmed := strings.TrimSpace(line)

	// Check for docstring markers
	if strings.HasPrefix(trimmed, "\"\"\"") || strings.HasPrefix(trimmed, "'''") {
		return true
	}

	// Check if line is within example/doc string context
	if strings.Contains(trimmed, ">>>") || strings.Contains(trimmed, "...") {
		return true
	}

	// Check for code fence markers (markdown)
	if strings.HasPrefix(trimmed, "```") {
		return true
	}

	return false
}

// Name returns detector name
func (d *EnhancedMissingHumanOversightDetector) Name() string {
	return "missing_human_oversight_enhanced"
}

// IsEnabled checks if pattern is enabled
func (d *EnhancedMissingHumanOversightDetector) IsEnabled() bool {
	patternConfig := d.config.GetPatternConfig("missing_human_oversight")
	return patternConfig.Enabled
}
