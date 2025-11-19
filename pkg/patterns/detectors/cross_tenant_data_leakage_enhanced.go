package detectors

import (
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// EnhancedCrossTenantDataLeakageDetector detects cross-tenant data access vulnerabilities
// Uses: Core detection + FileClassifier + SimpleConfidenceFramework + SimpleEnterpriseConfig
// Pattern: Missing tenant filters in ORM/SQL, global state without tenant scoping, missing ID-to-tenant validation
type EnhancedCrossTenantDataLeakageDetector struct {
	baseDetector        *CrossTenantDataLeakageDetector
	fileClassifier      *FileClassifier
	confidenceFramework *SimpleConfidenceFramework
	config              *SimpleEnterpriseConfig
}

// NewEnhancedCrossTenantDataLeakageDetector creates a new enhanced cross-tenant data leakage detector
func NewEnhancedCrossTenantDataLeakageDetector(
	config *SimpleEnterpriseConfig,
) *EnhancedCrossTenantDataLeakageDetector {
	if config == nil {
		config = NewSimpleEnterpriseConfig()
	}

	return &EnhancedCrossTenantDataLeakageDetector{
		baseDetector:        NewCrossTenantDataLeakageDetector(),
		fileClassifier:      NewFileClassifier(),
		confidenceFramework: NewSimpleConfidenceFramework(0.70), // 0.70 threshold for tenant isolation (critical)
		config:              config,
	}
}

// Detect performs cross-tenant data leakage detection with context-aware confidence
func (d *EnhancedCrossTenantDataLeakageDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	// Step 1: Check if pattern is enabled
	patternConfig := d.config.GetPatternConfig("cross_tenant_data_leakage")
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
		// Check for mitigating factors (tenant filters, authorization, etc.)
		hasSafeguard := d.hasSafeguard(sourceStr, lineContent, lineIdx, lines)

		adjusted := d.confidenceFramework.AdjustConfidence(
			finding.Confidence,
			isInTestFile,
			isInComment,
			isInString,
			hasSafeguard, // Presence of safeguards reduces confidence
		)

		// For cross-tenant leakage, use 0.70 threshold (high criticality)
		if !d.confidenceFramework.ShouldReport(adjusted) {
			continue
		}

		// Update finding with adjusted confidence
		finding.Confidence = adjusted

		enhancedFindings = append(enhancedFindings, finding)
	}

	return enhancedFindings, nil
}

// hasSafeguard checks for proper tenant isolation mechanisms
func (d *EnhancedCrossTenantDataLeakageDetector) hasSafeguard(sourceStr string, lineContent string, lineIdx int, lines []string) bool {
	lowerContent := strings.ToLower(lineContent)
	lowerSource := strings.ToLower(sourceStr)

	// Check for explicit tenant filtering patterns
	tenantFilters := []string{
		"tenant_id",
		"tenant_filter",
		"filter_by_tenant",
		"where_tenant",
		"tenant_context",
		"get_tenant",
		"current_tenant",
		"org_id",
		"organization_id",
		"workspace_id",
		"account_id",
		"customer_id",
		"company_id",
		"user_id in user_organizations",
		"belongs_to",
	}

	for _, filter := range tenantFilters {
		if strings.Contains(lowerContent, filter) {
			return true
		}
	}

	// Check for authorization/permission checks
	authPatterns := []string{
		"check_permission",
		"verify_ownership",
		"require_tenant",
		"assert_owner",
		"permission_check",
		"authorization",
		"access_control",
		"has_access",
		"can_access",
		"allowed_tenants",
		"belongs_to_tenant",
		"is_owner",
		"is_member",
		"check_tenant",
		"validate_tenant",
		"get_current_tenant",
		"get_user_tenant",
		"tenant_scope",
		"scoped_query",
	}

	for _, pattern := range authPatterns {
		if strings.Contains(lowerContent, pattern) {
			return true
		}
	}

	// Check for Row-Level Security (RLS) implementations
	rlsPatterns := []string{
		"row level security",
		"row_level_security",
		"rls",
		"enable_rls",
		"rls_policy",
		"set_rls",
		"create_policy",
		"policy.*tenant",
		"policy.*user",
	}

	for _, pattern := range rlsPatterns {
		if strings.Contains(lowerContent, pattern) {
			return true
		}
	}

	// Check for middleware or decorator patterns indicating global tenant context
	contextPatterns := []string{
		"middleware",
		"@require_tenant",
		"@authenticate",
		"@authorize",
		"decorator",
		"context.tenant",
		"request.tenant",
		"session.tenant",
		"g.tenant",
		"threadlocal",
		"thread_local",
		"request_context",
		"tenant_context",
	}

	for _, pattern := range contextPatterns {
		if strings.Contains(lowerContent, pattern) {
			return true
		}
	}

	// Check for scoped queries and parameterized approaches
	scopedPatterns := []string{
		"filter(",
		"where(",
		"filter_by",
		"where_tenant",
		"scoped",
		"scope ",
		"query.filter",
		"query.where",
		".filter(",
		".where(",
		"prepared statement",
		"parameterized",
		"bind_param",
	}

	for _, pattern := range scopedPatterns {
		if strings.Contains(lowerContent, pattern) {
			return true
		}
	}

	// Check for admin-only code sections (less likely to leak cross-tenant)
	adminPatterns := []string{
		"is_admin",
		"is_superuser",
		"admin only",
		"admin_only",
		"admin_check",
		"require_admin",
		"check_admin",
	}

	for _, pattern := range adminPatterns {
		if strings.Contains(lowerContent, pattern) {
			return true
		}
	}

	// Check for single-tenant detection (no multi-tenancy = no cross-tenant risk)
	singleTenantPatterns := []string{
		"single_tenant",
		"single tenant",
		"single-tenant",
		"single_org",
		"single org",
		"one org",
		"not multi-tenant",
		"not multitenant",
	}

	for _, pattern := range singleTenantPatterns {
		if strings.Contains(lowerContent, pattern) {
			return true
		}
	}

	// Check for index patterns indicating tenant-based partitioning
	indexPatterns := []string{
		"index.*tenant",
		"index.*organization",
		"composite_index",
		"composite index",
		"compound_key",
		"tenant.*index",
	}

	for _, pattern := range indexPatterns {
		if strings.Contains(lowerContent, pattern) {
			return true
		}
	}

	// Check for ORM-level safeguards (Django: get_object_or_404 with owner check, etc.)
	ormSafeguards := []string{
		"get_object_or_404",
		"get_or_404",
		"or_404",
		"raise_http_exception",
		"pk_and_query",
		"get_and_check",
		"lookup_with_user",
		"lookup_with_tenant",
	}

	for _, pattern := range ormSafeguards {
		if strings.Contains(lowerContent, pattern) {
			return true
		}
	}

	// Check surrounding lines for authorization/validation logic
	if lineIdx > 0 && lineIdx < len(lines) {
		// Look at previous lines for conditions and checks (up to 3 lines before)
		startIdx := lineIdx
		if lineIdx > 3 {
			startIdx = lineIdx - 3
		}

		for i := startIdx; i < lineIdx; i++ {
			prevLine := strings.ToLower(lines[i])
			if strings.Contains(prevLine, "if") || strings.Contains(prevLine, "check") ||
				strings.Contains(prevLine, "validate") || strings.Contains(prevLine, "assert") ||
				strings.Contains(prevLine, "tenant") || strings.Contains(prevLine, "owner") ||
				strings.Contains(prevLine, "permission") || strings.Contains(prevLine, "authorize") {
				return true
			}
		}

		// Look at next lines for safeguards (up to 3 lines after)
		endIdx := lineIdx + 3
		if endIdx >= len(lines) {
			endIdx = len(lines) - 1
		}

		for i := lineIdx + 1; i <= endIdx; i++ {
			if i < len(lines) {
				nextLine := strings.ToLower(lines[i])
				if strings.Contains(nextLine, "tenant") || strings.Contains(nextLine, "owner") ||
					strings.Contains(nextLine, "check") || strings.Contains(nextLine, "validate") ||
					strings.Contains(nextLine, "permission") || strings.Contains(nextLine, "404") {
					return true
				}
			}
		}
	}

	// Check if line is within a function that has "tenant" or "owner" in its name
	if strings.Contains(lowerSource, "def ") || strings.Contains(lowerSource, "func ") {
		// Look for function definition containing tenant/owner
		sourceParts := strings.Split(lowerSource, "\n")
		for i := range sourceParts {
			if i == lineIdx {
				// Found our line, search backwards for function definition
				for j := i; j >= 0 && j > i-30; j-- {
					if strings.Contains(sourceParts[j], "def ") || strings.Contains(sourceParts[j], "func ") {
						if strings.Contains(sourceParts[j], "tenant") || strings.Contains(sourceParts[j], "owner") ||
							strings.Contains(sourceParts[j], "user") || strings.Contains(sourceParts[j], "permission") {
							return true
						}
						break
					}
				}
				break
			}
		}
	}

	return false
}

// isDocstringExample checks if a line is within a docstring or example
func (d *EnhancedCrossTenantDataLeakageDetector) isDocstringExample(line string) bool {
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
func (d *EnhancedCrossTenantDataLeakageDetector) Name() string {
	return "cross_tenant_data_leakage_enhanced"
}

// IsEnabled checks if pattern is enabled
func (d *EnhancedCrossTenantDataLeakageDetector) IsEnabled() bool {
	patternConfig := d.config.GetPatternConfig("cross_tenant_data_leakage")
	return patternConfig.Enabled
}
