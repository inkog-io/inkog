package detectors

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// CrossTenantDataLeakageDetector detects potential cross-tenant data access vulnerabilities
// It identifies patterns where data from one tenant could be accessed by another due to
// missing tenant isolation, improper access control, or shared global state
type CrossTenantDataLeakageDetector struct {
	// Patterns for detecting missing tenant filters in ORM/DB calls
	ormPatterns []*regexp.Regexp
	// Raw SQL patterns
	sqlPatterns []*regexp.Regexp
	// Global state patterns
	globalPatterns []*regexp.Regexp
	// Safe patterns that indicate proper tenant handling
	safePatterns []*regexp.Regexp
	// Context patterns that indicate tenant-aware code
	contextPatterns []*regexp.Regexp
}

// NewCrossTenantDataLeakageDetector creates a new detector
func NewCrossTenantDataLeakageDetector() *CrossTenantDataLeakageDetector {
	detector := &CrossTenantDataLeakageDetector{
		ormPatterns:     []*regexp.Regexp{},
		sqlPatterns:     []*regexp.Regexp{},
		globalPatterns:  []*regexp.Regexp{},
		safePatterns:    []*regexp.Regexp{},
		contextPatterns: []*regexp.Regexp{},
	}

	// ORM patterns - detect .get, .filter, .find without tenant scope
	// Django: Model.objects.get(id=...) or .filter(id=...)
	detector.ormPatterns = append(detector.ormPatterns,
		regexp.MustCompile(`\.(?:get|filter|find|first|find_one)\s*\(\s*(?:id|user_id|record_id)\s*=\s*[^,)]*\)`),
		// Catches: .get(id=x), .filter(id=123), .find(user_id=...)
		regexp.MustCompile(`\.(?:get|filter|find|first)\s*\(\s*\{[^}]*(?:id|user_id)[^}]*\}`),
		// Catches: .get({id: x}), .filter({user_id: ...})
		regexp.MustCompile(`objects\.(?:filter|get|first|find)\s*\([^)]*\bid\b[^)]*\)`),
		// Catches: Model.objects.filter(...id...)
		regexp.MustCompile(`DB\.(?:Where|Query|Exec|QueryRow)\s*\([^)]*\bid\s*=`),
		// Catches Go GORM: DB.Where("id = ?", ...) or DB.Query("... id ...")
	)

	// SQL patterns - detect WHERE id without tenant
	detector.sqlPatterns = append(detector.sqlPatterns,
		regexp.MustCompile(`(?i)SELECT\s+\*?\s+FROM\s+\w+\s+WHERE\s+\w+\s*=`),
		// Catches: SELECT * FROM table WHERE id = ... (may or may not have tenant)
		regexp.MustCompile(`(?i)WHERE\s+\w*id\s*=\s*['"$?]`),
		// Catches: WHERE id = ? or WHERE user_id = '...'
		regexp.MustCompile(`(?i)\bFROM\s+\w+\s+WHERE\s+\w+\s*=`),
		// Generic WHERE clause with assignment pattern
	)

	// Global state patterns - detect shared caches/memory without tenant scoping
	detector.globalPatterns = append(detector.globalPatterns,
		regexp.MustCompile(`(?:var|const|let)\s+(?:CACHE|MEMORY|STORE|DATA_MAP)\s*=\s*(?:\{|map\[)`),
		// Catches: CACHE = {}, var MEMORY map[...], let DATA_MAP = {}
		regexp.MustCompile(`(?:global|GLOBAL)\s+\w*(?:cache|memory|state)\w*`),
		// Catches: global CACHE, GLOBAL_MEMORY, etc.
		regexp.MustCompile(`process\.env\s*(?:\[|\.)\w+\]?\s*(?:=|in\s+code)`),
		// Catches: process.env[KEY], dangerous env usage
		regexp.MustCompile(`os\.environ\s*\[\w+\]|os\.getenv\s*\(\w+\)\s+(?:without|no)\s+(?:tenant|isolation)`),
		// Catches: os.environ[KEY] in user-facing code
	)

	// Safe patterns - proper tenant handling
	detector.safePatterns = append(detector.safePatterns,
		regexp.MustCompile(`\.filter\s*\([^)]*(?:tenant_id|user_id|owner|organization_id|workspace_id)[^)]*\)`),
		// Catches: .filter(...tenant_id=...), proper scoping
		regexp.MustCompile(`WHERE\s+(?:tenant_id|user_id|org_id|workspace_id|owner_id)\s*=`),
		// Catches: WHERE tenant_id = ..., WHERE user_id = ...
		regexp.MustCompile(`(?:require_tenant|verify_ownership|check_permission|assert.*tenant|assert.*owner)\s*\(`),
		// Catches: require_tenant(), verify_ownership(), etc.
		regexp.MustCompile(`\[.*tenant.*\]\s*(?:\[|=)`),
		// Catches: CACHE[tenant_id][...], proper nesting
		regexp.MustCompile(`(?:getTenant|getCurrentTenant|get_current_user|getCurrentUser)\s*\(`),
		// Catches: getTenant(), getCurrentUser() - context retrieval
	)

	// Context patterns - indicate tenant context is being managed
	detector.contextPatterns = append(detector.contextPatterns,
		regexp.MustCompile(`(?:tenant_context|with_tenant|TenantContext|TenantScope)\s*\(`),
		// Catches: tenant_context(), with_tenant(), context managers
		regexp.MustCompile(`ctx\.Value\s*\(\s*['"]*(?:tenant|user)['"]*\s*\)`),
		// Catches: ctx.Value("tenant"), context retrieval
		regexp.MustCompile(`request\.(?:tenant|user|org|workspace)`),
		// Catches: request.tenant, request.user, etc.
		regexp.MustCompile(`middleware.*tenant|tenant.*middleware`),
		// Catches: middleware that handles tenants
	)

	return detector
}

// Detect analyzes code for cross-tenant data leakage vulnerabilities
func (d *CrossTenantDataLeakageDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	var findings []patterns.Finding
	sourceStr := string(src)
	lines := strings.Split(sourceStr, "\n")

	// Detect language and file type
	lang := d.detectLanguage(filePath, sourceStr)
	isDataAccessFile := d.isDataAccessFile(filePath, sourceStr)

	if !isDataAccessFile {
		// Pattern is most relevant for data access code
		// Still scan but with lower priority
	}

	// 1. Check for ORM calls without tenant filter
	findings = append(findings, d.checkOrmPatterns(sourceStr, lines)...)

	// 2. Check for raw SQL without tenant clause
	findings = append(findings, d.checkRawSqlPatterns(sourceStr, lines)...)

	// 3. Check for global state/cache issues
	findings = append(findings, d.checkGlobalStatePatterns(sourceStr, lines)...)

	// 4. Check for missing ID-to-tenant validation
	findings = append(findings, d.checkMissingValidation(sourceStr, lines, lang)...)

	// 5. Check for unsafe environment variable usage
	findings = append(findings, d.checkEnvironmentUsage(sourceStr, lines, lang)...)

	// Apply confidence scoring based on context
	findings = d.applyContextAwareness(findings, sourceStr, lines, lang)

	return findings, nil
}

// checkOrmPatterns detects ORM calls that lack tenant filtering
func (d *CrossTenantDataLeakageDetector) checkOrmPatterns(source string, lines []string) []patterns.Finding {
	var findings []patterns.Finding

	for i, line := range lines {
		// Skip if line contains safe patterns
		if d.containsSafePattern(line) {
			continue
		}

		// Check each ORM pattern
		for _, pattern := range d.ormPatterns {
			if pattern.MatchString(line) {
				// Verify it's actually a data access line
				if !strings.Contains(line, "//") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
					finding := patterns.Finding{
						PatternID:   "cross_tenant_data_leakage",
						Confidence:  0.85,
						Line:  i + 1,
						Column: 1,
						Severity:    "HIGH",
						Message:     fmt.Sprintf("Potential cross-tenant data access: ORM call lacks tenant filter - %s", strings.TrimSpace(line)),
						Code: strings.TrimSpace(line),
					}
					findings = append(findings, finding)
				}
			}
		}
	}

	return findings
}

// checkRawSqlPatterns detects SQL queries without tenant constraints
func (d *CrossTenantDataLeakageDetector) checkRawSqlPatterns(source string, lines []string) []patterns.Finding {
	var findings []patterns.Finding

	for i, line := range lines {
		// Skip comments and safe patterns
		if strings.HasPrefix(strings.TrimSpace(line), "--") || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}

		if d.containsSafePattern(line) {
			continue
		}

		// Check for SQL patterns
		for _, pattern := range d.sqlPatterns {
			if pattern.MatchString(line) {
				// Additional check: ensure it's actually SQL
				if strings.Contains(strings.ToUpper(line), "SELECT") || strings.Contains(strings.ToUpper(line), "WHERE") {
					finding := patterns.Finding{
						PatternID:   "cross_tenant_data_leakage",
						Confidence:  0.90,
						Line:  i + 1,
						Column: 1,
						Severity:    "CRITICAL",
						Message:     "SQL query with ID filter but no tenant clause detected - enables cross-tenant data access",
						Code: strings.TrimSpace(line),
					}
					findings = append(findings, finding)
				}
			}
		}
	}

	return findings
}

// checkGlobalStatePatterns detects dangerous global caches/state
func (d *CrossTenantDataLeakageDetector) checkGlobalStatePatterns(source string, lines []string) []patterns.Finding {
	var findings []patterns.Finding

	for i, line := range lines {
		if d.containsSafePattern(line) {
			continue
		}

		for _, pattern := range d.globalPatterns {
			if pattern.MatchString(line) {
				// Check if it's actually a problematic global (not a constant data)
				if d.isProblematicGlobal(line, source, i) {
					finding := patterns.Finding{
						PatternID:   "cross_tenant_data_leakage",
						Confidence:  0.75,
						Line:  i + 1,
						Column: 1,
						Severity:    "HIGH",
						Message:     "Global cache/memory detected without tenant scoping - potential data leakage between tenants",
						Code: strings.TrimSpace(line),
					}
					findings = append(findings, finding)
				}
			}
		}
	}

	return findings
}

// checkMissingValidation detects ID-based data access without ownership checks
func (d *CrossTenantDataLeakageDetector) checkMissingValidation(source string, lines []string, lang string) []patterns.Finding {
	var findings []patterns.Finding

	for i, line := range lines {
		// Look for patterns like: data = fetch_by_id(user_input) without validation
		if strings.Contains(line, "by_id") || strings.Contains(line, "ById") || strings.Contains(line, "by-id") {
			// Check if next few lines have validation
			hasValidation := false
			for j := i + 1; j < i+5 && j < len(lines); j++ {
				if d.hasOwnershipCheck(lines[j]) {
					hasValidation = true
					break
				}
			}

			if !hasValidation && d.isDataAccessLine(line) {
				finding := patterns.Finding{
					PatternID:   "cross_tenant_data_leakage",
					Confidence:  0.70,
					Line:  i + 1,
					Column: 1,
					Severity:    "HIGH",
					Message:     "ID-based data access without subsequent ownership/tenant validation detected",
					Code: strings.TrimSpace(line),
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// checkEnvironmentUsage detects unsafe environment variable usage
func (d *CrossTenantDataLeakageDetector) checkEnvironmentUsage(source string, lines []string, lang string) []patterns.Finding {
	var findings []patterns.Finding

	for i, line := range lines {
		// Check for direct env var usage without scoping
		if (strings.Contains(line, "process.env") || strings.Contains(line, "os.environ") || strings.Contains(line, "os.getenv")) &&
			!d.containsSafePattern(line) {

			// Check if it's in a sensitive context (custom code execution, sandbox injection)
			if d.isInSensitiveContext(source, i) {
				finding := patterns.Finding{
					PatternID:   "cross_tenant_data_leakage",
					Confidence:  0.85,
					Line:  i + 1,
					Column: 1,
					Severity:    "CRITICAL",
					Message:     "Environment variables accessed in user code context - all tenants' secrets could be exposed",
					Code: strings.TrimSpace(line),
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// Helper functions

func (d *CrossTenantDataLeakageDetector) detectLanguage(filePath string, source string) string {
	if strings.HasSuffix(filePath, ".py") {
		return "python"
	} else if strings.HasSuffix(filePath, ".go") {
		return "go"
	} else if strings.HasSuffix(filePath, ".js") || strings.HasSuffix(filePath, ".ts") {
		return "javascript"
	} else if strings.HasSuffix(filePath, ".java") {
		return "java"
	}
	return "unknown"
}

func (d *CrossTenantDataLeakageDetector) isDataAccessFile(filePath string, source string) bool {
	lowerPath := strings.ToLower(filePath)
	// Check if file is likely a data access module
	return strings.Contains(lowerPath, "model") ||
		strings.Contains(lowerPath, "repository") ||
		strings.Contains(lowerPath, "service") ||
		strings.Contains(lowerPath, "handler") ||
		strings.Contains(lowerPath, "controller") ||
		strings.Contains(lowerPath, "database") ||
		strings.Contains(lowerPath, "query")
}

func (d *CrossTenantDataLeakageDetector) containsSafePattern(line string) bool {
	for _, pattern := range d.safePatterns {
		if pattern.MatchString(line) {
			return true
		}
	}
	return false
}

func (d *CrossTenantDataLeakageDetector) isProblematicGlobal(line string, source string, lineIdx int) bool {
	// Check if global is used for data caching (not just constants)
	return strings.Contains(line, "=") &&
		!strings.Contains(line, "//") &&
		(strings.Contains(line, "cache") || strings.Contains(line, "CACHE") ||
		 strings.Contains(line, "memory") || strings.Contains(line, "MEMORY") ||
		 strings.Contains(line, "data") && strings.Contains(line, "map"))
}

func (d *CrossTenantDataLeakageDetector) isDataAccessLine(line string) bool {
	keywords := []string{"fetch", "get", "query", "retrieve", "load", "find", "select", "all", "first"}
	lowerLine := strings.ToLower(line)
	for _, kw := range keywords {
		if strings.Contains(lowerLine, kw) {
			return true
		}
	}
	return false
}

func (d *CrossTenantDataLeakageDetector) hasOwnershipCheck(line string) bool {
	checks := []string{"owner", "tenant", "user_id", "user", "authorize", "permission", "access", "check", "verify"}
	lowerLine := strings.ToLower(line)
	for _, check := range checks {
		if strings.Contains(lowerLine, check) {
			return true
		}
	}
	return false
}

func (d *CrossTenantDataLeakageDetector) isInSensitiveContext(source string, lineIdx int) bool {
	// Check if code is in a function that executes user code
	sensitiveContexts := []string{"exec", "eval", "Function(", "sandbox", "custom", "user_code", "plugin"}
	return strings.Contains(source, strings.Join(sensitiveContexts, "|"))
}

func (d *CrossTenantDataLeakageDetector) applyContextAwareness(findings []patterns.Finding, source string, lines []string, lang string) []patterns.Finding {
	var filtered []patterns.Finding

	for _, finding := range findings {
		lineIdx := finding.Line - 1
		confidence := finding.Confidence

		// Check for mitigating factors

		// Factor 1: Is this in a function with explicit tenant context?
		if d.isInTenantContextFunction(source, lineIdx) {
			confidence -= 0.15
		}

		// Factor 2: Is there middleware handling tenants?
		if strings.Contains(source, "middleware") && strings.Contains(source, "tenant") {
			confidence -= 0.10
		}

		// Factor 3: Is this admin-only code?
		if d.isAdminOnlyCode(lines, lineIdx) {
			confidence -= 0.20
		}

		// Factor 4: Is this single-tenant code?
		if d.isSingleTenantCode(source) {
			confidence -= 0.30 // significantly reduce false positives
		}

		// Only include if confidence still high enough
		if confidence >= 0.50 {
			finding.Confidence = confidence
			filtered = append(filtered, finding)
		}
	}

	return filtered
}

func (d *CrossTenantDataLeakageDetector) isInTenantContextFunction(source string, lineIdx int) bool {
	// Look backwards from the line to find function definition
	lines := strings.Split(source, "\n")
	for i := lineIdx; i >= 0 && i > lineIdx-50; i-- {
		if i >= 0 && i < len(lines) {
			line := strings.ToLower(lines[i])
			if strings.Contains(line, "def ") || strings.Contains(line, "func ") {
				// Simple heuristic: if function name has "tenant" or "user" in it
				if strings.Contains(line, "tenant") || strings.Contains(line, "user") {
					return true
				}
				// Found function definition without tenant/user - stop searching
				return false
			}
		}
	}
	return false
}

func (d *CrossTenantDataLeakageDetector) isAdminOnlyCode(lines []string, lineIdx int) bool {
	// Check if code is marked as admin-only
	if lineIdx < 0 || lineIdx >= len(lines) {
		return false
	}
	for i := lineIdx; i >= 0 && i > lineIdx-10; i-- {
		if i >= 0 && i < len(lines) {
			if strings.Contains(strings.ToLower(lines[i]), "admin") ||
				strings.Contains(strings.ToLower(lines[i]), "@admin") ||
				strings.Contains(strings.ToLower(lines[i]), "permission") {
				return true
			}
		}
	}
	return false
}

func (d *CrossTenantDataLeakageDetector) isSingleTenantCode(source string) bool {
	// Check if source code shows signs of being single-tenant
	hasMultiTenantIndicators := strings.Contains(source, "tenant_id") ||
		strings.Contains(source, "user_id") ||
		strings.Contains(source, "organization_id") ||
		strings.Contains(source, "workspace_id") ||
		strings.Contains(source, "org_id")

	return !hasMultiTenantIndicators
}

// GetPattern returns the pattern metadata
func (d *CrossTenantDataLeakageDetector) GetPattern() patterns.Pattern {
	return patterns.Pattern{
		ID:          "cross_tenant_data_leakage",
		Name:        "Cross-Tenant Data Leakage",
		Version:     "1.0",
		Category:    "data_exposure",
		Severity:    "CRITICAL",
		CVSS:        9.5,
		CWEIDs:      []string{"CWE-284", "CWE-862"},
		OWASP:       "A01:2021 Broken Access Control",
		Description: "Detects potential cross-tenant data leakage in multi-tenant agent systems",
	}
}

// GetConfidence returns the confidence score for this detector
func (d *CrossTenantDataLeakageDetector) GetConfidence() float32 {
	return 0.82
}

// Name returns the detector name
func (d *CrossTenantDataLeakageDetector) Name() string {
	return "cross_tenant_data_leakage"
}
