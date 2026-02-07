package secrets

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ShouldSkipFile returns true if the file should be excluded from secret REPORTING
// (findings are suppressed, but redaction still happens via DetectSecretsForRedaction)
func ShouldSkipFile(filePath string) bool {
	lower := strings.ToLower(filePath)
	base := strings.ToLower(filepath.Base(filePath))

	// Minified/bundled JS files
	if strings.HasSuffix(base, ".min.js") || strings.HasSuffix(base, ".bundle.js") {
		return true
	}

	// Check for large minified JS (line > 10K chars)
	if strings.HasSuffix(base, ".js") && hasLongLine(filePath, 10000) {
		return true
	}

	// Test files by path pattern
	testPathPatterns := []string{
		"/tests/", "/__tests__/", "/test_", "/_test/",
		"/fixtures/", "/mocks/", "/testdata/", "/test-data/",
		"/mock_", "/__mocks__/", "/__fixtures__/",
		// Benchmark & mock data (eliminates n8n mockApiData FPs)
		"/benchmark/", "/benchmarks/", "/mock-api/", "/mappings/",
		// Documentation example directories
		"/docs/examples/", "/doc/examples/",
		// Database migration files (class name entropy FPs)
		"/migrations/",
		// E2E/integration test dirs
		"/playwright/", "/e2e/", "/cypress/",
		// Examples dirs (for secret reporting only — redaction still happens)
		"/examples/",
	}
	for _, pattern := range testPathPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	// Test files by filename suffix
	testSuffixes := []string{
		"_test.go", "_test.py", ".test.ts", ".test.js",
		".spec.ts", ".spec.js", ".test.tsx", ".test.jsx",
		".spec.tsx", ".spec.jsx",
		// Jupyter notebooks — almost entirely documentation/example code
		".ipynb",
	}
	for _, suffix := range testSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}

	// Swagger/OpenAPI documentation files
	if base == "swagger.yml" || base == "swagger.yaml" ||
		base == "openapi.yml" || base == "openapi.yaml" {
		return true
	}

	return false
}

// hasLongLine checks if any line in a file exceeds maxLen characters
// Uses buffered reading to avoid loading the whole file
func hasLongLine(filePath string, maxLen int) bool {
	f, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// Increase scanner buffer to handle long lines
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	lineCount := 0
	for scanner.Scan() {
		lineCount++
		if len(scanner.Text()) > maxLen {
			return true
		}
		// Only check first 5 lines (minified files have it on line 1-2)
		if lineCount >= 5 {
			break
		}
	}
	return false
}

// placeholderValues are common non-secret values that trigger FPs
var placeholderValues = map[string]bool{
	"password":           true,
	"pass":               true,
	"secret":             true,
	"changeme":           true,
	"example":            true,
	"placeholder":        true,
	"your_password_here": true,
	"your_password":      true,
	"your_secret":        true,
	"your_api_key":       true,
	"xxx":                true,
	"xxxxxx":             true,
	"xxxxxxxx":           true,
	"test":               true,
	"testing":            true,
	"default":            true,
	"foobar":             true,
	"changeit":           true,
	"admin":              true,
	"root":               true,
	"none":               true,
	"null":               true,
	"undefined":          true,
	"replace_me":         true,
	"todo":               true,
	"fixme":              true,
	"dummy":              true,
	"fake":               true,
	"mock":               true,
	"sample":             true,
	"my_password":        true,
	"my_secret":          true,
	"giteapassword":      true,
	"adminpassword":      true,
	"testpassword":       true,
	"mysecret":           true,
	"mypassword":         true,
	"not-needed":         true,
	"nopassword":         true,
	"passw0rd":           true,
	"qwerty":             true,
	"letmein":            true,
	"trustno1":           true,
}

// placeholderPatterns match common FP value patterns
var placeholderPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^(test_?|mock_?|fake_?|dummy_?|sample_?|example_?)`),
	regexp.MustCompile(`(?i)^your[_-]`),
	regexp.MustCompile(`\.{3,}`),
	regexp.MustCompile(`(?i)^[x]{3,}$`),
	regexp.MustCompile(`^<[^>]+>$`),
	regexp.MustCompile(`(?i)^(TODO|FIXME|CHANGEME|REPLACE)`),
	regexp.MustCompile(`^[\*]{3,}$`),
	regexp.MustCompile(`^\$\{[^}]+\}$`),
	// Truncated API key prefixes in docs (sk-ant-..., sk-proj-...)
	regexp.MustCompile(`(?i)^(sk|pk)[-_](ant|proj|live|test)[-_]\.{2,}`),
	// ALL_CAPS_UNDERSCORE env var names — must contain underscore to distinguish
	// from actual credential values like AKIA1234567890123456
	regexp.MustCompile(`^[A-Z][A-Z0-9]*_[A-Z0-9_]{3,}$`),
	// user:password@ in connection string templates
	regexp.MustCompile(`(?i)^(user|username|admin|postgres|root):(password|pass|secret|admin|postgres|root)$`),
}

// IsPlaceholderValue returns true if the value looks like a placeholder, not a real secret
func IsPlaceholderValue(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))

	// Exact match against known placeholders
	if placeholderValues[lower] {
		return true
	}

	// Pattern match
	for _, p := range placeholderPatterns {
		if p.MatchString(value) {
			return true
		}
	}

	// Connection string doc patterns: user:password@host
	if strings.Contains(lower, "user:password@") || strings.Contains(lower, "username:password@") {
		return true
	}

	return false
}

// fieldNameIndicators suggest the matched value is a field name, not a credential
var fieldNameIndicators = []string{
	"_NAME", "_FIELD", "_KEY_NAME", "_COLUMN", "_ATTR", "_LABEL",
	"_HEADER", "_PARAM", "_TYPE", "_FORMAT",
}

// AdjustConfidence adjusts the confidence of a finding based on context
// Returns the modified finding (confidence may be lowered)
func AdjustConfidence(finding SecretFinding, lineText string, filePath string) SecretFinding {
	upperLine := strings.ToUpper(strings.TrimSpace(lineText))

	// Field name constant: FIELD_NAME_PASSWORD = "password"
	for _, indicator := range fieldNameIndicators {
		if strings.Contains(upperLine, indicator) {
			finding.Confidence *= 0.1
			return finding
		}
	}

	// Comment or docstring line
	trimmed := strings.TrimSpace(lineText)
	if strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "//") ||
		strings.HasPrefix(trimmed, "*") ||
		strings.HasPrefix(trimmed, "\"\"\"") ||
		strings.HasPrefix(trimmed, "'''") {
		finding.Confidence *= 0.3
		return finding
	}

	// Notebook files get a heavy confidence reduction (ensures drop below 0.4 threshold)
	if strings.HasSuffix(strings.ToLower(filePath), ".ipynb") {
		finding.Confidence *= 0.2
	}

	lowerPath := strings.ToLower(filePath)

	// JSON/YAML in marketplace/chatflow/workflow dirs — config data, not secrets
	if (strings.HasSuffix(lowerPath, ".json") || strings.HasSuffix(lowerPath, ".yml") ||
		strings.HasSuffix(lowerPath, ".yaml")) &&
		(strings.Contains(lowerPath, "/marketplace") || strings.Contains(lowerPath, "/chatflow") ||
			strings.Contains(lowerPath, "/workflow")) {
		finding.Confidence *= 0.3
	}

	// LangChain lc_secrets getter pattern — maps to env var names, not actual keys
	if strings.Contains(lineText, "lc_secrets") || strings.Contains(lineText, "lc_aliases") {
		finding.Confidence *= 0.1
	}

	return finding
}
