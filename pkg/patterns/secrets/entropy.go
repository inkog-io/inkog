package secrets

import (
	"math"
	"regexp"
	"strings"
	"unicode"
)

// Entropy detection constants
const (
	EntropyThreshold     = 4.5   // Balanced threshold for detection
	MinStringLength      = 16    // Minimum length for entropy analysis
	MaxStringLength      = 256   // Maximum length to analyze
	EntropyConfidence    = 0.75  // Confidence score for entropy findings
)

// stringLiteralRegex matches quoted string literals
var stringLiteralRegex = regexp.MustCompile(`["']([a-zA-Z0-9+/=_\-]{16,256})["']`)

// credentialContextRegex matches variable/key names suggesting credentials in assignment context.
// Requires assignment operator (= or :) after keyword to ensure we match assignments, not prose.
var credentialContextRegex = regexp.MustCompile(`(?i)(api[_-]?key\s*[=:]|_key\s*[=:]|token\s*[=:]|_token\s*[=:]|secret\s*[=:]|_secret\s*[=:]|password\s*[=:]|passwd\s*[=:]|pwd\s*[=:]|auth[_-]?token|credential|private[_-]?key|signing[_-]?key|access[_-]?key)`)

// ShannonEntropy calculates the Shannon entropy of a string
// Returns bits per character (0-8 for byte data)
// Higher entropy indicates more randomness (potential secrets)
func ShannonEntropy(data string) float64 {
	if len(data) == 0 {
		return 0
	}

	// Count character frequencies
	freq := make(map[rune]int)
	for _, c := range data {
		freq[c]++
	}

	// Calculate entropy: -sum(p * log2(p))
	var entropy float64
	length := float64(len(data))
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// EntropyFinding represents a high-entropy string detection
type EntropyFinding struct {
	Line       int
	Column     int
	Value      string
	Entropy    float64
	HasContext bool   // True if found near credential-related keywords
	Severity   string
	Confidence float32
}

// DetectHighEntropyStrings scans content for suspicious high-entropy strings
// that may be secrets not caught by regex patterns.
// filePath is used for file-type-aware threshold adjustment (e.g., JSON files).
func DetectHighEntropyStrings(content []byte, filePath string) []EntropyFinding {
	var findings []EntropyFinding
	lines := strings.Split(string(content), "\n")

	// JSON files have naturally higher-entropy strings (UUIDs, IDs, hashes)
	threshold := EntropyThreshold
	if strings.HasSuffix(strings.ToLower(filePath), ".json") {
		threshold = 5.0
	}

	for lineNum, line := range lines {
		// Find all string literals on this line
		matches := stringLiteralRegex.FindAllStringSubmatchIndex(line, -1)

		for _, match := range matches {
			if len(match) < 4 {
				continue
			}

			// Extract the string value (capture group 1)
			value := line[match[2]:match[3]]

			// Skip if too short or too long
			if len(value) < MinStringLength || len(value) > MaxStringLength {
				continue
			}

			// Calculate entropy
			entropy := ShannonEntropy(value)

			// Check if entropy exceeds threshold
			if entropy < threshold {
				continue
			}

			// Check for credential-like characteristics
			if !looksLikeCredential(value, line) {
				continue
			}

			// Fix 3C: Skip if variable name suggests non-secret (IDs, hashes, models)
			varName := extractAssignmentVariable(line)
			if isNonSecretVariableName(varName) {
				continue
			}

			// Check for context (nearby credential keywords)
			hasContext := credentialContextRegex.MatchString(line)

			// Fix 3A: Require credential context for entropy-only findings.
			// Without a nearby keyword (token, key, secret, password), entropy alone
			// generates too many FPs (Google IDs, UUIDs, model names, hashes).
			if !hasContext {
				// No credential keyword nearby — only flag if value matches known secret format
				if !matchesKnownSecretFormat(value) {
					continue
				}
			}

			// Adjust confidence based on context
			confidence := float32(EntropyConfidence)
			if hasContext {
				confidence = 0.85
			}

			finding := EntropyFinding{
				Line:       lineNum + 1, // Convert to 1-indexed
				Column:     match[2],
				Value:      value,
				Entropy:    entropy,
				HasContext: hasContext,
				Severity:   "MEDIUM",
				Confidence: confidence,
			}

			findings = append(findings, finding)
		}
	}

	// Fix 3D: File-level entropy flood detection.
	// If a file has 15+ entropy findings, it's likely documentation/config, not secrets.
	// Only keep findings with credential context.
	if len(findings) > 15 {
		var filtered []EntropyFinding
		for _, f := range findings {
			if f.HasContext {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	return findings
}

// matchesKnownSecretFormat checks if a high-entropy string matches known secret prefixes/formats.
// This allows flagging secrets even without credential context keywords nearby.
func matchesKnownSecretFormat(value string) bool {
	// AWS Access Key (AKIA...)
	if strings.HasPrefix(value, "AKIA") && len(value) == 20 {
		return true
	}
	// GitHub tokens (ghp_, gho_, ghs_, ghr_, github_pat_)
	if strings.HasPrefix(value, "ghp_") || strings.HasPrefix(value, "gho_") ||
		strings.HasPrefix(value, "ghs_") || strings.HasPrefix(value, "ghr_") ||
		strings.HasPrefix(value, "github_pat_") {
		return true
	}
	// Stripe keys (sk_live_, sk_test_, pk_live_, pk_test_)
	if strings.HasPrefix(value, "sk_live_") || strings.HasPrefix(value, "sk_test_") ||
		strings.HasPrefix(value, "pk_live_") || strings.HasPrefix(value, "pk_test_") {
		return true
	}
	// OpenAI keys (sk-...)
	if strings.HasPrefix(value, "sk-") && len(value) > 20 {
		return true
	}
	// Slack tokens (xoxb-, xoxp-)
	if strings.HasPrefix(value, "xoxb-") || strings.HasPrefix(value, "xoxp-") {
		return true
	}
	// Anthropic keys (sk-ant-)
	if strings.HasPrefix(value, "sk-ant-") {
		return true
	}
	// npm tokens (npm_)
	if strings.HasPrefix(value, "npm_") {
		return true
	}
	// Sendgrid (SG.)
	if strings.HasPrefix(value, "SG.") {
		return true
	}
	// Twilio (SK + 32 hex chars)
	if strings.HasPrefix(value, "SK") && len(value) == 34 && isHexString(value[2:]) {
		return true
	}
	return false
}

// extractAssignmentVariable extracts the variable/key name from an assignment line.
// Handles: VAR_NAME = "value", var_name: "value", "var_name": "value"
func extractAssignmentVariable(line string) string {
	trimmed := strings.TrimSpace(line)
	// Python/Go assignment: var = "value"
	if eqIdx := strings.Index(trimmed, "="); eqIdx > 0 {
		// Skip == comparison
		if eqIdx+1 < len(trimmed) && trimmed[eqIdx+1] == '=' {
			return ""
		}
		return strings.TrimSpace(trimmed[:eqIdx])
	}
	// YAML/JSON key: "var_name": "value" or var_name: "value"
	if colonIdx := strings.Index(trimmed, ":"); colonIdx > 0 {
		key := strings.TrimSpace(trimmed[:colonIdx])
		return strings.Trim(key, "\"'")
	}
	return ""
}

// isNonSecretVariableName checks if a variable name indicates a non-secret value.
// IDs, hashes, models, endpoints, etc. are not secrets even if high-entropy.
func isNonSecretVariableName(varName string) bool {
	if varName == "" {
		return false
	}
	lower := strings.ToLower(varName)
	nonSecretIndicators := []string{
		"_id", "_ids", "_hash", "_checksum", "_digest",
		"_uuid", "_guid", "_model", "_version",
		"_endpoint", "_url", "_uri", "_path", "_dir",
		"_name", "_label", "_title", "_description",
		"sheet_id", "doc_id", "drive_id", "file_id",
		"project_id", "account_id", "resource_id",
		"spreadsheet", "document", "worksheet",
		"model_id", "workflow_id", "node_id", "template_id",
		// Route/view/path suffixes
		"_view", "_route",
		// Model name suffixes
		"_model_id", "_model_name",
	}
	for _, indicator := range nonSecretIndicators {
		if strings.HasSuffix(lower, indicator) || strings.Contains(lower, indicator) {
			return true
		}
	}

	// Exact name matches for common non-secret identifiers
	exactNonSecretNames := map[string]bool{
		"client_id":    true,
		"app_id":       true,
		"project_id":   true,
		"workspace_id": true,
	}
	return exactNonSecretNames[lower]
}

// looksLikeCredential checks if a string has characteristics of a credential
// Returns true if the string appears to be a potential secret
func looksLikeCredential(value, lineContext string) bool {
	// Must have sufficient character variety (not repeated chars)
	if !hasCharacterVariety(value) {
		return false
	}

	// Skip common non-secret patterns
	if isLikelyNonSecret(value, lineContext) {
		return false
	}

	// Check for credential context in the line
	if credentialContextRegex.MatchString(lineContext) {
		return true
	}

	// High entropy alone with good character mix is suspicious
	if hasGoodCharacterMix(value) {
		return true
	}

	return false
}

// hasCharacterVariety checks if string has diverse characters
func hasCharacterVariety(s string) bool {
	uniqueChars := make(map[rune]bool)
	for _, c := range s {
		uniqueChars[c] = true
	}

	// Need at least 8 unique characters for 16+ char string
	return len(uniqueChars) >= 8
}

// hasGoodCharacterMix checks for mix of uppercase, lowercase, digits
func hasGoodCharacterMix(s string) bool {
	var hasUpper, hasLower, hasDigit bool

	for _, c := range s {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsDigit(c):
			hasDigit = true
		}

		// Early exit if all found
		if hasUpper && hasLower && hasDigit {
			return true
		}
	}

	// Need at least 2 of 3 character types
	count := 0
	if hasUpper {
		count++
	}
	if hasLower {
		count++
	}
	if hasDigit {
		count++
	}

	return count >= 2
}

// isHexString checks if a string is entirely hexadecimal characters.
// Requires minimum length of 16 to avoid matching short hex values that could be secrets.
func isHexString(s string) bool {
	if len(s) < 16 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// isLikelyNonSecret checks for patterns that are high-entropy but not secrets
func isLikelyNonSecret(value string, lineContext ...string) bool {
	lower := strings.ToLower(value)

	// Get line context if provided
	ctx := ""
	if len(lineContext) > 0 {
		ctx = lineContext[0]
	}

	// URLs are not secrets (even if they have high entropy from query params)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return true
	}
	// Also catch URLs without protocol that look like domains
	if strings.Contains(lower, ".com/") || strings.Contains(lower, ".io/") ||
		strings.Contains(lower, ".org/") || strings.Contains(lower, ".net/") ||
		strings.Contains(lower, ".dev/") || strings.Contains(lower, "api.") {
		return true
	}

	// Common non-secret patterns
	nonSecretPatterns := []string{
		// UUIDs (legitimate identifiers)
		"-4[0-9a-f]{3}-",
		// Base64 encoded common strings
		"aaaa", "bbbb", "cccc",
		// Lorem ipsum
		"lorem", "ipsum",
		// Test data
		"test", "example", "sample", "demo",
		// Sequential patterns
		"0123456789", "abcdefgh",
	}

	for _, pattern := range nonSecretPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	// Tool call IDs (call_XXXX pattern from OpenAI)
	if strings.HasPrefix(value, "call_") && len(value) < 30 {
		return true
	}

	// PostHog-style public analytics keys
	if strings.HasPrefix(lower, "phc_") || strings.HasPrefix(lower, "ph_") {
		return true
	}

	// Chatflow/workflow node IDs (Flowise format)
	if strings.Contains(value, "-input-") || strings.Contains(value, "-output-") {
		return true
	}

	// TypeORM/migration class names (CamelCase + 13-digit timestamp)
	if isMigrationClassName(value) {
		return true
	}

	// Pure hex strings (SHA hashes, checksums, git commit SHAs)
	// e.g., "a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9"
	if isHexString(value) {
		return true
	}

	// SRI integrity hashes (sha256-XXXXX, sha384-XXXXX, sha512-XXXXX)
	// Used in web security (Content-Security-Policy, <script integrity>)
	if strings.HasPrefix(lower, "sha256-") || strings.HasPrefix(lower, "sha384-") ||
		strings.HasPrefix(lower, "sha512-") {
		return true
	}

	// n8n-style sentinel/constant values — workflow node IDs with predictable patterns
	if strings.HasPrefix(lower, "n8n_") || strings.HasPrefix(lower, "workflow_") {
		return true
	}

	// __n8n_ sentinel values (internal n8n markers)
	if strings.HasPrefix(lower, "__n8n_") {
		return true
	}

	// OAuth client IDs: start with "client_" followed by 25+ alphanumeric chars
	// These are identifiers, not secrets
	if strings.HasPrefix(lower, "client_") && len(value) >= 32 {
		isAlphaNum := true
		for _, c := range value[7:] {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
				isAlphaNum = false
				break
			}
		}
		if isAlphaNum {
			return true
		}
	}

	// Base64-padded content (ends with = or ==, common in config/data files)
	// Only skip if the line context suggests data, not a secret assignment
	if (strings.HasSuffix(value, "==") || strings.HasSuffix(value, "=")) &&
		!credentialContextRegex.MatchString(ctx) {
		return true
	}

	// Hash context in surrounding line — if the line mentions hash/checksum keywords,
	// the value is likely a hash output, not a secret
	if ctx != "" {
		lowerCtx := strings.ToLower(ctx)
		hashKeywords := []string{"hash", "sha1", "sha256", "sha512", "checksum", "digest", "integrity", "fingerprint", "md5", "hmac"}
		for _, kw := range hashKeywords {
			if strings.Contains(lowerCtx, kw) {
				return true
			}
		}
	}

	// Model path IDs: strings containing /models/ or accounts/ or projects/
	// e.g., "accounts/fireworks/models/llama-v3p1-8b-instruct"
	if strings.Contains(lower, "/models/") || strings.Contains(lower, "accounts/") || strings.Contains(lower, "projects/") {
		return true
	}

	// UUID format: 36 chars with dashes at positions 8,13,18,23 (RFC 4122)
	if len(value) == 36 && value[8] == '-' && value[13] == '-' && value[18] == '-' && value[23] == '-' {
		return true
	}

	// Route/path strings: multiple URL path segments (e.g., "/api/v1/users/create")
	if strings.Count(value, "/") >= 3 {
		return true
	}

	// Version-like strings (semver): e.g., "1.2.3", "v2.0.0-beta.1"
	if len(value) < 30 && (strings.HasPrefix(lower, "v") || (value[0] >= '0' && value[0] <= '9')) &&
		strings.Count(value, ".") >= 2 {
		// Rough semver check: contains digits and dots
		isSemver := true
		for _, c := range value {
			if !((c >= '0' && c <= '9') || c == '.' || c == '-' || c == '+' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_') {
				isSemver = false
				break
			}
		}
		if isSemver {
			return true
		}
	}

	// Context-based skips: schema/example/placeholder/description/locale/i18n
	if ctx != "" {
		lowerCtx := strings.ToLower(ctx)
		contextSkipKeywords := []string{
			"example", "schema", "placeholder", "default", "description",
			"locale", "i18n", "translation", "message", "label",
			"model", "version", "revision",
		}
		for _, kw := range contextSkipKeywords {
			if strings.Contains(lowerCtx, kw) {
				return true
			}
		}
	}

	// Check for repeated substrings (likely not a secret)
	if hasRepeatedPatterns(value) {
		return true
	}

	return false
}

// isMigrationClassName checks if a value looks like a TypeORM migration class name
// e.g., "CreateUsersTable1672531200000" (CamelCase prefix + 13-digit Unix timestamp)
func isMigrationClassName(value string) bool {
	if len(value) < 20 {
		return false
	}
	digitSuffix := 0
	for i := len(value) - 1; i >= 0; i-- {
		if value[i] >= '0' && value[i] <= '9' {
			digitSuffix++
		} else {
			break
		}
	}
	// TypeORM timestamps are 13 digits (Unix ms)
	if digitSuffix >= 10 {
		prefix := value[:len(value)-digitSuffix]
		// Must start with uppercase (CamelCase class name)
		if len(prefix) > 0 && prefix[0] >= 'A' && prefix[0] <= 'Z' {
			return true
		}
	}
	return false
}

// hasRepeatedPatterns checks for repeated substrings
func hasRepeatedPatterns(s string) bool {
	if len(s) < 8 {
		return false
	}

	// Check for 4-char patterns that repeat
	for i := 0; i < len(s)-8; i++ {
		pattern := s[i : i+4]
		rest := s[i+4:]
		if strings.Count(rest, pattern) >= 2 {
			return true
		}
	}

	return false
}

// ConvertEntropyToSecretFinding converts an EntropyFinding to SecretFinding
func ConvertEntropyToSecretFinding(ef EntropyFinding) SecretFinding {
	description := "High-Entropy String (Potential Secret)"
	if ef.HasContext {
		description = "High-Entropy String in Credential Context"
	}

	return SecretFinding{
		Type:        "entropy_secret",
		Description: description,
		Line:        ef.Line,
		Column:      ef.Column,
		Value:       ef.Value,
		Severity:    ef.Severity,
		Confidence:  ef.Confidence,
		Pattern:     "entropy_detection",
	}
}

// IsDuplicateOfRegexFinding checks if an entropy finding overlaps with regex findings
func IsDuplicateOfRegexFinding(ef EntropyFinding, regexFindings []SecretFinding) bool {
	for _, rf := range regexFindings {
		// Same line and overlapping columns indicates duplicate
		if rf.Line == ef.Line {
			// Check if the values overlap
			if strings.Contains(rf.Value, ef.Value) || strings.Contains(ef.Value, rf.Value) {
				return true
			}
			// Check column proximity (within 20 chars)
			if abs(rf.Column-ef.Column) < 20 {
				return true
			}
		}
	}
	return false
}

// abs returns absolute value of an int
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
