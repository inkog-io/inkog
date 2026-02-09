package secrets

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
)

// SecretPattern defines a reusable secret detection pattern
type SecretPattern struct {
	Name        string // api_key, aws_key, password, etc.
	Description string
	Patterns    []*regexp.Regexp
	Severity    string // CRITICAL, HIGH, MEDIUM
	Confidence  float32
	CWE         string
	OWASP       string
}

// SecretFinding represents a detected secret
type SecretFinding struct {
	Type        string // Pattern name (api_key, aws_key, etc.)
	Description string
	Line        int
	Column      int
	Value       string // The secret itself (for local processing only)
	Severity    string
	Confidence  float32
	Pattern     string // The regex pattern that matched
}

// PatternDefinitions contains all reusable secret detection patterns
// These are shared between CLI and Server to ensure consistency
var PatternDefinitions = map[string]*SecretPattern{
	"api_key": {
		Name:        "api_key",
		Description: "Generic API Key Pattern",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9\-_]{20,})["\']`),
			regexp.MustCompile(`(?i)api_secret\s*[:=]\s*["\']([a-zA-Z0-9\-_]{20,})["\']`),
		},
		Severity:   "CRITICAL",
		Confidence: 0.95,
		CWE:        "CWE-798",
		OWASP:      "A02:2021",
	},
	"aws_access_key": {
		Name:        "aws_access_key",
		Description: "AWS Access Key ID",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		},
		Severity:   "CRITICAL",
		Confidence: 0.99,
		CWE:        "CWE-798",
		OWASP:      "A02:2021",
	},
	"aws_secret_key": {
		Name:        "aws_secret_key",
		Description: "AWS Secret Access Key",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)aws_secret_access_key\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']`),
		},
		Severity:   "CRITICAL",
		Confidence: 0.95,
		CWE:        "CWE-798",
		OWASP:      "A02:2021",
	},
	"private_key": {
		Name:        "private_key",
		Description: "Private Key (RSA, DSA, EC)",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----`),
			regexp.MustCompile(`-----BEGIN PRIVATE KEY-----`),
		},
		Severity:   "CRITICAL",
		Confidence: 0.99,
		CWE:        "CWE-798",
		OWASP:      "A02:2021",
	},
	"github_token": {
		Name:        "github_token",
		Description: "GitHub Personal Access Token or OAuth Token",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`ghp_[a-zA-Z0-9_]{36}`),
			regexp.MustCompile(`gho_[a-zA-Z0-9_]{36}`),
			regexp.MustCompile(`ghu_[a-zA-Z0-9_]{36}`),
		},
		Severity:   "CRITICAL",
		Confidence: 0.99,
		CWE:        "CWE-798",
		OWASP:      "A02:2021",
	},
	"slack_token": {
		Name:        "slack_token",
		Description: "Slack API Token or Bot Token",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`xox[baprs]-([0-9]{10,13})-([0-9]{10,24})-([a-zA-Z0-9\-_]{26,34})`),
		},
		Severity:   "CRITICAL",
		Confidence: 0.99,
		CWE:        "CWE-798",
		OWASP:      "A02:2021",
	},
	"database_password": {
		Name:        "database_password",
		Description: "Database Connection String with Password",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(mysql|postgres|mongodb|sql)://[a-zA-Z0-9]+:([a-zA-Z0-9\-_!@#$%^&*()]+)@`),
			// Require value to be 8+ chars to filter out "password", "pass", etc.
			regexp.MustCompile(`(?i)password\s*[:=]\s*["\']([a-zA-Z0-9\-_!@#$%^&*()+=]{8,})["\']`),
		},
		Severity:   "CRITICAL",
		Confidence: 0.90,
		CWE:        "CWE-798",
		OWASP:      "A02:2021",
	},
	"jwt_token": {
		Name:        "jwt_token",
		Description: "JSON Web Token (JWT)",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{50,}\.eyJ[a-zA-Z0-9_-]{50,}\.[a-zA-Z0-9_-]{40,}`),
		},
		Severity:   "HIGH",
		Confidence: 0.85,
		CWE:        "CWE-798",
		OWASP:      "A02:2021",
	},
	"stripe_key": {
		Name:        "stripe_key",
		Description: "Stripe API Key",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`sk_live_[a-zA-Z0-9]{24,}`),
			regexp.MustCompile(`pk_live_[a-zA-Z0-9]{24,}`),
			regexp.MustCompile(`sk_test_[a-zA-Z0-9]{24,}`),
			regexp.MustCompile(`pk_test_[a-zA-Z0-9]{24,}`),
		},
		Severity:   "CRITICAL",
		Confidence: 0.99,
		CWE:        "CWE-798",
		OWASP:      "A02:2021",
	},
	"sendgrid_api_key": {
		Name:        "sendgrid_api_key",
		Description: "SendGrid API Key",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`SG\.[a-zA-Z0-9_-]{60,}`),
		},
		Severity:   "CRITICAL",
		Confidence: 0.95,
		CWE:        "CWE-798",
		OWASP:      "A02:2021",
	},
	"nonce_seed": {
		Name:        "nonce_seed",
		Description: "High Entropy String (Potential Secret/Nonce)",
		Patterns: []*regexp.Regexp{
			// Narrowed keywords: removed "key" and "token" to avoid overlap with API key patterns.
			// "secret" is kept because "secret = '<value>'" is a strong signal for hardcoded secrets.
			regexp.MustCompile(`(?i)\b(secret|nonce|seed|salt|pepper|passwd|passphrase|private_key|signing_key|encryption_key)\s*[:=]\s*["\']([a-zA-Z0-9\-_!@#$%^&*()+=]{32,})["\']`),
		},
		Severity:   "MEDIUM",
		Confidence: 0.70,
		CWE:        "CWE-798",
		OWASP:      "A02:2021",
	},
	"entropy_secret": {
		Name:        "entropy_secret",
		Description: "High-Entropy String (Potential Secret)",
		Patterns:    []*regexp.Regexp{}, // Detected via entropy analysis, not regex
		Severity:    "MEDIUM",
		Confidence:  0.75,
		CWE:         "CWE-798",
		OWASP:       "A02:2021",
	},
}

// DetectSecrets scans content for hardcoded secrets with FP filtering.
// Used for REPORTING findings to the user. Test files, placeholders, and
// low-confidence context matches are filtered out.
// For redaction (privacy), use DetectSecretsForRedaction which returns ALL findings.
func DetectSecrets(filePath string, content []byte) []SecretFinding {
	// Layer 1: File-level skip (test files, minified JS, fixtures)
	if ShouldSkipFile(filePath) {
		return nil
	}

	// Get raw findings
	allFindings := detectSecretsRaw(content, filePath)

	// Layer 2+3: Filter each finding
	lines := strings.Split(string(content), "\n")
	var filtered []SecretFinding
	for _, f := range allFindings {
		// Layer 2: Placeholder check
		if IsPlaceholderValue(f.Value) {
			continue
		}

		// Layer 2.5: Docstring check (applies to all finding types)
		if f.Line > 0 && isInsideDocstring(f.Line-1, lines) {
			continue
		}

		// Layer 2.7: Adjacent-line context for private_key/PEM — check if preceding lines
		// contain "placeholder", "description", or "example" keywords (credential form fields)
		if f.Type == "private_key" {
			if isAdjacentLineContext(f.Line-1, lines, []string{"placeholder", "description", "example", "format"}) {
				continue
			}
		}

		// Layer 3: Context-aware confidence adjustment
		lineText := ""
		if f.Line > 0 && f.Line <= len(lines) {
			lineText = lines[f.Line-1]
		}
		f = AdjustConfidence(f, lineText, filePath)
		if f.Confidence >= 0.4 {
			filtered = append(filtered, f)
		}
	}

	return filtered
}

// DetectSecretsForRedaction scans content for ALL potential secrets without filtering.
// Used by the redaction pipeline to ensure privacy — even FP-filtered values get redacted.
func DetectSecretsForRedaction(filePath string, content []byte) []SecretFinding {
	return detectSecretsRaw(content, filePath)
}

// detectSecretsRaw performs unfiltered detection (regex + entropy)
func detectSecretsRaw(content []byte, filePath string) []SecretFinding {
	// Step 1: Detect secrets using regex patterns
	regexFindings := detectByRegex(content)

	// Step 2: Detect high-entropy strings that may be secrets
	entropyFindings := DetectHighEntropyStrings(content, filePath)

	// Step 3: Merge findings, avoiding duplicates
	var allFindings []SecretFinding
	allFindings = append(allFindings, regexFindings...)

	for _, ef := range entropyFindings {
		// Skip if already detected by regex
		if !IsDuplicateOfRegexFinding(ef, regexFindings) {
			allFindings = append(allFindings, ConvertEntropyToSecretFinding(ef))
		}
	}

	return allFindings
}

// detectByRegex performs regex-based secret detection
func detectByRegex(content []byte) []SecretFinding {
	var findings []SecretFinding
	lines := strings.Split(string(content), "\n")

	for lineNum, line := range lines {
		for patternName, patternDef := range PatternDefinitions {
			// Skip entropy_secret pattern (handled separately)
			if patternName == "entropy_secret" {
				continue
			}

			for _, pattern := range patternDef.Patterns {
				matches := pattern.FindAllStringSubmatchIndex(line, -1)
				for _, match := range matches {
					// match[0:2] is the full match, match[2:4] is group 1, match[4:6] is group 2, etc.
					if len(match) >= 2 {
						secret := line[match[0]:match[1]]
						// Extract the LAST capture group (the actual secret value, not the key name)
						value := secret
						if len(match) >= 4 {
							lastGroupIdx := len(match) - 2
							value = line[match[lastGroupIdx]:match[lastGroupIdx+1]]
						}

						// Filter api_key FPs: skip if the matched value is an ALL_CAPS env var name
						if patternName == "api_key" && isAllCapsEnvVarName(value) {
							continue
						}

						// Filter api_key FPs: skip if line references env var getter
						if patternName == "api_key" && isEnvVarReference(line) {
							continue
						}

						// Filter api_key FPs: skip public/publishable key prefixes (not secrets)
						if patternName == "api_key" && hasPublicKeyPrefix(value) {
							continue
						}

						// Filter api_key FPs: skip Algolia/DocSearch search-only key contexts
						// Single-line check first, then multi-line context (appId on different line)
						if patternName == "api_key" && isAlgoliaSearchContext(line) {
							continue
						}
						if patternName == "api_key" && isAlgoliaSearchContextMultiLine(lineNum, lines) {
							continue
						}

						// Filter api_key FPs: skip sentinel/identifier values (not real secrets)
						// e.g., "data-public-amplitude-api-key" (HTML attr name, not a key value)
						if patternName == "api_key" && isSentinelOrIdentifierValue(value) {
							continue
						}

						// Filter api_key FPs: skip pure hex values (public search keys, hashes)
						if patternName == "api_key" && isHexOnlyValue(value) {
							continue
						}

						// Filter stripe_key FPs: pk_ prefixes are publishable (public) keys, not secrets
						if patternName == "stripe_key" && (strings.HasPrefix(value, "pk_live_") || strings.HasPrefix(value, "pk_test_")) {
							continue
						}

						// Filter FPs: skip lines inside Python docstring blocks
						if isInsideDocstring(lineNum, lines) {
							continue
						}

						// Filter private_key FPs: skip if the line is a comment/docstring
						if patternName == "private_key" && isCommentLine(line) {
							continue
						}

						// Filter private_key FPs: skip PEM header/footer constants used for parsing
						// e.g., const pemHeader = '-----BEGIN PRIVATE KEY-----'
						if patternName == "private_key" && isPEMParsingConstant(line) {
							continue
						}

						// Filter database_password FPs: skip default dev/Docker database passwords
						// e.g., postgres://postgres:postgres@langgraph-postgres:5432/postgres
						if patternName == "database_password" && isDefaultDatabasePassword(line) {
							continue
						}

						// Filter database_password FPs: skip sentinel/identifier values
						if patternName == "database_password" && isSentinelOrIdentifierValue(value) {
							continue
						}
						if patternName == "database_password" && isHumanReadableIdentifier(value) {
							continue
						}

						finding := SecretFinding{
							Type:        patternName,
							Description: patternDef.Description,
							Line:        lineNum + 1, // Convert to 1-indexed
							Column:      match[0],
							Value:       value,
							Severity:    patternDef.Severity,
							Confidence:  patternDef.Confidence,
							Pattern:     patternDef.Name,
						}
						findings = append(findings, finding)
					}
				}
			}
		}
	}

	return findings
}

// isAllCapsEnvVarName checks if a value looks like an ALL_CAPS environment variable name
// (not an actual secret value). E.g., "OPENAI_API_KEY" is a name, not a key.
func isAllCapsEnvVarName(value string) bool {
	if len(value) < 5 || !strings.Contains(value, "_") {
		return false
	}
	for _, c := range value {
		if c != '_' && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// isEnvVarReference checks if a line contains an environment variable getter pattern.
// These lines reference env var names as values, not actual secrets.
func isEnvVarReference(line string) bool {
	lower := strings.ToLower(line)
	return strings.Contains(lower, "os.environ") ||
		strings.Contains(lower, "os.getenv") ||
		strings.Contains(lower, "process.env") ||
		strings.Contains(lower, "env.get(") ||
		strings.Contains(lower, "getenv(")
}

// isCommentLine checks if a line is a code comment or docstring
func isCommentLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "//") ||
		strings.HasPrefix(trimmed, "*") ||
		strings.HasPrefix(trimmed, "/*") ||
		strings.HasPrefix(trimmed, "\"\"\"") ||
		strings.HasPrefix(trimmed, "'''") ||
		strings.HasPrefix(trimmed, "<!--")
}

// isPEMParsingConstant checks if a line contains a PEM header/footer constant used for
// parsing rather than an actual private key. These constants are used in code that parses
// PEM-encoded certificates/keys, not code that embeds actual secrets.
// Only matches when the line has a variable assignment or function call context,
// NOT when the PEM header appears alone (which could be an actual key file).
func isPEMParsingConstant(line string) bool {
	trimmed := strings.TrimSpace(line)
	lower := strings.ToLower(trimmed)

	// Must have an assignment or function call context — a bare PEM header
	// (e.g., "-----BEGIN RSA PRIVATE KEY-----") is a real key, not parsing code
	hasAssignment := strings.Contains(trimmed, "=")
	hasFunctionCall := strings.Contains(lower, "replace(") || strings.Contains(lower, "strip(") ||
		strings.Contains(lower, "split(") || strings.Contains(lower, "remove(") ||
		strings.Contains(lower, "index(") || strings.Contains(lower, "find(")
	if !hasAssignment && !hasFunctionCall {
		return false
	}

	// Check if the variable name or context indicates PEM parsing
	// e.g., PEM_HEADER = '-----BEGIN PRIVATE KEY-----'
	//        const pemHeader = '-----BEGIN PRIVATE KEY-----';
	parsingIndicators := []string{
		"header", "footer", "prefix", "suffix",
		"marker", "delimiter", "format", "pem",
	}
	for _, indicator := range parsingIndicators {
		if strings.Contains(lower, indicator) {
			return true
		}
	}

	// Function calls that process PEM strings (not store them)
	if hasFunctionCall {
		return true
	}

	// Variable name is UPPER_CASE constant (e.g., PEM_HEADER, KEY_BEGIN)
	if eqIdx := strings.Index(trimmed, "="); eqIdx > 0 {
		varPart := strings.TrimSpace(trimmed[:eqIdx])
		// Remove const/let/var/export keywords
		for _, kw := range []string{"const ", "let ", "var ", "export "} {
			varPart = strings.TrimPrefix(varPart, kw)
		}
		varPart = strings.TrimSpace(varPart)
		if len(varPart) > 3 && isAllUpperOrUnderscore(varPart) {
			return true
		}
	}

	return false
}

// isAllUpperOrUnderscore returns true if the string contains only uppercase letters and underscores.
func isAllUpperOrUnderscore(s string) bool {
	for _, c := range s {
		if c != '_' && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}

// isDefaultDatabasePassword checks if a line contains a default dev/Docker database password
// in a connection string. These are safe to skip because they use well-known default credentials
// against local/containerized databases, not production secrets.
func isDefaultDatabasePassword(line string) bool {
	lower := strings.ToLower(line)

	// Default passwords in connection strings with dev/Docker hosts
	defaultPasswords := []string{
		"postgres", "password", "root", "admin", "test",
		"changeme", "example", "secret", "default", "dev",
	}
	devHosts := []string{
		"localhost", "127.0.0.1", "docker", "container",
		"langgraph-", "compose", "devcontainer",
	}

	// Require both a dev host and a default password in the same line
	hasDevHost := false
	for _, host := range devHosts {
		if strings.Contains(lower, host) {
			hasDevHost = true
			break
		}
	}
	if !hasDevHost {
		return false
	}

	// Check for default password in connection string pattern ":password@"
	for _, pwd := range defaultPasswords {
		if strings.Contains(lower, ":"+pwd+"@") {
			return true
		}
	}

	return false
}

// publicKeyPrefixes are key prefixes that indicate public/publishable keys, not secrets.
var publicKeyPrefixes = []string{
	"phc_",              // PostHog (public analytics key)
	"pk_live_",          // Stripe publishable key (live)
	"pk_test_",          // Stripe publishable key (test)
	"ALGOLIASEARCH_",    // Algolia search-only key
	"DOCSEARCH_",        // Algolia DocSearch key
}

// hasPublicKeyPrefix returns true if the value starts with a known public key prefix.
// These are not secrets — they are designed to be embedded in client-side code.
func hasPublicKeyPrefix(value string) bool {
	for _, prefix := range publicKeyPrefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

// isAlgoliaSearchContext returns true if the line (or surrounding lines) looks like an
// Algolia/DocSearch config where apiKey is a search-only key (not a secret).
// Supports multi-line detection: in JS objects, appId and apiKey are often on different lines.
func isAlgoliaSearchContext(line string) bool {
	lower := strings.ToLower(line)
	// DocSearch/Algolia configs pair appId with apiKey on the same line
	if (strings.Contains(lower, "appid") || strings.Contains(lower, "app_id")) &&
		(strings.Contains(lower, "apikey") || strings.Contains(lower, "api_key")) {
		return true
	}
	// Algolia search config context on same line
	if strings.Contains(lower, "docsearch") || strings.Contains(lower, "algolia") {
		if strings.Contains(lower, "apikey") || strings.Contains(lower, "api_key") {
			return true
		}
	}
	return false
}

// isAlgoliaSearchContextMultiLine checks if the apiKey line is part of an Algolia/DocSearch
// config by examining surrounding lines. In JS objects, appId and apiKey are typically
// within 5 lines of each other.
func isAlgoliaSearchContextMultiLine(lineIndex int, lines []string) bool {
	// Check ±5 lines for Algolia/DocSearch indicators
	for offset := -5; offset <= 5; offset++ {
		checkIdx := lineIndex + offset
		if checkIdx < 0 || checkIdx >= len(lines) || checkIdx == lineIndex {
			continue
		}
		lower := strings.ToLower(lines[checkIdx])
		// Look for Algolia/DocSearch context markers
		if strings.Contains(lower, "algolia") || strings.Contains(lower, "docsearch") ||
			strings.Contains(lower, "appid") || strings.Contains(lower, "app_id") ||
			strings.Contains(lower, "indexname") || strings.Contains(lower, "index_name") {
			// Verify this is in a search/doc context (not a generic API key)
			if strings.Contains(lower, "algolia") || strings.Contains(lower, "docsearch") ||
				strings.Contains(lower, "appid") || strings.Contains(lower, "indexname") {
				return true
			}
		}
	}
	return false
}

// isSentinelOrIdentifierValue checks if a matched value looks like a sentinel string,
// identifier, or human-readable placeholder rather than a real secret.
// Examples: "litellm_proxy_master_key", "reworkd_platform", "data-public-amplitude-api-key"
func isSentinelOrIdentifierValue(value string) bool {
	// HTML data attribute names: start with "data-" (these are DOM attribute names, not values)
	if strings.HasPrefix(value, "data-") {
		return true
	}

	// All-lowercase-with-underscores/hyphens that look like identifiers (no entropy)
	// Real secrets have mixed case, digits, special chars. Pure identifiers don't.
	if isHumanReadableIdentifier(value) {
		return true
	}

	return false
}

// isHumanReadableIdentifier checks if a value looks like a human-readable identifier
// (package name, service name, placeholder alias) rather than a real secret.
// Returns true for values like "litellm_proxy_master_key", "reworkd_platform".
// Returns false for secret-like values like "sk_live_abcdef1234567890abcd".
func isHumanReadableIdentifier(value string) bool {
	if len(value) < 8 {
		return false
	}

	// Must be all lowercase letters, digits, underscores, and hyphens
	hasLetter := false
	hasSeparator := false
	for _, c := range value {
		if c >= 'a' && c <= 'z' {
			hasLetter = true
		} else if c == '_' || c == '-' {
			hasSeparator = true
		} else if c >= '0' && c <= '9' {
			// digits OK
		} else {
			return false // uppercase, special chars → not a simple identifier
		}
	}

	// Must have both letters and separators (to be a compound identifier)
	if !hasLetter || !hasSeparator {
		return false
	}

	// Must have at least 2 word segments separated by _ or -
	segments := strings.FieldsFunc(value, func(c rune) bool {
		return c == '_' || c == '-'
	})
	if len(segments) < 2 {
		return false
	}

	// All segments must be readable words (not random-looking)
	for _, seg := range segments {
		if len(seg) < 2 {
			return false // single-char segments suggest random data
		}
		// If any segment is long (>10 chars) and contains mixed letters+digits,
		// it's likely a random token, not a human-readable word.
		if len(seg) > 10 && containsMixedAlphaDigit(seg) {
			return false
		}
	}

	// Known secret key prefixes — never treat as identifiers
	secretPrefixes := []string{"sk_", "pk_", "ghp_", "gho_", "xoxb", "xoxp", "akia"}
	lowerVal := strings.ToLower(value)
	for _, prefix := range secretPrefixes {
		if strings.HasPrefix(lowerVal, prefix) {
			return false
		}
	}

	return true
}

// containsMixedAlphaDigit checks if a string contains both letters and digits.
func containsMixedAlphaDigit(s string) bool {
	hasLetter := false
	hasDigit := false
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			hasLetter = true
		}
		if c >= '0' && c <= '9' {
			hasDigit = true
		}
		if hasLetter && hasDigit {
			return true
		}
	}
	return false
}

// isHexOnlyValue checks if a value is a pure hexadecimal string.
// Pure hex strings from regex matches (like Algolia search keys) are typically
// not secrets — they're public API keys or hashes.
func isHexOnlyValue(value string) bool {
	if len(value) < 20 {
		return false
	}
	for _, c := range value {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// isInsideDocstring returns true if the line at lineIndex is inside a Python docstring block.
// It scans from the beginning of the file tracking triple-quote open/close state.
func isInsideDocstring(lineIndex int, lines []string) bool {
	insideDouble := false // tracking """ blocks
	insideSingle := false // tracking ''' blocks

	for i := 0; i < lineIndex; i++ {
		if i >= len(lines) {
			break
		}
		line := lines[i]
		// Count triple quotes on this line
		// A line can open AND close a docstring (single-line docstring like: """description""")
		doubleCount := strings.Count(line, `"""`)
		singleCount := strings.Count(line, `'''`)

		// Each triple-quote toggles state
		if doubleCount%2 == 1 {
			insideDouble = !insideDouble
		}
		if singleCount%2 == 1 {
			insideSingle = !insideSingle
		}
	}

	return insideDouble || insideSingle
}

// isAdjacentLineContext checks if any of the preceding 1-3 lines contain any of the given keywords.
// Used for multi-line structures where context (placeholder:, description:) is on a previous line.
func isAdjacentLineContext(lineIndex int, lines []string, keywords []string) bool {
	for offset := 1; offset <= 3; offset++ {
		checkIdx := lineIndex - offset
		if checkIdx < 0 || checkIdx >= len(lines) {
			continue
		}
		lowerLine := strings.ToLower(lines[checkIdx])
		for _, kw := range keywords {
			if strings.Contains(lowerLine, kw) {
				return true
			}
		}
	}
	return false
}

// RedactSecrets replaces detected secrets in content with [REDACTED]
// Returns the sanitized content suitable for transmission
func RedactSecrets(content []byte, secrets []SecretFinding) []byte {
	if len(secrets) == 0 {
		return content
	}

	lines := strings.Split(string(content), "\n")

	// Process secrets by line (in reverse to maintain indices)
	lineSecrets := make(map[int][]SecretFinding)
	for _, secret := range secrets {
		lineNum := secret.Line - 1 // Convert back to 0-indexed
		lineSecrets[lineNum] = append(lineSecrets[lineNum], secret)
	}

	// Redact each line
	for lineNum, secrets := range lineSecrets {
		if lineNum < len(lines) {
			line := lines[lineNum]
			// Sort secrets by column position (descending) to maintain correct indices during replacement
			sort.Slice(secrets, func(i, j int) bool {
				return secrets[i].Column > secrets[j].Column
			})

			for _, secret := range secrets {
				// Use a marker to identify the secret type (never expose the actual value)
				placeholder := "[REDACTED-" + strings.ToUpper(secret.Type) + "]"

				// Replace only the first occurrence to avoid over-redaction
				// This handles cases where the same secret appears multiple times
				line = strings.Replace(line, secret.Value, placeholder, 1)
			}
			lines[lineNum] = line
		}
	}

	return []byte(strings.Join(lines, "\n"))
}

// SecretsVersionHash returns a hash of all patterns for version control
// This ensures CLI and Server have matching pattern versions
func SecretsVersionHash() string {
	// Compute hash of all pattern definitions for consistency verification
	h := sha256.New()

	// Get sorted pattern names for deterministic hash
	names := make([]string, 0, len(PatternDefinitions))
	for name := range PatternDefinitions {
		names = append(names, name)
	}
	sort.Strings(names)

	// Hash each pattern's key attributes
	for _, name := range names {
		p := PatternDefinitions[name]
		h.Write([]byte(p.Name))
		h.Write([]byte(p.Severity))
		h.Write([]byte(p.CWE))
		for _, re := range p.Patterns {
			h.Write([]byte(re.String()))
		}
	}

	// Return truncated hash (first 12 chars) prefixed with version
	hash := hex.EncodeToString(h.Sum(nil))
	return "v1-" + hash[:12]
}
