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
			regexp.MustCompile(`(?i)password\s*[:=]\s*["\']([^"\']+)["\']`),
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
			regexp.MustCompile(`(?i)(secret|token|nonce|seed|key|passwd)\s*[:=]\s*["\']([a-zA-Z0-9\-_!@#$%^&*()+=]{32,})["\']`),
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

// DetectSecrets scans content for hardcoded secrets using both regex and entropy detection
// Returns a list of secrets found without modifying the content
func DetectSecrets(filePath string, content []byte) []SecretFinding {
	// Step 1: Detect secrets using regex patterns
	regexFindings := detectByRegex(content)

	// Step 2: Detect high-entropy strings that may be secrets
	entropyFindings := DetectHighEntropyStrings(content)

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
					// match[0:2] is the full match, match[2:4] is group 1, etc.
					if len(match) >= 2 {
						secret := line[match[0]:match[1]]
						// Try to extract just the secret value (last capture group)
						value := secret
						if len(match) >= 4 {
							value = line[match[2]:match[3]]
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
