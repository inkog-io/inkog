package detectors

import (
	"fmt"
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
	"github.com/inkog-io/inkog/action/pkg/patterns/metadata"
)

// HardcodedCredentialsDetector detects hardcoded API keys, tokens, and passwords
type HardcodedCredentialsDetector struct {
	pattern    patterns.Pattern
	confidence float32
	regexes    []credentialPattern
}

// credentialPattern holds a regex pattern string and its metadata
type credentialPattern struct {
	pattern     string
	name        string
	description string
}

// Regex patterns for credentials (pre-compiled via cache on first use)
var credentialPatterns = []credentialPattern{
	{
		pattern:     `(?i)(sk-|sk_|sk_live_|ghp_|sk-ant-)[a-zA-Z0-9_\-]{20,}`,
		name:        "Known API Key Format",
		description: "OpenAI (sk-proj-, sk-ant-), Stripe (sk_live_), GitHub (ghp_) and other service prefixes",
	},
	{
		pattern:     `(?i)(api_?key|secret_?key|secret|token|password|api_?secret)\s*[=:]\s*["']([a-zA-Z0-9_\-\.]{15,})["']`,
		name:        "Hardcoded Credential Variable",
		description: "Variable assignment with 15+ character value",
	},
	{
		pattern:     `(?i)(openai|stripe|github|anthropic|database|api|secret|token)_?(key|password|secret|token)\s*=\s*["']([a-zA-Z0-9_\-\.]{15,})["']`,
		name:        "Hardcoded Service Credential",
		description: "Named constant with secret value",
	},
	{
		pattern:     `(?i)(jwt|token|auth|bearer)\s*[=:]\s*["']([a-zA-Z0-9_\-\.]{20,})["']`,
		name:        "Hardcoded Token",
		description: "JWT, auth token, or bearer token",
	},
	{
		pattern:     `(?i)(db_?password|db_?user|db_?host|database_?url)\s*[=:]\s*["']([^"']{8,})["']`,
		name:        "Hardcoded Database Credential",
		description: "Database connection string or password",
	},
}

// NewHardcodedCredentialsDetector creates a new hardcoded credentials detector
func NewHardcodedCredentialsDetector() *HardcodedCredentialsDetector {
	pattern := patterns.Pattern{
		ID:       "hardcoded_credentials",
		Name:     "Hardcoded API Keys and Credentials",
		Version:  "1.0",
		Category: "secrets_management",
		Severity: "CRITICAL",
		CVSS:     9.1,
		CWEIDs:   []string{"CWE-798"},
		OWASP:    "LLM02",
		Description: "API keys, tokens, and passwords hardcoded in source code are compromised when code is shared, committed to version control, or accessed by unauthorized parties",
		Remediation: "Use environment variables, secrets management systems (Vault, AWS Secrets Manager), or CI/CD secrets injection",
		FinancialImpact: struct {
			Severity    string
			Description string
			RiskPerYear float32
		}{
			Severity:    "CRITICAL",
			Description: "Stolen OpenAI API key = $50K/month unauthorized consumption. GitHub token = full repo access. Database credentials = multi-tenant data breach.",
			RiskPerYear: 600000, // $50K/month × 12
		},
	}

	// Use the global regex cache - patterns are compiled once and reused
	regexes := make([]credentialPattern, len(credentialPatterns))
	copy(regexes, credentialPatterns)

	return &HardcodedCredentialsDetector{
		pattern:    pattern,
		confidence: 0.98,
		regexes:    regexes,
	}
}

// Name returns the detector name
func (d *HardcodedCredentialsDetector) Name() string {
	return "hardcoded_credentials"
}

// GetPatternID returns the canonical detector ID (implements Detector interface)
func (d *HardcodedCredentialsDetector) GetPatternID() string {
	return metadata.ID_HARDCODED_CREDENTIALS
}


// GetPattern returns the pattern metadata
func (d *HardcodedCredentialsDetector) GetPattern() patterns.Pattern {
	return d.pattern
}

// GetConfidence returns confidence score
func (d *HardcodedCredentialsDetector) GetConfidence() float32 {
	return d.confidence
}

// Detect analyzes code for hardcoded credentials
func (d *HardcodedCredentialsDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	var findings []patterns.Finding

	// Skip unsupported files
	if !isSupportedFile(filePath) {
		return findings, nil
	}

	// Skip test/example files (false positive reduction)
	if isTestFile(filePath) || d.isExampleFile(filePath) {
		return findings, nil
	}

	lines := strings.Split(string(src), "\n")

	for i, line := range lines {
		trimmedLine := strings.TrimSpace(line)

		// Skip comments and empty lines
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") || strings.HasPrefix(trimmedLine, "//") {
			continue
		}

		// Skip lines with placeholder values
		if d.isPlaceholder(line) {
			continue
		}

		// Check each regex pattern (using global regex cache for performance)
		for _, credPattern := range d.regexes {
			// Get regex from cache (compiled once, reused thereafter)
			regex, err := GlobalRegexCache.Get(credPattern.pattern)
			if err != nil {
				continue
			}

			if regex.MatchString(line) {
				// Extract the secret for masking
				matches := regex.FindStringSubmatch(line)
				var maskedSecret string
				if len(matches) > 0 {
					maskedSecret = d.maskSecret(matches[0])
				}

				finding := patterns.Finding{
					ID:            fmt.Sprintf("hardcoded_credential_%d_%s", i, filePath),
					PatternID:     d.pattern.ID,
					Pattern:       d.pattern.Name,
					File:          filePath,
					Line:          i + 1,
					Column:        len(line) - len(trimmedLine) + 1,
					Message:       fmt.Sprintf("%s detected: %s", credPattern.description, maskedSecret),
					Code:          line,
					Severity:      d.pattern.Severity,
					Confidence:    d.confidence,
					CWE:           "CWE-798",
					CVSS:          d.pattern.CVSS,
					OWASP:         d.pattern.OWASP,
					FinancialRisk: "Account compromise, $50K+/month unauthorized API usage",
				}

				findings = append(findings, finding)
				break // Only add once per line
			}
		}
	}

	return findings, nil
}

// isPlaceholder checks if a line contains a placeholder value
func (d *HardcodedCredentialsDetector) isPlaceholder(line string) bool {
	placeholders := []string{
		"your_", "your-", "replace_", "replace-",
		"xxx", "test_", "sample_", "demo_",
		"example", "placeholder",
	}

	lowerLine := strings.ToLower(line)
	for _, ph := range placeholders {
		if strings.Contains(lowerLine, ph) {
			return true
		}
	}

	return false
}

// maskSecret masks the secret for reporting
func (d *HardcodedCredentialsDetector) maskSecret(secret string) string {
	if len(secret) <= 8 {
		return "***"
	}
	return secret[:4] + "***" + secret[len(secret)-4:]
}

// isExampleFile checks if file is an example/sample file
func (d *HardcodedCredentialsDetector) isExampleFile(path string) bool {
	examples := []string{
		"example", "sample", "demo", "docs/",
		"README", "TUTORIAL",
	}

	lowerPath := strings.ToLower(path)
	for _, ex := range examples {
		if strings.Contains(lowerPath, ex) {
			return true
		}
	}

	return false
}
