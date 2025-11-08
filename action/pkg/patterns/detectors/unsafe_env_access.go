package detectors

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// UnsafeEnvAccessDetector detects unsafe environment variable access without defaults
type UnsafeEnvAccessDetector struct {
	pattern    patterns.Pattern
	confidence float32
	regex      *regexp.Regexp
}

// NewUnsafeEnvAccessDetector creates a new unsafe env access detector
func NewUnsafeEnvAccessDetector() *UnsafeEnvAccessDetector {
	pattern := patterns.Pattern{
		ID:       "unsafe_env_access",
		Name:     "Unsafe Environment Variable Access",
		Version:  "1.0",
		Category: "configuration",
		Severity: "MEDIUM",
		CVSS:     6.5,
		CWEIDs:   []string{"CWE-665"},
		OWASP:    "LLM02",
		Description: "Accessing environment variables without default values causes runtime failures and missing configuration errors in production",
		Remediation: "Always use os.environ.get('KEY', 'default') or validate environment variables on startup",
		FinancialImpact: struct {
			Severity    string
			Description string
			RiskPerYear float32
		}{
			Severity:    "MEDIUM",
			Description: "Missing environment variable causes agent crash on first customer interaction",
			RiskPerYear: 50000,
		},
	}

	// Match: os.environ["KEY"] without .get()
	regex := regexp.MustCompile(`os\.environ\s*\[\s*["']`)

	return &UnsafeEnvAccessDetector{
		pattern:    pattern,
		confidence: 0.92,
		regex:      regex,
	}
}

// Name returns the detector name
func (d *UnsafeEnvAccessDetector) Name() string {
	return "unsafe_env_access"
}

// GetPattern returns the pattern metadata
func (d *UnsafeEnvAccessDetector) GetPattern() patterns.Pattern {
	return d.pattern
}

// GetConfidence returns confidence score
func (d *UnsafeEnvAccessDetector) GetConfidence() float32 {
	return d.confidence
}

// Detect analyzes code for unsafe environment access
func (d *UnsafeEnvAccessDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	var findings []patterns.Finding

	// Skip unsupported files
	if !isSupportedFile(filePath) {
		return findings, nil
	}

	// Skip test files
	if isTestFile(filePath) {
		return findings, nil
	}

	lines := strings.Split(string(src), "\n")

	for i, line := range lines {
		trimmedLine := strings.TrimSpace(line)

		// Skip comments and empty lines
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") || strings.HasPrefix(trimmedLine, "//") {
			continue
		}

		// Check for os.environ[...] pattern
		if d.regex.MatchString(line) {
			// Verify it's NOT using .get() (which is safe)
			if !strings.Contains(line, ".get(") {
				finding := patterns.Finding{
					ID:            fmt.Sprintf("unsafe_env_%d_%s", i, filePath),
					PatternID:     d.pattern.ID,
					Pattern:       d.pattern.Name,
					File:          filePath,
					Line:          i + 1,
					Column:        strings.Index(line, "os.environ") + 1,
					Message:       "Unsafe environment variable access: os.environ[] without default value will crash if variable is missing",
					Code:          line,
					Severity:      d.pattern.Severity,
					Confidence:    d.confidence,
					CWE:           "CWE-665",
					CVSS:          d.pattern.CVSS,
					OWASP:         d.pattern.OWASP,
					FinancialRisk: "Agent crash on missing configuration - production downtime",
				}

				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}
