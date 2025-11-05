package patterns

import (
	"regexp"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/inkog-io/inkog/action/pkg/models"
	"github.com/inkog-io/inkog/action/pkg/parser"
)

// APIKeyDetector detects hardcoded API keys and credentials
type APIKeyDetector struct {
	apiKeyRegex     *regexp.Regexp
	secretKeyRegex  *regexp.Regexp
	passwordRegex   *regexp.Regexp
	tokenRegex      *regexp.Regexp
}

// NewAPIKeyDetector creates a new API key detector
func NewAPIKeyDetector() *APIKeyDetector {
	return &APIKeyDetector{
		// Matches common API key patterns (at least 20 alphanumeric chars)
		apiKeyRegex:    regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[=:]\s*['""]?([a-z0-9]{20,})['""]?`),
		secretKeyRegex: regexp.MustCompile(`(?i)(secret|secret[_-]?key|secret[_-]?access[_-]?key)\s*[=:]\s*['""]?([a-z0-9]{20,})['""]?`),
		passwordRegex:  regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[=:]\s*['""]?(\S{6,})['""]?`),
		tokenRegex:     regexp.MustCompile(`(?i)(token|access[_-]?token|bearer)\s*[=:]\s*['""]?([a-z0-9_-]{20,})['""]?`),
	}
}

// Detect finds hardcoded API keys and credentials
func (a *APIKeyDetector) Detect(fileInfo *parser.FileInfo) []models.Finding {
	var findings []models.Finding

	// Scan raw content for hardcoded credentials
	content := string(fileInfo.Content)
	findings = append(findings, a.findHardcodedCredentials(content, fileInfo)...)

	// Also scan for suspicious environment variable usage
	if fileInfo.Tree != nil {
		cursor := sitter.NewTreeCursor(fileInfo.Tree.RootNode())
		findings = append(findings, a.findEnvVariableUsage(cursor, fileInfo)...)
	}

	return findings
}

// findHardcodedCredentials looks for literal credentials in code
func (a *APIKeyDetector) findHardcodedCredentials(content string, fileInfo *parser.FileInfo) []models.Finding {
	var findings []models.Finding

	lines := strings.Split(content, "\n")

	// Check each line for credential patterns
	for idx, line := range lines {
		lineNum := idx + 1

		// Skip comments
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}

		// Check for API keys
		if a.apiKeyRegex.MatchString(line) {
			finding := models.Finding{
				ID:              "hardcoded_api_key",
				Pattern:         "Hardcoded API Key",
				Severity:        models.RiskLevelHigh,
				Confidence:      0.95,
				File:            fileInfo.Path,
				Line:            lineNum,
				Column:          1,
				Message:         "Hardcoded API key detected in source code",
				Code:            truncateCode(line, 80),
				Remediation:     "Move credentials to environment variables or use a secrets management service",
				ReferenceLinks:  []string{"https://owasp.org/www-community/Sensitive_Data_Exposure"},
				CWEIdentifiers:  []string{"CWE-798", "CWE-259"},
				DetectionMethod: "Regex pattern matching on raw content",
			}
			findings = append(findings, finding)
		}

		// Check for secret keys
		if a.secretKeyRegex.MatchString(line) {
			finding := models.Finding{
				ID:              "hardcoded_secret_key",
				Pattern:         "Hardcoded Secret Key",
				Severity:        models.RiskLevelHigh,
				Confidence:      0.95,
				File:            fileInfo.Path,
				Line:            lineNum,
				Column:          1,
				Message:         "Hardcoded secret key detected in source code",
				Code:            truncateCode(line, 80),
				Remediation:     "Move credentials to environment variables or use a secrets management service",
				ReferenceLinks:  []string{"https://owasp.org/www-community/Sensitive_Data_Exposure"},
				CWEIdentifiers:  []string{"CWE-798", "CWE-259"},
				DetectionMethod: "Regex pattern matching on raw content",
			}
			findings = append(findings, finding)
		}

		// Check for passwords
		if a.passwordRegex.MatchString(line) && !isFalsePositive(line) {
			finding := models.Finding{
				ID:              "hardcoded_password",
				Pattern:         "Hardcoded Password",
				Severity:        models.RiskLevelHigh,
				Confidence:      0.90,
				File:            fileInfo.Path,
				Line:            lineNum,
				Column:          1,
				Message:         "Hardcoded password detected in source code",
				Code:            truncateCode(line, 80),
				Remediation:     "Move credentials to environment variables or configuration files outside version control",
				ReferenceLinks:  []string{"https://owasp.org/www-community/Sensitive_Data_Exposure"},
				CWEIdentifiers:  []string{"CWE-798"},
				DetectionMethod: "Regex pattern matching on raw content",
			}
			findings = append(findings, finding)
		}

		// Check for tokens
		if a.tokenRegex.MatchString(line) {
			finding := models.Finding{
				ID:              "hardcoded_token",
				Pattern:         "Hardcoded Token",
				Severity:        models.RiskLevelHigh,
				Confidence:      0.85,
				File:            fileInfo.Path,
				Line:            lineNum,
				Column:          1,
				Message:         "Hardcoded token or access token detected",
				Code:            truncateCode(line, 80),
				Remediation:     "Store tokens in environment variables or secrets management system",
				ReferenceLinks:  []string{"https://owasp.org/www-community/Sensitive_Data_Exposure"},
				CWEIdentifiers:  []string{"CWE-798"},
				DetectionMethod: "Regex pattern matching on raw content",
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// findEnvVariableUsage looks for insecure environment variable usage
func (a *APIKeyDetector) findEnvVariableUsage(cursor *sitter.TreeCursor, fileInfo *parser.FileInfo) []models.Finding {
	var findings []models.Finding

	node := cursor.Node()
	text := string(fileInfo.Content[node.StartByte():node.EndByte()])

	// Check for os.environ or process.env without defaults
	if fileInfo.Language == parser.LanguagePython {
		if strings.Contains(text, "os.environ[") && !strings.Contains(text, "os.environ.get(") {
			// Direct dictionary access without default - will crash if var not set
			finding := models.Finding{
				ID:              "unsafe_env_access",
				Pattern:         "Unsafe Environment Variable Access",
				Severity:        models.RiskLevelMedium,
				Confidence:      0.75,
				File:            fileInfo.Path,
				Line:            parser.GetNodeLine(node),
				Column:          parser.GetNodeColumn(node),
				Message:         "Using os.environ[] directly without default value - will raise KeyError if variable not set",
				Code:            truncateCode(text, 100),
				Remediation:     "Use os.environ.get(key, default) instead of os.environ[key]",
				ReferenceLinks:  []string{"https://docs.python.org/3/library/os.html#os.environ"},
				CWEIdentifiers:  []string{"CWE-665"},
				DetectionMethod: "AST pattern matching on environment variable access",
			}
			findings = append(findings, finding)
		}
	}

	// Recursively check children
	if cursor.GoToFirstChild() {
		findings = append(findings, a.findEnvVariableUsage(cursor, fileInfo)...)
		for cursor.GoToNextSibling() {
			findings = append(findings, a.findEnvVariableUsage(cursor, fileInfo)...)
		}
		cursor.GoToParent()
	}

	return findings
}

// isFalsePositive checks if a match is likely a false positive
func isFalsePositive(line string) bool {
	// Common false positives
	falsePositives := []string{
		"test", "example", "demo", "sample", "fake", "placeholder",
		"TODO", "FIXME", "XXX", "HACK",
	}

	lowerLine := strings.ToLower(line)
	for _, fp := range falsePositives {
		if strings.Contains(lowerLine, strings.ToLower(fp)) {
			return true
		}
	}

	return false
}

func (a *APIKeyDetector) Name() string {
	return "API Key and Credential Detection"
}

func (a *APIKeyDetector) Version() string {
	return "1.0.0"
}
