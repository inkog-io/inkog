package detectors

import (
	"regexp"
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// LoggingSensitiveDataDetector detects logging of sensitive information (CWE-532 & CWE-209)
// This pattern identifies cases where sensitive data (passwords, API keys, tokens, PII, etc.)
// are logged, which can lead to:
// - Credential exposure in logs
// - Privacy violations (logging SSN, credit cards, etc.)
// - Compliance issues (GDPR, PCI-DSS, HIPAA)
// - Security breaches if logs are leaked
//
// Examples:
// - logging.info(f"password={password}")
// - console.log("API_KEY: " + apiKey)
// - logger.error(f"Failed login with token {access_token}")
// - log.Printf("User SSN: %s", ssn)
// - print(f"Credit card: {card_number}")
type LoggingSensitiveDataDetector struct {
	// Sensitive data keywords
	passwordPattern      *regexp.Regexp // password, passphrase, passwd, pwd
	secretPattern        *regexp.Regexp // secret, private_key, private_secret
	apiKeyPattern        *regexp.Regexp // api[_]?key, apikey, api_secret
	tokenPattern         *regexp.Regexp // token, access_token, refresh_token, bearer
	credentialPattern    *regexp.Regexp // credential, credentials, auth, authorization
	ssnPattern           *regexp.Regexp // SSN, social security number
	creditCardPattern    *regexp.Regexp // credit[_]?card, card[_]?number, cc[_]?number, card_data
	privateKeyPattern    *regexp.Regexp // private[_]?key, rsa_key, dsa_key, ec_key
	dbPasswordPattern    *regexp.Regexp // db[_]?password, database[_]?password, db[_]?pass
	oauthPattern         *regexp.Regexp // oauth[_]?token, client[_]?secret, client[_]?id with secret
	jwtPattern           *regexp.Regexp // jwt, jti, authorization header values
	certificatePattern   *regexp.Regexp // certificate, cert, private[_]?cert, pem, pkcs

	// Logging function patterns
	pythonLoggingPattern *regexp.Regexp // logging.info, logging.error, logging.debug, logger.*
	pythonPrintPattern   *regexp.Regexp // print(...) functions
	goLogPattern         *regexp.Regexp // log.Printf, log.Println, log.Print
	goLogrusPattern      *regexp.Regexp // logrus.Info, logrus.Error, logrus.Debug
	goZapPattern         *regexp.Regexp // zap.String, zap.Error with field values
	jsConsolePattern     *regexp.Regexp // console.log, console.error, console.warn
	jsPrintPattern       *regexp.Regexp // print, alert, document.write
	javalangPattern      *regexp.Regexp // System.out, System.err
	javaLoggerPattern    *regexp.Regexp // logger.info, logger.error, logger.debug

	// Variable naming patterns that suggest sensitive data
	sensitiveVarPattern  *regexp.Regexp // Variables named after sensitive data

	// Safe patterns (mitigations)
	maskedPattern        *regexp.Regexp // ****,  [FILTERED],  [REDACTED], etc.
	safeContextPattern   *regexp.Regexp // Safe contexts like "password reset", "password field"
	testFilePattern      *regexp.Regexp // Patterns indicating test code
	structuredSafePattern *regexp.Regexp // Structured logging frameworks with field names (logrus.WithField)
}

// NewLoggingSensitiveDataDetector creates a new logging sensitive data detector
func NewLoggingSensitiveDataDetector() *LoggingSensitiveDataDetector {
	return &LoggingSensitiveDataDetector{
		// Sensitive data patterns
		passwordPattern: regexp.MustCompile(
			`(?i)password|passphrase|passwd|pwd`,
		),
		secretPattern: regexp.MustCompile(
			`(?i)secret|private_secret|private_key_secret`,
		),
		apiKeyPattern: regexp.MustCompile(
			`(?i)api[_]?key|apikey|api_secret|api_token`,
		),
		tokenPattern: regexp.MustCompile(
			`(?i)token|access_token|refresh_token|bearer|bearer_token`,
		),
		credentialPattern: regexp.MustCompile(
			`(?i)credential|credentials|auth|authorization|auth_token`,
		),
		ssnPattern: regexp.MustCompile(
			`(?i)ssn|social.?security|social[_]?security[_]?number`,
		),
		creditCardPattern: regexp.MustCompile(
			`(?i)credit[_]?card|card[_]?number|cc[_]?number|card[_]?data|cvv|cvc`,
		),
		privateKeyPattern: regexp.MustCompile(
			`(?i)private[_]?key|private_key|pem|pkcs12|rsa_key|dsa_key|ec_key`,
		),
		dbPasswordPattern: regexp.MustCompile(
			`(?i)db[_]?password|database[_]?password|db[_]?pass|db[_]?secret`,
		),
		oauthPattern: regexp.MustCompile(
			`(?i)oauth[_]?token|client[_]?secret|client[_]?id|refresh[_]?token`,
		),
		jwtPattern: regexp.MustCompile(
			`(?i)jwt|jti|authorization.*bearer`,
		),
		certificatePattern: regexp.MustCompile(
			`(?i)certificate|cert|private[_]?cert|pem|pkcs|x509`,
		),

		// Logging patterns
		pythonLoggingPattern: regexp.MustCompile(
			`(?i)logging\.(info|debug|error|warning|warn|critical|exception)\s*\(|logger\.(info|debug|error|warning|warn|critical)\s*\(`,
		),
		pythonPrintPattern: regexp.MustCompile(
			`(?i)\bprint\s*\(`,
		),
		goLogPattern: regexp.MustCompile(
			`(?i)log\.(Printf|Println|Print|Fatalf|Fatal|Panic|Panicf)\s*\(`,
		),
		goLogrusPattern: regexp.MustCompile(
			`(?i)logrus\.(Info|Error|Debug|Warning|Warn|Fatal|Panic|Infof|Errorf|Debugf|Warnf)\s*\(|\.WithField\s*\(|\.WithError\s*\(|\.Info\s*\(|\.Error\s*\(|\.Debug\s*\(`,
		),
		goZapPattern: regexp.MustCompile(
			`(?i)zap\.(String|Error|Any)\s*\(|\.With\(`,
		),
		jsConsolePattern: regexp.MustCompile(
			`(?i)console\.(log|error|warn|info|debug|trace)\s*\(`,
		),
		jsPrintPattern: regexp.MustCompile(
			`(?i)\bprint\s*\(|\balert\s*\(|document\.write\s*\(`,
		),
		javalangPattern: regexp.MustCompile(
			`(?i)System\.(out|err)\.(print|println)\s*\(`,
		),
		javaLoggerPattern: regexp.MustCompile(
			`(?i)logger\.(info|error|debug|warn|fatal)\s*\(|log\.log\s*\(`,
		),

		// Variable naming that suggests sensitive data
		sensitiveVarPattern: regexp.MustCompile(
			`(?i)(password|secret|token|api[_]?key|credential|ssn|card|cert|key|auth)`,
		),

		// Safe patterns (mitigations) - match asterisks, brackets with FILTERED/REDACTED, or angle brackets
		maskedPattern: regexp.MustCompile(
			`\*\*\*|\[FILTERED\]|\[REDACTED\]|\[MASKED\]|<redacted>|<masked>`,
		),
		safeContextPattern: regexp.MustCompile(
			`(?i)password\s+(reset|change|field|column|parameter|updated|changed|length|requirement|strength|policy)|secret\s+(in\s+)?code|password\s+for\s+(user|account)`,
		),
		testFilePattern: regexp.MustCompile(
			`(?i)test_|_test\.|_spec\.|\.spec\.|mock|fixture|stub|fake`,
		),
		structuredSafePattern: regexp.MustCompile(
			`(?i)\.WithField\s*\(|\.With\s*\(|withField\s*\(|withValue\s*\(`,
		),
	}
}

// Detect performs logging sensitive data detection
func (d *LoggingSensitiveDataDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	sourceStr := string(src)
	lines := strings.Split(sourceStr, "\n")
	var findings []patterns.Finding

	// Determine language
	lang := d.detectLanguage(filePath, sourceStr)

	// Second pass: Report findings
	for i, line := range lines {
		lineNum := i + 1
		trimmedLine := strings.TrimSpace(line)

		// Skip empty lines
		if trimmedLine == "" {
			continue
		}

		// Skip lines that are only comments
		if strings.HasPrefix(trimmedLine, "//") || strings.HasPrefix(trimmedLine, "#") {
			continue
		}

		// Check if this is a logging line
		isLoggingLine := d.isLoggingLine(line, lang)
		if !isLoggingLine {
			continue
		}

		// Check if this logging line contains sensitive data
		sensitiveKeywords := d.extractSensitiveKeywords(line)
		if len(sensitiveKeywords) == 0 {
			continue
		}

		// Calculate confidence
		confidence := d.calculateConfidence(line, sensitiveKeywords)

		// Check for mitigating factors
		if d.maskedPattern.MatchString(line) {
			confidence -= 0.4
		}

		if d.safeContextPattern.MatchString(line) {
			confidence -= 0.3
		}

		// Skip if this is in a test file
		if d.testFilePattern.MatchString(filePath) {
			confidence -= 0.2
		}

		// Check for structured logging with field names only (not values)
		if d.structuredSafePattern.MatchString(line) && !d.hasLoggingValue(line) {
			continue // Field names are OK, values would be flagged
		}

		// Report if confidence is high enough
		if confidence >= 0.5 {
			finding := d.createFinding(
				filePath,
				lineNum,
				"Sensitive data logged",
				d.createMessage(sensitiveKeywords, line),
				"MEDIUM",
				confidence,
			)
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// isLoggingLine checks if a line contains a logging call
func (d *LoggingSensitiveDataDetector) isLoggingLine(line string, lang string) bool {
	switch lang {
	case "python":
		return d.pythonLoggingPattern.MatchString(line) || d.pythonPrintPattern.MatchString(line)
	case "go":
		return d.goLogPattern.MatchString(line) || d.goLogrusPattern.MatchString(line) || d.goZapPattern.MatchString(line)
	case "javascript":
		return d.jsConsolePattern.MatchString(line) || d.jsPrintPattern.MatchString(line)
	case "java":
		return d.javalangPattern.MatchString(line) || d.javaLoggerPattern.MatchString(line)
	default:
		// Try all patterns for unknown language
		return d.pythonLoggingPattern.MatchString(line) ||
			d.pythonPrintPattern.MatchString(line) ||
			d.goLogPattern.MatchString(line) ||
			d.goLogrusPattern.MatchString(line) ||
			d.jsConsolePattern.MatchString(line) ||
			d.javaLoggerPattern.MatchString(line)
	}
}

// extractSensitiveKeywords extracts which sensitive keywords are present in the line
func (d *LoggingSensitiveDataDetector) extractSensitiveKeywords(line string) []string {
	var keywords []string

	if d.passwordPattern.MatchString(line) {
		keywords = append(keywords, "password")
	}
	if d.secretPattern.MatchString(line) {
		keywords = append(keywords, "secret")
	}
	if d.apiKeyPattern.MatchString(line) {
		keywords = append(keywords, "api_key")
	}
	if d.tokenPattern.MatchString(line) {
		keywords = append(keywords, "token")
	}
	if d.credentialPattern.MatchString(line) {
		keywords = append(keywords, "credential")
	}
	if d.ssnPattern.MatchString(line) {
		keywords = append(keywords, "ssn")
	}
	if d.creditCardPattern.MatchString(line) {
		keywords = append(keywords, "credit_card")
	}
	if d.privateKeyPattern.MatchString(line) {
		keywords = append(keywords, "private_key")
	}
	if d.dbPasswordPattern.MatchString(line) {
		keywords = append(keywords, "db_password")
	}
	if d.oauthPattern.MatchString(line) {
		keywords = append(keywords, "oauth_token")
	}
	if d.jwtPattern.MatchString(line) {
		keywords = append(keywords, "jwt")
	}
	if d.certificatePattern.MatchString(line) {
		keywords = append(keywords, "certificate")
	}

	return keywords
}

// calculateConfidence calculates confidence based on patterns and context
func (d *LoggingSensitiveDataDetector) calculateConfidence(line string, keywords []string) float32 {
	confidence := float32(0.50) // Base confidence

	// Add confidence for each sensitive keyword
	for _, keyword := range keywords {
		switch keyword {
		case "password", "secret", "api_key", "token", "credential":
			confidence += 0.2 // High-value keywords
		case "ssn", "credit_card", "private_key":
			confidence += 0.25 // Very critical keywords
		default:
			confidence += 0.15 // Other keywords
		}
	}

	// Bonus if multiple keywords (high likelihood)
	if len(keywords) > 1 {
		confidence += 0.15
	}

	// Check for direct variable assignment pattern (higher risk)
	if strings.Contains(line, "=") && d.sensitiveVarPattern.MatchString(line) {
		confidence += 0.1
	}

	// Check for string interpolation or concatenation (direct logging of value)
	if (strings.Contains(line, "${") || strings.Contains(line, "{") || strings.Contains(line, "f\"") || strings.Contains(line, "+")) &&
		d.sensitiveVarPattern.MatchString(line) {
		confidence += 0.15
	}

	// Cap at 0.95
	if confidence > 0.95 {
		confidence = 0.95
	}

	return confidence
}

// hasLoggingValue checks if a structured logging line has actual values (not just field names)
func (d *LoggingSensitiveDataDetector) hasLoggingValue(line string) bool {
	// If it has string interpolation or variable names, it likely has values
	return strings.Contains(line, "${") || strings.Contains(line, "f\"") ||
		strings.Contains(line, "{") || strings.Count(line, "\"") > 2
}

// createMessage creates a descriptive message for the finding
func (d *LoggingSensitiveDataDetector) createMessage(keywords []string, line string) string {
	var keywordStr string
	if len(keywords) > 0 {
		keywordStr = strings.Join(keywords, ", ")
	} else {
		keywordStr = "sensitive data"
	}

	return "Logging of " + keywordStr + " detected. This may expose sensitive information in logs. Ensure logs are properly protected or mask sensitive values before logging."
}

// detectLanguage determines code language from file extension and content
func (d *LoggingSensitiveDataDetector) detectLanguage(filePath string, sourceStr string) string {
	if strings.HasSuffix(filePath, ".py") {
		return "python"
	}
	if strings.HasSuffix(filePath, ".js") || strings.HasSuffix(filePath, ".ts") || strings.HasSuffix(filePath, ".jsx") || strings.HasSuffix(filePath, ".tsx") {
		return "javascript"
	}
	if strings.HasSuffix(filePath, ".go") {
		return "go"
	}
	if strings.HasSuffix(filePath, ".java") {
		return "java"
	}
	// Fallback: check content
	if strings.Contains(sourceStr, "def ") && strings.Contains(sourceStr, "import ") {
		return "python"
	}
	if strings.Contains(sourceStr, "function ") || strings.Contains(sourceStr, "const ") {
		return "javascript"
	}
	if strings.Contains(sourceStr, "func ") && strings.Contains(sourceStr, "package ") {
		return "go"
	}
	if strings.Contains(sourceStr, "public class") || strings.Contains(sourceStr, "public static") {
		return "java"
	}
	return "unknown"
}

// createFinding creates a Finding struct with provided parameters
func (d *LoggingSensitiveDataDetector) createFinding(
	filePath string,
	lineNum int,
	title string,
	message string,
	severity string,
	confidence float32,
) patterns.Finding {
	return patterns.Finding{
		File:       filePath,
		Line:       lineNum,
		Message:    title + ": " + message,
		Severity:   severity,
		Confidence: confidence,
		PatternID:  "logging_sensitive_data",
	}
}

// Name returns the detector name
func (d *LoggingSensitiveDataDetector) Name() string {
	return "logging_sensitive_data"
}

// GetPattern returns the pattern metadata
func (d *LoggingSensitiveDataDetector) GetPattern() patterns.Pattern {
	return patterns.Pattern{
		ID:          "logging_sensitive_data",
		Name:        "Logging Sensitive Data",
		Version:     "1.0",
		Category:    "data_exposure",
		Severity:    "HIGH",
		CVSS:        7.5,
		CWEIDs:      []string{"CWE-532", "CWE-209"},
		OWASP:       "A01:2021 Broken Access Control",
		Description: "Detects sensitive data (PII, credentials) being logged in code",
	}
}

// GetConfidence returns the confidence score for this detector
func (d *LoggingSensitiveDataDetector) GetConfidence() float32 {
	return 0.82
}
