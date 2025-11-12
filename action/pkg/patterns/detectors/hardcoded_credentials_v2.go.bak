package detectors

import (
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// HardcodedCredentialsDetectorV2 implements comprehensive credential detection
// with support for 30+ credential formats, encoding detection, entropy analysis,
// dynamic confidence scoring, and AST-based semantic analysis for credential exfiltration detection.
type HardcodedCredentialsDetectorV2 struct {
	pattern      patterns.Pattern
	confidence   float32
	astFramework *ASTAnalysisFramework

	// PRIORITY 1: Critical credential format patterns
	awsAccessKeyID         *regexp.Regexp // AKIA[0-9A-Z]{16}
	awsSecretKey           *regexp.Regexp // 40-char base64 AWS secrets
	awsSessionToken        *regexp.Regexp // aws_session_token patterns
	azureStorageKey        *regexp.Regexp // DefaultEndpointsProtocol=https;
	azureConnectionString  *regexp.Regexp // BlobEndpoint=https://
	gcpAPIKey              *regexp.Regexp // AIza[0-9A-Za-z\-_]{35}
	gcpServiceAccount      *regexp.Regexp // "type": "service_account"
	gcpOAuthToken          *regexp.Regexp // ya29\.
	stripeAPIKey           *regexp.Regexp // sk_live_, sk_test_, rk_live_
	githubToken            *regexp.Regexp // ghp_, gho_, ghu_
	sendGridKey            *regexp.Regexp // SG\.
	slackToken             *regexp.Regexp // xoxb-, xoxp-, xoxo-
	twilioKey              *regexp.Regexp // ACxxxxxxxxxxxxx
	jwtPattern             *regexp.Regexp // eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+
	pagerDutyKey           *regexp.Regexp // u\+[a-zA-Z0-9_\-]{20,}
	digitalOceanToken      *regexp.Regexp // dop_v1_
	npmToken               *regexp.Regexp // npm_[A-Za-z0-9]+
	pypiToken              *regexp.Regexp // pypi-[A-Za-z0-9]+

	// PRIORITY 1: Private key detection
	rsaPrivateKey          *regexp.Regexp // -----BEGIN RSA PRIVATE KEY-----
	ecPrivateKey           *regexp.Regexp // -----BEGIN EC PRIVATE KEY-----
	dsaPrivateKey          *regexp.Regexp // -----BEGIN DSA PRIVATE KEY-----
	opensshPrivateKey      *regexp.Regexp // -----BEGIN OPENSSH PRIVATE KEY-----
	pkcs8PrivateKey        *regexp.Regexp // -----BEGIN PRIVATE KEY-----
	pgpPrivateKey          *regexp.Regexp // -----BEGIN PGP PRIVATE KEY BLOCK-----

	// PRIORITY 1: Generic patterns with variable name matching
	apiKeyPattern          *regexp.Regexp // Generic API_KEY, api_key patterns
	passwordPattern        *regexp.Regexp // password, pwd patterns
	secretPattern          *regexp.Regexp // secret, secret_key patterns
	tokenPattern           *regexp.Regexp // token patterns
	credentialPattern      *regexp.Regexp // credential patterns

	// PRIORITY 2: Encoding detection
	base64Pattern          *regexp.Regexp // [A-Za-z0-9+/]{40,}={0,2}
	hexPattern             *regexp.Regexp // 0x[0-9a-fA-F]{16,}
	urlEncodingPattern     *regexp.Regexp // %[0-9A-F]{2}
	charCodePattern        *regexp.Regexp // String.fromCharCode

	// PRIORITY 2: False positive reduction
	placeholderPattern     *regexp.Regexp // YOUR_API_KEY, REPLACE_WITH_, INSERT_
	publicKeyPattern       *regexp.Regexp // ssh-rsa, ssh-ed25519, BEGIN PUBLIC KEY
	commonDummyValues      *regexp.Regexp // password123, admin, test123, etc.

	// PRIORITY 3: Obfuscation detection
	charArrayLoop          *regexp.Regexp // String construction via loops
	base64Decode           *regexp.Regexp // atob(), base64_decode
	obfuscationPattern     *regexp.Regexp // eval, String.fromCharCode, String constructor
}

// NewHardcodedCredentialsDetectorV2 creates a new V2 credential detector
func NewHardcodedCredentialsDetectorV2() *HardcodedCredentialsDetectorV2 {
	return &HardcodedCredentialsDetectorV2{
		pattern: patterns.Pattern{
			ID:          "hardcoded-credentials-v2",
			Name:        "Hardcoded Credentials V2",
			Version:     "2.0",
			Category:    "hardcoded_credentials",
			Severity:    "CRITICAL",
			CVSS:        9.8,
			CWEIDs:      []string{"CWE-798", "CWE-259", "CWE-321"},
			OWASP:       "A01:2021 - Broken Access Control",
			Description: "Detects 30+ hardcoded credential formats including API keys, private keys, tokens, and encoded secrets",
		},
		confidence:   0.98,
		astFramework: NewASTAnalysisFramework(),

		// PRIORITY 1: AWS Patterns
		awsAccessKeyID:    regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`),
		awsSecretKey:      regexp.MustCompile(`(?i)aws_secret_access_key\s*=\s*["']?[A-Za-z0-9/+=]{40}["']?`),
		awsSessionToken:   regexp.MustCompile(`(?i)aws_session_token\s*=\s*["'][A-Za-z0-9/+=]{100,}["']`),
		azureStorageKey:   regexp.MustCompile(`(?i)DefaultEndpointsProtocol=https;AccountName=`),
		azureConnectionString: regexp.MustCompile(`(?i)BlobEndpoint=https://|FileEndpoint=https://`),

		// PRIORITY 1: Google Cloud Patterns
		gcpAPIKey:         regexp.MustCompile(`(?i)AIza[0-9A-Za-z\-_]{35}`),
		gcpServiceAccount: regexp.MustCompile(`(?i)"type"\s*:\s*"service_account"`),
		gcpOAuthToken:     regexp.MustCompile(`(?i)ya29\.[A-Za-z0-9\-_]{20,}`),

		// PRIORITY 1: Third-party API Keys
		stripeAPIKey:      regexp.MustCompile(`(?i)(sk_live|sk_test|rk_live)_[A-Za-z0-9]{20,}`),
		githubToken:       regexp.MustCompile(`(?i)(ghp|gho|ghu|ghs|ghu)_[A-Za-z0-9_]{36,255}`),
		sendGridKey:       regexp.MustCompile(`(?i)SG\.[A-Za-z0-9_-]{20,}`),
		slackToken:        regexp.MustCompile(`(?i)(xoxb|xoxp|xoxo)-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,28}`),
		twilioKey:         regexp.MustCompile(`(?i)AC[a-zA-Z0-9]{32}`),
		jwtPattern:        regexp.MustCompile(`(?i)eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.?[A-Za-z0-9_-]*`),
		pagerDutyKey:      regexp.MustCompile(`(?i)u\+[a-zA-Z0-9_\-]{20,}`),
		digitalOceanToken: regexp.MustCompile(`(?i)dop_v1_[A-Za-z0-9]{20,}`),
		npmToken:          regexp.MustCompile(`(?i)npm_[A-Za-z0-9]{36,}`),
		pypiToken:         regexp.MustCompile(`(?i)pypi-[A-Za-z0-9]{32,}`),

		// PRIORITY 1: Private Key Patterns
		rsaPrivateKey:     regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
		ecPrivateKey:      regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`),
		dsaPrivateKey:     regexp.MustCompile(`-----BEGIN DSA PRIVATE KEY-----`),
		opensshPrivateKey: regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`),
		pkcs8PrivateKey:   regexp.MustCompile(`-----BEGIN PRIVATE KEY-----`),
		pgpPrivateKey:     regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`),

		// PRIORITY 1: Generic variable patterns
		apiKeyPattern:     regexp.MustCompile(`(?i)(api[_-]?key|apikey|api_secret|secret_key)\s*[=:]\s*["']([A-Za-z0-9\-_]{16,})["']`),
		passwordPattern:   regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[=:]\s*["']([^"']{8,})["']`),
		secretPattern:     regexp.MustCompile(`(?i)(secret|secret_access_key)\s*[=:]\s*["']([A-Za-z0-9/+=]{20,})["']`),
		tokenPattern:      regexp.MustCompile(`(?i)(token|access_token|bearer|auth)\s*[=:]\s*["']([A-Za-z0-9\-_]{20,})["']`),
		credentialPattern: regexp.MustCompile(`(?i)(credential|credentials|private_key|private_key_id)\s*[=:]\s*["']([^"']{16,})["']`),

		// PRIORITY 2: Encoding patterns
		base64Pattern:     regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`),
		hexPattern:        regexp.MustCompile(`0x[0-9a-fA-F]{16,}|\\x[0-9a-fA-F]{2}`),
		urlEncodingPattern: regexp.MustCompile(`%[0-9A-F]{2}`),
		charCodePattern:   regexp.MustCompile(`(?i)String\.fromCharCode|\\u[0-9a-fA-F]{4}`),

		// PRIORITY 2: False positive reduction
		placeholderPattern: regexp.MustCompile(`(?i)YOUR_|REPLACE_WITH_|INSERT_|CHANGE_ME|TODO|FIXME|EXAMPLE|PLACEHOLDER`),
		publicKeyPattern:   regexp.MustCompile(`(?i)ssh-rsa|ssh-ed25519|ssh-dss|-----BEGIN PUBLIC KEY-----|BEGIN CERTIFICATE`),
		commonDummyValues:  regexp.MustCompile(`(?i)^(password123|admin|123456|changeme|test|demo|example|secret|default|letmein)$`),

		// PRIORITY 3: Obfuscation patterns
		charArrayLoop:     regexp.MustCompile(`(?i)for\s*\(.*?\)\s*\{.*?String\.fromCharCode|for\s*in\s+.*?String\[`),
		base64Decode:      regexp.MustCompile(`(?i)atob|base64_decode|base64\.b64decode|base64\.StdEncoding\.DecodeString`),
		obfuscationPattern: regexp.MustCompile(`(?i)eval\s*\(|Function\s*\(|String\.constructor|__import__`),
	}
}

// Name returns detector name
func (d *HardcodedCredentialsDetectorV2) Name() string {
	return d.pattern.Name
}

// GetPattern returns the pattern metadata
func (d *HardcodedCredentialsDetectorV2) GetPattern() patterns.Pattern {
	return d.pattern
}

// GetConfidence returns detector confidence
func (d *HardcodedCredentialsDetectorV2) GetConfidence() float32 {
	return d.confidence
}

// Detect scans for hardcoded credentials using both pattern matching and AST-based semantic analysis
func (d *HardcodedCredentialsDetectorV2) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	if !d.isSupportedCredentialFile(filePath) {
		return []patterns.Finding{}, nil
	}

	// Skip test files and documentation
	if isTestFile(filePath) {
		return []patterns.Finding{}, nil
	}

	content := string(src)
	lines := strings.Split(content, "\n")
	var findings []patterns.Finding

	// PASS 1: Perform AST-based semantic analysis for credential tracking and exfiltration detection
	analysis := d.astFramework.AnalyzeCode(filePath, lines)

	// PASS 2: Identify credentials and their exfiltration paths using variable tracking
	variableTracker := d.astFramework.GetVariableTracker()
	credentialsWithUsage := variableTracker.GetCredentialsWithUsage(analysis.Variables)

	// Check each credential variable for exfiltration
	for credVar, usageContexts := range credentialsWithUsage {
		for _, context := range usageContexts {
			// High-risk contexts: print, log, send, write, http, network, return
			riskContexts := []string{"print", "log", "send", "write", "http", "request", "network", "return", "yield"}
			for _, riskCtx := range riskContexts {
				if strings.Contains(strings.ToLower(context), riskCtx) {
					// Find the line where this credential is used in this context
					for i, line := range lines {
						if strings.Contains(line, credVar) && strings.Contains(strings.ToLower(line), riskCtx) {
							confidence := d.astFramework.EnhanceConfidenceScore(0.88, analysis, i+1)
							finding := d.createFinding(line, i+1, filePath, "CRITICAL", confidence, "Credential "+credVar+" exfiltrated via "+context)
							findings = append(findings, finding...)
						}
					}
				}
			}
		}
	}

	// PASS 3: Traditional regex-based pattern detection
	for i, line := range lines {
		// Skip comments and docstrings
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}

		// Check for various credential patterns
		credentialFindings := d.scanLine(line, i+1, filePath, lines, i)
		findings = append(findings, credentialFindings...)
	}

	return findings, nil
}

// scanLine checks a single line for credentials
func (d *HardcodedCredentialsDetectorV2) scanLine(line string, lineNum int, filePath string, allLines []string, lineIdx int) []patterns.Finding {
	var findings []patterns.Finding

	// PRIORITY 1: Check private keys (highest severity)
	if d.checkPrivateKeys(line) {
		return d.createFinding(line, lineNum, filePath, "CRITICAL", 0.95, "Private key detected in source code")
	}

	// PRIORITY 1: Check AWS patterns
	if d.awsAccessKeyID.MatchString(line) {
		findings = append(findings, d.createFinding(line, lineNum, filePath, "CRITICAL", 0.92, "AWS Access Key ID detected")...)
	}
	if d.awsSecretKey.MatchString(line) || d.awsSessionToken.MatchString(line) {
		findings = append(findings, d.createFinding(line, lineNum, filePath, "CRITICAL", 0.95, "AWS credential detected")...)
	}

	// PRIORITY 1: Check Azure patterns
	if d.azureStorageKey.MatchString(line) || d.azureConnectionString.MatchString(line) {
		findings = append(findings, d.createFinding(line, lineNum, filePath, "CRITICAL", 0.93, "Azure credential detected")...)
	}

	// PRIORITY 1: Check Google Cloud patterns
	if d.gcpAPIKey.MatchString(line) {
		findings = append(findings, d.createFinding(line, lineNum, filePath, "CRITICAL", 0.90, "Google Cloud API key detected")...)
	}
	if d.gcpServiceAccount.MatchString(line) {
		findings = append(findings, d.createFinding(line, lineNum, filePath, "CRITICAL", 0.94, "Google Cloud service account detected")...)
	}
	if d.gcpOAuthToken.MatchString(line) {
		findings = append(findings, d.createFinding(line, lineNum, filePath, "CRITICAL", 0.91, "Google OAuth token detected")...)
	}

	// PRIORITY 1: Check third-party API keys
	if d.stripeAPIKey.MatchString(line) {
		findings = append(findings, d.createFinding(line, lineNum, filePath, "CRITICAL", 0.96, "Stripe API key detected")...)
	}
	if d.githubToken.MatchString(line) {
		findings = append(findings, d.createFinding(line, lineNum, filePath, "CRITICAL", 0.97, "GitHub token detected")...)
	}
	if d.sendGridKey.MatchString(line) {
		findings = append(findings, d.createFinding(line, lineNum, filePath, "CRITICAL", 0.91, "SendGrid API key detected")...)
	}
	if d.slackToken.MatchString(line) {
		findings = append(findings, d.createFinding(line, lineNum, filePath, "CRITICAL", 0.94, "Slack bot token detected")...)
	}
	if d.twilioKey.MatchString(line) {
		findings = append(findings, d.createFinding(line, lineNum, filePath, "CRITICAL", 0.89, "Twilio account SID detected")...)
	}

	// PRIORITY 1: Check JWT tokens
	if d.jwtPattern.MatchString(line) && !strings.Contains(line, "example") && !strings.Contains(line, "test") {
		findings = append(findings, d.createFinding(line, lineNum, filePath, "HIGH", 0.75, "Possible JWT token detected")...)
	}

	// PRIORITY 2: Check generic variable patterns with confidence scoring
	if d.checkGenericCredentials(line, filePath) {
		credFindings := d.checkCredentialVariable(line, lineNum, filePath)
		findings = append(findings, credFindings...)
	}

	// PRIORITY 2: Check encoding patterns
	if d.checkEncodedSecrets(line) {
		encodingFindings := d.analyzeEncodedContent(line, lineNum, filePath)
		findings = append(findings, encodingFindings...)
	}

	// PRIORITY 3: Check obfuscation patterns
	if d.checkObfuscation(line) {
		findings = append(findings, d.createFinding(line, lineNum, filePath, "HIGH", 0.70, "Possible obfuscated credential or secret assembly detected")...)
	}

	// Filter out false positives
	findings = d.filterFalsePositives(findings)

	return findings
}

// checkPrivateKeys detects private key headers
func (d *HardcodedCredentialsDetectorV2) checkPrivateKeys(line string) bool {
	return d.rsaPrivateKey.MatchString(line) ||
		d.ecPrivateKey.MatchString(line) ||
		d.dsaPrivateKey.MatchString(line) ||
		d.opensshPrivateKey.MatchString(line) ||
		d.pkcs8PrivateKey.MatchString(line) ||
		d.pgpPrivateKey.MatchString(line)
}

// checkGenericCredentials checks for generic credential variable assignments
func (d *HardcodedCredentialsDetectorV2) checkGenericCredentials(line string, filePath string) bool {
	// Skip if this looks like a placeholder
	if d.placeholderPattern.MatchString(line) {
		return false
	}

	// Skip if this looks like a public key
	if d.publicKeyPattern.MatchString(line) {
		return false
	}

	return d.apiKeyPattern.MatchString(line) ||
		d.passwordPattern.MatchString(line) ||
		d.secretPattern.MatchString(line) ||
		d.tokenPattern.MatchString(line) ||
		d.credentialPattern.MatchString(line)
}

// checkCredentialVariable analyzes a credential variable with confidence scoring
func (d *HardcodedCredentialsDetectorV2) checkCredentialVariable(line string, lineNum int, filePath string) []patterns.Finding {
	confidence := d.calculateCredentialConfidence(line, filePath)

	if confidence >= 0.5 {
		severity := "CRITICAL"
		if confidence < 0.7 {
			severity = "HIGH"
		}

		return d.createFinding(line, lineNum, filePath, severity, confidence, fmt.Sprintf("Hardcoded credential detected (confidence: %.2f)", confidence))
	}

	return []patterns.Finding{}
}

// calculateCredentialConfidence implements dynamic confidence scoring
func (d *HardcodedCredentialsDetectorV2) calculateCredentialConfidence(line string, filePath string) float32 {
	confidence := float32(0.5) // Base score

	// Increase confidence based on variable name
	if strings.Contains(strings.ToLower(line), "api_key") || strings.Contains(strings.ToLower(line), "apikey") {
		confidence += 0.15
	}
	if strings.Contains(strings.ToLower(line), "password") {
		confidence += 0.20
	}
	if strings.Contains(strings.ToLower(line), "secret") {
		confidence += 0.15
	}
	if strings.Contains(strings.ToLower(line), "token") {
		confidence += 0.10
	}

	// Increase confidence based on value characteristics
	value := d.extractValue(line)
	if len(value) >= 20 {
		confidence += 0.10
	}
	if len(value) >= 40 {
		confidence += 0.10
	}

	// Check entropy (high entropy indicates likely secret)
	if d.hasHighEntropy(value) {
		confidence += 0.15
	}

	// Decrease confidence for placeholder patterns
	if d.commonDummyValues.MatchString(value) {
		confidence -= 0.30
	}
	if strings.Contains(strings.ToLower(filePath), "test") {
		confidence -= 0.15
	}
	if strings.Contains(strings.ToLower(filePath), "example") {
		confidence -= 0.15
	}

	// Clamp to [0, 1]
	if confidence < 0.0 {
		confidence = 0.0
	}
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// extractValue extracts the value part from an assignment
func (d *HardcodedCredentialsDetectorV2) extractValue(line string) string {
	// Split by assignment operators
	parts := strings.FieldsFunc(line, func(r rune) bool {
		return r == '=' || r == ':'
	})

	if len(parts) > 1 {
		value := strings.TrimSpace(parts[len(parts)-1])
		// Remove quotes
		value = strings.Trim(value, `"'`)
		return value
	}

	return ""
}

// hasHighEntropy checks if a string has high entropy (indicator of random/secret data)
func (d *HardcodedCredentialsDetectorV2) hasHighEntropy(s string) bool {
	if len(s) < 16 {
		return false
	}

	// Calculate Shannon entropy
	frequencies := make(map[rune]float64)
	for _, ch := range s {
		frequencies[ch]++
	}

	entropy := 0.0
	for _, freq := range frequencies {
		p := freq / float64(len(s))
		entropy -= p * math.Log2(p)
	}

	// Threshold: >4.0 bits/char indicates likely secret
	return entropy > 4.0
}

// checkEncodedSecrets checks for base64/hex encoded content
func (d *HardcodedCredentialsDetectorV2) checkEncodedSecrets(line string) bool {
	// Only check longer lines (to avoid false positives with short strings)
	if len(line) < 50 {
		return false
	}

	return d.base64Pattern.MatchString(line) || d.hexPattern.MatchString(line)
}

// analyzeEncodedContent analyzes potentially encoded secrets
func (d *HardcodedCredentialsDetectorV2) analyzeEncodedContent(line string, lineNum int, filePath string) []patterns.Finding {
	var findings []patterns.Finding

	// High confidence if Base64 is in a credential context
	if d.base64Pattern.MatchString(line) &&
		(strings.Contains(strings.ToLower(line), "secret") ||
		 strings.Contains(strings.ToLower(line), "api") ||
		 strings.Contains(strings.ToLower(line), "key")) {
		findings = append(findings, d.createFinding(line, lineNum, filePath, "HIGH", 0.78, "Base64-encoded credential detected")...)
	}

	// Hex patterns in credential context
	if d.hexPattern.MatchString(line) &&
		(strings.Contains(strings.ToLower(line), "secret") ||
		 strings.Contains(strings.ToLower(line), "key")) {
		findings = append(findings, d.createFinding(line, lineNum, filePath, "HIGH", 0.72, "Hex-encoded potential credential detected")...)
	}

	return findings
}

// checkObfuscation checks for obfuscation techniques
func (d *HardcodedCredentialsDetectorV2) checkObfuscation(line string) bool {
	return d.base64Decode.MatchString(line) ||
		d.charArrayLoop.MatchString(line) ||
		(d.obfuscationPattern.MatchString(line) && len(line) > 40)
}

// filterFalsePositives removes known false positive patterns
func (d *HardcodedCredentialsDetectorV2) filterFalsePositives(findings []patterns.Finding) []patterns.Finding {
	var filtered []patterns.Finding

	falsePositivePatterns := []string{
		"example", "test", "demo", "placeholder",
		"YOUR_", "REPLACE_WITH_", "INSERT_",
		"todo", "fixme", "note:",
		"placeholder", "dummy", "mock",
	}

	for _, finding := range findings {
		isHidden := false
		lowerMessage := strings.ToLower(finding.Message)

		for _, pattern := range falsePositivePatterns {
			if strings.Contains(lowerMessage, pattern) {
				isHidden = true
				break
			}
		}

		if !isHidden {
			filtered = append(filtered, finding)
		}
	}

	return filtered
}

// isSupportedCredentialFile checks if file should be scanned for credentials
func (d *HardcodedCredentialsDetectorV2) isSupportedCredentialFile(path string) bool {
	supported := []string{".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".cs", ".rb", ".php", ".env", ".yml", ".yaml", ".json", ".xml", ".pem", ".key", ".pub"}
	for _, ext := range supported {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	// Also check for files without extensions like 'id_rsa'
	if strings.Contains(path, "id_rsa") || strings.Contains(path, "id_dsa") || strings.Contains(path, "id_ed25519") {
		return true
	}
	return false
}

// createFinding creates a Finding with the given parameters
func (d *HardcodedCredentialsDetectorV2) createFinding(line string, lineNum int, filePath string, severity string, confidence float32, message string) []patterns.Finding {
	return []patterns.Finding{
		{
			Pattern:    d.pattern.Name,
			PatternID:  d.pattern.ID,
			Severity:   severity,
			CVSS:       d.pattern.CVSS,
			Confidence: confidence,
			Line:       lineNum,
			Column:     1,
			Message:    message,
			Code:       strings.TrimSpace(line),
			File:       filePath,
			CWE:        strings.Join(d.pattern.CWEIDs, ", "),
			OWASP:      d.pattern.OWASP,
		},
	}
}
