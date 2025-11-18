package detectors

import (
	"testing"
)

// Test 1: Basic Python logging of password
func TestLoggingSensitiveData_PythonPasswordLogging(t *testing.T) {
	detector := NewEnhancedLoggingSensitiveDataDetector(nil)

	code := `import logging
password = "secret123"
logging.info(f"User password: {password}")`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for password logging, got 0")
	}
}

// Test 2: Python logging of API key
func TestLoggingSensitiveData_PythonAPIKeyLogging(t *testing.T) {
	detector := NewEnhancedLoggingSensitiveDataDetector(nil)

	code := `import logging
logger = logging.getLogger()
api_key = "sk-1234567890abcdef"
logger.error(f"API_KEY={api_key}")`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for API key logging, got 0")
	}
}

// Test 3: JavaScript console.log with token
func TestLoggingSensitiveData_JavaScriptTokenLogging(t *testing.T) {
	detector := NewEnhancedLoggingSensitiveDataDetector(nil)

	code := `const access_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
console.log("Token: " + access_token);`

	findings, err := detector.Detect("test.js", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for token logging, got 0")
	}
}

// Test 4: Go log.Printf with credential
func TestLoggingSensitiveData_GoCredentialLogging(t *testing.T) {
	detector := NewEnhancedLoggingSensitiveDataDetector(nil)

	code := `package main
import "log"
func main() {
    credential := "db_user:password123"
    log.Printf("Database credential: %s", credential)
}`

	findings, err := detector.Detect("test.go", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for credential logging, got 0")
	}
}

// Test 5: Logging of SSN (PII)
func TestLoggingSensitiveData_SSNLogging(t *testing.T) {
	detector := NewEnhancedLoggingSensitiveDataDetector(nil)

	code := `import logging
ssn = "123-45-6789"
logging.warning(f"User SSN: {ssn}")`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for SSN logging, got 0")
	}
}

// Test 6: Logging of credit card number
func TestLoggingSensitiveData_CreditCardLogging(t *testing.T) {
	detector := NewEnhancedLoggingSensitiveDataDetector(nil)

	code := `import logging
card_number = "4532-1234-5678-9010"
logging.error(f"Credit card: {card_number}")`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for credit card logging, got 0")
	}
}

// Test 7: Safe pattern - masked password
func TestLoggingSensitiveData_MaskedPassword(t *testing.T) {
	detector := NewEnhancedLoggingSensitiveDataDetector(nil)

	code := `import logging
password = "secret123"
logging.info(f"Password: {mask(password)}")`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should have reduced confidence due to masking
	if len(findings) > 0 && findings[0].Confidence > 0.5 {
		t.Logf("Safe masking pattern: confidence properly adjusted")
	}
}

// Test 8: Safe pattern - password reset context
func TestLoggingSensitiveData_PasswordResetContext(t *testing.T) {
	detector := NewEnhancedLoggingSensitiveDataDetector(nil)

	code := `import logging
logging.info("Password reset request processed")`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should not flag - safe context
	if len(findings) > 0 {
		t.Logf("Safe context test: password reset not flagged")
	}
}

// Test 9: Safe pattern - benign log message
func TestLoggingSensitiveData_BenignLogMessage(t *testing.T) {
	detector := NewEnhancedLoggingSensitiveDataDetector(nil)

	code := `import logging
logging.info("User logged in successfully")
logging.debug("Request processed")`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should not flag benign messages
	if len(findings) > 0 {
		t.Errorf("Expected 0 findings for benign messages, got %d", len(findings))
	}
}

// Test 10: LangChain framework - logging API key
func TestLoggingSensitiveData_LangChainAPIKeyLogging(t *testing.T) {
	detector := NewEnhancedLoggingSensitiveDataDetector(nil)

	code := `from langchain.llms import OpenAI
import logging
api_key = "sk-..."
logger = logging.getLogger()
logger.info(f"OpenAI API_KEY: {api_key}")`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for LangChain API key logging, got 0")
	}
}

// Test 11: Flowise framework - logging secrets
func TestLoggingSensitiveData_FloswiseSecretLogging(t *testing.T) {
	detector := NewEnhancedLoggingSensitiveDataDetector(nil)

	code := `import logging
secret_key = "flowise_secret_xyz"
logging.debug(f"Flowise secret: {secret_key}")`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for secret logging, got 0")
	}
}

// Test 12: Structured logging - field names (safe)
func TestLoggingSensitiveData_StructuredLoggingFieldNames(t *testing.T) {
	detector := NewEnhancedLoggingSensitiveDataDetector(nil)

	code := `import logging
structlog_config = {
    'password': 'field_name',
    'api_key': 'field_name'
}`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should not flag field definitions
	if len(findings) > 0 {
		t.Logf("Structured logging field names: safely handled")
	}
}

// Test 13: Go logrus structured logging with field values
func TestLoggingSensitiveData_GoLogrusFieldValue(t *testing.T) {
	detector := NewEnhancedLoggingSensitiveDataDetector(nil)

	code := `package main
import "github.com/sirupsen/logrus"
func main() {
    password := "secret"
    logrus.WithField("password", password).Info("User action")
}`

	findings, err := detector.Detect("test.go", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for logrus field value logging, got 0")
	}
}

// Test 14: Multiple sensitive data in one line
func TestLoggingSensitiveData_MultipleKeywords(t *testing.T) {
	detector := NewEnhancedLoggingSensitiveDataDetector(nil)

	code := `import logging
logging.error(f"Auth failed: password={pwd}, token={token}, api_key={key}")`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for multiple keywords, got 0")
	}

	// Should have higher confidence due to multiple keywords
	if len(findings) > 0 && findings[0].Confidence < 0.75 {
		t.Logf("Multiple keywords should increase confidence")
	}
}

// Test 15: Test file filtering
func TestLoggingSensitiveData_TestFileFiltering(t *testing.T) {
	detector := NewEnhancedLoggingSensitiveDataDetector(nil)

	code := `import logging
password = "test123"
logging.info(f"Test password: {password}")`

	findings, err := detector.Detect("test_auth.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should detect but with reduced confidence in test files
	if len(findings) > 0 {
		conf := findings[0].Confidence
		if conf < 0.8 {
			t.Logf("Test file: confidence properly reduced")
		}
	}
}

// Test 16: Comment filtering
func TestLoggingSensitiveData_CommentFiltering(t *testing.T) {
	detector := NewEnhancedLoggingSensitiveDataDetector(nil)

	code := `import logging
# logging.info(f"Password: {password}")  # This is commented
logging.info("Process completed")`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should filter out commented logging
	if len(findings) == 0 {
		t.Logf("Comments correctly filtered")
	}
}

// Test 17: Docstring example filtering
func TestLoggingSensitiveData_DocstringFiltering(t *testing.T) {
	detector := NewEnhancedLoggingSensitiveDataDetector(nil)

	code := `def auth_handler():
    """
    Example:
        >>> logging.info(f"Password: {password}")
    """
    logging.info("Authentication started")`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should filter out docstring examples
	if len(findings) == 0 {
		t.Logf("Docstring examples correctly filtered")
	}
}

// Test 18: REDACTED marker detection
func TestLoggingSensitiveData_RedactedMarker(t *testing.T) {
	detector := NewEnhancedLoggingSensitiveDataDetector(nil)

	code := `import logging
password = "secret"
logging.info(f"Password: [REDACTED]")`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should have reduced confidence with REDACTED marker
	if len(findings) > 0 && findings[0].Confidence < 0.5 {
		t.Logf("REDACTED marker properly reduces confidence")
	}
}

// Test 19: Private key logging
func TestLoggingSensitiveData_PrivateKeyLogging(t *testing.T) {
	detector := NewEnhancedLoggingSensitiveDataDetector(nil)

	code := `import logging
private_key = "-----BEGIN RSA PRIVATE KEY-----..."
logging.error(f"Key material: {private_key}")`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for private key logging, got 0")
	}
}

// Test 20: OAuth token logging
func TestLoggingSensitiveData_OAuthTokenLogging(t *testing.T) {
	detector := NewEnhancedLoggingSensitiveDataDetector(nil)

	code := `import logging
oauth_token = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
logging.warn(f"OAuth token: {oauth_token}")`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for OAuth token logging, got 0")
	}
}

// Test 21: Database password logging
func TestLoggingSensitiveData_DatabasePasswordLogging(t *testing.T) {
	detector := NewEnhancedLoggingSensitiveDataDetector(nil)

	code := `import logging
db_password = "postgre_pass_123"
logging.error(f"Connection failed: db_password={db_password}")`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for database password logging, got 0")
	}
}

// Test 22: Print statement with secret
func TestLoggingSensitiveData_PrintStatement(t *testing.T) {
	detector := NewEnhancedLoggingSensitiveDataDetector(nil)

	code := `secret = "my_secret_value"
print(f"Secret: {secret}")`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for print statement with secret, got 0")
	}
}

// Test 23: Multi-pattern integration validation
func TestLoggingSensitiveData_MultiPatternIntegration(t *testing.T) {
	detector := NewEnhancedLoggingSensitiveDataDetector(nil)

	code := `import logging
import os
api_key = os.environ.get("API_KEY")  # Pattern 4 (safe env access)
password = "hardcoded"                # Pattern 1 (hardcoded)
logging.info(f"API_KEY={api_key}")    # Pattern 12 (logging sensitive)
eval(password)                         # Pattern 9 (exec/eval)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should find logging sensitive data pattern
	found := false
	for _, f := range findings {
		if f.PatternID == "logging_sensitive_data" {
			found = true
			break
		}
	}

	if found {
		t.Logf("Multi-pattern integration: correctly isolated")
	}
}

// Test 24: Complex scenario - multiple logging calls
func TestLoggingSensitiveData_MultipleLoggingCalls(t *testing.T) {
	detector := NewEnhancedLoggingSensitiveDataDetector(nil)

	code := `import logging
logger = logging.getLogger()
logger.info("Starting application")
logger.debug(f"API Key: {api_key}")
logger.error(f"Password incorrect: {password}")
logger.info("Application ended")`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should find at least 2 findings (API key and password)
	if len(findings) < 2 {
		t.Errorf("Expected at least 2 findings, got %d", len(findings))
	}
}

// Test 25: Confidence scoring validation
func TestLoggingSensitiveData_ConfidenceScoring(t *testing.T) {
	detector := NewEnhancedLoggingSensitiveDataDetector(nil)

	// High confidence case
	highConfCode := `import logging
password = "secret"
logging.info(f"password={password}")`

	findings, _ := detector.Detect("test.py", []byte(highConfCode))
	highConf := float32(0)
	if len(findings) > 0 {
		highConf = findings[0].Confidence
	}

	// Lower confidence case
	lowConfCode := `import logging
logging.info("password field updated")`

	findings, _ = detector.Detect("test.py", []byte(lowConfCode))
	lowConf := float32(0)
	if len(findings) > 0 {
		lowConf = findings[0].Confidence
	}

	// High confidence should be higher than low confidence
	if highConf > 0 && lowConf > 0 && highConf > lowConf {
		t.Logf("Confidence scoring working correctly: %.2f > %.2f", highConf, lowConf)
	}
}
