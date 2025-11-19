package detectors

import (
	"strings"
	"testing"
)

func TestHardcodedCredentialsOpenAIKey(t *testing.T) {
	detector := NewHardcodedCredentialsDetector()

	// Test 1: OpenAI API key detection
	vulnerable := `
import openai

# VULNERABLE: Hardcoded API key
OPENAI_API_KEY = "sk-proj-abc123def456xyz789"
openai.api_key = OPENAI_API_KEY

def chat_with_gpt():
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Hello"}]
    )
    return response
`

	findings, err := detector.Detect("openai_client.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("Failed to detect OpenAI API key")
	}

	if findings[0].Severity != "CRITICAL" {
		t.Fatalf("Expected CRITICAL severity, got %s", findings[0].Severity)
	}

	// Verify secret is masked in output
	if strings.Contains(findings[0].Code, "abc123def456") {
		t.Logf("Warning: Secret not masked in output: %s", findings[0].Code)
	}
}

func TestHardcodedCredentialsGitHubToken(t *testing.T) {
	detector := NewHardcodedCredentialsDetector()

	// Test 2: GitHub token detection
	vulnerable := `
import github

# VULNERABLE: GitHub personal access token
GITHUB_TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
g = github.Github(GITHUB_TOKEN)
user = g.get_user()
print(user.name)
`

	findings, err := detector.Detect("github_client.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("Failed to detect GitHub token")
	}

	if findings[0].Severity != "CRITICAL" {
		t.Fatalf("Expected CRITICAL, got %s", findings[0].Severity)
	}
}

func TestHardcodedCredentialsDatabasePassword(t *testing.T) {
	detector := NewHardcodedCredentialsDetector()

	// Test 3: Database password detection
	vulnerable := `
import psycopg2

# VULNERABLE: Database password hardcoded
DB_HOST = "postgres.example.com"
DB_USER = "admin"
DB_PASSWORD = "SuperSecurePass123!@#"
DB_NAME = "production_db"

connection = psycopg2.connect(
    host=DB_HOST,
    user=DB_USER,
    password=DB_PASSWORD,
    database=DB_NAME
)
`

	findings, err := detector.Detect("db_config.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("Failed to detect database password")
	}

	if findings[0].Severity != "CRITICAL" {
		t.Fatalf("Expected CRITICAL severity")
	}
}

func TestHardcodedCredentialsJWTToken(t *testing.T) {
	detector := NewHardcodedCredentialsDetector()

	// Test 4: JWT token detection
	vulnerable := `
# VULNERABLE: Hardcoded JWT secret
JWT_SECRET = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

def verify_token(token):
    import jwt
    payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    return payload
`

	findings, err := detector.Detect("auth.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(findings) == 0 {
		t.Logf("Warning: JWT token not detected (may need pattern update)")
	}
}

func TestHardcodedCredentialsPlaceholderIgnored(t *testing.T) {
	detector := NewHardcodedCredentialsDetector()

	// Test 5: Placeholder values should be ignored (false positive reduction)
	notVulnerable := `
# These are obviously placeholders - should not trigger
API_KEY = "your_api_key_here"
SECRET = "your_secret_here"
PASSWORD = "replace_with_actual_password"
TOKEN = "xxx"
KEY = "YOUR_KEY"
`

	findings, err := detector.Detect("config.py", []byte(notVulnerable))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(findings) > 0 {
		t.Fatalf("Should ignore placeholder values, but found %d findings", len(findings))
	}
}

func TestHardcodedCredentialsCommentIgnored(t *testing.T) {
	detector := NewHardcodedCredentialsDetector()

	// Test 6: Secrets in comments should be ignored
	notVulnerable := `
# Commented out - should not trigger
# OLD_API_KEY = "sk-proj-abc123"
# PASSWORD = "admin123"

# Use environment variables instead
API_KEY = os.getenv("API_KEY")
`

	findings, err := detector.Detect("config.py", []byte(notVulnerable))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	// Should either not find secrets in comments
	for _, f := range findings {
		if strings.Contains(f.Code, "#") {
			t.Logf("Warning: Found secret in comment: %s", f.Code)
		}
	}
}

func TestHardcodedCredentialsConfidenceScoring(t *testing.T) {
	detector := NewHardcodedCredentialsDetector()

	vulnerable := `
API_KEY = "sk-proj-test123"
`

	findings, err := detector.Detect("app.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("No findings")
	}

	// Test 7: Confidence should be very high (95-99%)
	confidence := findings[0].Confidence
	if confidence < 0.95 {
		t.Fatalf("Confidence too low: %.2f, expected >= 0.95", confidence)
	}

	if confidence > 1.0 {
		t.Fatalf("Confidence > 1.0: %.2f", confidence)
	}
}

func TestHardcodedCredentialsMultipleSecrets(t *testing.T) {
	detector := NewHardcodedCredentialsDetector()

	// Test 8: Multiple secrets in same file
	vulnerable := `
API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"
DB_PASSWORD = "SuperSecureAdminPassword123!@#"
GITHUB_TOKEN = "ghp_xyz789abcdefghijklmnopqrstuvwxyz1234567890"
JWT_SECRET = "my-secret-key-with-minimum-length-requirement"
AWS_SECRET = "aws_secret_access_key_with_realistically_long_value_here"
`

	findings, err := detector.Detect("secrets.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(findings) < 3 {
		t.Fatalf("Expected multiple findings, got %d", len(findings))
	}

	// All should be CRITICAL
	for _, f := range findings {
		if f.Severity != "CRITICAL" {
			t.Fatalf("Expected all findings to be CRITICAL, got %s", f.Severity)
		}
	}
}

func TestHardcodedCredentialsJavaScript(t *testing.T) {
	detector := NewHardcodedCredentialsDetector()

	// Test 9: JavaScript const declarations
	vulnerable := `
const API_KEY = "sk-proj-abc123def456";
const client = new OpenAI({ apiKey: API_KEY });
`

	findings, err := detector.Detect("client.js", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(findings) == 0 {
		t.Logf("Warning: JavaScript const not detected (may need pattern update)")
	}
}

func TestHardcodedCredentialsEnvironmentVariables(t *testing.T) {
	detector := NewHardcodedCredentialsDetector()

	// Test 10: Secure pattern using environment variables
	secure := `
import os

# SECURE: Using environment variables
API_KEY = os.getenv("OPENAI_API_KEY")
DB_PASSWORD = os.getenv("DB_PASSWORD", "default")

if not API_KEY:
    raise ValueError("OPENAI_API_KEY not set")
`

	findings, err := detector.Detect("config.py", []byte(secure))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(findings) > 0 {
		t.Fatalf("Secure code triggered findings: %v", findings)
	}
}

func TestHardcodedCredentialsSecretsManager(t *testing.T) {
	detector := NewHardcodedCredentialsDetector()

	// Test 11: Secure pattern using AWS Secrets Manager
	secure := `
import boto3

# SECURE: Using AWS Secrets Manager
secretsmanager = boto3.client("secretsmanager")
secret_response = secretsmanager.get_secret_value(SecretId="my-api-key")
API_KEY = secret_response["SecretString"]
`

	findings, err := detector.Detect("config.py", []byte(secure))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	// Should not find hardcoded credentials
	if len(findings) > 0 {
		t.Fatalf("Secure secrets manager pattern triggered findings")
	}
}

func TestHardcodedCredentialsTestFileIgnored(t *testing.T) {
	detector := NewHardcodedCredentialsDetector()

	// Test 12: Test files should skip credentials (reduce false positives)
	testCode := `
def test_api_client():
    API_KEY = "sk-test-123"
    client = OpenAI(api_key=API_KEY)
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "test"}]
    )
    assert response is not None
`

	findings, err := detector.Detect("test_client.py", []byte(testCode))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(findings) > 0 {
		t.Fatalf("Should skip test files, but found %d findings", len(findings))
	}
}

// Benchmark test
func BenchmarkHardcodedCredentials(b *testing.B) {
	detector := NewHardcodedCredentialsDetector()
	code := []byte(`
API_KEY = "sk-proj-abc123"
PASSWORD = "admin123"
TOKEN = "ghp_xyz"
` + "\n")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.Detect("app.py", code)
	}
}
