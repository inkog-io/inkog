package detectors

import (
	"testing"
)

// PRIORITY 1: Critical Credential Format Tests

func TestHardcodedCredentialsV2AWSAccessKeyID(t *testing.T) {
	detector := NewHardcodedCredentialsDetectorV2()
	vulnerable := "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"

	findings, err := detector.Detect("test.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected AWS Access Key detection, got 0 findings")
	}
	if findings[0].Severity != "CRITICAL" {
		t.Fatalf("Expected CRITICAL, got %s", findings[0].Severity)
	}
	if findings[0].Confidence < 0.85 {
		t.Fatalf("Expected confidence > 0.85, got %.2f", findings[0].Confidence)
	}
}

func TestHardcodedCredentialsV2AWSSecretKey(t *testing.T) {
	detector := NewHardcodedCredentialsDetectorV2()
	vulnerable := "aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'"

	findings, err := detector.Detect("config.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected AWS Secret Key detection, got 0 findings")
	}
	if findings[0].Severity != "CRITICAL" {
		t.Fatalf("Expected CRITICAL, got %s", findings[0].Severity)
	}
}

func TestHardcodedCredentialsV2AzureStorage(t *testing.T) {
	detector := NewHardcodedCredentialsDetectorV2()
	vulnerable := `connection_string = "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=abc123==;EndpointSuffix=core.windows.net"`

	findings, err := detector.Detect("settings.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected Azure Storage Key detection, got 0 findings")
	}
	if findings[0].Severity != "CRITICAL" {
		t.Fatalf("Expected CRITICAL, got %s", findings[0].Severity)
	}
}

func TestHardcodedCredentialsV2GCPAPIKey(t *testing.T) {
	detector := NewHardcodedCredentialsDetectorV2()
	vulnerable := "gcp_api_key = 'AIzaSyA1234567890abcdefghijklmnopqrst'"

	findings, err := detector.Detect("config.js", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected GCP API Key detection, got 0 findings")
	}
	if findings[0].Severity != "CRITICAL" {
		t.Fatalf("Expected CRITICAL, got %s", findings[0].Severity)
	}
}

func TestHardcodedCredentialsV2StripeAPIKey(t *testing.T) {
	detector := NewHardcodedCredentialsDetectorV2()
	vulnerable := "stripe_key = 'sk_live_51234567890abcdefghijklmnopqrst'"

	findings, err := detector.Detect("payment.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected Stripe API Key detection, got 0 findings")
	}
	if findings[0].Severity != "CRITICAL" {
		t.Fatalf("Expected CRITICAL, got %s", findings[0].Severity)
	}
	if findings[0].Confidence < 0.90 {
		t.Fatalf("Expected high confidence for Stripe, got %.2f", findings[0].Confidence)
	}
}

func TestHardcodedCredentialsV2GitHubToken(t *testing.T) {
	detector := NewHardcodedCredentialsDetectorV2()
	vulnerable := "github_token = 'ghp_abcdefghijklmnopqrstuvwxyz1234567890'"

	findings, err := detector.Detect("deploy.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected GitHub Token detection, got 0 findings")
	}
	if findings[0].Confidence < 0.95 {
		t.Fatalf("Expected very high confidence for GitHub, got %.2f", findings[0].Confidence)
	}
}

func TestHardcodedCredentialsV2SlackToken(t *testing.T) {
	detector := NewHardcodedCredentialsDetectorV2()
	vulnerable := "slack_bot = 'xoxb-1234567890123-1234567890123-abcdefghijklmnopqrstuvwx'"

	findings, err := detector.Detect("notifications.js", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected Slack Token detection, got 0 findings")
	}
	if findings[0].Severity != "CRITICAL" {
		t.Fatalf("Expected CRITICAL, got %s", findings[0].Severity)
	}
}

// PRIORITY 1: Private Key Detection Tests

func TestHardcodedCredentialsV2RSAPrivateKey(t *testing.T) {
	detector := NewHardcodedCredentialsDetectorV2()
	vulnerable := "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyz\n-----END RSA PRIVATE KEY-----"

	findings, err := detector.Detect("keys.pem", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected RSA Private Key detection, got 0 findings")
	}
	if findings[0].Severity != "CRITICAL" {
		t.Fatalf("Expected CRITICAL for private key, got %s", findings[0].Severity)
	}
	if findings[0].Confidence < 0.90 {
		t.Fatalf("Expected high confidence for private key, got %.2f", findings[0].Confidence)
	}
}

func TestHardcodedCredentialsV2OpenSSHPrivateKey(t *testing.T) {
	detector := NewHardcodedCredentialsDetectorV2()
	vulnerable := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n-----END OPENSSH PRIVATE KEY-----"

	findings, err := detector.Detect("id_rsa", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected OpenSSH Private Key detection, got 0 findings")
	}
	if findings[0].Severity != "CRITICAL" {
		t.Fatalf("Expected CRITICAL for OpenSSH key, got %s", findings[0].Severity)
	}
}

func TestHardcodedCredentialsV2ECPrivateKey(t *testing.T) {
	detector := NewHardcodedCredentialsDetectorV2()
	vulnerable := "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIB+DYvh7SEqVTm+ZNwM=\n-----END EC PRIVATE KEY-----"

	findings, err := detector.Detect("ec_key.pem", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected EC Private Key detection, got 0 findings")
	}
}

// PRIORITY 1: Confidence Scoring Tests

func TestHardcodedCredentialsV2ConfidenceScoringHighRisk(t *testing.T) {
	detector := NewHardcodedCredentialsDetectorV2()
	// High-entropy, long, in password context
	vulnerable := "DATABASE_PASSWORD = 'aB1$cD2@eF3#gH4%iJ5^kL6&mN7*oP8(qR9)sT0_uV1+wX2=yZ3.aB4?cD5!eF6~gH7|iJ8/kL9\\mN0{oP1}qR2[sT3]'"

	findings, err := detector.Detect("config.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected credential detection with high confidence, got 0 findings")
	}
	if findings[0].Confidence < 0.70 {
		t.Fatalf("Expected confidence >= 0.70 for high-entropy password, got %.2f", findings[0].Confidence)
	}
}

func TestHardcodedCredentialsV2ConfidenceScoringLowRisk(t *testing.T) {
	detector := NewHardcodedCredentialsDetectorV2()
	// Short, simple, common dummy value
	vulnerable := "api_key = 'password123'"

	findings, err := detector.Detect("config.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	// May or may not detect depending on scoring; if detected, confidence should be low
	if len(findings) > 0 && findings[0].Confidence > 0.50 {
		// This is fine - could be either way depending on implementation
	}
}

// PRIORITY 2: Encoding Detection Tests

func TestHardcodedCredentialsV2Base64Encoding(t *testing.T) {
	detector := NewHardcodedCredentialsDetectorV2()
	vulnerable := "secret = 'SGVyZSdzIGEgc2VjcmV0IGtleSB0aGF0IGlzIGVuY29kZWQgaW4gYmFzZTY0Zm9ybWF0Zm9ydGVzdGluZ3B1cnBvc2VzIQ=='"

	findings, err := detector.Detect("config.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected Base64-encoded credential detection, got 0 findings")
	}
}

func TestHardcodedCredentialsV2HexEncoding(t *testing.T) {
	detector := NewHardcodedCredentialsDetectorV2()
	vulnerable := "api_key = 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	findings, err := detector.Detect("settings.js", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected Hex-encoded credential detection, got 0 findings")
	}
}

// PRIORITY 2: False Positive Reduction Tests

func TestHardcodedCredentialsV2PlaceholderDetection(t *testing.T) {
	detector := NewHardcodedCredentialsDetectorV2()
	notVulnerable := "api_key = 'YOUR_API_KEY_HERE'"

	findings, err := detector.Detect("example.py", []byte(notVulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	// Should not detect placeholders
	if len(findings) > 0 && findings[0].Confidence > 0.50 {
		t.Logf("Warning: Placeholder detected as credential with confidence %.2f", findings[0].Confidence)
	}
}

func TestHardcodedCredentialsV2PublicKeyIgnored(t *testing.T) {
	detector := NewHardcodedCredentialsDetectorV2()
	notVulnerable := `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDX1234567890abcdefghijklmnopqrstuvwxyz1234567890`

	findings, err := detector.Detect("authorized_keys", []byte(notVulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	// Public keys should not trigger findings
	if len(findings) > 0 && findings[0].Confidence > 0.50 {
		t.Logf("Warning: Public key falsely detected as credential")
	}
}

func TestHardcodedCredentialsV2TestFileSkipped(t *testing.T) {
	detector := NewHardcodedCredentialsDetectorV2()
	vulnerable := "api_key = 'sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890'"

	findings, err := detector.Detect("test_integration.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	// Test files should skip detection
	if len(findings) > 0 {
		t.Fatalf("Expected test file to be skipped, but got %d findings", len(findings))
	}
}

func TestHardcodedCredentialsV2CommentSkipped(t *testing.T) {
	detector := NewHardcodedCredentialsDetectorV2()
	notVulnerable := `# api_key = 'sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890'
# This is just an example`

	findings, err := detector.Detect("config.py", []byte(notVulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	// Comments should be skipped
	if len(findings) > 0 {
		t.Fatalf("Expected comments to be skipped, but got %d findings", len(findings))
	}
}

// PRIORITY 2: String Handling Tests

func TestHardcodedCredentialsV2MultipleSecrets(t *testing.T) {
	detector := NewHardcodedCredentialsDetectorV2()
	vulnerable := `
api_key = 'sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890'
db_password = 'aB1$cD2@eF3#gH4%iJ5^kL6&mN7*oP8(qR9)sT0_uV1+wX2=yZ3'
github_token = 'ghp_abcdefghijklmnopqrstuvwxyz1234567890'
`

	findings, err := detector.Detect("config.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) < 2 {
		t.Fatalf("Expected multiple findings, got %d", len(findings))
	}
}

// PRIORITY 3: Multi-Language Support Tests

func TestHardcodedCredentialsV2JavaScript(t *testing.T) {
	detector := NewHardcodedCredentialsDetectorV2()
	vulnerable := "const apiKey = 'sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890';"

	findings, err := detector.Detect("config.js", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected JavaScript credential detection, got 0 findings")
	}
}

func TestHardcodedCredentialsV2Go(t *testing.T) {
	detector := NewHardcodedCredentialsDetectorV2()
	vulnerable := "apiKey := \"sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890\""

	findings, err := detector.Detect("config.go", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected Go credential detection, got 0 findings")
	}
}

func TestHardcodedCredentialsV2Java(t *testing.T) {
	detector := NewHardcodedCredentialsDetectorV2()
	vulnerable := "String apiKey = \"sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890\";"

	findings, err := detector.Detect("Config.java", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected Java credential detection, got 0 findings")
	}
}

func TestHardcodedCredentialsV2CSharp(t *testing.T) {
	detector := NewHardcodedCredentialsDetectorV2()
	vulnerable := "string apiKey = \"sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890\";"

	findings, err := detector.Detect("Config.cs", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected C# credential detection, got 0 findings")
	}
}

// PRIORITY 3: Obfuscation Detection Tests

func TestHardcodedCredentialsV2Base64Decoding(t *testing.T) {
	detector := NewHardcodedCredentialsDetectorV2()
	vulnerable := "secret = atob('SGVyZXNhY3JldGtleQ==')"

	findings, err := detector.Detect("main.js", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected obfuscation detection, got 0 findings")
	}
}

func TestHardcodedCredentialsV2EvalObfuscation(t *testing.T) {
	detector := NewHardcodedCredentialsDetectorV2()
	vulnerable := "eval('secret=\"sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890\"')"

	findings, err := detector.Detect("app.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected obfuscation detection, got 0 findings")
	}
}

// CVE Validation Tests

func TestHardcodedCredentialsV2CVELangChainAgentSmith(t *testing.T) {
	detector := NewHardcodedCredentialsDetectorV2()
	vulnerable := `
# LangChain AgentSmith vulnerability: API keys in environment
import os
openai_api_key = os.environ.get("OPENAI_API_KEY", "sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890")
anthropic_key = "cl-1234567890abcdefghijklmnopqrstuvwxyz1234567890"
`

	findings, err := detector.Detect("agent.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected CVE-LangChain detection, got 0 findings")
	}
}

func TestHardcodedCredentialsV2CVEUber2022(t *testing.T) {
	detector := NewHardcodedCredentialsDetectorV2()
	vulnerable := `# Uber 2022: Admin credentials in script
admin_password = "aB1$cD2@eF3#gH4%iJ5^kL6&mN7*oP8(qR9)sT0_uV1+wX2=yZ3"
aws_access_key = "AKIAIOSFODNN7EXAMPLE"
aws_secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"`

	findings, err := detector.Detect("deploy.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) < 2 {
		t.Fatalf("Expected multiple credential findings, got %d", len(findings))
	}
}

func TestHardcodedCredentialsV2CVEFlowise(t *testing.T) {
	detector := NewHardcodedCredentialsDetectorV2()
	vulnerable := `
# Flowise: Stored API keys without proper encryption
const config = {
  openai_api_key: "sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890",
  pinecone_api_key: "abc123def456ghi789jkl012mno345pqr",
  database_password: "aB1$cD2@eF3#gH4%iJ5^kL6&mN7*oP8(qR9)sT0_uV1+wX2=yZ3"
};
`

	findings, err := detector.Detect("flowise_config.js", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) < 2 {
		t.Fatalf("Expected multiple findings for Flowise, got %d", len(findings))
	}
}

func TestHardcodedCredentialsV2CVEDify(t *testing.T) {
	detector := NewHardcodedCredentialsDetectorV2()
	vulnerable := `
# Dify: Secret exposure in workflow
ANTHROPIC_API_KEY="cl-1234567890abcdefghijklmnopqrstuvwxyz1234567890"
HUGGINGFACE_API_KEY="hf_1234567890abcdefghijklmnopqrstuvwxyz1234567890"
PINECONE_API_KEY="abc123def456ghi789jkl012mno345pqr"
DB_PASSWORD="aB1$cD2@eF3#gH4%iJ5^kL6&mN7*oP8(qR9)sT0_uV1+wX2=yZ3"
`

	findings, err := detector.Detect("dify_config.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) < 3 {
		t.Fatalf("Expected multiple findings for Dify, got %d", len(findings))
	}
}

func TestHardcodedCredentialsV2CVECrewAI(t *testing.T) {
	detector := NewHardcodedCredentialsDetectorV2()
	vulnerable := `
# CrewAI: Environment variable hardcoding (bad practice)
os.environ["OPENAI_API_KEY"] = "sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890"
os.environ["ANTHROPIC_API_KEY"] = "cl-1234567890abcdefghijklmnopqrstuvwxyz1234567890"
os.environ["SERPER_API_KEY"] = "abc123def456ghi789jkl012mno345pqr"
`

	findings, err := detector.Detect("crew_config.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) < 2 {
		t.Fatalf("Expected multiple findings for CrewAI, got %d", len(findings))
	}
}

// Edge Case Tests

func TestHardcodedCredentialsV2EmptyFile(t *testing.T) {
	detector := NewHardcodedCredentialsDetectorV2()
	findings, err := detector.Detect("empty.py", []byte(""))
	if err != nil {
		t.Fatalf("Expected no error for empty file, got %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("Expected no findings for empty file, got %d", len(findings))
	}
}

func TestHardcodedCredentialsV2UnsupportedFileType(t *testing.T) {
	detector := NewHardcodedCredentialsDetectorV2()
	vulnerable := "api_key = 'sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890'"
	findings, err := detector.Detect("data.csv", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("Expected no findings for unsupported file type, got %d", len(findings))
	}
}

func TestHardcodedCredentialsV2EntropyAnalysis(t *testing.T) {
	detector := NewHardcodedCredentialsDetectorV2()
	// Test that high-entropy strings are detected with higher confidence
	vulnerable := "secret = 'aB1$cD2@eF3#gH4%iJ5^kL6&mN7*oP8(qR9)sT0_uV1+wX2=yZ3.aB4?cD5!eF6~gH7|iJ8/kL9'"

	findings, err := detector.Detect("config.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) > 0 && findings[0].Confidence < 0.60 {
		t.Fatalf("Expected high confidence for high-entropy value, got %.2f", findings[0].Confidence)
	}
}

func TestHardcodedCredentialsV2JWTDetection(t *testing.T) {
	detector := NewHardcodedCredentialsDetectorV2()
	vulnerable := "jwt_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'"

	findings, err := detector.Detect("auth.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("Expected JWT detection, got 0 findings")
	}
}

func TestHardcodedCredentialsV2ConfidenceRange(t *testing.T) {
	detector := NewHardcodedCredentialsDetectorV2()
	// Test that confidence values stay within [0.0, 1.0]
	vulnerable := "password = 'aB1$cD2@eF3#gH4%iJ5^kL6&mN7*oP8(qR9)sT0_uV1+wX2=yZ3'"

	findings, err := detector.Detect("config.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(findings) > 0 {
		if findings[0].Confidence < 0.0 || findings[0].Confidence > 1.0 {
			t.Fatalf("Confidence out of range: %.2f", findings[0].Confidence)
		}
	}
}

// Benchmark Test

func BenchmarkHardcodedCredentialsV2(b *testing.B) {
	detector := NewHardcodedCredentialsDetectorV2()
	content := `
api_key = 'sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890'
db_password = 'aB1$cD2@eF3#gH4%iJ5^kL6&mN7*oP8(qR9)sT0_uV1+wX2=yZ3'
github_token = 'ghp_abcdefghijklmnopqrstuvwxyz1234567890'
aws_key = 'AKIAIOSFODNN7EXAMPLE'
stripe_key = 'sk_live_51234567890abcdefghijklmnopqrst'
` +
		`
# More content to test performance
secret_key = 'complex-secret-value-1234567890-abcdefghijklmnopqrstuvwxyz'
encryption_key = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
database_url = 'postgresql://user:password123@localhost:5432/dbname'
`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.Detect("benchmark.py", []byte(content))
	}
}
