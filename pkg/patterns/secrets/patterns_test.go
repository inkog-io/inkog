package secrets

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestRedactSecrets_JSONSafe verifies that redaction preserves valid JSON syntax
// The primary goal is JSON validity - the specific redaction marker may vary
// based on whether regex or entropy detection catches the secret first
func TestRedactSecrets_JSONSafe(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		wantValidJSON bool
		wantRedacted  bool // Should contain any [REDACTED-*] marker
	}{
		{
			name:          "AWS Access Key in JSON object",
			input:         `{"credentials": {"aws_key": "AKIA1234567890123456"}}`,
			wantValidJSON: true,
			wantRedacted:  true,
		},
		{
			name:          "Stripe key in JSON",
			input:         `{"payment": {"stripe_key": "` + "sk_" + `test_XXXXXXXXXXXXXXXXXXXXXXXX"}}`,
			wantValidJSON: true,
			wantRedacted:  true,
		},
		{
			name:          "GitHub token in JSON array",
			input:         `{"tokens": ["ghp_abcdefghij1234567890abcdefghij123456"]}`,
			wantValidJSON: true,
			wantRedacted:  true,
		},
		{
			name:          "Multiple secrets in JSON",
			input:         `{"aws": "AKIA1234567890123456", "github": "ghp_abcdefghij1234567890abcdefghij123456"}`,
			wantValidJSON: true,
			wantRedacted:  true,
		},
		{
			name:          "n8n-style workflow config with high-entropy key",
			input:         `{"nodes": [{"name": "HTTP Request", "parameters": {"api_key": "` + "sk_" + `test_XXXXXXXXXXXXXXXXXXXXXXXX"}}]}`,
			wantValidJSON: true,
			wantRedacted:  true,
		},
		{
			name:          "Nested JSON with password",
			input:         `{"database": {"connection": "postgres://admin:supersecretpassword123@localhost/db"}}`,
			wantValidJSON: true,
			wantRedacted:  true,
		},
		{
			name:          "Clean JSON without secrets",
			input:         `{"name": "test", "count": 42}`,
			wantValidJSON: true,
			wantRedacted:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Detect secrets
			findings := DetectSecrets("test.json", []byte(tt.input))

			// Redact secrets
			redacted := RedactSecrets([]byte(tt.input), findings)
			redactedStr := string(redacted)

			// Test 1: Output should be valid JSON (CRITICAL)
			if tt.wantValidJSON {
				var result interface{}
				err := json.Unmarshal(redacted, &result)
				if err != nil {
					t.Errorf("Redacted JSON is invalid: %v\nInput:  %s\nOutput: %s", err, tt.input, redactedStr)
				}
			}

			// Test 2: Should contain redaction marker if secrets expected
			hasRedaction := strings.Contains(redactedStr, "[REDACTED-")
			if tt.wantRedacted && !hasRedaction {
				t.Errorf("Expected redaction but none found\nInput:  %s\nOutput: %s", tt.input, redactedStr)
			}
			if !tt.wantRedacted && hasRedaction {
				t.Errorf("Unexpected redaction found\nInput:  %s\nOutput: %s", tt.input, redactedStr)
			}
		})
	}
}

// TestRedactSecrets_JSONStructurePreserved verifies JSON structure is unchanged
func TestRedactSecrets_JSONStructurePreserved(t *testing.T) {
	input := `{
  "config": {
    "api_key": "AKIA1234567890123456",
    "settings": {
      "enabled": true,
      "count": 42
    }
  }
}`
	// Detect and redact
	findings := DetectSecrets("config.json", []byte(input))
	redacted := RedactSecrets([]byte(input), findings)

	// Parse both as JSON
	var original, redactedResult map[string]interface{}
	if err := json.Unmarshal([]byte(input), &original); err != nil {
		t.Fatalf("Original JSON invalid: %v", err)
	}
	if err := json.Unmarshal(redacted, &redactedResult); err != nil {
		t.Fatalf("Redacted JSON invalid: %v", err)
	}

	// Verify structure preserved (same keys at top level)
	if _, ok := redactedResult["config"]; !ok {
		t.Error("Redacted JSON missing 'config' key")
	}

	// Verify nested structure
	config, ok := redactedResult["config"].(map[string]interface{})
	if !ok {
		t.Fatal("Redacted JSON 'config' is not an object")
	}

	if _, ok := config["api_key"]; !ok {
		t.Error("Redacted JSON missing 'api_key' inside config")
	}

	if _, ok := config["settings"]; !ok {
		t.Error("Redacted JSON missing 'settings' inside config")
	}
}

// TestDetectSecrets_FindsAWSKey verifies AWS key detection works
func TestDetectSecrets_FindsAWSKey(t *testing.T) {
	content := `aws_key = "AKIA1234567890123456"`
	findings := DetectSecrets("test.py", []byte(content))

	if len(findings) == 0 {
		t.Error("Expected to find AWS key, but found nothing")
		return
	}

	found := false
	for _, f := range findings {
		if f.Type == "aws_access_key" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected aws_access_key finding, got: %v", findings)
	}
}

// TestDetectSecrets_FindsStripeKey verifies Stripe key detection works
// Note: Using sk_test_ prefix which is Stripe's test mode prefix
func TestDetectSecrets_FindsStripeKey(t *testing.T) {
	// sk_test_ prefix is Stripe's test mode - still a real key that should be detected
	content := `stripe_api_key = "` + "sk_" + `test_TESTKEY1234567890abcdef"`
	findings := DetectSecrets("test.py", []byte(content))

	// Stripe keys may be detected by entropy or regex, both are valid
	if len(findings) == 0 {
		t.Error("Expected to find Stripe key pattern, but found nothing")
		return
	}

	// Detection by stripe_key, entropy_secret, or api_key pattern is acceptable
	found := false
	for _, f := range findings {
		if f.Type == "stripe_key" || f.Type == "entropy_secret" || f.Type == "api_key" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected stripe_key, entropy_secret, or api_key finding, got: %v", findings)
	}
}

// TestDetectSecrets_FindsGitHubToken verifies GitHub token detection works
func TestDetectSecrets_FindsGitHubToken(t *testing.T) {
	content := `token = "ghp_abcdefghij1234567890abcdefghij123456"`
	findings := DetectSecrets("test.py", []byte(content))

	if len(findings) == 0 {
		t.Error("Expected to find GitHub token, but found nothing")
		return
	}

	found := false
	for _, f := range findings {
		if f.Type == "github_token" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected github_token finding, got: %v", findings)
	}
}

// TestRedactSecrets_NoSecretsUnchanged verifies files without secrets are unchanged
func TestRedactSecrets_NoSecretsUnchanged(t *testing.T) {
	input := `{"name": "test", "value": 123, "enabled": true}`
	findings := DetectSecrets("test.json", []byte(input))
	redacted := RedactSecrets([]byte(input), findings)

	if string(redacted) != input {
		t.Errorf("Content without secrets was modified\nInput:  %s\nOutput: %s", input, string(redacted))
	}
}

// TestRedactSecrets_YAMLSafe verifies YAML config redaction works
func TestRedactSecrets_YAMLSafe(t *testing.T) {
	input := `
credentials:
  aws_key: AKIA1234567890123456
  region: us-east-1
`
	findings := DetectSecrets("config.yaml", []byte(input))
	redacted := RedactSecrets([]byte(input), findings)

	if !strings.Contains(string(redacted), "[REDACTED-AWS_ACCESS_KEY]") {
		t.Errorf("YAML redaction failed\nInput:  %s\nOutput: %s", input, string(redacted))
	}
}

// === Layer 1 Tests: ShouldSkipFile ===

func TestShouldSkipFile_BenchmarkDir(t *testing.T) {
	if !ShouldSkipFile("/app/benchmark/data/mockApiData.json") {
		t.Error("Should skip benchmark directory files")
	}
}

func TestShouldSkipFile_MockApiDir(t *testing.T) {
	if !ShouldSkipFile("/app/mock-api/data.json") {
		t.Error("Should skip mock-api directory files")
	}
}

func TestShouldSkipFile_MigrationsDir(t *testing.T) {
	if !ShouldSkipFile("/app/src/migrations/1672531200000-CreateUser.ts") {
		t.Error("Should skip migrations directory files")
	}
}

func TestShouldSkipFile_JupyterNotebook(t *testing.T) {
	if !ShouldSkipFile("/app/docs/example.ipynb") {
		t.Error("Should skip Jupyter notebook files")
	}
}

func TestShouldSkipFile_SwaggerFile(t *testing.T) {
	if !ShouldSkipFile("/app/api/swagger.yaml") {
		t.Error("Should skip swagger.yaml files")
	}
	if !ShouldSkipFile("/app/api/openapi.yml") {
		t.Error("Should skip openapi.yml files")
	}
}

func TestShouldSkipFile_ExamplesDir(t *testing.T) {
	if !ShouldSkipFile("/app/examples/config.py") {
		t.Error("Should skip examples directory files")
	}
}

func TestShouldSkipFile_NormalSourceFile(t *testing.T) {
	if ShouldSkipFile("/app/src/main.py") {
		t.Error("Should NOT skip normal source files")
	}
}

// === Layer 2 Tests: IsPlaceholderValue ===

func TestIsPlaceholderValue_EnvVarNames(t *testing.T) {
	// ALL_CAPS_UNDERSCORE patterns are env var names, not actual values
	if !IsPlaceholderValue("OPENAI_API_KEY") {
		t.Error("Should detect ALL_CAPS env var names as placeholders")
	}
	if !IsPlaceholderValue("DATABASE_PASSWORD") {
		t.Error("Should detect DATABASE_PASSWORD as placeholder")
	}
}

func TestIsPlaceholderValue_TruncatedApiKeys(t *testing.T) {
	if !IsPlaceholderValue("sk-ant-...") {
		t.Error("Should detect truncated API key prefix as placeholder")
	}
	if !IsPlaceholderValue("sk-proj-...") {
		t.Error("Should detect truncated sk-proj- prefix as placeholder")
	}
}

func TestIsPlaceholderValue_DevPasswords(t *testing.T) {
	devPasswords := []string{"giteapassword", "adminpassword", "testpassword", "nopassword"}
	for _, pw := range devPasswords {
		if !IsPlaceholderValue(pw) {
			t.Errorf("Should detect %q as placeholder", pw)
		}
	}
}

func TestIsPlaceholderValue_ConnectionStringTemplates(t *testing.T) {
	if !IsPlaceholderValue("user:password") {
		t.Error("Should detect connection string template user:password")
	}
	if !IsPlaceholderValue("admin:admin") {
		t.Error("Should detect connection string template admin:admin")
	}
	if !IsPlaceholderValue("postgres:postgres") {
		t.Error("Should detect connection string template postgres:postgres")
	}
}

func TestIsPlaceholderValue_RealSecret(t *testing.T) {
	// Real secrets should NOT be detected as placeholders
	if IsPlaceholderValue("sk_" + "test_YYYYYYYYYYYYYYYYYYYYYYYY") {
		t.Error("Should NOT detect real Stripe key as placeholder")
	}
	if IsPlaceholderValue("AKIA1234567890123456") {
		t.Error("Should NOT detect real AWS key as placeholder")
	}
}

// === Layer 3 Tests: AdjustConfidence ===

func TestAdjustConfidence_NotebookDropsBelowThreshold(t *testing.T) {
	f := SecretFinding{Confidence: 0.75} // entropy finding
	f = AdjustConfidence(f, `"some_value"`, "/app/docs/notebook.ipynb")
	if f.Confidence >= 0.4 {
		t.Errorf("Notebook entropy finding should drop below 0.4 threshold, got %.2f", f.Confidence)
	}
}

func TestAdjustConfidence_LcSecretsGetter(t *testing.T) {
	f := SecretFinding{Confidence: 0.95}
	f = AdjustConfidence(f, `def lc_secrets(self) -> dict:`, "/app/langchain.py")
	if f.Confidence >= 0.4 {
		t.Errorf("lc_secrets getter should drop below 0.4 threshold, got %.2f", f.Confidence)
	}
}

func TestAdjustConfidence_MarketplaceJSON(t *testing.T) {
	f := SecretFinding{Confidence: 0.75}
	f = AdjustConfidence(f, `"api_key": "placeholder"`, "/app/marketplace/template.json")
	if f.Confidence >= 0.4 {
		t.Errorf("Marketplace JSON should drop below 0.4 threshold, got %.2f", f.Confidence)
	}
}

// === Entropy Tests ===

func TestEntropy_SkipsMigrationClassNames(t *testing.T) {
	if !isMigrationClassName("CreateUsersTable1672531200000") {
		t.Error("Should detect TypeORM migration class name")
	}
	if isMigrationClassName("realSecretKey123") {
		t.Error("Should NOT detect short strings as migration names")
	}
}

func TestEntropy_SkipsToolCallIDs(t *testing.T) {
	if !isLikelyNonSecret("call_abc123def456") {
		t.Error("Should detect OpenAI tool call IDs as non-secret")
	}
}

func TestEntropy_HigherThresholdForJSON(t *testing.T) {
	// Create content with a string that has entropy ~4.7 (above default 4.5, below JSON 5.0)
	// This should be flagged for .py but not for .json
	content := []byte(`secret = "aB3cD4eF5gH6iJ7kL8mN9"`)

	pyFindings := DetectHighEntropyStrings(content, "test.py")
	jsonFindings := DetectHighEntropyStrings(content, "test.json")

	// The .json threshold is higher (5.0), so may have fewer findings
	t.Logf("Python entropy findings: %d, JSON entropy findings: %d", len(pyFindings), len(jsonFindings))
	if len(jsonFindings) > len(pyFindings) {
		t.Error("JSON should have equal or fewer entropy findings than Python due to higher threshold")
	}
}

func TestEntropy_SkipsChatflowNodeIDs(t *testing.T) {
	if !isLikelyNonSecret("chatflow-input-handler-v2") {
		t.Error("Should detect chatflow node IDs as non-secret")
	}
}

// === Regression Tests: Real secrets must still be detected ===

func TestDetectSecrets_StillFindsRealAWSKey(t *testing.T) {
	content := `AWS_ACCESS_KEY_ID = "AKIA1234567890123456"`
	findings := DetectSecrets("config.py", []byte(content))
	found := false
	for _, f := range findings {
		if f.Type == "aws_access_key" {
			found = true
		}
	}
	if !found {
		t.Error("REGRESSION: Real AWS key no longer detected!")
	}
}

func TestDetectSecrets_StillFindsRealGitHubToken(t *testing.T) {
	content := `token = "ghp_abcdefghij1234567890abcdefghij123456"`
	findings := DetectSecrets("auth.py", []byte(content))
	found := false
	for _, f := range findings {
		if f.Type == "github_token" {
			found = true
		}
	}
	if !found {
		t.Error("REGRESSION: Real GitHub token no longer detected!")
	}
}

func TestDetectSecrets_StillFindsRealPrivateKey(t *testing.T) {
	content := `-----BEGIN RSA PRIVATE KEY-----`
	findings := DetectSecrets("keys.pem", []byte(content))
	found := false
	for _, f := range findings {
		if f.Type == "private_key" {
			found = true
		}
	}
	if !found {
		t.Error("REGRESSION: Private key no longer detected!")
	}
}

func TestDetectSecrets_StillFindsRealStripeKey(t *testing.T) {
	content := `stripe_key = "` + "sk_" + `test_ZZZZZZZZZZZZZZZZZZZZZZZZ"`
	findings := DetectSecrets("billing.py", []byte(content))
	if len(findings) == 0 {
		t.Error("REGRESSION: Real Stripe key no longer detected!")
	}
}
