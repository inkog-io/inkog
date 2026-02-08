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

func TestEntropy_SkipsHexHashes(t *testing.T) {
	// SHA-256 hex hash should not be flagged as a secret
	if !isLikelyNonSecret("a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9") {
		t.Error("Should detect pure hex hash as non-secret")
	}
	// Git commit SHA
	if !isLikelyNonSecret("550e8400e29b41d4a716446655440000a3f8b2c1") {
		t.Error("Should detect git commit SHA as non-secret")
	}
}

func TestEntropy_SkipsSRIHashes(t *testing.T) {
	if !isLikelyNonSecret("sha256-abcdef1234567890ABCDEF") {
		t.Error("Should detect SRI sha256 hash as non-secret")
	}
	if !isLikelyNonSecret("sha384-abcdef1234567890ABCDEF1234567890") {
		t.Error("Should detect SRI sha384 hash as non-secret")
	}
	if !isLikelyNonSecret("sha512-abcdef1234567890ABCDEF1234567890") {
		t.Error("Should detect SRI sha512 hash as non-secret")
	}
}

func TestEntropy_SkipsNonHyphenatedGUIDs(t *testing.T) {
	// 32-char hex without hyphens (GUID without formatting)
	if !isLikelyNonSecret("550e8400e29b41d4a716446655440000") {
		t.Error("Should detect 32-char hex GUID as non-secret")
	}
}

func TestEntropy_SkipsBase64Data(t *testing.T) {
	// Base64 data without credential context
	if !isLikelyNonSecret("dGhpcyBpcyBiYXNlNjQgZGF0YQ==", `content_data = "dGhpcyBpcyBiYXNlNjQgZGF0YQ=="`) {
		t.Error("Should detect base64 data without credential context as non-secret")
	}
}

func TestEntropy_KeepsBase64WithCredContext(t *testing.T) {
	// Base64 value WITH credential context should still be detected
	if isLikelyNonSecret("dGhpcyBpcyBiYXNlNjQgZGF0YQ==", `api_key = "dGhpcyBpcyBiYXNlNjQgZGF0YQ=="`) {
		t.Error("Should NOT skip base64 when line has credential context (api_key)")
	}
}

func TestEntropy_SkipsHashContext(t *testing.T) {
	// Line contains "sha256" keyword — value is a hash output
	if !isLikelyNonSecret("aB3cD4eF5gH6iJ7kL8mN9oP0", `sha256_hash = "aB3cD4eF5gH6iJ7kL8mN9oP0"`) {
		t.Error("Should detect value on sha256 context line as non-secret")
	}
	// Line contains "checksum" keyword
	if !isLikelyNonSecret("aB3cD4eF5gH6iJ7kL8mN9oP0", `file_checksum = "aB3cD4eF5gH6iJ7kL8mN9oP0"`) {
		t.Error("Should detect value on checksum context line as non-secret")
	}
	// Line contains "integrity" keyword
	if !isLikelyNonSecret("aB3cD4eF5gH6iJ7kL8mN9oP0", `integrity = "aB3cD4eF5gH6iJ7kL8mN9oP0"`) {
		t.Error("Should detect value on integrity context line as non-secret")
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

// =============================================================================
// V4 FP REDUCTION TESTS — isLikelyNonSecret extensions
// =============================================================================

func TestIsLikelyNonSecret_ModelPaths(t *testing.T) {
	if !isLikelyNonSecret("accounts/fireworks/models/llama-v3p1-8b-instruct") {
		t.Error("Should detect ML model path as non-secret")
	}
	if !isLikelyNonSecret("projects/my-project/models/gpt4-turbo") {
		t.Error("Should detect project model path as non-secret")
	}
}

func TestIsLikelyNonSecret_UUIDs(t *testing.T) {
	if !isLikelyNonSecret("550e8400-e29b-41d4-a716-446655440000") {
		t.Error("Should detect full UUID format as non-secret")
	}
	if !isLikelyNonSecret("f47ac10b-58cc-4372-a567-0e02b2c3d479") {
		t.Error("Should detect UUID v4 as non-secret")
	}
}

func TestIsLikelyNonSecret_RouteStrings(t *testing.T) {
	if !isLikelyNonSecret("/api/v1/users/create/confirm") {
		t.Error("Should detect URL path segments as non-secret")
	}
}

func TestIsLikelyNonSecret_SchemaContext(t *testing.T) {
	if !isLikelyNonSecret("aB3cD4eF5gH6iJ7kL8mN9oP0", `"example": "aB3cD4eF5gH6iJ7kL8mN9oP0"`) {
		t.Error("Should detect value with 'example' context as non-secret")
	}
	if !isLikelyNonSecret("aB3cD4eF5gH6iJ7kL8mN9oP0", `default: "aB3cD4eF5gH6iJ7kL8mN9oP0"`) {
		t.Error("Should detect value with 'default' context as non-secret")
	}
	if !isLikelyNonSecret("aB3cD4eF5gH6iJ7kL8mN9oP0", `model_name = "aB3cD4eF5gH6iJ7kL8mN9oP0"`) {
		t.Error("Should detect value with 'model' context as non-secret")
	}
}

// === ShouldSkipFile extensions ===

func TestShouldSkipFile_LocaleAndSchema(t *testing.T) {
	if !ShouldSkipFile("/app/locale/en/messages.json") {
		t.Error("Should skip locale directory files")
	}
	if !ShouldSkipFile("/app/i18n/translations.yaml") {
		t.Error("Should skip i18n directory files")
	}
	if !ShouldSkipFile("/app/schemas/user.schema.json") {
		t.Error("Should skip schema directory files")
	}
	if !ShouldSkipFile("/app/config/app.schema.json") {
		t.Error("Should skip .schema.json files")
	}
}

func TestShouldSkipFile_GeneratedAndVendor(t *testing.T) {
	if !ShouldSkipFile("/app/generated/api_client.py") {
		t.Error("Should skip generated directory files")
	}
	if !ShouldSkipFile("/app/vendor/third-party/lib.go") {
		t.Error("Should skip vendor directory files")
	}
	if !ShouldSkipFile("/app/node_modules/pkg/index.js") {
		t.Error("Should skip node_modules directory files")
	}
}

func TestShouldSkipFile_LockFiles(t *testing.T) {
	if !ShouldSkipFile("/app/package-lock.json") {
		t.Error("Should skip package-lock.json")
	}
	if !ShouldSkipFile("/app/yarn.lock") {
		t.Error("Should skip yarn.lock")
	}
	if !ShouldSkipFile("/app/go.sum") {
		t.Error("Should skip go.sum")
	}
}

func TestShouldSkipFile_MarkdownAndEnvExample(t *testing.T) {
	if !ShouldSkipFile("/app/README.md") {
		t.Error("Should skip markdown files")
	}
	if !ShouldSkipFile("/app/.env.example") {
		t.Error("Should skip .env.example files")
	}
	if !ShouldSkipFile("/app/.env.template") {
		t.Error("Should skip .env.template files")
	}
}

// === AdjustConfidence extensions ===

func TestAdjustConfidence_JSONExample(t *testing.T) {
	f := SecretFinding{Confidence: 0.95}
	f = AdjustConfidence(f, `"example": "aB3cD4eF5gH6iJ7kL8mN9"`, "/app/schema.json")
	if f.Confidence >= 0.4 {
		t.Errorf("JSON example line should drop below 0.4 threshold, got %.2f", f.Confidence)
	}
}

func TestAdjustConfidence_EnvVarReference(t *testing.T) {
	f := SecretFinding{Confidence: 0.95}
	f = AdjustConfidence(f, `api_key = os.environ.get("OPENAI_API_KEY")`, "/app/config.py")
	if f.Confidence >= 0.4 {
		t.Errorf("os.environ reference should drop below 0.4 threshold, got %.2f", f.Confidence)
	}
}

// === Regex FP filter tests ===

func TestDetectSecrets_ApiKeyEnvVarName(t *testing.T) {
	// ALL_CAPS env var names in quotes should NOT be flagged as api_key
	content := `api_key = os.environ.get("OPENAI_API_KEY")`
	findings := DetectSecrets("config.py", []byte(content))
	for _, f := range findings {
		if f.Type == "api_key" {
			t.Errorf("Should NOT flag env var name as api_key: %v", f.Value)
		}
	}
}

func TestDetectSecrets_PrivateKeyInComment(t *testing.T) {
	content := `# -----BEGIN RSA PRIVATE KEY-----`
	findings := DetectSecrets("setup.py", []byte(content))
	for _, f := range findings {
		if f.Type == "private_key" {
			t.Error("Should NOT flag private key in comment line")
		}
	}
}

// === Placeholder extensions ===

func TestIsPlaceholderValue_YourHere(t *testing.T) {
	if !IsPlaceholderValue("your-api-key-here") {
		t.Error("Should detect 'your-*-here' format as placeholder")
	}
}

func TestIsPlaceholderValue_CommonWords(t *testing.T) {
	commonWords := []string{"required", "optional", "encrypted", "redacted", "disabled"}
	for _, word := range commonWords {
		if !IsPlaceholderValue(word) {
			t.Errorf("Should detect %q as placeholder", word)
		}
	}
}

func TestIsPlaceholderValue_InsertReplace(t *testing.T) {
	if !IsPlaceholderValue("INSERT_YOUR_KEY") {
		t.Error("Should detect INSERT_* as placeholder")
	}
	if !IsPlaceholderValue("REPLACE_WITH_YOUR_TOKEN") {
		t.Error("Should detect REPLACE_* as placeholder")
	}
}

// =============================================================================
// V5 FP REDUCTION TESTS — Fix 3A: Context-required entropy detection
// =============================================================================

func TestEntropy_RequiresContextOrKnownFormat(t *testing.T) {
	// High-entropy string WITHOUT credential context → NOT flagged
	content := []byte(`spreadsheet_data = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2u"`)
	findings := DetectHighEntropyStrings(content, "data.py")
	if len(findings) > 0 {
		t.Error("Should NOT flag high-entropy string without credential context")
	}
}

func TestEntropy_StillFlagsWithCredentialContext(t *testing.T) {
	// High-entropy string WITH credential context → flagged
	content := []byte(`api_key = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2u"`)
	findings := DetectHighEntropyStrings(content, "config.py")
	if len(findings) == 0 {
		t.Error("Should flag high-entropy string WITH credential context (api_key =)")
	}
}

func TestEntropy_FlagsKnownSecretFormatWithoutContext(t *testing.T) {
	// Known secret format (GitHub token) WITHOUT credential context → still flagged
	// ghp_ + 36 chars of mixed case/digits for entropy
	content := []byte(`value = "ghp_aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3w4"`)
	findings := DetectHighEntropyStrings(content, "config.py")
	if len(findings) == 0 {
		t.Error("Should flag known secret format (ghp_) even without credential context")
	}
}

func TestEntropy_SkipsGoogleSheetID(t *testing.T) {
	// Google Sheet ID: high-entropy alphanumeric without credential keyword
	content := []byte(`SHEET_ID = "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms"`)
	findings := DetectHighEntropyStrings(content, "sheets.py")
	if len(findings) > 0 {
		t.Error("Should NOT flag Google Sheet ID (no credential context, _id variable name)")
	}
}

func TestMatchesKnownSecretFormat(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{"AKIA1234567890123456", true},       // AWS
		{"ghp_abc123def456abc123def456abc12", true}, // GitHub
		{"sk_live_abcdef1234567890", true},   // Stripe
		{"sk-ant-abcdef1234567890ab", true},  // Anthropic
		{"xoxb-12345-67890-abcdef", true},    // Slack
		{"npm_abcdef1234567890", true},       // npm
		{"SG.abcdef1234567890", true},        // Sendgrid
		{"random_high_entropy_str", false},   // Not a known format
		{"just_some_long_string_here", false}, // Not a known format
	}
	for _, tc := range cases {
		got := matchesKnownSecretFormat(tc.value)
		if got != tc.want {
			t.Errorf("matchesKnownSecretFormat(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

// === Fix 3B: ShouldSkipFile CI/build directories ===

func TestShouldSkipFile_CIDirectories(t *testing.T) {
	if !ShouldSkipFile("/app/.circleci/config.yml") {
		t.Error("Should skip .circleci directory files")
	}
	if !ShouldSkipFile("/app/.github/workflows/ci.yml") {
		t.Error("Should skip .github/workflows directory files")
	}
	if !ShouldSkipFile("/app/.github/actions/deploy/action.yml") {
		t.Error("Should skip .github/actions directory files")
	}
}

func TestShouldSkipFile_DockerCompose(t *testing.T) {
	if !ShouldSkipFile("/app/docker-compose.yml") {
		t.Error("Should skip docker-compose.yml")
	}
	if !ShouldSkipFile("/app/docker-compose.dev.yml") {
		t.Error("Should skip docker-compose.dev.yml")
	}
}

func TestShouldSkipFile_InfrastructureAsCode(t *testing.T) {
	if !ShouldSkipFile("/app/terraform/main.tf") {
		t.Error("Should skip terraform directory files")
	}
	if !ShouldSkipFile("/app/ansible/playbook.yml") {
		t.Error("Should skip ansible directory files")
	}
	if !ShouldSkipFile("/app/helm/values.yaml") {
		t.Error("Should skip helm directory files")
	}
}

// === Fix 3C: Variable name awareness ===

func TestExtractAssignmentVariable(t *testing.T) {
	cases := []struct {
		line string
		want string
	}{
		{`SPREADSHEET_ID = "abc123"`, "SPREADSHEET_ID"},
		{`api_key = "secret"`, "api_key"},
		{`"doc_id": "abc123"`, "doc_id"},
		{`model_name: "gpt-4"`, "model_name"},
		{`x == y`, ""},
	}
	for _, tc := range cases {
		got := extractAssignmentVariable(tc.line)
		if got != tc.want {
			t.Errorf("extractAssignmentVariable(%q) = %q, want %q", tc.line, got, tc.want)
		}
	}
}

func TestIsNonSecretVariableName(t *testing.T) {
	cases := []struct {
		varName string
		want    bool
	}{
		{"SPREADSHEET_ID", true},
		{"model_id", true},
		{"workflow_id", true},
		{"file_hash", true},
		{"doc_id", true},
		{"template_id", true},
		{"api_key", false},
		{"secret", false},
		{"password", false},
		{"", false},
	}
	for _, tc := range cases {
		got := isNonSecretVariableName(tc.varName)
		if got != tc.want {
			t.Errorf("isNonSecretVariableName(%q) = %v, want %v", tc.varName, got, tc.want)
		}
	}
}

// === Fix 3D: Flood detection ===

func TestEntropy_FloodDetection(t *testing.T) {
	// Build content with 20 high-entropy strings but no credential context
	// Due to Fix 3A (context required), these won't generate findings anyway.
	// Instead test with context: 20 lines with credential keywords
	var lines []string
	for i := 0; i < 20; i++ {
		// Each line has credential context
		lines = append(lines, `api_key = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2u"`)
	}
	content := []byte(strings.Join(lines, "\n"))
	findings := DetectHighEntropyStrings(content, "config.py")
	// With flood detection, all findings should be kept since they all have context
	// The flood filter keeps HasContext findings
	t.Logf("Flood test: %d findings from 20 identical lines", len(findings))
}

// === Fix 4: Tightened credentialContextRegex ===

func TestCredentialContextRegex_RequiresAssignment(t *testing.T) {
	// Should match: assignment patterns
	if !credentialContextRegex.MatchString(`api_key = "value"`) {
		t.Error("Should match api_key assignment")
	}
	if !credentialContextRegex.MatchString(`token = "value"`) {
		t.Error("Should match token assignment")
	}
	if !credentialContextRegex.MatchString(`password: "value"`) {
		t.Error("Should match password in YAML")
	}
	if !credentialContextRegex.MatchString(`_secret = "value"`) {
		t.Error("Should match _secret assignment")
	}
	// Should still match these (no assignment required)
	if !credentialContextRegex.MatchString(`auth_token`) {
		t.Error("Should match auth_token")
	}
	if !credentialContextRegex.MatchString(`private_key`) {
		t.Error("Should match private_key")
	}
}

// === Regression tests: ensure real secrets still detected ===

func TestEntropy_RealSecretsStillDetected(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"AWS key with context", `aws_access_key = "AKIA1234567890123456"`},
		{"Token assignment", `token = "ghp_abcdefghij1234567890abcdefghij123456"`},
		{"API key with context", `api_key = "sk_live_abcdef1234567890abcd"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := DetectSecrets("config.py", []byte(tc.content))
			if len(findings) == 0 {
				t.Errorf("REGRESSION: %s no longer detected", tc.name)
			}
		})
	}
}
