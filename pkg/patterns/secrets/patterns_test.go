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
			input:         `{"payment": {"stripe_key": "sk_live_abc123def456ghi789jkl"}}`,
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
			input:         `{"nodes": [{"name": "HTTP Request", "parameters": {"api_key": "sk_live_abc123def456ghi789jkl"}}]}`,
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
	// sk_live_ pattern - using test-safe pattern that matches regex but isn't a real key
	content := `stripe_api_key = "sk_live_TESTKEY1234567890abcdef"`
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
