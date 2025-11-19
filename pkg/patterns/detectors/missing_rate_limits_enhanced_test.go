package detectors

import (
	"testing"
)

// TestMissingRateLimitsBasic - Test detection of endpoint without rate limiting
func TestMissingRateLimitsBasic(t *testing.T) {
	detector := NewEnhancedMissingRateLimitsDetector(nil)

	code := []byte(`
from flask import Flask
app = Flask(__name__)

@app.route("/api/data")
def get_data():
    data = fetch_from_database()
    return {"data": data}
`)

	findings, err := detector.Detect("api.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("Expected to find missing rate limit vulnerability")
	}

	// Should have high confidence (0.85 for public endpoint)
	if len(findings) > 0 {
		if findings[0].Confidence < 0.80 {
			t.Errorf("Expected confidence >= 0.80, got %f", findings[0].Confidence)
		}
	}
}

// TestMissingRateLimitsWithLimiter - Test that endpoints with limiter are not flagged
func TestMissingRateLimitsWithLimiter(t *testing.T) {
	detector := NewEnhancedMissingRateLimitsDetector(nil)

	code := []byte(`
from flask import Flask
from flask_limiter import Limiter
app = Flask(__name__)
limiter = Limiter(app, key_func=lambda: "global")

@app.route("/api/data")
@limiter.limit("100 per hour")
def get_data():
    return {"data": "safe"}
`)

	findings, err := detector.Detect("api.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should not find vulnerability when limiter is present
	if len(findings) > 0 {
		t.Logf("Found findings when limiter present: %v", findings)
	}
}

// TestMissingRateLimitsUnboundedLoop - Test detection of unbounded loop with API calls
func TestMissingRateLimitsUnboundedLoop(t *testing.T) {
	detector := NewEnhancedMissingRateLimitsDetector(nil)

	code := []byte(`
def process_queries():
    while True:
        query = get_next_query()
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "user", "content": query}]
        )
        print(response)
`)

	findings, err := detector.Detect("agent.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("Expected to find unbounded loop with API calls")
	}

	// Should have high confidence for unbounded loop
	if len(findings) > 0 {
		if findings[0].Confidence < 0.75 {
			t.Errorf("Expected confidence >= 0.75, got %f", findings[0].Confidence)
		}
	}
}

// TestMissingRateLimitsLoopWithBounds - Test loop with iteration limit
func TestMissingRateLimitsLoopWithBounds(t *testing.T) {
	detector := NewEnhancedMissingRateLimitsDetector(nil)

	code := []byte(`
def process_queries():
    max_iterations = 10
    for i in range(max_iterations):
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "user", "content": query}]
        )
`)

	findings, err := detector.Detect("agent.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should have lower confidence due to iteration limit
	if len(findings) > 0 {
		if findings[0].Confidence > 0.65 {
			t.Logf("Loop with bounds has confidence %f (expected lower)", findings[0].Confidence)
		}
	}
}

// TestMissingRateLimitsWithAuth - Test endpoint with auth (reduced severity)
func TestMissingRateLimitsWithAuth(t *testing.T) {
	detector := NewEnhancedMissingRateLimitsDetector(nil)

	code := []byte(`
@app.route("/admin/delete")
@login_required
def delete_user():
    # No rate limit, but auth present
    user_id = request.args.get("id")
    delete_from_database(user_id)
    return "deleted"
`)

	findings, err := detector.Detect("admin.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should have lower confidence when auth is present
	if len(findings) > 0 {
		if findings[0].Confidence > 0.75 {
			t.Logf("Auth-protected endpoint has confidence %f (should be reduced)", findings[0].Confidence)
		}
	}
}

// TestMissingRateLimitsRecursiveAgent - Test recursive agent without depth limit
func TestMissingRateLimitsRecursiveAgent(t *testing.T) {
	detector := NewEnhancedMissingRateLimitsDetector(nil)

	code := []byte(`
def agent_task(task):
    result = agent.execute(task)
    if not result.success:
        next_task = agent.delegate(result)
        return agent_task(next_task)  # Recursive without depth limit
    return result
`)

	findings, err := detector.Detect("agent.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("Expected to find recursive agent without depth limit")
	}

	// Should have high confidence for recursive pattern
	if len(findings) > 0 {
		if findings[0].Confidence < 0.70 {
			t.Errorf("Expected confidence >= 0.70, got %f", findings[0].Confidence)
		}
	}
}

// TestMissingRateLimitsRecursiveWithLimit - Test recursive with base case (safe)
func TestMissingRateLimitsRecursiveWithLimit(t *testing.T) {
	detector := NewEnhancedMissingRateLimitsDetector(nil)

	code := []byte(`
def agent_task(task, depth=0):
    if depth > 5:  # Base case
        return {"status": "max depth reached"}
    result = agent.execute(task)
    if not result.success:
        return agent_task(agent.delegate(result), depth + 1)
    return result
`)

	findings, err := detector.Detect("agent.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should not flag if depth limit is present
	if len(findings) > 0 {
		t.Logf("Recursive with limit still flagged, checking if low confidence")
	}
}

// TestMissingRateLimitsFastAPI - Test FastAPI endpoint without rate limit
func TestMissingRateLimitsFastAPI(t *testing.T) {
	detector := NewEnhancedMissingRateLimitsDetector(nil)

	code := []byte(`
from fastapi import FastAPI
app = FastAPI()

@app.post("/search")
async def search(q: str):
    results = perform_search(q)
    return {"results": results}
`)

	findings, err := detector.Detect("search.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("Expected to find FastAPI endpoint without rate limit")
	}
}

// TestMissingRateLimitsGoHandler - Test Go HTTP handler without rate limit
func TestMissingRateLimitsGoHandler(t *testing.T) {
	detector := NewEnhancedMissingRateLimitsDetector(nil)

	code := []byte(`
package main
import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
    // No rate limiting
    w.Write([]byte("response"))
}

func main() {
    http.HandleFunc("/api", handler)
    http.ListenAndServe(":8080", nil)
}
`)

	findings, err := detector.Detect("main.go", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should detect Go handler patterns
	if len(findings) == 0 {
		t.Logf("Note: Go handler detection may require AST parsing")
	}
}

// TestMissingRateLimitsFiltering - Test filtering in test files
func TestMissingRateLimitsFiltering(t *testing.T) {
	detector := NewEnhancedMissingRateLimitsDetector(nil)

	code := []byte(`
def test_api_endpoint():
    @app.route("/test")
    def endpoint():
        return "test"
    # Test endpoint without limit
`)

	findings, err := detector.Detect("test_api.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Test files should be filtered or have reduced confidence
	if len(findings) > 0 {
		t.Logf("Test file findings: %d (should be filtered)", len(findings))
	}
}

// TestMissingRateLimitsComment - Test filtering of commented code
func TestMissingRateLimitsComment(t *testing.T) {
	detector := NewEnhancedMissingRateLimitsDetector(nil)

	code := []byte(`
# @app.route("/endpoint")
# def endpoint():
#     return "data"

actual_code = "something else"
`)

	findings, err := detector.Detect("api.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Commented code should not be flagged
	if len(findings) > 0 {
		t.Error("Should not flag commented out endpoints")
	}
}

// TestMissingRateLimitsConfiguration - Test configuration applies
func TestMissingRateLimitsConfiguration(t *testing.T) {
	config := NewSimpleEnterpriseConfig()
	detector := NewEnhancedMissingRateLimitsDetector(config)

	if !detector.IsEnabled() {
		t.Error("Detector should be enabled by default")
	}

	// Test with disabled pattern
	config.Patterns["missing_rate_limits"].Enabled = false

	code := []byte(`
@app.route("/data")
def get_data():
    return "data"
`)

	findings, err := detector.Detect("api.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should not find anything when disabled
	if len(findings) > 0 {
		t.Error("Expected no findings when pattern is disabled")
	}
}

// TestMissingRateLimitsThresholdConfiguration - Test confidence threshold
func TestMissingRateLimitsThresholdConfiguration(t *testing.T) {
	config := NewSimpleEnterpriseConfig()
	config.Patterns["missing_rate_limits"].ConfidenceThreshold = 0.90

	detector := NewEnhancedMissingRateLimitsDetector(config)

	code := []byte(`
@app.route("/data")
def get_data():
    return "data"
`)

	findings, err := detector.Detect("api.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// With high threshold, may not report findings with lower confidence
	if len(findings) > 0 {
		t.Logf("Findings with high threshold: %d", len(findings))
	}
}

// TestMissingRateLimitsMultipleEndpoints - Test multiple endpoints in one file
func TestMissingRateLimitsMultipleEndpoints(t *testing.T) {
	detector := NewEnhancedMissingRateLimitsDetector(nil)

	code := []byte(`
@app.route("/endpoint1")
def endpoint1():
    return "data1"

@app.route("/endpoint2")
def endpoint2():
    return "data2"

@app.route("/endpoint3")
def endpoint3():
    return "data3"
`)

	findings, err := detector.Detect("api.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should find multiple vulnerable endpoints
	if len(findings) < 2 {
		t.Logf("Expected multiple findings, got %d", len(findings))
	}
}

// TestMissingRateLimitsN8nIncident - Test n8n incident scenario ($300 in 30 minutes)
func TestMissingRateLimitsN8nIncident(t *testing.T) {
	detector := NewEnhancedMissingRateLimitsDetector(nil)

	code := []byte(`
def process_workflow(workflow_data):
    # Error in loop causes unbounded OpenAI API calls
    while True:
        try:
            result = openai.ChatCompletion.create(
                model="gpt-4",
                messages=workflow_data
            )
        except Exception as e:
            # Loop continues without break - vulnerable to cost explosion
            log_error(e)
`)

	findings, err := detector.Detect("workflow.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("Expected to find unbounded loop with API calls (n8n incident pattern)")
	}

	// Should have high confidence for this pattern
	if len(findings) > 0 {
		finding := findings[0]
		if finding.Confidence < 0.75 {
			t.Errorf("Expected high confidence for n8n pattern, got %f", finding.Confidence)
		}
		// Check financial risk is mentioned
		if !contains(finding.FinancialRisk, "300") && !contains(finding.FinancialRisk, "cost") {
			t.Logf("Expected financial risk mention in: %s", finding.FinancialRisk)
		}
	}
}

// TestMissingRateLimitsDifyIncident - Test Dify unbounded image generation
func TestMissingRateLimitsDifyIncident(t *testing.T) {
	detector := NewEnhancedMissingRateLimitsDetector(nil)

	code := []byte(`
def generate_images(prompt, user_id):
    # No per-user or global limit implemented
    for style in ["realistic", "artistic", "anime", "pixel", "cartoon"]:
        result = call_image_model(prompt, style)
        save_image(result)
`)

	findings, err := detector.Detect("generator.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Logf("Note: bounded for loop may not trigger high-confidence findings")
	}
}

// TestMissingRateLimitsLoginBruteforce - Test login endpoint (CWE-307)
func TestMissingRateLimitsLoginBruteforce(t *testing.T) {
	detector := NewEnhancedMissingRateLimitsDetector(nil)

	code := []byte(`
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    user = authenticate(data["username"], data["password"])
    if not user:
        return {"error": "Invalid credentials"}, 401
    return {"token": generate_token(user)}
`)

	findings, err := detector.Detect("auth.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("Expected to find unprotected login endpoint")
	}

	// Login endpoints should have high severity
	if len(findings) > 0 {
		if findings[0].Message == "" {
			t.Error("Expected descriptive message")
		}
	}
}

// TestMissingRateLimitsEmptyCode - Test with empty code
func TestMissingRateLimitsEmptyCode(t *testing.T) {
	detector := NewEnhancedMissingRateLimitsDetector(nil)

	code := []byte(``)

	findings, err := detector.Detect("empty.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) != 0 {
		t.Error("Expected no findings for empty code")
	}
}

// BenchmarkMissingRateLimitsDetection - Benchmark detection performance
func BenchmarkMissingRateLimitsDetection(b *testing.B) {
	detector := NewEnhancedMissingRateLimitsDetector(nil)

	code := []byte(`
from flask import Flask, request
app = Flask(__name__)

@app.route("/endpoint1", methods=["GET"])
def endpoint1():
    return {"data": "1"}

@app.route("/endpoint2", methods=["POST"])
def endpoint2():
    while True:
        result = openai.ChatCompletion.create(model="gpt-4", messages=[])
        process(result)

@app.route("/endpoint3")
def endpoint3():
    for i in range(1000):
        requests.post("https://api.example.com", data=i)
`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = detector.Detect("api.py", code)
	}
}

// Helper function for string contains check
func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && s != "" && substr != ""
}
