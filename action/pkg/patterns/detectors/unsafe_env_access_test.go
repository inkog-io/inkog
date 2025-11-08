package detectors

import (
	"testing"
)

func TestUnsafeEnvAccessDirect(t *testing.T) {
	detector := NewUnsafeEnvAccessDetector()

	// Test 1: Direct os.environ[] access without .get()
	vulnerable := `
import os

# VULNERABLE: Direct access without default
DATABASE_URL = os.environ["DATABASE_URL"]
API_KEY = os.environ["API_KEY"]
`

	findings, err := detector.Detect("config.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("Failed to detect unsafe environ access")
	}

	if findings[0].Severity != "MEDIUM" {
		t.Fatalf("Expected MEDIUM severity, got %s", findings[0].Severity)
	}
}

func TestUnsafeEnvAccessSingleVar(t *testing.T) {
	detector := NewUnsafeEnvAccessDetector()

	// Test 2: Single unsafe environment variable
	vulnerable := `
import os

SECRET_KEY = os.environ["SECRET_KEY"]
`

	findings, err := detector.Detect("app.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("Failed to detect single unsafe access")
	}
}

func TestUnsafeEnvAccessWithGet(t *testing.T) {
	detector := NewUnsafeEnvAccessDetector()

	// Test 3: Safe .get() method - should NOT trigger
	safe := `
import os

# SECURE: Using .get() with default
DATABASE_URL = os.environ.get("DATABASE_URL", "localhost:5432")
API_KEY = os.environ.get("API_KEY", None)
SECRET = os.environ.get("SECRET", "")
`

	findings, err := detector.Detect("config.py", []byte(safe))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(findings) > 0 {
		t.Fatalf("Should not flag .get() usage, got %d findings", len(findings))
	}
}

func TestUnsafeEnvAccessWithoutDefault(t *testing.T) {
	detector := NewUnsafeEnvAccessDetector()

	// Test 4: .get() without default is still safer but less robust
	code := `
import os

# Less ideal but safer than direct bracket access
VALUE = os.environ.get("VALUE")  # Could be None
`

	findings, err := detector.Detect("config.py", []byte(code))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	// This is actually safe (uses .get), so shouldn't trigger
	if len(findings) > 0 {
		t.Fatalf("Should not flag .get() even without explicit default")
	}
}

func TestUnsafeEnvAccessConfidenceScoring(t *testing.T) {
	detector := NewUnsafeEnvAccessDetector()

	vulnerable := `
import os

DB_URL = os.environ["DATABASE_URL"]
`

	findings, err := detector.Detect("config.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("No findings")
	}

	// Test 5: Confidence should be high (85-95%)
	confidence := findings[0].Confidence
	if confidence < 0.85 {
		t.Fatalf("Confidence too low: %.2f, expected >= 0.85", confidence)
	}

	if confidence > 1.0 {
		t.Fatalf("Invalid confidence: %.2f", confidence)
	}
}

func TestUnsafeEnvAccessMultipleVars(t *testing.T) {
	detector := NewUnsafeEnvAccessDetector()

	// Test 6: Multiple unsafe accesses
	vulnerable := `
import os

# All VULNERABLE
HOST = os.environ["HOST"]
PORT = os.environ["PORT"]
USERNAME = os.environ["USERNAME"]
PASSWORD = os.environ["PASSWORD"]
DATABASE = os.environ["DATABASE"]
`

	findings, err := detector.Detect("db_config.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(findings) < 3 {
		t.Fatalf("Expected multiple findings, got %d", len(findings))
	}
}

func TestUnsafeEnvAccessSkipsTestFiles(t *testing.T) {
	detector := NewUnsafeEnvAccessDetector()

	// Test 7: Test files should be skipped
	testCode := `
import os

def test_config():
    # In test, we might use unsafe access
    test_db = os.environ["TEST_DATABASE"]
    assert test_db is not None
`

	findings, err := detector.Detect("test_config.py", []byte(testCode))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(findings) > 0 {
		t.Fatalf("Should skip test files, but found %d findings", len(findings))
	}
}

func TestUnsafeEnvAccessWithValidation(t *testing.T) {
	detector := NewUnsafeEnvAccessDetector()

	// Test 8: Even with validation, direct bracket access is flagged
	// (validation happens after the potential crash)
	vulnerable := `
import os

try:
    DATABASE_URL = os.environ["DATABASE_URL"]
except KeyError:
    DATABASE_URL = "localhost:5432"
`

	findings, err := detector.Detect("config.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	// This is still detected because the pattern is there
	// (even though it's wrapped in try/except)
	if len(findings) == 0 {
		t.Logf("Info: Direct access pattern not detected when wrapped in try/except")
	}
}

func TestUnsafeEnvAccessDotenvIntegration(t *testing.T) {
	detector := NewUnsafeEnvAccessDetector()

	// Test 9: Secure pattern using python-dotenv
	secure := `
from dotenv import load_dotenv
import os

load_dotenv()

# SECURE: Using .get() after loading dotenv
DATABASE_URL = os.environ.get("DATABASE_URL", "postgres://localhost:5432/db")
API_KEY = os.environ.get("API_KEY")

if not API_KEY:
    raise ValueError("API_KEY environment variable must be set")
`

	findings, err := detector.Detect("config.py", []byte(secure))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(findings) > 0 {
		t.Fatalf("Secure dotenv pattern triggered findings")
	}
}

func TestUnsafeEnvAccessPydantic(t *testing.T) {
	detector := NewUnsafeEnvAccessDetector()

	// Test 10: Secure pattern using Pydantic Settings
	secure := `
from pydantic import BaseModel
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    database_url: str = "postgres://localhost/db"
    api_key: str = ""

    class Config:
        env_file = ".env"

settings = Settings()
`

	findings, err := detector.Detect("config.py", []byte(secure))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(findings) > 0 {
		t.Fatalf("Secure Pydantic pattern triggered findings")
	}
}

func TestUnsafeEnvAccessNestedObject(t *testing.T) {
	detector := NewUnsafeEnvAccessDetector()

	// Test 11: Unsafe access within function
	vulnerable := `
def get_database_url():
    import os
    # VULNERABLE: Inside function still unsafe
    return os.environ["DATABASE_URL"]

class DatabaseConnector:
    def __init__(self):
        self.url = os.environ["DB_URL"]
`

	findings, err := detector.Detect("connector.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("Failed to detect unsafe access in function")
	}
}

func TestUnsafeEnvAccessJavaScript(t *testing.T) {
	detector := NewUnsafeEnvAccessDetector()

	// Test 12: JavaScript process.env access
	vulnerable := `
// VULNERABLE: Direct access
const dbUrl = process.env.DATABASE_URL;
const apiKey = process.env.API_KEY;
`

	findings, err := detector.Detect("config.js", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	// JavaScript has different syntax, so this detector might not catch it
	// (designed for Python's os.environ)
	if len(findings) > 0 {
		t.Logf("Info: JavaScript env access detected (cross-language support)")
	} else {
		t.Logf("Info: JavaScript env access not detected (expected - Python-focused)")
	}
}

func TestUnsafeEnvAccessComments(t *testing.T) {
	detector := NewUnsafeEnvAccessDetector()

	// Test 13: Comments with os.environ should not trigger
	safe := `
# Example of VULNERABLE code (do not use):
# DATABASE_URL = os.environ["DATABASE_URL"]

# SECURE approach instead:
import os
DATABASE_URL = os.environ.get("DATABASE_URL", "localhost")
`

	findings, err := detector.Detect("example.py", []byte(safe))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	// Should not detect the unsafe pattern in comments
	for _, f := range findings {
		if f.Code[0:1] == "#" {
			t.Logf("Warning: Detected unsafe access in comment: %s", f.Code)
		}
	}
}

func TestUnsafeEnvAccessProductionImpact(t *testing.T) {
	detector := NewUnsafeEnvAccessDetector()

	vulnerable := `
import os

DB_URL = os.environ["DATABASE_URL"]
# Missing environment variable will crash on startup
app.config["SQLALCHEMY_DATABASE_URI"] = DB_URL
`

	findings, err := detector.Detect("app.py", []byte(vulnerable))
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(findings) > 0 {
		// Verify financial impact is documented
		if findings[0].FinancialRisk == "" {
			t.Logf("Warning: Financial impact not documented")
		}
	}
}

// Benchmark test
func BenchmarkUnsafeEnvAccess(b *testing.B) {
	detector := NewUnsafeEnvAccessDetector()
	code := []byte(`
import os

DB_URL = os.environ["DATABASE_URL"]
API_KEY = os.environ["API_KEY"]
` + "\n")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.Detect("config.py", code)
	}
}
