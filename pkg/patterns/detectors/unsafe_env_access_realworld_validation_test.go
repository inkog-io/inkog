package detectors

import (
	"fmt"
	"testing"
)

// TestUnsafeEnvAccessDetectorRealWorldValidation tests Pattern 4 against real CVEs
func TestUnsafeEnvAccessDetectorRealWorldValidation(t *testing.T) {
	detector := &UnsafeEnvAccessDetector{}

	cveTestCases := []struct {
		cveID       string
		description string
		cveDir      string
	}{
		{cveID: "CVE-2025-61913", description: "Flowise WriteFileTool RCE", cveDir: "testdata/cves/2025"},
		{cveID: "CVE-2024-28088", description: "LangChain Directory Traversal", cveDir: "testdata/cves/2024"},
	}

	t.Run("DetectUnsafeEnvironmentAccess", func(t *testing.T) {
		detectedCount := 0
		for _, tc := range cveTestCases {
			testCase, err := LoadCVETestCase(tc.cveDir, tc.cveID)
			if err != nil {
				continue
			}
			result := RunCVEDetectionTest(detector, testCase)
			if result.Passed {
				detectedCount++
			}
		}
		t.Logf("Detected: %d/%d", detectedCount, len(cveTestCases))
	})

	t.Run("SafeEnvironmentHandling", func(t *testing.T) {
		samples := []struct {
			language string
			code     string
		}{
			{"python", "db_host = os.getenv('DB_HOST', 'localhost')\nupload_dir = '/var/app/uploads'"},
			{"javascript", "const apiKey = process.env.API_KEY || ''"},
		}

		for _, sample := range samples {
			result := RunCleanCodeTest(detector, sample.code, sample.language)
			if result.Passed {
				fmt.Printf("OK %s: No false positives\n", sample.language)
			}
		}
	})
}

// BenchmarkUnsafeEnvAccessDetector benchmarks performance
func BenchmarkUnsafeEnvAccessDetector(b *testing.B) {
	detector := &UnsafeEnvAccessDetector{}
	code := "import os\nupload_dir = os.getenv('UPLOAD_DIR')\nos.system(f'rm -rf {upload_dir}')"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.Detect("benchmark.py", []byte(code))
	}
}
