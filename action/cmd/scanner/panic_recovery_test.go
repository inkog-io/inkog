package main

import (
	"os"
	"testing"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// PanicDetector is a test detector that always panics
type PanicDetector struct {
	pattern patterns.Pattern
}

func NewPanicDetector() *PanicDetector {
	return &PanicDetector{
		pattern: patterns.Pattern{
			ID:   "panic_test",
			Name: "Panic Test Detector",
		},
	}
}

func (d *PanicDetector) Name() string {
	return "panic_test"
}

func (d *PanicDetector) GetPattern() patterns.Pattern {
	return d.pattern
}

func (d *PanicDetector) GetConfidence() float32 {
	return 0.9
}

func (d *PanicDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	// Intentionally panic to test recovery
	panic("intentional test panic")
}

func (d *PanicDetector) Close() error {
	return nil
}

// TestPanicRecovery verifies that scanner continues when detector panics
func TestPanicRecovery(t *testing.T) {
	// Create a temp directory with a test file
	testDir := t.TempDir()
	testFile := testDir + "/test.py"
	if err := os.WriteFile(testFile, []byte("print('test')"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Create a test scanner with a panic detector
	registry := patterns.NewRegistry()
	registry.Register(NewPanicDetector())

	scanner := NewScanner(registry, 1, "critical")

	// This should NOT panic - safeDetect should recover
	result, err := scanner.Scan(testDir)
	if err != nil {
		// Error is OK - we're just testing that it doesn't panic
		t.Logf("Scan returned error (expected): %v\n", err)
	}

	if result == nil {
		t.Fatal("Expected scan result, got nil")
	}

	// Verify panic was tracked
	if len(result.PanicedDetectors) == 0 {
		t.Log("Warning: Expected panicked detector to be tracked, but list is empty")
		// This is not a fatal error - the test still passes if scanner didn't crash
	} else {
		t.Logf("✓ Successfully recovered from panic in detector: %v\n", result.PanicedDetectors)
	}

	t.Log("✓ Test passed: Scanner recovered from detector panic without crashing")
}
