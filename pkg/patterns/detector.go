package patterns

// Detector is the interface that all pattern detectors must implement
// This ensures compile-time safety for detector IDs and enforces canonical metadata
type Detector interface {
	// GetPatternID returns the canonical detector ID from the metadata registry
	// This MUST match one of the ID_* constants in metadata package
	GetPatternID() string

	// GetPattern returns the pattern definition (for backward compatibility)
	GetPattern() Pattern

	// Detect performs the vulnerability detection and returns findings
	Detect(filePath string, source []byte) ([]Finding, error)

	// Name returns the detector name for logging/reporting
	Name() string

	// GetConfidence returns the detector's confidence level (0.0 to 1.0)
	GetConfidence() float32
}
