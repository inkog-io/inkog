package patterns

// Detector interface - all security patterns implement this
type Detector interface {
	// Name returns the detector name (e.g., "prompt_injection")
	Name() string

	// Detect analyzes source code and returns findings
	Detect(filePath string, src []byte) ([]Finding, error)

	// GetPattern returns metadata about this pattern
	GetPattern() Pattern

	// GetConfidence returns confidence score (0.0-1.0)
	// Higher confidence = fewer false positives
	GetConfidence() float32
}

// DetectorFunc implements Detector with a simple function
// Allows creating simple detectors without full struct
type DetectorFunc struct {
	name       string
	pattern    Pattern
	confidence float32
	detect     func(filePath string, src []byte) ([]Finding, error)
}

func (d *DetectorFunc) Name() string {
	return d.name
}

func (d *DetectorFunc) GetPattern() Pattern {
	return d.pattern
}

func (d *DetectorFunc) GetConfidence() float32 {
	return d.confidence
}

func (d *DetectorFunc) Detect(filePath string, src []byte) ([]Finding, error) {
	return d.detect(filePath, src)
}

// NewDetectorFunc creates a simple detector from a function
func NewDetectorFunc(name string, pattern Pattern, confidence float32,
	detect func(filePath string, src []byte) ([]Finding, error)) *DetectorFunc {
	return &DetectorFunc{
		name:       name,
		pattern:    pattern,
		confidence: confidence,
		detect:     detect,
	}
}
