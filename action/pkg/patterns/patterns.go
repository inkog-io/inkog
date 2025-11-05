package patterns

import (
	"github.com/inkog-io/inkog/action/pkg/models"
	"github.com/inkog-io/inkog/action/pkg/parser"
)

// Detector is the interface for pattern detectors
type Detector interface {
	Detect(fileInfo *parser.FileInfo) []models.Finding
	Name() string
	Version() string
}

// Registry holds all available detectors
type Registry struct {
	detectors []Detector
}

// NewRegistry creates a new pattern registry with all detectors
func NewRegistry() *Registry {
	return &Registry{
		detectors: []Detector{
			&PromptInjectionDetector{},
			&InfiniteLoopDetector{},
			NewAPIKeyDetector(),
		},
	}
}

// DetectAll runs all pattern detectors on a file
func (r *Registry) DetectAll(fileInfo *parser.FileInfo) []models.Finding {
	var allFindings []models.Finding

	for _, detector := range r.detectors {
		findings := detector.Detect(fileInfo)
		allFindings = append(allFindings, findings...)
	}

	return allFindings
}

// GetDetectors returns all registered detectors
func (r *Registry) GetDetectors() []Detector {
	return r.detectors
}
