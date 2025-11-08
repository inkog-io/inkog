package patterns

import (
	"sync"
)

// Registry manages all available security pattern detectors
type Registry struct {
	detectors map[string]Detector
	mu        sync.RWMutex
}

// NewRegistry creates a new pattern registry
func NewRegistry() *Registry {
	return &Registry{
		detectors: make(map[string]Detector),
	}
}

// Register adds a detector to the registry
func (r *Registry) Register(detector Detector) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	pattern := detector.GetPattern()
	r.detectors[pattern.ID] = detector

	return nil
}

// Get retrieves a detector by pattern ID
func (r *Registry) Get(patternID string) (Detector, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	detector, ok := r.detectors[patternID]
	return detector, ok
}

// GetAll returns all registered detectors
func (r *Registry) GetAll() []Detector {
	r.mu.RLock()
	defer r.mu.RUnlock()

	detectors := make([]Detector, 0, len(r.detectors))
	for _, d := range r.detectors {
		detectors = append(detectors, d)
	}

	return detectors
}

// Count returns the number of registered patterns
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.detectors)
}

// List returns all pattern IDs
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids := make([]string, 0, len(r.detectors))
	for id := range r.detectors {
		ids = append(ids, id)
	}

	return ids
}
