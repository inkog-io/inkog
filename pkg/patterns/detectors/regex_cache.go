package detectors

import (
	"regexp"
	"sync"
)

// RegexCache provides thread-safe caching of compiled regex patterns
// This prevents recompilation overhead and significantly improves performance
type RegexCache struct {
	cache map[string]*regexp.Regexp
	mu    sync.RWMutex
}

// NewRegexCache creates a new regex cache
func NewRegexCache() *RegexCache {
	return &RegexCache{
		cache: make(map[string]*regexp.Regexp),
	}
}

// GlobalRegexCache is a singleton instance shared across all detectors
var GlobalRegexCache = NewRegexCache()

// Get retrieves a compiled regex from cache, compiling if necessary
func (rc *RegexCache) Get(pattern string) (*regexp.Regexp, error) {
	// First check without lock (fast path for common case)
	rc.mu.RLock()
	if regex, exists := rc.cache[pattern]; exists {
		rc.mu.RUnlock()
		return regex, nil
	}
	rc.mu.RUnlock()

	// Compile the regex if not in cache
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	// Store in cache (write lock)
	rc.mu.Lock()
	rc.cache[pattern] = regex
	rc.mu.Unlock()

	return regex, nil
}

// MustGet is like Get but panics on error (for patterns we know are valid)
func (rc *RegexCache) MustGet(pattern string) *regexp.Regexp {
	regex, err := rc.Get(pattern)
	if err != nil {
		panic("Invalid regex pattern: " + pattern)
	}
	return regex
}

// Clear empties the cache (useful for testing)
func (rc *RegexCache) Clear() {
	rc.mu.Lock()
	rc.cache = make(map[string]*regexp.Regexp)
	rc.mu.Unlock()
}

// Size returns number of cached regexes
func (rc *RegexCache) Size() int {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return len(rc.cache)
}
