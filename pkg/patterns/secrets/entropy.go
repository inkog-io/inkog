package secrets

import (
	"math"
	"regexp"
	"strings"
	"unicode"
)

// Entropy detection constants
const (
	EntropyThreshold     = 4.5   // Balanced threshold for detection
	MinStringLength      = 16    // Minimum length for entropy analysis
	MaxStringLength      = 256   // Maximum length to analyze
	EntropyConfidence    = 0.75  // Confidence score for entropy findings
)

// stringLiteralRegex matches quoted string literals
var stringLiteralRegex = regexp.MustCompile(`["']([a-zA-Z0-9+/=_\-]{16,256})["']`)

// credentialContextRegex matches variable/key names suggesting credentials
var credentialContextRegex = regexp.MustCompile(`(?i)(key|token|secret|password|passwd|pwd|api|auth|credential|private|signing)`)

// ShannonEntropy calculates the Shannon entropy of a string
// Returns bits per character (0-8 for byte data)
// Higher entropy indicates more randomness (potential secrets)
func ShannonEntropy(data string) float64 {
	if len(data) == 0 {
		return 0
	}

	// Count character frequencies
	freq := make(map[rune]int)
	for _, c := range data {
		freq[c]++
	}

	// Calculate entropy: -sum(p * log2(p))
	var entropy float64
	length := float64(len(data))
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// EntropyFinding represents a high-entropy string detection
type EntropyFinding struct {
	Line       int
	Column     int
	Value      string
	Entropy    float64
	HasContext bool   // True if found near credential-related keywords
	Severity   string
	Confidence float32
}

// DetectHighEntropyStrings scans content for suspicious high-entropy strings
// that may be secrets not caught by regex patterns
func DetectHighEntropyStrings(content []byte) []EntropyFinding {
	var findings []EntropyFinding
	lines := strings.Split(string(content), "\n")

	for lineNum, line := range lines {
		// Find all string literals on this line
		matches := stringLiteralRegex.FindAllStringSubmatchIndex(line, -1)

		for _, match := range matches {
			if len(match) < 4 {
				continue
			}

			// Extract the string value (capture group 1)
			value := line[match[2]:match[3]]

			// Skip if too short or too long
			if len(value) < MinStringLength || len(value) > MaxStringLength {
				continue
			}

			// Calculate entropy
			entropy := ShannonEntropy(value)

			// Check if entropy exceeds threshold
			if entropy < EntropyThreshold {
				continue
			}

			// Check for credential-like characteristics
			if !looksLikeCredential(value, line) {
				continue
			}

			// Check for context (nearby credential keywords)
			hasContext := credentialContextRegex.MatchString(line)

			// Adjust confidence based on context
			confidence := float32(EntropyConfidence)
			if hasContext {
				confidence = 0.85
			}

			finding := EntropyFinding{
				Line:       lineNum + 1, // Convert to 1-indexed
				Column:     match[2],
				Value:      value,
				Entropy:    entropy,
				HasContext: hasContext,
				Severity:   "MEDIUM",
				Confidence: confidence,
			}

			findings = append(findings, finding)
		}
	}

	return findings
}

// looksLikeCredential checks if a string has characteristics of a credential
// Returns true if the string appears to be a potential secret
func looksLikeCredential(value, lineContext string) bool {
	// Must have sufficient character variety (not repeated chars)
	if !hasCharacterVariety(value) {
		return false
	}

	// Skip common non-secret patterns
	if isLikelyNonSecret(value) {
		return false
	}

	// Check for credential context in the line
	if credentialContextRegex.MatchString(lineContext) {
		return true
	}

	// High entropy alone with good character mix is suspicious
	if hasGoodCharacterMix(value) {
		return true
	}

	return false
}

// hasCharacterVariety checks if string has diverse characters
func hasCharacterVariety(s string) bool {
	uniqueChars := make(map[rune]bool)
	for _, c := range s {
		uniqueChars[c] = true
	}

	// Need at least 8 unique characters for 16+ char string
	return len(uniqueChars) >= 8
}

// hasGoodCharacterMix checks for mix of uppercase, lowercase, digits
func hasGoodCharacterMix(s string) bool {
	var hasUpper, hasLower, hasDigit bool

	for _, c := range s {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsDigit(c):
			hasDigit = true
		}

		// Early exit if all found
		if hasUpper && hasLower && hasDigit {
			return true
		}
	}

	// Need at least 2 of 3 character types
	count := 0
	if hasUpper {
		count++
	}
	if hasLower {
		count++
	}
	if hasDigit {
		count++
	}

	return count >= 2
}

// isLikelyNonSecret checks for patterns that are high-entropy but not secrets
func isLikelyNonSecret(value string) bool {
	lower := strings.ToLower(value)

	// Common non-secret patterns
	nonSecretPatterns := []string{
		// UUIDs (legitimate identifiers)
		"-4[0-9a-f]{3}-",
		// Base64 encoded common strings
		"aaaa", "bbbb", "cccc",
		// Lorem ipsum
		"lorem", "ipsum",
		// Test data
		"test", "example", "sample", "demo",
		// Sequential patterns
		"0123456789", "abcdefgh",
	}

	for _, pattern := range nonSecretPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	// Check for repeated substrings (likely not a secret)
	if hasRepeatedPatterns(value) {
		return true
	}

	return false
}

// hasRepeatedPatterns checks for repeated substrings
func hasRepeatedPatterns(s string) bool {
	if len(s) < 8 {
		return false
	}

	// Check for 4-char patterns that repeat
	for i := 0; i < len(s)-8; i++ {
		pattern := s[i : i+4]
		rest := s[i+4:]
		if strings.Count(rest, pattern) >= 2 {
			return true
		}
	}

	return false
}

// ConvertEntropyToSecretFinding converts an EntropyFinding to SecretFinding
func ConvertEntropyToSecretFinding(ef EntropyFinding) SecretFinding {
	description := "High-Entropy String (Potential Secret)"
	if ef.HasContext {
		description = "High-Entropy String in Credential Context"
	}

	return SecretFinding{
		Type:        "entropy_secret",
		Description: description,
		Line:        ef.Line,
		Column:      ef.Column,
		Value:       ef.Value,
		Severity:    ef.Severity,
		Confidence:  ef.Confidence,
		Pattern:     "entropy_detection",
	}
}

// IsDuplicateOfRegexFinding checks if an entropy finding overlaps with regex findings
func IsDuplicateOfRegexFinding(ef EntropyFinding, regexFindings []SecretFinding) bool {
	for _, rf := range regexFindings {
		// Same line and overlapping columns indicates duplicate
		if rf.Line == ef.Line {
			// Check if the values overlap
			if strings.Contains(rf.Value, ef.Value) || strings.Contains(ef.Value, rf.Value) {
				return true
			}
			// Check column proximity (within 20 chars)
			if abs(rf.Column-ef.Column) < 20 {
				return true
			}
		}
	}
	return false
}

// abs returns absolute value of an int
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
