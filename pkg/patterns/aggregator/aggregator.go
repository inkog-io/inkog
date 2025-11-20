package aggregator

import (
	"fmt"
	"sort"
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
	"github.com/inkog-io/inkog/action/pkg/patterns/metadata"
)

// DeduplicateAndEnrich processes raw findings to:
// 1. Normalize metadata from registry
// 2. Deduplicate findings at same location
// 3. Filter out safe/ignored findings
// Returns clean, enriched findings ready for reporting
func DeduplicateAndEnrich(rawFindings []patterns.Finding) []patterns.Finding {
	if len(rawFindings) == 0 {
		return []patterns.Finding{}
	}

	// Step 1: Normalize all findings with canonical metadata
	normalized := normalizeFindings(rawFindings)

	// Step 2: Deduplicate findings at same location
	deduplicated := deduplicateByLocation(normalized)

	// Step 3: Sort for consistent output
	sortFindings(deduplicated)

	return deduplicated
}

// normalizeFindings enriches findings with canonical metadata from registry
func normalizeFindings(findings []patterns.Finding) []patterns.Finding {
	var normalized []patterns.Finding

	for i := range findings {
		f := findings[i]

		// Look up canonical metadata by PatternID
		meta := metadata.Get(f.PatternID)

		// Normalize Title: use registry if empty
		if f.Pattern == "" && meta != nil {
			f.Pattern = meta.Title
		}

		// Normalize CVSS: use registry if 0.0 or empty
		if f.CVSS == 0.0 && meta != nil {
			f.CVSS = meta.CVSS
		}

		// Normalize Severity: use registry if empty
		if f.Severity == "" && meta != nil {
			f.Severity = meta.DefaultSeverity
		}

		// Normalize CWE: use registry if empty
		if f.CWE == "" && meta != nil && len(meta.CWEIDs) > 0 {
			f.CWE = strings.Join(meta.CWEIDs, ", ")
		}

		// Ensure File is never empty
		if f.File == "" {
			f.File = "unknown"
		}

		// Ensure ID is set
		if f.ID == "" {
			f.ID = fmt.Sprintf("%s_%d", f.PatternID, i)
		}

		// Ensure Confidence is reasonable
		if f.Confidence == 0.0 {
			f.Confidence = 0.5 // Default to medium confidence
		}

		normalized = append(normalized, f)
	}

	return normalized
}

// deduplicateByLocation groups findings by FilePath+LineNumber and keeps best match
func deduplicateByLocation(findings []patterns.Finding) []patterns.Finding {
	// Group findings by location
	locationMap := make(map[string][]patterns.Finding)

	for _, f := range findings {
		key := fmt.Sprintf("%s:%d", f.File, f.Line)
		locationMap[key] = append(locationMap[key], f)
	}

	var result []patterns.Finding

	// For each location, select best finding(s)
	for _, group := range locationMap {
		if len(group) == 1 {
			result = append(result, group[0])
			continue
		}

		// Multiple findings at same location - select by criteria
		best := selectBestFindings(group)
		result = append(result, best...)
	}

	return result
}

// selectBestFindings chooses exactly ONE finding to keep when multiple exist at same location
// Strategy: Highest severity first, filter out language mismatches (e.g., JavaScript for Python)
func selectBestFindings(group []patterns.Finding) []patterns.Finding {
	if len(group) == 0 {
		return []patterns.Finding{}
	}

	if len(group) == 1 {
		return group
	}

	// Sort by severity (descending) then by confidence (descending)
	sort.Slice(group, func(i, j int) bool {
		sevI := severityScore(group[i].Severity)
		sevJ := severityScore(group[j].Severity)

		if sevI != sevJ {
			return sevI > sevJ
		}

		// If severity equal, compare confidence
		return group[i].Confidence > group[j].Confidence
	})

	// STRICT DEDUPLICATION: Return exactly ONE finding (the best)
	// Filter out language mismatches (e.g., JavaScript detectors for Python files)
	isPythonFile := strings.HasSuffix(group[0].File, ".py")

	for i := 0; i < len(group); i++ {
		finding := group[i]

		// Skip findings that mention JavaScript when scanning Python files
		if isPythonFile && strings.Contains(strings.ToLower(finding.Message), "javascript") {
			continue
		}

		// Return the first valid (best-scored) finding
		return []patterns.Finding{finding}
	}

	// Fallback: return highest severity regardless (shouldn't reach here)
	return []patterns.Finding{group[0]}
}

// severityScore converts severity string to numeric score for comparison
func severityScore(severity string) int {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

// sortFindings sorts findings by File, Line, then PatternID for consistent output
func sortFindings(findings []patterns.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].PatternID < findings[j].PatternID
	})
}

// ValidateFindings performs sanity checks on enriched findings
func ValidateFindings(findings []patterns.Finding) []string {
	var issues []string

	for i, f := range findings {
		// Check for empty Title
		if f.Pattern == "" {
			issues = append(issues, fmt.Sprintf("Finding %d: Missing title/pattern", i))
		}

		// Check for 0.0 CVSS
		if f.CVSS == 0.0 {
			issues = append(issues, fmt.Sprintf("Finding %d (%s): CVSS is 0.0", i, f.PatternID))
		}

		// Check for empty File
		if f.File == "" || f.File == "unknown" {
			issues = append(issues, fmt.Sprintf("Finding %d: Missing file path", i))
		}

		// Check for empty Message
		if f.Message == "" {
			issues = append(issues, fmt.Sprintf("Finding %d: Missing message", i))
		}

		// Check Severity is valid
		if !isValidSeverity(f.Severity) {
			issues = append(issues, fmt.Sprintf("Finding %d: Invalid severity '%s'", i, f.Severity))
		}
	}

	return issues
}

// isValidSeverity checks if severity is one of the accepted values
func isValidSeverity(severity string) bool {
	valid := map[string]bool{
		"CRITICAL": true,
		"HIGH":     true,
		"MEDIUM":   true,
		"LOW":      true,
	}
	return valid[strings.ToUpper(severity)]
}

// GetFindingsByPatternID returns all findings matching a specific pattern ID
func GetFindingsByPatternID(findings []patterns.Finding, patternID string) []patterns.Finding {
	var matches []patterns.Finding
	for _, f := range findings {
		if f.PatternID == patternID {
			matches = append(matches, f)
		}
	}
	return matches
}

// GetFindingsBySeverity returns all findings at or above specified severity
func GetFindingsBySeverity(findings []patterns.Finding, minSeverity string) []patterns.Finding {
	minScore := severityScore(minSeverity)
	var filtered []patterns.Finding

	for _, f := range findings {
		if severityScore(f.Severity) >= minScore {
			filtered = append(filtered, f)
		}
	}

	return filtered
}

// GetFindingsByFile returns all findings in a specific file
func GetFindingsByFile(findings []patterns.Finding, filePath string) []patterns.Finding {
	var matches []patterns.Finding
	for _, f := range findings {
		if f.File == filePath {
			matches = append(matches, f)
		}
	}
	return matches
}
