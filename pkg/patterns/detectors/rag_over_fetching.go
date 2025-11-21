package detectors

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
	"github.com/inkog-io/inkog/action/pkg/patterns/metadata"
)

// RAGOverFetchingDetector detects unrestricted vector store retrievals in RAG systems
type RAGOverFetchingDetector struct {
	pattern    patterns.Pattern
	confidence float32
	// Regex patterns for detection
	asRetrieverRegex     *regexp.Regexp
	similaritySearchRegex *regexp.Regexp
	getDocumentsRegex    *regexp.Regexp
}

// NewRAGOverFetchingDetector creates a new RAG over-fetching detector
func NewRAGOverFetchingDetector() *RAGOverFetchingDetector {
	pattern := patterns.Pattern{
		ID:       "rag_over_fetching",
		Name:     "RAG Over-fetching",
		Version:  "1.0",
		Category: "resource_exhaustion",
		Severity: "HIGH",
		CVSS:     7.5,
		CWEIDs:   []string{"CWE-770", "CWE-400"},
		OWASP:    "LLM04",
		Description: "Unrestricted vector store retrievals without k parameter limits enable attackers to cause resource exhaustion, data exposure, and financial drain through unbounded API calls and excessive data fetching",
		Remediation: "Always specify k parameter with reasonable limits (k <= 10), implement semantic caching, add rate limiting, validate search_kwargs parameters",
		FinancialImpact: struct {
			Severity    string
			Description string
			RiskPerYear float32
		}{
			Severity:    "CRITICAL",
			Description: "Unrestricted RAG queries can cost $270K/year vs $30K with limits (9x increase)",
			RiskPerYear: 240000, // $270K - $30K
		},
	}

	// Regex for detecting .as_retriever() without k parameter
	asRetrieverRegex := regexp.MustCompile(`\.as_retriever\s*\(\s*\)`)

	// Regex for detecting .similarity_search() calls
	similaritySearchRegex := regexp.MustCompile(`\.similarity_search\s*\([^)]*\)`)

	// Regex for detecting .get_relevant_documents() without limits
	getDocumentsRegex := regexp.MustCompile(`\.get_relevant_documents\s*\([^)]*\)`)

	return &RAGOverFetchingDetector{
		pattern:              pattern,
		confidence:           0.85,
		asRetrieverRegex:     asRetrieverRegex,
		similaritySearchRegex: similaritySearchRegex,
		getDocumentsRegex:    getDocumentsRegex,
	}
}

// Name returns the detector name
func (d *RAGOverFetchingDetector) Name() string {
	return "rag_over_fetching"
}

// GetPatternID returns the canonical detector ID (implements Detector interface)
func (d *RAGOverFetchingDetector) GetPatternID() string {
	return metadata.ID_RAG_OVER_FETCHING
}


// GetPattern returns the pattern metadata
func (d *RAGOverFetchingDetector) GetPattern() patterns.Pattern {
	return d.pattern
}

// GetConfidence returns confidence score
func (d *RAGOverFetchingDetector) GetConfidence() float32 {
	return d.confidence
}

// Detect analyzes code for RAG over-fetching vulnerabilities
func (d *RAGOverFetchingDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	var findings []patterns.Finding

	// Skip unsupported files
	if !isSupportedFile(filePath) {
		return findings, nil
	}

	// Skip test files (false positive reduction)
	if isTestFile(filePath) {
		return findings, nil
	}

	lines := strings.Split(string(src), "\n")

	for i, line := range lines {
		trimmedLine := strings.TrimSpace(line)

		// Skip comments and empty lines
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") || strings.HasPrefix(trimmedLine, "//") {
			continue
		}

		// Check for .as_retriever() without k parameter
		if d.asRetrieverRegex.MatchString(line) {
			finding := patterns.Finding{
				ID:            fmt.Sprintf("rag_over_fetching_retriever_%d_%s", i, filePath),
				PatternID:     d.pattern.ID,
				Pattern:       d.pattern.Name,
				File:          filePath,
				Line:          i + 1,
				Column:        len(line) - len(trimmedLine) + 1,
				Message:       "RAG retriever created without k parameter - enables unbounded data fetching and resource exhaustion",
				Code:          line,
				Severity:      d.pattern.Severity,
				Confidence:    0.85, // High confidence - missing k is clear vulnerability
				CWE:           "CWE-770",
				CVSS:          d.pattern.CVSS,
				OWASP:         d.pattern.OWASP,
				FinancialRisk: "Data exposure, cost increase ($270K/year vs $30K)",
			}

			findings = append(findings, finding)
		}

		// Check for .similarity_search() with unbounded parameters
		if d.similaritySearchRegex.MatchString(line) {
			confidence := d.checkSimilaritySearchBounds(line)
			if confidence > 0 {
				finding := patterns.Finding{
					ID:            fmt.Sprintf("rag_over_fetching_search_%d_%s", i, filePath),
					PatternID:     d.pattern.ID,
					Pattern:       d.pattern.Name,
					File:          filePath,
					Line:          i + 1,
					Column:        len(line) - len(trimmedLine) + 1,
					Message:       "Potential unbounded similarity search - missing or high k parameter",
					Code:          line,
					Severity:      d.pattern.Severity,
					Confidence:    confidence,
					CWE:           "CWE-770",
					CVSS:          d.pattern.CVSS,
					OWASP:         d.pattern.OWASP,
					FinancialRisk: "Excessive data fetching and API costs",
				}

				findings = append(findings, finding)
			}
		}

		// Check for .get_relevant_documents() without limits
		if d.getDocumentsRegex.MatchString(line) {
			confidence := d.checkDocumentFetchLimits(line)
			if confidence > 0 {
				finding := patterns.Finding{
					ID:            fmt.Sprintf("rag_over_fetching_docs_%d_%s", i, filePath),
					PatternID:     d.pattern.ID,
					Pattern:       d.pattern.Name,
					File:          filePath,
					Line:          i + 1,
					Column:        len(line) - len(trimmedLine) + 1,
					Message:       "Document retrieval without fetch limits - potential resource exhaustion",
					Code:          line,
					Severity:      d.pattern.Severity,
					Confidence:    confidence,
					CWE:           "CWE-770",
					CVSS:          d.pattern.CVSS,
					OWASP:         d.pattern.OWASP,
					FinancialRisk: "Unbounded document fetching costs",
				}

				findings = append(findings, finding)
			}
		}

		// Check for retriever without search_kwargs
		if strings.Contains(line, "as_retriever(") && d.hasSearchKwargs(line) {
			if !d.hasKParameter(line) {
				finding := patterns.Finding{
					ID:            fmt.Sprintf("rag_over_fetching_kwargs_%d_%s", i, filePath),
					PatternID:     d.pattern.ID,
					Pattern:       d.pattern.Name,
					File:          filePath,
					Line:          i + 1,
					Column:        len(line) - len(trimmedLine) + 1,
					Message:       "Retriever configured with search_kwargs but missing k parameter limit",
					Code:          line,
					Severity:      d.pattern.Severity,
					Confidence:    0.80,
					CWE:           "CWE-770",
					CVSS:          d.pattern.CVSS,
					OWASP:         d.pattern.OWASP,
					FinancialRisk: "Incomplete retrieval configuration",
				}

				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// checkSimilaritySearchBounds checks if similarity_search has reasonable k bounds
func (d *RAGOverFetchingDetector) checkSimilaritySearchBounds(line string) float32 {
	// Extract k parameter if present
	kRegex := regexp.MustCompile(`k\s*=\s*(\d+)`)
	match := kRegex.FindStringSubmatch(line)

	if len(match) == 0 {
		// No k parameter at all - high confidence vulnerability
		return 0.85
	}

	// Check if k value is reasonable by parsing as integer
	kStr := match[1]
	if len(kStr) > 0 {
		// Try to parse k as integer
		var kValue int
		_, err := fmt.Sscanf(kStr, "%d", &kValue)
		if err != nil {
			// If we can't parse it, assume it's a variable and flag it
			return 0.75 // Medium-high confidence for unparseable k values
		}
		// If k > 50, it's suspicious (potential over-fetching)
		// k > 20 is moderate concern, k > 50 is high concern
		if kValue > 50 {
			return 0.85 // High confidence for very high k values
		} else if kValue > 20 {
			return 0.70 // Medium confidence for high k values
		}
	}

	// k <= 20 seems reasonable, no vulnerability
	return 0
}

// checkDocumentFetchLimits checks if document fetching has limits
func (d *RAGOverFetchingDetector) checkDocumentFetchLimits(line string) float32 {
	// Check for k parameter
	if strings.Contains(line, "k=") {
		return 0 // Has k parameter, seems safe
	}

	// Check for max_results parameter
	if strings.Contains(line, "max_results=") {
		return 0 // Has max_results, seems safe
	}

	// Check for limit parameter
	if strings.Contains(line, "limit=") {
		return 0 // Has limit, seems safe
	}

	// No limits detected
	return 0.75
}

// hasSearchKwargs checks if line contains search_kwargs parameter
func (d *RAGOverFetchingDetector) hasSearchKwargs(line string) bool {
	return strings.Contains(line, "search_kwargs")
}

// hasKParameter checks if line contains k parameter in search_kwargs
func (d *RAGOverFetchingDetector) hasKParameter(line string) bool {
	kRegex := regexp.MustCompile(`search_kwargs\s*=\s*\{[^}]*"k"`)
	return kRegex.MatchString(line)
}
