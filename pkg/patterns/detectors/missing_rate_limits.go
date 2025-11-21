package detectors

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
	"github.com/inkog-io/inkog/action/pkg/patterns/metadata"
)

// MissingRateLimitsDetector detects endpoints and loops without rate limiting
type MissingRateLimitsDetector struct {
	pattern    patterns.Pattern
	confidence float32
	// Regex patterns for detection
	routeRegex            *regexp.Regexp
	rateLimitRegex        *regexp.Regexp
	apiCallLoopRegex      *regexp.Regexp
	externalAPIRegex      *regexp.Regexp
	globalLimiterRegex    *regexp.Regexp
}

// NewMissingRateLimitsDetector creates a new missing rate limits detector
func NewMissingRateLimitsDetector() *MissingRateLimitsDetector {
	pattern := patterns.Pattern{
		ID:       "missing_rate_limits",
		Name:     "Missing Rate Limits",
		Version:  "1.0",
		Category: "resource_exhaustion",
		Severity: "HIGH",
		CVSS:     7.8,
		CWEIDs:   []string{"CWE-770", "CWE-799", "CWE-400"},
		OWASP:    "API4",
		Description: "Missing or insufficient rate limiting allows attackers to cause denial of service, resource exhaustion, or brute-force attacks by making unlimited requests. In AI agents, this can cause runaway API calls with massive financial impact.",
		Remediation: "Implement rate limiting using decorators (Flask-Limiter), middleware (FastAPI dependencies), framework features (Django throttle), or golang.org/x/time/rate. Set appropriate thresholds per endpoint.",
		FinancialImpact: struct {
			Severity    string
			Description string
			RiskPerYear float32
		}{
			Severity:    "CRITICAL",
			Description: "Uncontrolled API calls can cost $300+ in 30 minutes. LangChain runaway loops, Dify unbounded image generation, n8n errors create bills.",
			RiskPerYear: 100000, // $300 incident suggests high impact potential
		},
	}

	// Regex for detecting Flask/FastAPI/Django route handlers
	routeRegex := regexp.MustCompile(`(?m)^@(?:app|.*router|.*api)\.(?:route|get|post|put|delete|patch|post|head|options)\(`)

	// Regex for detecting rate limiting mechanisms
	rateLimitRegex := regexp.MustCompile(`(?i)(?:@limiter\.limit|@throttle|RateLimit|rate\.NewLimiter|Limiter\(|ModelCallLimitMiddleware|throttle_classes|limit_rate|@ratelimit)`)

	// Regex for detecting API call loops (while/for with external API)
	apiCallLoopRegex := regexp.MustCompile(`(?m)(?:while\s+[Tt]rue|for\s+\w+\s+in\s+.+:|for\s+\w+\s*:=\s*0).*?\n.*?(?:openai\.|client\.|requests\.|ChatCompletion|generate|create|invoke|execute)`)

	// Regex for detecting external API calls (OpenAI, Anthropic, etc.)
	externalAPIRegex := regexp.MustCompile(`(?i)(?:openai\.|anthropic\.|google\.|cohere\.|client\.messages|client\.chat|ChatCompletion\.create|create\(|invoke\(|execute\(|requests\.(?:post|get|put))`)

	// Regex for detecting global rate limiters in file
	globalLimiterRegex := regexp.MustCompile(`(?i)(?:limiter\s*=|rate\.NewLimiter|Limiter\s*\(|DEFAULT_THROTTLE|api_rate_limit)`)

	return &MissingRateLimitsDetector{
		pattern:             pattern,
		confidence:          0.80,
		routeRegex:          routeRegex,
		rateLimitRegex:      rateLimitRegex,
		apiCallLoopRegex:    apiCallLoopRegex,
		externalAPIRegex:    externalAPIRegex,
		globalLimiterRegex:  globalLimiterRegex,
	}
}

// Name returns the detector name
func (d *MissingRateLimitsDetector) Name() string {
	return "missing_rate_limits"
}

// GetPatternID returns the canonical detector ID (implements Detector interface)
func (d *MissingRateLimitsDetector) GetPatternID() string {
	return metadata.ID_MISSING_RATE_LIMITS
}


// GetPattern returns the pattern metadata
func (d *MissingRateLimitsDetector) GetPattern() patterns.Pattern {
	return d.pattern
}

// GetConfidence returns confidence score
func (d *MissingRateLimitsDetector) GetConfidence() float32 {
	return d.confidence
}

// Detect analyzes code for missing rate limits vulnerabilities
func (d *MissingRateLimitsDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	var findings []patterns.Finding

	// Skip unsupported files
	if !isSupportedFile(filePath) {
		return findings, nil
	}

	// Skip test files (false positive reduction)
	if isTestFile(filePath) {
		return findings, nil
	}

	sourceStr := string(src)
	lines := strings.Split(sourceStr, "\n")

	// Check if file has global rate limiter (if yes, reduce severity for endpoints)
	hasGlobalLimiter := d.globalLimiterRegex.MatchString(sourceStr)

	// Pattern 1: Detect endpoints without rate limiting
	for i, line := range lines {
		trimmedLine := strings.TrimSpace(line)

		// Skip comments and empty lines
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") || strings.HasPrefix(trimmedLine, "//") {
			continue
		}

		// Check for route decorators without rate limiting
		if d.routeRegex.MatchString(line) {
			// Look ahead to see if this route has a limiter decorator in the next few lines
			hasLimiter := d.hasLimiterAboveOrBelow(lines, i)

			if !hasLimiter && !hasGlobalLimiter {
				var confidence float32 = 0.85 // High confidence for public endpoints

				// Check if there's auth on the endpoint (reduces severity)
				if d.hasAuthContext(lines, i) {
					confidence = 0.70 // Medium confidence if auth is present
				}

				finding := patterns.Finding{
					ID:            fmt.Sprintf("missing_rate_limit_endpoint_%d_%s", i, filePath),
					PatternID:     d.pattern.ID,
					Pattern:       d.pattern.Name,
					File:          filePath,
					Line:          i + 1,
					Column:        len(line) - len(trimmedLine) + 1,
					Message:       "API endpoint lacks rate limiting - vulnerable to brute force, DoS, and abuse",
					Code:          line,
					Severity:      d.pattern.Severity,
					Confidence:    confidence,
					CWE:           "CWE-770",
					CVSS:          d.pattern.CVSS,
					OWASP:         d.pattern.OWASP,
					FinancialRisk: "Brute force attacks, account takeover, denial of service",
				}

				findings = append(findings, finding)
			}
		}
	}

	// Pattern 2: Detect unbounded loops with external API calls
	for i, line := range lines {
		trimmedLine := strings.TrimSpace(line)

		// Skip comments
		if strings.HasPrefix(trimmedLine, "#") || strings.HasPrefix(trimmedLine, "//") {
			continue
		}

		// Check for while True or for loops
		if (strings.Contains(line, "while") && strings.Contains(line, "True")) ||
			(strings.Contains(line, "for") && !strings.Contains(line, "break")) {

			// Look ahead for external API calls
			hasAPICall := false
			lookAhead := 30 // Check next 30 lines for API calls
			for j := i; j < i+lookAhead && j < len(lines); j++ {
				if d.externalAPIRegex.MatchString(lines[j]) {
					hasAPICall = true
					break
				}
				// Stop if we hit a break, return, or new function
				if strings.Contains(lines[j], "break") || strings.Contains(lines[j], "return") ||
					strings.HasPrefix(strings.TrimSpace(lines[j]), "def ") || strings.HasPrefix(strings.TrimSpace(lines[j]), "func ") {
					break
				}
			}

			if hasAPICall {
				// Check if there's any sleep or rate limiting
				hasThrottling := d.hasThrottlingLogic(lines, i, i+lookAhead)

				if !hasThrottling {
					var confidence float32 = 0.80 // High confidence for unbounded loops with API calls

					// Check for token limits or max iterations
					if d.hasIterationLimit(lines, i, i+lookAhead) {
						confidence = 0.60 // Lower confidence if there are some bounds
					}

					finding := patterns.Finding{
						ID:            fmt.Sprintf("missing_rate_limit_loop_%d_%s", i, filePath),
						PatternID:     d.pattern.ID,
						Pattern:       d.pattern.Name,
						File:          filePath,
						Line:          i + 1,
						Column:        len(line) - len(trimmedLine) + 1,
						Message:       "Unbounded loop with external API calls - risk of runaway costs and DoS",
						Code:          line,
						Severity:      d.pattern.Severity,
						Confidence:    confidence,
						CWE:           "CWE-400",
						CVSS:          d.pattern.CVSS,
						OWASP:         d.pattern.OWASP,
						FinancialRisk: "Runaway API calls: $300+ in 30 minutes possible (n8n incident)",
					}

					findings = append(findings, finding)
				}
			}
		}
	}

	// Pattern 3: Detect recursive calls without depth limits
	for i, line := range lines {
		trimmedLine := strings.TrimSpace(line)

		// Skip comments
		if strings.HasPrefix(trimmedLine, "#") || strings.HasPrefix(trimmedLine, "//") {
			continue
		}

		// Look for recursive function calls (function calling itself)
		if strings.Contains(line, "return ") && d.hasRecursivePattern(lines, i) {
			// Check if this is a recursive call without depth/base case limit
			if !d.hasRecursionLimit(lines, i) {
				finding := patterns.Finding{
					ID:            fmt.Sprintf("missing_rate_limit_recursive_%d_%s", i, filePath),
					PatternID:     d.pattern.ID,
					Pattern:       d.pattern.Name,
					File:          filePath,
					Line:          i + 1,
					Column:        len(line) - len(trimmedLine) + 1,
					Message:       "Recursive call without depth limit - can cause runaway loops and massive API costs",
					Code:          line,
					Severity:      d.pattern.Severity,
					Confidence:    0.75,
					CWE:           "CWE-400",
					CVSS:          d.pattern.CVSS,
					OWASP:         d.pattern.OWASP,
					FinancialRisk: "Unbounded recursion leading to exponential API calls or stack exhaustion",
				}

				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// hasLimiterAboveOrBelow checks if there's a limiter decorator near the function
func (d *MissingRateLimitsDetector) hasLimiterAboveOrBelow(lines []string, funcLine int) bool {
	// Check 3 lines above for limiter decorator
	start := 0
	if funcLine >= 3 {
		start = funcLine - 3
	}

	for i := start; i < funcLine && i < len(lines); i++ {
		if d.rateLimitRegex.MatchString(lines[i]) {
			return true
		}
	}

	return false
}

// hasAuthContext checks if endpoint has authentication
func (d *MissingRateLimitsDetector) hasAuthContext(lines []string, funcLine int) bool {
	// Look within function for auth checks
	for i := funcLine; i < funcLine+10 && i < len(lines); i++ {
		line := strings.ToLower(lines[i])
		if strings.Contains(line, "login") || strings.Contains(line, "auth") ||
			strings.Contains(line, "token") || strings.Contains(line, "verify") ||
			strings.Contains(line, "permission") || strings.Contains(line, "required") {
			return true
		}
		// Stop if we hit next function/route
		if (i > funcLine) && (strings.HasPrefix(strings.TrimSpace(lines[i]), "@") ||
			strings.HasPrefix(strings.TrimSpace(lines[i]), "def ") ||
			strings.HasPrefix(strings.TrimSpace(lines[i]), "func ")) {
			break
		}
	}

	return false
}

// hasThrottlingLogic checks for rate limiting, sleep, or delay logic
func (d *MissingRateLimitsDetector) hasThrottlingLogic(lines []string, start, end int) bool {
	for i := start; i < end && i < len(lines); i++ {
		line := strings.ToLower(lines[i])
		if strings.Contains(line, "sleep") || strings.Contains(line, "time.sleep") ||
			strings.Contains(line, "rate") || strings.Contains(line, "throttle") ||
			strings.Contains(line, "limiter") || strings.Contains(line, "limit") ||
			strings.Contains(line, "wait") {
			return true
		}
	}

	return false
}

// hasIterationLimit checks for max_iterations, max_calls, etc.
func (d *MissingRateLimitsDetector) hasIterationLimit(lines []string, start, end int) bool {
	for i := start; i < end && i < len(lines); i++ {
		line := strings.ToLower(lines[i])
		if strings.Contains(line, "max_iter") || strings.Contains(line, "max_call") ||
			strings.Contains(line, "max_token") || strings.Contains(line, "call_limit") ||
			strings.Contains(line, "run_limit") {
			return true
		}
	}

	return false
}

// hasRecursivePattern checks if function makes recursive calls
func (d *MissingRateLimitsDetector) hasRecursivePattern(lines []string, agentCallLine int) bool {
	// Extract function name if this line is inside a function
	for i := agentCallLine - 1; i >= 0 && i >= agentCallLine-30; i-- {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "def ") || strings.HasPrefix(line, "func ") {
			// Found function definition
			funcNameMatch := regexp.MustCompile(`(?:def|func)\s+(\w+)`).FindStringSubmatch(line)
			if len(funcNameMatch) > 1 {
				funcName := funcNameMatch[1]
				// Now check if funcName is called recursively anywhere in the next 30 lines
				for j := agentCallLine; j < agentCallLine+30 && j < len(lines); j++ {
					// Check for function call (including with spaces)
					if strings.Contains(lines[j], "return "+funcName) ||
						strings.Contains(lines[j], funcName+"(") {
						return true
					}
				}
			}
			break
		}
	}

	return false
}

// hasRecursionLimit checks for depth tracking or recursion depth parameter
func (d *MissingRateLimitsDetector) hasRecursionLimit(lines []string, startLine int) bool {
	for i := startLine - 15; i < startLine+5 && i < len(lines); i++ {
		if i >= 0 && i < len(lines) {
			line := strings.ToLower(lines[i])
			// Look for specific depth/recursion limit patterns
			if strings.Contains(line, "depth") && strings.Contains(line, "max") ||
				strings.Contains(line, "max_depth") ||
				strings.Contains(line, "max_recursion") ||
				strings.Contains(line, "if depth >=") ||
				strings.Contains(line, "if depth >") ||
				strings.Contains(line, "if recursion_depth") ||
				(strings.Contains(line, "depth=0") && strings.Contains(lines[i], "(")) ||
				strings.Contains(line, "recursion.*limit") {
				return true
			}
		}
	}

	return false
}
