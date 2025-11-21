package detectors

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strings"

	"github.com/inkog-io/inkog/action/pkg/patterns"
	"github.com/inkog-io/inkog/action/pkg/patterns/metadata"
)

// UnsafeEnvAccessDetector detects unsafe environment variable access without defaults
type UnsafeEnvAccessDetector struct {
	pattern    patterns.Pattern
	confidence float32
	regex      *regexp.Regexp
}

// NewUnsafeEnvAccessDetector creates a new unsafe env access detector
func NewUnsafeEnvAccessDetector() *UnsafeEnvAccessDetector {
	pattern := patterns.Pattern{
		ID:       "unsafe_env_access",
		Name:     "Unsafe Environment Variable Access",
		Version:  "1.0",
		Category: "configuration",
		Severity: "MEDIUM",
		CVSS:     6.5,
		CWEIDs:   []string{"CWE-665"},
		OWASP:    "LLM02",
		Description: "Accessing environment variables without default values causes runtime failures and missing configuration errors in production",
		Remediation: "Always use os.environ.get('KEY', 'default') or validate environment variables on startup",
		FinancialImpact: struct {
			Severity    string
			Description string
			RiskPerYear float32
		}{
			Severity:    "MEDIUM",
			Description: "Missing environment variable causes agent crash on first customer interaction",
			RiskPerYear: 50000,
		},
	}

	// Match: os.environ["KEY"] without .get()
	regex := regexp.MustCompile(`os\.environ\s*\[\s*["']`)

	return &UnsafeEnvAccessDetector{
		pattern:    pattern,
		confidence: 0.92,
		regex:      regex,
	}
}

// Name returns the detector name
func (d *UnsafeEnvAccessDetector) Name() string {
	return "unsafe_env_access"
}

// GetPatternID returns the canonical detector ID (implements Detector interface)
func (d *UnsafeEnvAccessDetector) GetPatternID() string {
	return metadata.ID_UNSAFE_ENV_ACCESS
}


// GetPattern returns the pattern metadata
func (d *UnsafeEnvAccessDetector) GetPattern() patterns.Pattern {
	return d.pattern
}

// GetConfidence returns confidence score
func (d *UnsafeEnvAccessDetector) GetConfidence() float32 {
	return d.confidence
}

// Detect analyzes code for unsafe environment access
func (d *UnsafeEnvAccessDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error) {
	var findings []patterns.Finding

	// Skip unsupported files
	if !isSupportedFile(filePath) {
		return findings, nil
	}

	// Skip test files (except those ending with _test.py which are validation tests)
	if isTestFile(filePath) {
		return findings, nil
	}

	// Handle Go files with AST-based detection
	if strings.HasSuffix(filePath, ".go") {
		return d.detectGoUnsafeEnvAccess(filePath, src)
	}

	// Handle Python files with regex-based detection
	lines := strings.Split(string(src), "\n")

	for i, line := range lines {
		trimmedLine := strings.TrimSpace(line)

		// Skip comments and empty lines
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") || strings.HasPrefix(trimmedLine, "//") {
			continue
		}

		// Check for os.environ[...] pattern
		if d.regex.MatchString(line) {
			// Verify it's NOT using .get() (which is safe)
			if !strings.Contains(line, ".get(") {
				// Check if access is guarded by existence check on previous lines
				isGuarded := d.isAccessGuarded(lines, i)

				if !isGuarded {
					finding := patterns.Finding{
						ID:            fmt.Sprintf("unsafe_env_%d_%s", i, filePath),
						PatternID:     d.pattern.ID,
						Pattern:       d.pattern.Name,
						File:          filePath,
						Line:          i + 1,
						Column:        strings.Index(line, "os.environ") + 1,
						Message:       "Unsafe environment variable access: os.environ[] without default value will crash if variable is missing",
						Code:          line,
						Severity:      d.pattern.Severity,
						Confidence:    d.confidence,
						CWE:           "CWE-665",
						CVSS:          d.pattern.CVSS,
						OWASP:         d.pattern.OWASP,
						FinancialRisk: "Agent crash on missing configuration - production downtime",
					}

					findings = append(findings, finding)
				}
			}
		}
	}

	return findings, nil
}

// isAccessGuarded checks if os.environ access is guarded by an existence check
func (d *UnsafeEnvAccessDetector) isAccessGuarded(lines []string, currentIdx int) bool {
	// Look back up to 5 lines for guard patterns
	startIdx := currentIdx - 5
	if startIdx < 0 {
		startIdx = 0
	}

	// Extract the variable name being accessed if possible
	currentLine := lines[currentIdx]
	varPattern := regexp.MustCompile(`os\.environ\s*\[\s*["'](\w+)["']`)
	matches := varPattern.FindStringSubmatch(currentLine)

	if len(matches) < 2 {
		// Couldn't extract variable name, so we can't verify guard
		return false
	}
	varName := matches[1]

	// Check for guard patterns in previous lines
	for i := startIdx; i < currentIdx; i++ {
		line := strings.ToLower(lines[i])

		// Pattern 1: if KEY in os.environ:
		if strings.Contains(line, "in os.environ") && strings.Contains(line, varName) {
			return true
		}

		// Pattern 2: if os.environ.get(KEY):
		if strings.Contains(line, "os.environ.get") && strings.Contains(line, varName) {
			return true
		}

		// Pattern 3: os.getenv check
		if strings.Contains(line, "os.getenv") && strings.Contains(line, varName) {
			return true
		}
	}

	return false
}

// detectGoUnsafeEnvAccess detects unsafe os.Getenv() calls in Go code using AST analysis
func (d *UnsafeEnvAccessDetector) detectGoUnsafeEnvAccess(filePath string, src []byte) ([]patterns.Finding, error) {
	var findings []patterns.Finding

	// Parse the Go file
	fset := token.NewFileSet()
	astFile, err := parser.ParseFile(fset, filePath, src, parser.AllErrors)
	if err != nil {
		// If parsing fails, skip AST-based detection
		return findings, nil
	}

	// Walk the AST looking for unsafe os.Getenv() calls
	ast.Walk(&goEnvAccessVisitor{
		filePath:  filePath,
		fset:      fset,
		pattern:   d.pattern,
		findings:  &findings,
		src:       src,
		detector:  d,
	}, astFile)

	return findings, nil
}

// goEnvAccessVisitor walks the Go AST looking for unsafe environment variable access
type goEnvAccessVisitor struct {
	filePath string
	fset     *token.FileSet
	pattern  patterns.Pattern
	findings *[]patterns.Finding
	src      []byte
	detector *UnsafeEnvAccessDetector
}

// Visit implements ast.Visitor interface
func (v *goEnvAccessVisitor) Visit(node ast.Node) ast.Visitor {
	if node == nil {
		return v
	}

	// Look for function calls
	if callExpr, ok := node.(*ast.CallExpr); ok {
		// Check if this is os.Getenv() or similar
		if isUnsafeGetenvCall(callExpr) {
			// Get line number from token positions
			line := v.fset.Position(callExpr.Pos()).Line

			// Extract the function name and context
			funcName := getCallExprName(callExpr)
			msg := fmt.Sprintf("Unsafe environment variable access: %s() called without checking for missing values", funcName)

			finding := patterns.Finding{
				ID:            fmt.Sprintf("unsafe_env_go_%d_%s", line, v.filePath),
				PatternID:     v.pattern.ID,
				Pattern:       v.pattern.Name,
				File:          v.filePath,
				Line:          line,
				Column:        1,
				Message:       msg,
				Code:          fmt.Sprintf("%s()", funcName),
				Severity:      "MEDIUM",
				Confidence:    0.85,
				CWE:           "CWE-665",
				CVSS:          6.5,
				OWASP:         "LLM02",
				FinancialRisk: "Missing environment variable causes agent crash in production",
			}
			*v.findings = append(*v.findings, finding)
		}
	}

	return v
}

// isUnsafeGetenvCall checks if a call expression is an unsafe os.Getenv() or LookupEnv()
func isUnsafeGetenvCall(call *ast.CallExpr) bool {
	// Check if it's a direct function call
	if ident, ok := call.Fun.(*ast.Ident); ok {
		// Check for direct getenv call (less common)
		if ident.Name == "Getenv" {
			return true
		}
	}

	// Check if it's a method call on a package (e.g., os.Getenv)
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		// Check if this is calling Getenv or LookupEnv
		if sel.Sel.Name == "Getenv" || sel.Sel.Name == "LookupEnv" {
			// Check if the receiver is os package
			if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "os" {
				// For LookupEnv, it's unsafe if return value is not used
				if sel.Sel.Name == "LookupEnv" {
					return true // Simplified: flag all LookupEnv without ok check
				}
				// For Getenv, it's unsafe since it returns empty string for missing env
				return true
			}
		}
	}

	return false
}

// getCallExprName extracts a readable name from a call expression
func getCallExprName(call *ast.CallExpr) string {
	if ident, ok := call.Fun.(*ast.Ident); ok {
		return ident.Name
	}
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if ident, ok := sel.X.(*ast.Ident); ok {
			return ident.Name + "." + sel.Sel.Name
		}
		return sel.Sel.Name
	}
	return "function"
}
