package detectors

import (
	"strings"
)

// isSupportedFile checks if file extension is supported
func isSupportedFile(path string) bool {
	supported := []string{".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".c", ".cpp", ".h", ".hpp", ".cs", ".rb", ".php", ".scala", ".kt"}
	for _, ext := range supported {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// isTestFile checks if file is a test file (false positive reduction)
// Uses FileClassifier for consistent, maintainable test file detection
// Covers: test_ prefix, _test suffix, tests/ directories, spec files, mocks, fixtures, etc.
func isTestFile(path string) bool {
	classifier := NewFileClassifier()
	return classifier.IsTestFile(path)
}

// isInLLMContext checks if code is within an LLM function call context
func isInLLMContext(line string) bool {
	llmFuncs := []string{
		"chat(", "invoke(", "predict(",
		"run(", "execute(", "call(",
		"completion(", "generate(",
	}

	for _, fn := range llmFuncs {
		if strings.Contains(line, fn) {
			return true
		}
	}

	return false
}
