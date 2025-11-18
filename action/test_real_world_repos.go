package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/inkog-io/inkog/action/pkg/patterns/detectors"
)

// RealWorldTestResult captures results from testing a real repository
type RealWorldTestResult struct {
	RepoName string
	RepoURL  string
	FilesScanned int
	TotalFindings int
	ByPattern map[string]int
	Duration time.Duration
	Error string
}

func main() {
	fmt.Println("=== Inkog Scanner Real-World Repository Testing ===\n")

	results := []RealWorldTestResult{}

	// Test 1: Clone and scan a real repository
	fmt.Println("Downloading test repositories...")

	// For this test, we'll create some realistic test code files instead of cloning
	// This is faster and doesn't require network access
	testRepo := createTestRepository()
	defer os.RemoveAll(testRepo)

	fmt.Printf("\n[Test 1] Scanning realistic AI/agent code patterns\n")
	result := scanRepository(testRepo, "ai-patterns")
	results = append(results, result)
	printResult(result)

	// Summary
	fmt.Println("\n=== Final Summary ===\n")
	totalScanned := 0
	totalFindings := 0
	for _, r := range results {
		totalScanned += r.FilesScanned
		totalFindings += r.TotalFindings
		fmt.Printf("%-30s: %d files, %d findings\n", r.RepoName, r.FilesScanned, r.TotalFindings)
	}

	fmt.Printf("\nTotal: %d files scanned, %d vulnerabilities found\n", totalScanned, totalFindings)
	fmt.Println("\n✅ Real-world testing complete")
}

func createTestRepository() string {
	tmpDir, _ := ioutil.TempDir("", "inkog-realworld-*")

	// Create realistic vulnerable code samples
	samples := map[string]string{
		"langchain_app.py": `
import os
import openai
from langchain.vectorstores import Chroma

# Pattern 1: Hardcoded credentials
OPENAI_API_KEY = "sk-proj-abc123def456xyz789secret"
openai.api_key = OPENAI_API_KEY

# Pattern 2: Prompt injection
user_query = request.args.get('q')
prompt = f"Search results for: {user_query}"

# Pattern 3: Infinite loop
def process_forever():
    while True:
        data = fetch_data()

# Pattern 4: Unsafe env access
db_password = os.environ["DB_PASSWORD"]

# Pattern 5: Token bombing
def token_bomb():
    for i in range(10000):
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "x" * 4000}],
            max_tokens=4096
        )

# Pattern 6: Recursive tool calling
def agent_task(task):
    result = agent.execute(task)
    if not result.success:
        return agent_task(next_task)

# Pattern 7: RAG over-fetching
retriever = vectorstore.as_retriever()
results = retriever.invoke("query")

# Pattern 8: Missing rate limits
@app.route("/api/data")
def get_data():
    while True:
        response = openai.ChatCompletion.create(model="gpt-4", messages=[])
        yield response

# Pattern 9: Unvalidated exec/eval
response = openai.ChatCompletion.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Write Python code"}]
)
# CVE-2023-36258: Directly executing LLM output
eval(response['choices'][0]['message']['content'])
`,

		"crewai_app.py": `
from crewai import Agent, Task, Crew

# Multiple agents with delegation enabled (Pattern 6)
agent1 = Agent(
    role="Researcher",
    goal="Research information",
    allow_delegation=True
)

agent2 = Agent(
    role="Writer",
    goal="Write content",
    allow_delegation=True
)

# Pattern 3: Unbounded agent loop
def run_agents():
    while True:
        for agent in [agent1, agent2]:
            result = agent.execute()
`,

		"dify_workflow.py": `
import asyncio

# Pattern 5: Token bombing in loop
async def generate_content(prompt, styles):
    for style in ["realistic", "artistic", "anime", "pixel", "cartoon", "watercolor"]:
        image = await call_image_model(prompt, style)
        save_image(image)

    # Pattern 3: Another infinite loop risk
    while True:
        response = await openai.ChatCompletion.create(...)

    # Pattern 9: Unvalidated exec/eval - Dify CVE
    code = request.json.get('code')
    exec(code)  # Dangerous!
`,

		"secure_code.py": `
# This code is SECURE - should not trigger false positives
import os
from functools import lru_cache

api_key = os.environ.get("OPENAI_API_KEY", None)
if not api_key:
    raise ValueError("API key required")

# Safe rate limiting
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(app, key_func=get_remote_address)

@app.route("/api/safe")
@limiter.limit("10 per minute")
def safe_endpoint():
    return {"data": "safe"}

# Bounded recursion
def factorial(n, depth=0):
    if depth > 100:
        return 0
    if n <= 1:
        return 1
    return n * factorial(n - 1, depth + 1)
`,
	}

	for filename, content := range samples {
		ioutil.WriteFile(filepath.Join(tmpDir, filename), []byte(content), 0644)
	}

	return tmpDir
}

func scanRepository(repoPath string, repoName string) RealWorldTestResult {
	result := RealWorldTestResult{
		RepoName: repoName,
		ByPattern: make(map[string]int),
	}

	// Initialize all detectors
	detectorFunctions := []struct {
		name string
		fn   func(string, []byte) ([]interface{}, error)
	}{
		{"Hardcoded Credentials", func(path string, src []byte) ([]interface{}, error) {
			findings, _ := detectors.NewHardcodedCredentialsDetector().Detect(path, src)
			var result []interface{}
			for _, f := range findings {
				result = append(result, f)
			}
			return result, nil
		}},
		{"Prompt Injection", func(path string, src []byte) ([]interface{}, error) {
			findings, _ := detectors.NewPromptInjectionDetector().Detect(path, src)
			var result []interface{}
			for _, f := range findings {
				result = append(result, f)
			}
			return result, nil
		}},
		{"Infinite Loops", func(path string, src []byte) ([]interface{}, error) {
			findings, _ := detectors.NewInfiniteLoopDetector().Detect(path, src)
			var result []interface{}
			for _, f := range findings {
				result = append(result, f)
			}
			return result, nil
		}},
		{"Unsafe Env Access", func(path string, src []byte) ([]interface{}, error) {
			findings, _ := detectors.NewUnsafeEnvAccessDetector().Detect(path, src)
			var result []interface{}
			for _, f := range findings {
				result = append(result, f)
			}
			return result, nil
		}},
		{"Token Bombing", func(path string, src []byte) ([]interface{}, error) {
			findings, _ := detectors.NewTokenBombingDetector().Detect(path, src)
			var result []interface{}
			for _, f := range findings {
				result = append(result, f)
			}
			return result, nil
		}},
		{"Recursive Tool Calling", func(path string, src []byte) ([]interface{}, error) {
			findings, _ := detectors.NewRecursiveToolCallingDetector().Detect(path, src)
			var result []interface{}
			for _, f := range findings {
				result = append(result, f)
			}
			return result, nil
		}},
		{"RAG Over-fetching", func(path string, src []byte) ([]interface{}, error) {
			findings, _ := detectors.NewEnhancedRAGOverFetchingDetector(nil).Detect(path, src)
			var result []interface{}
			for _, f := range findings {
				result = append(result, f)
			}
			return result, nil
		}},
		{"Missing Rate Limits", func(path string, src []byte) ([]interface{}, error) {
			findings, _ := detectors.NewEnhancedMissingRateLimitsDetector(nil).Detect(path, src)
			var result []interface{}
			for _, f := range findings {
				result = append(result, f)
			}
			return result, nil
		}},
		{"Unvalidated Exec/Eval", func(path string, src []byte) ([]interface{}, error) {
			findings, _ := detectors.NewEnhancedUnvalidatedExecEvalDetector(nil).Detect(path, src)
			var result []interface{}
			for _, f := range findings {
				result = append(result, f)
			}
			return result, nil
		}},
	}

	start := time.Now()

	// Scan all Python files in repo
	filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		if !strings.HasSuffix(path, ".py") && !strings.HasSuffix(path, ".js") &&
			!strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, ".ts") {
			return nil
		}

		src, err := ioutil.ReadFile(path)
		if err != nil {
			return nil
		}

		result.FilesScanned++

		// Run all detectors
		for _, detector := range detectorFunctions {
			findings, _ := detector.fn(path, src)
			if len(findings) > 0 {
				result.ByPattern[detector.name] += len(findings)
				result.TotalFindings += len(findings)
			}
		}

		return nil
	})

	result.Duration = time.Since(start)
	return result
}

func printResult(result RealWorldTestResult) {
	fmt.Printf("Repository: %s\n", result.RepoName)
	fmt.Printf("Files Scanned: %d\n", result.FilesScanned)
	fmt.Printf("Total Findings: %d\n", result.TotalFindings)
	fmt.Printf("Duration: %v\n", result.Duration)

	fmt.Println("\nFindings by Pattern:")
	for pattern, count := range result.ByPattern {
		if count > 0 {
			fmt.Printf("  %-30s: %d\n", pattern, count)
		}
	}
	fmt.Println()
}
