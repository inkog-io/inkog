package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/inkog-io/inkog/action/pkg/validation"
)

func main() {
	// Command line flags
	repositoriesPath := flag.String("repos", "", "Path to test repositories (or comma-separated URLs)")
	outputPath := flag.String("output", "validation_results", "Output directory for reports")
	listRepos := flag.Bool("list-repos", false, "List recommended test repositories")
	testMode := flag.Bool("test", false, "Run in test mode with minimal data")

	flag.Parse()

	if *listRepos {
		listRecommendedRepositories()
		return
	}

	if *repositoriesPath == "" && !*testMode {
		fmt.Println("Error: --repos path required or use --test for demo mode")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Create validator
	validator := validation.NewValidator(*repositoriesPath, *outputPath)

	// Register test repositories
	if *testMode {
		registerDemoRepositories(validator)
	} else {
		registerRepositoriesFromPath(validator, *repositoriesPath)
	}

	// Run validation
	fmt.Println()
	fmt.Println("════════════════════════════════════════════════════════════════")
	fmt.Println("         INKOG SCANNER - WEEK 7-8 VALIDATION PHASE              ")
	fmt.Println("════════════════════════════════════════════════════════════════")
	fmt.Println()

	err := validator.RunValidation()
	if err != nil {
		log.Fatalf("Validation failed: %v", err)
	}

	fmt.Println()
	fmt.Println("════════════════════════════════════════════════════════════════")
	fmt.Println("✅ VALIDATION COMPLETE")
	fmt.Println("════════════════════════════════════════════════════════════════")
	fmt.Println()
	fmt.Printf("📊 Results saved to: %s\n", *outputPath)
	fmt.Println()
}

// registerDemoRepositories registers sample repositories for testing
func registerDemoRepositories(v *validation.Validator) {
	repos := []validation.RepositoryMetadata{
		{
			Name:              "LangChain",
			URL:               "https://github.com/langchain-ai/langchain",
			Languages:         []string{"Python", "JavaScript", "TypeScript"},
			FileCount:         5000,
			CodeLinesCount:    500000,
			AILLMRelevance:    "Core LLM agent framework with extensive API patterns",
			SelectionReason:   "Primary framework for LLM integration testing",
		},
		{
			Name:              "AutoGen",
			URL:               "https://github.com/microsoft/autogen",
			Languages:         []string{"Python"},
			FileCount:         2000,
			CodeLinesCount:    200000,
			AILLMRelevance:    "Multi-agent conversation framework",
			SelectionReason:   "Advanced agent patterns with tool calling",
		},
		{
			Name:              "CrewAI",
			URL:               "https://github.com/joaomdmoura/crewai",
			Languages:         []string{"Python"},
			FileCount:         1500,
			CodeLinesCount:    150000,
			AILLMRelevance:    "AI agent orchestration framework",
			SelectionReason:   "Real-world agent composition patterns",
		},
	}

	for _, repo := range repos {
		v.RegisterRepository(repo)
	}

	fmt.Printf("📋 Registered %d demo repositories\n", len(repos))
}

// registerRepositoriesFromPath reads repositories from a directory or config
func registerRepositoriesFromPath(v *validation.Validator, path string) {
	// Check if path is a file (config) or directory
	info, err := os.Stat(path)
	if err != nil {
		log.Fatalf("Invalid path: %v", err)
	}

	if info.IsDir() {
		// Scan directory for repositories
		entries, err := os.ReadDir(path)
		if err != nil {
			log.Fatalf("Failed to read directory: %v", err)
		}

		for _, entry := range entries {
			if entry.IsDir() {
				repoPath := filepath.Join(path, entry.Name())
				meta := validation.RepositoryMetadata{
					Name:              entry.Name(),
					URL:               repoPath,
					Languages:         detectLanguages(repoPath),
					AILLMRelevance:    "Local repository",
					SelectionReason:   "Manual selection",
				}
				v.RegisterRepository(meta)
			}
		}
	} else {
		// Assume it's a config file (JSON) with repository list
		// TODO: Implement config file parsing
		log.Fatal("Config file parsing not yet implemented")
	}
}

// detectLanguages scans a directory for source files to detect languages
func detectLanguages(dirPath string) []string {
	languageMap := make(map[string]bool)

	filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		ext := filepath.Ext(path)
		switch ext {
		case ".py":
			languageMap["Python"] = true
		case ".js", ".jsx":
			languageMap["JavaScript"] = true
		case ".ts", ".tsx":
			languageMap["TypeScript"] = true
		case ".go":
			languageMap["Go"] = true
		case ".java":
			languageMap["Java"] = true
		case ".cs":
			languageMap["C#"] = true
		}
		return nil
	})

	var languages []string
	if languageMap["Python"] {
		languages = append(languages, "Python")
	}
	if languageMap["JavaScript"] {
		languages = append(languages, "JavaScript")
	}
	if languageMap["TypeScript"] {
		languages = append(languages, "TypeScript")
	}
	if languageMap["Go"] {
		languages = append(languages, "Go")
	}
	if languageMap["Java"] {
		languages = append(languages, "Java")
	}
	if languageMap["C#"] {
		languages = append(languages, "C#")
	}

	return languages
}

// listRecommendedRepositories prints recommended repositories for validation
func listRecommendedRepositories() {
	fmt.Println()
	fmt.Println("════════════════════════════════════════════════════════════════")
	fmt.Println("       RECOMMENDED TEST REPOSITORIES FOR WEEK 7-8 VALIDATION     ")
	fmt.Println("════════════════════════════════════════════════════════════════")
	fmt.Println()

	repos := []struct {
		name     string
		url      string
		language string
		reason   string
	}{
		{
			name:     "LangChain",
			url:      "https://github.com/langchain-ai/langchain",
			language: "Python/JavaScript/TypeScript",
			reason:   "Core LLM framework with extensive API patterns (5K+ files)",
		},
		{
			name:     "AutoGen",
			url:      "https://github.com/microsoft/autogen",
			language: "Python",
			reason:   "Multi-agent conversation framework with tool calling (2K+ files)",
		},
		{
			name:     "CrewAI",
			url:      "https://github.com/joaomdmoura/crewai",
			language: "Python",
			reason:   "AI agent orchestration with real-world patterns (1.5K+ files)",
		},
		{
			name:     "OpenAI Python SDK",
			url:      "https://github.com/openai/openai-python",
			language: "Python",
			reason:   "Official OpenAI API bindings with provider patterns",
		},
		{
			name:     "Anthropic Python SDK",
			url:      "https://github.com/anthropics/anthropic-sdk-python",
			language: "Python",
			reason:   "Anthropic Claude API integration patterns",
		},
		{
			name:     "Vercel AI SDK",
			url:      "https://github.com/vercel/ai",
			language: "TypeScript/JavaScript",
			reason:   "Multi-provider LLM abstraction layer",
		},
	}

	for i, repo := range repos {
		fmt.Printf("%d. %s\n", i+1, repo.name)
		fmt.Printf("   URL: %s\n", repo.url)
		fmt.Printf("   Language: %s\n", repo.language)
		fmt.Printf("   Why: %s\n", repo.reason)
		fmt.Println()
	}

	fmt.Println("════════════════════════════════════════════════════════════════")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  # Clone and test local repositories:")
	fmt.Println("  git clone <repo-url> /tmp/validation/langchain")
	fmt.Println("  inkog-validation --repos /tmp/validation --output results")
	fmt.Println()
	fmt.Println("  # Test in demo mode with minimal data:")
	fmt.Println("  inkog-validation --test --output demo_results")
	fmt.Println()
}
