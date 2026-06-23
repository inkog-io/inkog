package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/inkog-io/inkog/pkg/contract"
)

var openClawConfigFiles = map[string]bool{
	"AGENTS.md": true,
	"SHIELD.md": true,
	"SKILL.md":  true,
	"SOUL.md":   true,
	"TOOLS.md":  true,
}

var destructiveOpenClawTerms = []string{
	"delete", "destroy", "drop table", "exec", "execute_code", "filesystem",
	"kill", "modify file", "subprocess", "transfer", "write file",
}

var approvalOpenClawTerms = []string{
	"approval", "approve", "confirm", "human", "manual review", "oversight",
}

var promptInjectionTerms = []string{
	"bypass", "developer message", "ignore previous", "ignore prior",
	"override instructions",
}

func isOpenClawConfigFile(filename string) bool {
	return openClawConfigFiles[filename]
}

func scanOpenClawFindings(sourcePath string, files map[string]bool) []contract.Finding {
	configs := openClawConfigs(sourcePath, files)
	if len(configs) == 0 {
		return nil
	}

	findings := make([]contract.Finding, 0)
	if _, ok := configs["SHIELD.md"]; !ok {
		findings = append(findings, openClawFinding(
			"openclaw_missing_shield",
			"Missing OpenClaw guardrail configuration",
			"OpenClaw project defines agent configuration files but no SHIELD.md guardrail file was found.",
			"SHIELD.md",
			1,
			"CRITICAL",
			"oversight",
		))
	}

	hasApproval := openClawHasApprovalLanguage(configs)
	for name, path := range configs {
		if name != "TOOLS.md" && name != "SKILL.md" {
			continue
		}
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if line, ok := firstMatchingLine(string(content), destructiveOpenClawTerms); ok && !hasApproval {
			findings = append(findings, openClawFinding(
				"openclaw_destructive_tool_without_approval",
				"OpenClaw destructive tool lacks human approval",
				fmt.Sprintf("OpenClaw %s references a destructive capability without nearby approval or oversight language.", name),
				relativeOpenClawPath(sourcePath, path),
				line,
				"HIGH",
				"authorization",
			))
		}
		if line, ok := firstMatchingLine(string(content), promptInjectionTerms); ok {
			findings = append(findings, openClawFinding(
				"openclaw_prompt_injection_vector",
				"OpenClaw config contains prompt-injection language",
				fmt.Sprintf("OpenClaw %s contains wording commonly used to bypass or override agent instructions.", name),
				relativeOpenClawPath(sourcePath, path),
				line,
				"MEDIUM",
				"oversight",
			))
		}
	}

	return findings
}

func openClawConfigs(sourcePath string, files map[string]bool) map[string]string {
	configs := make(map[string]string)
	for path := range files {
		name := filepath.Base(path)
		if isOpenClawConfigFile(name) {
			configs[name] = path
		}
	}

	if info, err := os.Stat(sourcePath); err == nil && info.IsDir() {
		for name := range openClawConfigFiles {
			path := filepath.Join(sourcePath, name)
			if _, err := os.Stat(path); err == nil {
				configs[name] = path
			}
		}
	}

	return configs
}

func openClawHasApprovalLanguage(configs map[string]string) bool {
	for _, path := range configs {
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if _, ok := firstMatchingLine(string(content), approvalOpenClawTerms); ok {
			return true
		}
	}
	return false
}

func firstMatchingLine(content string, terms []string) (int, bool) {
	for idx, line := range strings.Split(content, "\n") {
		lower := strings.ToLower(line)
		for _, term := range terms {
			if strings.Contains(lower, term) {
				return idx + 1, true
			}
		}
	}
	return 0, false
}

func relativeOpenClawPath(sourcePath, path string) string {
	if rel, err := filepath.Rel(sourcePath, path); err == nil && rel != "." {
		return rel
	}
	return filepath.Base(path)
}

func openClawFinding(patternID, pattern, message, file string, line int, severity, governanceCategory string) contract.Finding {
	return contract.Finding{
		ID:                 fmt.Sprintf("%s_%s_%d", patternID, strings.ReplaceAll(file, string(filepath.Separator), "_"), line),
		PatternID:          patternID,
		Pattern:            pattern,
		Source:             contract.SourceLocalCLI,
		File:               file,
		Line:               line,
		Severity:           severity,
		Confidence:         0.82,
		Message:            message,
		Category:           "governance",
		RiskTier:           contract.TierRiskPattern,
		FindingType:        contract.TypeGovernanceViolation,
		GovernanceCategory: governanceCategory,
		OWASP:              "LLM08",
		ComplianceMapping: &contract.ComplianceMapping{
			EUAIActArticles: []string{"Article 14"},
			NISTCategories:  []string{"GOVERN 4.1"},
			OWASPItems:      []string{"LLM08"},
		},
	}
}
