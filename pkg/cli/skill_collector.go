package cli

import (
	"os"
	"path/filepath"
	"strings"
)

// SkillFormat represents the detected skill package format.
type SkillFormat string

const (
	SkillFormatMCP       SkillFormat = "mcp"
	SkillFormatSkillMD   SkillFormat = "skill_md"
	SkillFormatAgentTool SkillFormat = "agent_tool"
)

// SkillPackageSummary describes the detected skill package.
type SkillPackageSummary struct {
	Format    SkillFormat
	Name      string
	FileCount int
	ToolCount int
	Path      string
}

// CollectSkillFiles collects all relevant files from a skill package directory
// and returns them as a map of path -> content for upload to the API.
func CollectSkillFiles(dirPath string) (map[string]string, *SkillPackageSummary, error) {
	files := make(map[string]string)
	summary := &SkillPackageSummary{
		Path: dirPath,
	}

	// Detect format
	summary.Format = detectSkillFormat(dirPath)

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		// Skip hidden directories and common non-source dirs
		if info.IsDir() {
			name := info.Name()
			if strings.HasPrefix(name, ".") || name == "node_modules" ||
				name == "__pycache__" || name == "venv" || name == ".venv" ||
				name == "dist" || name == "build" || name == ".git" {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip large files (1MB)
		if info.Size() > 1024*1024 {
			return nil
		}

		// Only include relevant file types
		ext := strings.ToLower(filepath.Ext(info.Name()))
		if !isSkillFileExt(ext) && info.Name() != "SKILL.md" {
			return nil
		}

		relPath, err := filepath.Rel(dirPath, path)
		if err != nil {
			relPath = path
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		files[relPath] = string(content)
		return nil
	})

	if err != nil {
		return nil, nil, err
	}

	summary.FileCount = len(files)

	// Extract name from metadata
	if content, ok := files["SKILL.md"]; ok {
		summary.Name = extractSkillName(content)
	} else if content, ok := files["package.json"]; ok {
		summary.Name = extractPackageName(content)
	}

	return files, summary, nil
}

// detectSkillFormat determines the skill format from directory contents.
func detectSkillFormat(dirPath string) SkillFormat {
	// Check for SKILL.md
	if fileExistsAt(filepath.Join(dirPath, "SKILL.md")) {
		return SkillFormatSkillMD
	}

	// Check for MCP server patterns in package.json
	pkgPath := filepath.Join(dirPath, "package.json")
	if data, err := os.ReadFile(pkgPath); err == nil {
		content := string(data)
		if strings.Contains(content, "@modelcontextprotocol") ||
			strings.Contains(content, "mcp-server") {
			return SkillFormatMCP
		}
	}

	// Check for pyproject.toml with MCP
	pyPath := filepath.Join(dirPath, "pyproject.toml")
	if data, err := os.ReadFile(pyPath); err == nil {
		content := string(data)
		if strings.Contains(content, "mcp") {
			return SkillFormatMCP
		}
	}

	return SkillFormatAgentTool
}

func isSkillFileExt(ext string) bool {
	switch ext {
	case ".py", ".ts", ".js", ".sh", ".bash",
		".md", ".json", ".yaml", ".yml", ".toml",
		".txt", ".cfg", ".ini", ".env":
		return true
	}
	return false
}

func fileExistsAt(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func extractSkillName(content string) string {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "name:") {
			value := strings.TrimSpace(strings.TrimPrefix(trimmed, "name:"))
			return strings.Trim(value, "\"'")
		}
	}
	return ""
}

func extractPackageName(content string) string {
	// Simple JSON name extraction
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "\"name\"") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				value := strings.TrimSpace(parts[1])
				value = strings.Trim(value, ",\"' ")
				return value
			}
		}
	}
	return ""
}
