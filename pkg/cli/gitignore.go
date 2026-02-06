package cli

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// GitIgnore represents parsed .gitignore patterns for a directory tree.
type GitIgnore struct {
	patterns []gitignorePattern
}

type gitignorePattern struct {
	pattern  string
	negation bool   // starts with !
	dirOnly  bool   // ends with /
	anchored bool   // contains / in the middle (anchored to gitignore location)
	raw      string // original line for debugging
}

// LoadGitIgnore reads .gitignore from the given root directory.
// Returns an empty GitIgnore (matches nothing) if no .gitignore exists.
func LoadGitIgnore(rootDir string) *GitIgnore {
	gi := &GitIgnore{}

	path := filepath.Join(rootDir, ".gitignore")
	f, err := os.Open(path)
	if err != nil {
		return gi // No .gitignore — return empty matcher
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		gi.addPattern(line)
	}

	return gi
}

func (gi *GitIgnore) addPattern(line string) {
	// Strip trailing whitespace (but not leading — that's significant in git)
	line = strings.TrimRight(line, " \t\r")

	// Skip empty lines and comments
	if line == "" || strings.HasPrefix(line, "#") {
		return
	}

	p := gitignorePattern{raw: line}

	// Handle negation
	if strings.HasPrefix(line, "!") {
		p.negation = true
		line = line[1:]
	}

	// Handle directory-only patterns
	if strings.HasSuffix(line, "/") {
		p.dirOnly = true
		line = strings.TrimRight(line, "/")
	}

	// Strip leading slash (anchors the pattern but isn't part of matching)
	if strings.HasPrefix(line, "/") {
		p.anchored = true
		line = line[1:]
	} else if strings.Contains(line, "/") {
		// A pattern with a slash in the middle is also anchored
		p.anchored = true
	}

	p.pattern = line
	if p.pattern != "" {
		gi.patterns = append(gi.patterns, p)
	}
}

// Match returns true if the given path (relative to the .gitignore root) should be ignored.
// isDir should be true if the path is a directory.
func (gi *GitIgnore) Match(relPath string, isDir bool) bool {
	if len(gi.patterns) == 0 {
		return false
	}

	// Normalize to forward slashes for matching
	relPath = filepath.ToSlash(relPath)

	// Last matching pattern wins (git behavior)
	matched := false
	for _, p := range gi.patterns {
		if p.dirOnly && !isDir {
			continue
		}

		if p.matches(relPath) {
			matched = !p.negation
		}
	}

	return matched
}

func (p *gitignorePattern) matches(relPath string) bool {
	pattern := p.pattern

	if p.anchored {
		// Anchored: match from the root
		return matchGlob(pattern, relPath)
	}

	// Unanchored: match against the basename OR any path suffix
	// e.g., "*.pyc" matches "foo/bar.pyc" and "bar.pyc"
	if matchGlob(pattern, filepath.Base(relPath)) {
		return true
	}

	// Also try matching against progressively longer path suffixes
	// e.g., pattern "build" should match "src/build" at directory level
	parts := strings.Split(relPath, "/")
	for i := range parts {
		suffix := strings.Join(parts[i:], "/")
		if matchGlob(pattern, suffix) {
			return true
		}
	}

	return false
}

// matchGlob implements simple glob matching supporting *, ?, and **.
func matchGlob(pattern, name string) bool {
	// Handle ** (matches any number of directories)
	if strings.Contains(pattern, "**") {
		return matchDoublestar(pattern, name)
	}

	return matchSimple(pattern, name)
}

// matchSimple handles * and ? (single-level matching, * doesn't match /).
func matchSimple(pattern, name string) bool {
	px, nx := 0, 0
	pLen, nLen := len(pattern), len(name)
	starPx, starNx := -1, -1

	for nx < nLen {
		if px < pLen && pattern[px] == '*' {
			// * matches everything except /
			starPx = px
			starNx = nx
			px++
			continue
		}

		if px < pLen && (pattern[px] == '?' || pattern[px] == name[nx]) {
			// ? matches any single char except /
			if pattern[px] == '?' && name[nx] == '/' {
				// ? doesn't match /
				if starPx >= 0 {
					px = starPx + 1
					starNx++
					nx = starNx
					continue
				}
				return false
			}
			px++
			nx++
			continue
		}

		if starPx >= 0 {
			// Backtrack: advance the star match
			if name[starNx] == '/' {
				// * doesn't match /
				return false
			}
			px = starPx + 1
			starNx++
			nx = starNx
			continue
		}

		return false
	}

	// Consume remaining *s in pattern
	for px < pLen && pattern[px] == '*' {
		px++
	}

	return px == pLen
}

// matchDoublestar handles ** which matches zero or more directories.
func matchDoublestar(pattern, name string) bool {
	// Split pattern on **
	parts := strings.SplitN(pattern, "**", 2)
	prefix := parts[0]
	suffix := ""
	if len(parts) > 1 {
		suffix = parts[1]
	}

	// Remove trailing/leading slashes from the ** boundaries
	prefix = strings.TrimRight(prefix, "/")
	suffix = strings.TrimLeft(suffix, "/")

	if prefix == "" && suffix == "" {
		// Pattern is just "**" — matches everything
		return true
	}

	if prefix == "" {
		// Pattern starts with ** — suffix must match end of path
		// Try matching suffix against every possible tail
		nameParts := strings.Split(name, "/")
		for i := range nameParts {
			tail := strings.Join(nameParts[i:], "/")
			if matchSimple(suffix, tail) {
				return true
			}
		}
		return matchSimple(suffix, name)
	}

	if suffix == "" {
		// Pattern ends with ** — prefix must match start of path
		nameParts := strings.Split(name, "/")
		for i := 1; i <= len(nameParts); i++ {
			head := strings.Join(nameParts[:i], "/")
			if matchSimple(prefix, head) {
				return true
			}
		}
		return false
	}

	// Both prefix and suffix — prefix must match start, suffix must match end
	nameParts := strings.Split(name, "/")
	for i := 1; i <= len(nameParts); i++ {
		head := strings.Join(nameParts[:i], "/")
		if matchSimple(prefix, head) {
			for j := i; j <= len(nameParts); j++ {
				tail := strings.Join(nameParts[j:], "/")
				if matchSimple(suffix, tail) {
					return true
				}
			}
		}
	}

	return false
}
