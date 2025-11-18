# Contributing to Inkog

Thank you for your interest in contributing to Inkog! This document provides guidelines for reporting bugs, proposing features, and submitting pull requests.

## Code of Conduct

- Be respectful and inclusive
- Focus on the work, not the person
- Help create a welcoming environment for everyone

## How to Contribute

### Reporting Bugs

1. **Check existing issues** to avoid duplicates
2. **Use the bug template** when creating an issue
3. **Include reproduction steps** with minimal test case
4. **Specify your environment**: Go version, OS, etc.

**Example:**
```
Title: Scanner crashes on Python 3.6 syntax

Steps to reproduce:
1. Run `./inkog-scanner --path ./test-python36`
2. Scanner crashes after processing main.py

Expected: Scanner completes without error
Actual: Runtime panic in pattern detector
```

### Suggesting Features

1. **Check the roadmap** in `/internal/action/ROADMAP.md`
2. **Describe the use case** you're trying to solve
3. **Provide examples** of the expected behavior
4. **Explain the impact**: Who benefits and why?

### Submitting Pull Requests

1. **Fork and create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Development Setup**
   ```bash
   cd action
   go mod download
   go test ./...
   ```

3. **Code Style**
   - Follow standard Go conventions
   - Run `go fmt` before committing
   - Keep functions focused and well-documented
   - Add comments for non-obvious logic

4. **Write Tests**
   - Add tests for new features
   - Ensure existing tests pass: `go test ./...`
   - Aim for >80% code coverage on new code
   - Test both success and failure paths

5. **Commit Messages**
   - Use clear, descriptive commit messages
   - Start with verb: "Add", "Fix", "Update", "Refactor", "Document"
   - Reference issues: "Fixes #123"
   - Keep first line to 72 characters

   Example:
   ```
   Add panic recovery for detector failures

   When a detector panics, it should not crash the entire scanner.
   This change implements defer/recover pattern to gracefully handle
   detector panics and continue scanning with remaining patterns.

   Fixes #456
   ```

6. **Open Pull Request**
   - Provide a clear description of changes
   - Link related issues
   - Explain the rationale
   - Include performance implications (if any)

7. **Code Review Process**
   - Address feedback promptly
   - Discuss disagreements openly
   - Maintainers have final decision
   - Plan for 2-3 day review cycle

## Development Workflow

### Building the Scanner

```bash
cd action
go build -o inkog-scanner ./cmd/scanner
./inkog-scanner --list-patterns  # Verify build
```

### Running Tests

```bash
# All tests
go test ./...

# Specific package
go test ./cmd/scanner

# With coverage
go test -cover ./...

# Verbose output
go test -v ./...
```

### Adding a New Security Pattern

1. **Create detector file** in `pkg/patterns/detectors/`
2. **Implement Detector interface**:
   ```go
   type MyDetector struct{}
   func (d *MyDetector) Name() string
   func (d *MyDetector) GetPattern() patterns.Pattern
   func (d *MyDetector) GetConfidence() float32
   func (d *MyDetector) Detect(filePath string, src []byte) ([]patterns.Finding, error)
   ```

3. **Register in** `cmd/scanner/init_registry.go`
4. **Add tests** in `pkg/patterns/detectors/mydetector_test.go`
5. **Document** the pattern in `/docs/patterns/`

## Project Structure

```
inkog/
├── action/              # Main scanner application
│   ├── cmd/scanner/     # CLI entry point
│   ├── pkg/patterns/    # Pattern detection logic
│   │   ├── detectors/   # Individual pattern detectors
│   │   ├── types.go     # Core types (Finding, ScanResult)
│   │   └── registry.go  # Pattern registry
│   ├── go.mod           # Go module definition
│   └── README.md        # Scanner documentation
├── docs/                # User documentation
│   └── patterns/        # Pattern-specific guides
├── demo/                # Interactive web demo
├── testdata/            # Test files and fixtures
├── test-agents/         # Example agent code
├── internal/            # Internal development docs (not for release)
├── LICENSE              # MIT License
└── README.md            # Project overview
```

## Testing Standards

### Unit Tests
- Test both normal and edge cases
- Use table-driven tests for multiple scenarios
- Mock external dependencies

### Integration Tests
- Test against real code samples
- Verify cross-pattern interactions
- Run on multiple Go versions

### Test File Naming
- Use `_test.go` suffix
- Example: `hardcoded_credentials_test.go`

## Documentation

- **Code Comments**: Explain "why", not "what"
- **Commit Messages**: Clear, descriptive, with context
- **Pull Requests**: Link issues, explain changes
- **README**: Keep current and accurate
- **Changelog**: Record all significant changes

## Release Process

1. **Version Bumping**: Semantic versioning (MAJOR.MINOR.PATCH)
2. **Changelog Update**: Document all changes
3. **Tag Release**: Create git tag
4. **Build Artifacts**: Compile binaries
5. **Publish**: Release to GitHub and package managers

## Getting Help

- **Questions?** Check `/docs/DEVELOPMENT.md`
- **Architecture?** See `/internal/action/ROADMAP.md`
- **Pattern Details?** Review `/internal/SECURITY_PATTERNS.md`
- **Chat**: Open an issue for discussion

## License

By contributing to Inkog, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to making AI agents safer!** 🛡️
