# Inkog Setup Guide

This guide will help you set up the Inkog development environment and get started contributing.

## Prerequisites

### Required
- **Go 1.21+** - Download from https://golang.org/dl/
- **PostgreSQL 14+** - Download from https://www.postgresql.org/download/
- **Docker** - Download from https://www.docker.com/
- **Git** - Download from https://git-scm.com/

### Recommended
- **VS Code** with Go extension
- **Postman** for API testing
- **pgAdmin** for database management

## Local Development Setup

### 1. Clone the Repository

```bash
git clone https://github.com/inkog-io/inkog.git
cd inkog
```

### 2. Install Dependencies

```bash
# Download Go dependencies
go mod download

# Install required tools
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
```

### 3. Set Up PostgreSQL

#### Option A: Using Docker (Recommended)
```bash
docker run --name inkog-postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=inkog \
  -p 5432:5432 \
  -d postgres:15
```

#### Option B: Local PostgreSQL Installation
```bash
# Create database
createdb inkog

# Run migrations (when available)
psql inkog < migrations/001_init.sql
```

### 4. Configure Environment Variables

Create a `.env` file in the project root:

```bash
# Database
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=postgres
DB_NAME=inkog

# Environment
ENV=development
LOG_LEVEL=debug

# API
API_PORT=8080
API_HOST=0.0.0.0

# GitHub (for future integrations)
GITHUB_TOKEN=your_token_here
```

### 5. Build the Project

```bash
# Build CLI binary
go build -o inkog ./cmd/cli

# Run the scanner
./inkog --help
```

### 6. Run Tests

```bash
# Run all tests
go test ./...

# Run with verbose output
go test -v ./...

# Run specific test package
go test ./internal/parser -v
```

### 7. Code Quality Checks

```bash
# Run linter
golangci-lint run

# Format code
go fmt ./...

# Run vet
go vet ./...
```

## Project Structure

```
inkog/
├── cmd/
│   ├── cli/              # CLI entry point
│   └── api/              # API server (future)
├── internal/
│   ├── parser/           # tree-sitter parser wrapper
│   ├── patterns/         # Pattern detection rules
│   ├── scanner/          # Main scanner logic
│   ├── storage/          # Database operations
│   └── models/           # Data structures
├── pkg/
│   ├── report/           # Report generation
│   └── compliance/       # Compliance helpers
├── migrations/           # Database migrations
├── tests/                # Integration tests
├── docs/                 # Documentation
├── go.mod              # Go dependencies
└── Dockerfile          # Docker configuration
```

## Running the Scanner

### CLI Usage

```bash
# Scan a directory
./inkog scan ./path/to/agent

# Scan with specific framework
./inkog scan ./path/to/agent --framework langchain

# Scan with risk threshold
./inkog scan ./path/to/agent --risk-threshold high

# Generate compliance report
./inkog scan ./path/to/agent --compliance-report
```

### Example Scan

```bash
# Create a test agent
mkdir test-agent
cat > test-agent/agent.py << 'EOF'
from langchain.agents import initialize_agent

def create_agent():
    # Agent code here
    pass
EOF

# Run scan
./inkog scan ./test-agent
```

## GitHub Action Integration

### Local Testing

```bash
# Install act (GitHub Actions local runner)
brew install act

# Run workflow locally
act push
```

### Testing Your Changes

```bash
# Push to feature branch
git checkout -b feature/my-feature
git push origin feature/my-feature

# Create pull request on GitHub
# GitHub Actions will run automatically
```

## Database Development

### Running Migrations

```bash
# Create a new migration
migrate create -ext sql -dir migrations -seq add_users_table

# Run all pending migrations
psql inkog < migrations/*.sql

# Rollback (manual)
psql inkog < migrations/rollback.sql
```

### Querying Data

```bash
# Connect to database
psql -h localhost -U postgres -d inkog

# Example queries
SELECT * FROM scan_results;
SELECT * FROM patterns;
```

## Docker Development

### Build Docker Image

```bash
docker build -t inkog:latest .
```

### Run in Docker

```bash
docker run \
  -e DB_HOST=host.docker.internal \
  -e DB_PORT=5432 \
  -e DB_USER=postgres \
  -e DB_PASSWORD=postgres \
  -e DB_NAME=inkog \
  inkog:latest
```

## Debugging

### Using VS Code Debugger

1. Install "Go" extension by Go Team
2. Create `.vscode/launch.json`:

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Launch Scanner",
      "type": "go",
      "request": "launch",
      "mode": "debug",
      "program": "${workspaceFolder}/cmd/cli",
      "args": ["scan", "./test-agent"]
    }
  ]
}
```

3. Press F5 to start debugging

### Debug Output

```bash
# Enable debug logging
LOG_LEVEL=debug ./inkog scan ./path/to/agent
```

## Common Issues

### PostgreSQL Connection Error
```
Error: could not connect to database
```
**Solution:** Ensure PostgreSQL is running and credentials in `.env` are correct.

### Go Module Issues
```
go: command not found
```
**Solution:** Ensure Go 1.21+ is installed and in your PATH.

### Docker Cannot Start
```
Docker daemon is not running
```
**Solution:** Start Docker Desktop or docker daemon.

## Testing

### Running Scanner Tests

Test the scanner against real agent code:

```bash
cd action

# Build the scanner
go build -o inkog-scanner ./cmd/scanner

# Test against LangChain example
./inkog-scanner \
  --path ../test-agents/langchain-example \
  --framework langchain \
  --json-report ../langchain-report.json

# Test against CrewAI example
./inkog-scanner \
  --path ../test-agents/crewai-example \
  --framework crewai \
  --json-report ../crewai-report.json

# View results
cat ../langchain-report.json | jq '.'
```

### Test Agents

Pre-built test agents with intentional vulnerabilities:

- **LangChain**: `test-agents/langchain-example/agent.py` (8+ vulnerabilities)
- **CrewAI**: `test-agents/crewai-example/crew.py` (8+ vulnerabilities)

See `test-agents/README.md` for detailed vulnerability descriptions.

### GitHub Actions Tests

Tests run automatically on:
- Pushes to `test-agents/` directory
- Pushes to `action/` directory
- Pushes to workflow files

View results at: https://github.com/inkog-io/inkog/actions

### Test Documentation

See `TEST_RESULTS.md` for:
- Detailed test setup and configuration
- Expected findings and risk scores
- Analysis commands
- Success criteria

## Contributing

1. Create a feature branch: `git checkout -b feature/my-feature`
2. Make your changes and add tests
3. Run tests and linting: `go test ./... && golangci-lint run`
4. Test against test agents: `action/inkog-scanner --path test-agents`
5. Commit: `git commit -am 'Add my feature'`
6. Push: `git push origin feature/my-feature`
7. Create a Pull Request on GitHub

## Additional Resources

- [Go Documentation](https://golang.org/doc/)
- [tree-sitter Documentation](https://tree-sitter.github.io/)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [Docker Documentation](https://docs.docker.com/)

## Support

For questions or issues:
1. Check existing [GitHub Issues](https://github.com/inkog-io/inkog/issues)
2. Create a new issue with detailed information
3. Join our community discussions

---

Happy coding! 🚀
