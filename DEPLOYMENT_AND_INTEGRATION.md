# Inkog Deployment & Integration Guide

**Version:** 1.0
**Date:** November 12, 2025
**Audience:** DevOps, Security Teams, Integrators

---

## Overview

This guide covers deploying Inkog scanner and integrating it into CI/CD pipelines, security tools, and enterprise systems.

---

## Deployment Options

### Option 1: Standalone Scanner

**Best for:** One-time security audits, small projects

```bash
# Download binary
wget https://releases.inkog.io/inkog-scanner/v1.0/inkog-scanner-linux-amd64

# Make executable
chmod +x inkog-scanner

# Run scan
./inkog-scanner /path/to/code
```

### Option 2: Docker Container

**Best for:** Containerized deployments, CI/CD pipelines

```dockerfile
FROM golang:1.21-alpine
WORKDIR /app
COPY . .
RUN go build -o inkog-scanner ./cmd/scanner/
ENTRYPOINT ["./inkog-scanner"]
```

**Usage:**
```bash
docker build -t inkog-scanner .
docker run -v /path/to/code:/code inkog-scanner /code
```

### Option 3: CI/CD Integration

**Best for:** Automated security checks in pipelines

#### GitHub Actions

```yaml
name: Inkog Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'

      - name: Build Inkog Scanner
        run: go build -o inkog-scanner ./cmd/scanner/

      - name: Run Security Scan
        run: |
          ./inkog-scanner . --strict
          if [ $? -ne 0 ]; then
            echo "Security vulnerabilities detected!"
            exit 1
          fi
```

#### GitLab CI

```yaml
scan:security:
  image: golang:1.21
  script:
    - go build -o inkog-scanner ./cmd/scanner/
    - ./inkog-scanner . --strict
  artifacts:
    reports:
      sast: inkog-findings.json
```

#### Jenkins

```groovy
pipeline {
    agent any

    stages {
        stage('Build Inkog') {
            steps {
                sh 'go build -o inkog-scanner ./cmd/scanner/'
            }
        }

        stage('Security Scan') {
            steps {
                sh './inkog-scanner . --output json --format inkog-findings.json'
            }
        }

        stage('Analyze Results') {
            steps {
                script {
                    def findings = readJSON file: 'inkog-findings.json'
                    if (findings.criticalCount > 0) {
                        error("Critical vulnerabilities found!")
                    }
                }
            }
        }
    }
}
```

### Option 4: Cloud Deployment

**AWS Lambda:**
```bash
# Package for Lambda
zip function.zip inkog-scanner

# Deploy
aws lambda create-function \
  --function-name inkog-scanner \
  --runtime go1.x \
  --zip-file fileb://function.zip \
  --handler main
```

**GCP Cloud Functions:**
```bash
# Deploy
gcloud functions deploy inkog-scanner \
  --runtime go121 \
  --trigger-http \
  --allow-unauthenticated
```

---

## Configuration

### Command-Line Options

```bash
./inkog-scanner [OPTIONS] [PATH]

Options:
  -h, --help              Show help message
  -v, --version           Show version
  -o, --output FORMAT     Output format: text, json, sarif, csv
  -f, --format FILE       Save findings to file
  --strict                Fail on HIGH/CRITICAL (exit code 1)
  --patterns LIST         Only check specific patterns (comma-separated)
  --exclude PATTERNS      Exclude patterns (comma-separated)
  --max-findings N        Stop after N findings
  --min-confidence SCORE  Only report findings >= confidence score
  --timeout SECONDS       Timeout per file (default: 30s)
  --threads N             Number of parallel threads
  --no-colors             Disable colored output

Examples:
  # Basic scan
  ./inkog-scanner /path/to/code

  # Scan specific patterns only
  ./inkog-scanner /path/to/code --patterns token_bombing,recursive_calling

  # Fail on findings
  ./inkog-scanner /path/to/code --strict

  # JSON output
  ./inkog-scanner /path/to/code --output json --format results.json
```

### Configuration File

**File:** `.inkog.yaml`

```yaml
# Inkog Configuration
version: "1.0"

# Patterns to enable (default: all)
patterns:
  enabled:
    - hardcoded_credentials
    - prompt_injection
    - infinite_loop
    - unsafe_env_access
    - token_bombing
    - recursive_tool_calling
  disabled: []

# Severity threshold
severity:
  fail_on: HIGH  # Fail build if CRITICAL or HIGH found
  report: MEDIUM # Report all findings >= MEDIUM

# Confidence threshold
confidence:
  minimum: 0.70  # Only report findings >= 70% confidence

# Exclusions
exclusions:
  paths:
    - node_modules/
    - vendor/
    - .git/
    - __pycache__/
  files:
    - "*.test.py"
    - "*_test.go"
    - "*.spec.js"

# Output
output:
  format: json
  file: inkog-findings.json
  colors: true

# Scanning options
scan:
  timeout: 30        # Seconds per file
  max_findings: 0    # 0 = unlimited
  parallel: 4        # Number of threads
```

---

## Integration Examples

### Integration with Pre-Commit Hooks

**File:** `.pre-commit-config.yaml`

```yaml
repos:
  - repo: https://github.com/inkog-io/inkog
    rev: v1.0
    hooks:
      - id: inkog-scanner
        name: Inkog Security Scanner
        entry: inkog-scanner
        language: go
        types: [python, javascript, go]
        stages: [commit]
```

### Integration with SonarQube

**Plugin:** `sonar-inkog-plugin`

```xml
<!-- pom.xml -->
<plugin>
    <groupId>io.inkog</groupId>
    <artifactId>sonar-inkog-plugin</artifactId>
    <version>1.0</version>
</plugin>
```

### Integration with IDE

**VSCode Extension:** `inkog-security`

```json
{
  "inkog.enabled": true,
  "inkog.scanOnSave": true,
  "inkog.patterns": ["all"],
  "inkog.severityThreshold": "MEDIUM"
}
```

---

## Monitoring & Alerting

### Metrics to Track

**Scanner Metrics:**
- Scans per day
- Average scan duration
- Files scanned per scan
- Findings per scan

**Finding Metrics:**
- CRITICAL findings count
- HIGH findings count
- False positive rate
- Time to remediation

### Alert Conditions

```yaml
alerts:
  - name: "Critical Vulnerability"
    condition: findings.critical > 0
    action: notify_security_team

  - name: "Scan Failure"
    condition: scan_status == FAILED
    action: notify_devops

  - name: "Performance Degradation"
    condition: avg_scan_duration > 2m
    action: investigate_scanner
```

### Dashboards

**Grafana Dashboard:**
```json
{
  "dashboard": {
    "title": "Inkog Security Scanner",
    "panels": [
      {
        "title": "Findings by Severity",
        "targets": [
          {"expr": "inkog_findings{severity=~\"CRITICAL|HIGH\"}"}
        ]
      },
      {
        "title": "Scan Duration Trend",
        "targets": [
          {"expr": "inkog_scan_duration_seconds"}
        ]
      }
    ]
  }
}
```

---

## Troubleshooting

### Common Issues

**Issue: Scanner crashes on large file**
```bash
# Solution: Increase timeout
./inkog-scanner /path --timeout 120
```

**Issue: High false positive rate**
```bash
# Solution: Increase confidence threshold
./inkog-scanner /path --min-confidence 0.85
```

**Issue: Scanner is slow**
```bash
# Solution: Increase parallelism
./inkog-scanner /path --threads 8
```

**Issue: Out of memory**
```bash
# Solution: Set memory limit and reduce parallelism
ulimit -m 2097152  # 2GB
./inkog-scanner /path --threads 2
```

### Debug Mode

```bash
# Enable debug logging
INKOG_DEBUG=1 ./inkog-scanner /path

# Verbose output
./inkog-scanner /path -v -v -v

# Profile CPU
./inkog-scanner /path --cpu-profile cpu.prof
go tool pprof cpu.prof
```

---

## Performance Optimization

### Scanning Large Codebases

**Divide and Conquer:**
```bash
# Scan directories in parallel
for dir in src tests lib; do
    ./inkog-scanner $dir --output json --format $dir.json &
done
wait

# Merge results
jq -s 'map(.findings) | add' *.json > all_findings.json
```

**Exclude Non-Code Files:**
```yaml
# .inkog.yaml
exclusions:
  paths:
    - node_modules/
    - vendor/
    - dist/
    - build/
    - .git/
    - .venv/
```

**Use Caching:**
```bash
# Cache compiled patterns
export INKOG_CACHE=/tmp/inkog_cache
./inkog-scanner /path  # First run: slow
./inkog-scanner /path  # Subsequent runs: fast
```

---

## Integration Checklist

```
DEPLOYMENT SETUP
☐ Binary built for target platform
☐ Configuration file created (.inkog.yaml)
☐ CI/CD pipeline configured
☐ Secrets management set up (API keys, credentials)
☐ Log aggregation configured

INTEGRATION
☐ Scanner integrated in development workflow
☐ Pre-commit hooks set up (optional)
☐ IDE extension installed (optional)
☐ Security dashboard created
☐ Alert system configured

TESTING
☐ Scan test codebase successfully
☐ False positives verified and handled
☐ Performance tested on target codebase
☐ Timeout and resource limits verified
☐ Edge cases tested (empty files, large files, etc.)

MONITORING
☐ Metrics exported to monitoring system
☐ Dashboards created
☐ Alerts configured for critical findings
☐ Baseline established for trending
☐ Remediation SLAs defined

DOCUMENTATION
☐ Deployment guide written for team
☐ Configuration documented
☐ Troubleshooting guide created
☐ Example outputs provided
☐ Integration patterns documented

MAINTENANCE
☐ Update strategy defined
☐ Rollback plan prepared
☐ Support channels established
☐ Regular health checks scheduled
☐ Performance monitoring active
```

---

## Enterprise Deployment

### Inkog Enterprise Features

**Available:**
- ✅ Multi-tenant scanning
- ✅ Central dashboard
- ✅ RBAC (role-based access control)
- ✅ Audit logging
- ✅ Custom patterns
- ✅ API access
- ✅ Integration with SIEM

**Enterprise Deployment:**

```bash
# License activation
inkog-scanner --license-file enterprise.lic

# Multi-tenant configuration
inkog-scanner --tenant prod --vault /secure/vault

# Custom patterns
inkog-scanner --custom-patterns /etc/inkog/patterns/

# API server
inkog-api --port 8080 --workers 4
```

### High Availability Setup

**Kubernetes Deployment:**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: inkog-scanner
spec:
  replicas: 3
  selector:
    matchLabels:
      app: inkog-scanner
  template:
    metadata:
      labels:
        app: inkog-scanner
    spec:
      containers:
      - name: inkog-scanner
        image: inkog:1.0
        resources:
          requests:
            memory: "256Mi"
            cpu: "500m"
          limits:
            memory: "512Mi"
            cpu: "1000m"
        env:
        - name: INKOG_WORKERS
          value: "4"
        - name: INKOG_TIMEOUT
          value: "30"
```

---

## Support & Documentation

**Resources:**
- Documentation: https://docs.inkog.io
- API Reference: https://api.inkog.io/docs
- Community: https://github.com/inkog-io/inkog/discussions
- Issues: https://github.com/inkog-io/inkog/issues
- Enterprise Support: support@inkog.io

---

## Compliance

### Standards Compliance

- ✅ OWASP Top 10 coverage
- ✅ CWE/CVE aligned
- ✅ GDPR data protection
- ✅ SOC 2 audit ready
- ✅ Enterprise security standards

### Audit & Reporting

```bash
# Generate audit report
./inkog-scanner /path --audit-report

# Export for compliance tools
./inkog-scanner /path --output sarif > findings.sarif
./inkog-scanner /path --output cyclonedx > sbom.xml
```

---

## Summary

This guide covers deploying Inkog for:
- ✅ Standalone use
- ✅ CI/CD integration
- ✅ Container deployment
- ✅ Cloud platforms
- ✅ Enterprise systems

Key takeaways:
1. **Configure properly** - Use .inkog.yaml for consistent behavior
2. **Integrate early** - Add to CI/CD before production
3. **Monitor actively** - Track metrics and set up alerts
4. **Optimize performance** - Use caching, parallelism, exclusions
5. **Maintain regularly** - Keep scanner updated, review findings

For detailed support, visit https://docs.inkog.io

---

**Version:** 1.0
**Last Updated:** November 12, 2025
**Status:** Ready for Production
