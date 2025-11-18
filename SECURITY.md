# Security Policy

This document describes how the Inkog project handles security vulnerabilities and how to responsibly report them.

## Supported Versions

| Version | Supported | Notes |
|---------|-----------|-------|
| 1.0.x   | ✅ Yes    | Current release |
| 0.9.x   | ✅ Yes    | Previous stable |
| < 0.9.0 | ❌ No     | End of life |

## Reporting Security Vulnerabilities

**Please do not file public issues for security vulnerabilities.**

### Disclosure Process

1. **Email Report**
   - Send details to: `security@inkog.io`
   - Use PGP encryption if possible (see below)
   - Include reproduction steps if applicable

2. **Initial Response**
   - We acknowledge receipt within 48 hours
   - We provide a timeline for addressing the issue
   - We may request additional information

3. **Fix Development**
   - We develop and test the fix
   - We create a security patch release
   - Typical timeline: 7-14 days depending on severity

4. **Disclosure**
   - We announce the fix via GitHub Security Advisory
   - We credit the reporter (unless requested otherwise)
   - We release the patched version publicly

### Vulnerability Email Template

```
Subject: Security Vulnerability Report - [Brief Description]

Severity: CRITICAL | HIGH | MEDIUM | LOW
Affected Version(s): [version numbers]

## Description
[Detailed description of the vulnerability]

## Reproduction Steps
1. [Step 1]
2. [Step 2]
...

## Expected Behavior
[What should happen]

## Actual Behavior
[What actually happens]

## Impact
[Who is affected and what's the impact]

## Timeline
[Any relevant timeline constraints]
```

### Responsible Disclosure Guidelines

1. **Give us reasonable time** to fix before public disclosure (typically 90 days)
2. **Report only to us** - don't share with others until coordinated
3. **Don't exploit** beyond understanding the vulnerability
4. **Test on your own system** - not production systems you don't own
5. **Document clearly** - help us understand the issue quickly

## Security Best Practices

### For Inkog Users

1. **Keep Inkog Updated**
   - Run `go get -u github.com/inkog-io/inkog` regularly
   - Subscribe to GitHub releases

2. **Review Scan Results**
   - Don't ignore CRITICAL findings
   - Understand false positives in your context
   - Use high risk threshold in production

3. **Secure Your Agents**
   - Follow the remediation suggestions
   - Use environment variables for secrets
   - Implement proper error handling
   - Add rate limiting to API calls

### For Inkog Contributors

1. **Code Review**
   - All changes go through code review
   - Security-sensitive code gets extra scrutiny
   - Tests required for bug fixes

2. **Dependency Management**
   - Keep Go and dependencies current
   - Run `go mod audit` regularly
   - Report supply chain issues immediately

3. **Secure Development**
   - Never commit secrets
   - Use `.gitignore` for local files
   - Sign commits with GPG when possible

## Known Security Considerations

### Limitations

1. **Pattern-Based Detection**
   - Inkog detects patterns, not actual exploits
   - May miss novel attack vectors
   - False positives possible in edge cases

2. **AST-Based Analysis**
   - Limited to syntactic patterns
   - Cannot perform full semantic analysis
   - Cannot track runtime behavior

3. **Supported Languages**
   - Currently: Python, JavaScript, TypeScript, Go
   - Dialects and extensions may not be fully supported
   - Unsupported syntax may cause analysis gaps

### What Inkog Doesn't Do

- ❌ Execute your agent code
- ❌ Access remote systems
- ❌ Store your code
- ❌ Require credentials
- ❌ Modify your code automatically

### Recommended Complements

Inkog is a **pre-deployment scanner**, not a complete security solution. Combine with:

- **SAST Tools**: SonarQube, Semgrep for additional patterns
- **DAST Tools**: Dynamic testing in staging environments
- **Runtime Monitoring**: APM and security monitoring in production
- **Code Review**: Manual review by security team
- **Threat Modeling**: Identify risks before development

## Security Update Policy

### Release Cycles

- **Security Patches**: Released as soon as ready
- **Minor Updates**: Monthly (if changes warrant)
- **Major Updates**: Quarterly or as needed
- **Emergency**: Critical issues get 24-48 hour turnaround

### Announcement Channels

1. **GitHub Security Advisories** (recommended)
2. **GitHub Releases** (all updates)
3. **Email notification** (opt-in, coming soon)

## Compliance

Inkog is designed with security in mind:

- ✅ No code execution (static analysis only)
- ✅ No data transmission (local scanning)
- ✅ No credential storage
- ✅ Open source (transparent security)
- ✅ MIT Licensed (community auditable)

### Standards & Frameworks

- **OWASP Top 10**: Detects common vulnerabilities
- **CWE/CVSS**: Industry-standard risk scoring
- **EU AI Act**: Compliance-ready logging
- **SANS Top 25**: Coverage of dangerous patterns

## Contact

- **Security Issues**: `security@inkog.io`
- **General Questions**: Open an issue on GitHub
- **Feature Requests**: Check ROADMAP.md
- **Questions**: See CONTRIBUTING.md

## Changelog

Security fixes are documented in [CHANGELOG.md](CHANGELOG.md) with clear indicators of security-related updates.

---

**Thank you for helping keep Inkog secure.** 🛡️

_Last Updated: November 17, 2024_
