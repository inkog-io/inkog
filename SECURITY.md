# Security Policy

We take security seriously. Inkog is a security tool, so we hold ourselves to the same standard we ask of our users.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.2.x   | :white_check_mark: |
| 1.1.x   | :white_check_mark: (security fixes only) |
| < 1.1   | :x:                |

We strongly recommend always running the latest minor release. Upgrade with `brew upgrade inkog`, `go install github.com/inkog-io/inkog/cmd/inkog@latest`, or pin a specific tag in your GitHub Action.

## Reporting a Vulnerability

**Please don't open a public GitHub issue for security reports.**

Two ways to report privately:

1. **GitHub Security Advisories** — preferred. Go to the [Security tab → Report a vulnerability](https://github.com/inkog-io/inkog/security/advisories/new). This is end-to-end encrypted with us.
2. **Email** — `security@inkog.io`. PGP available on request.

### What to include

- A clear description of the vulnerability
- Steps to reproduce (or proof-of-concept)
- Affected versions
- Potential impact
- Any suggested fixes (optional, but helpful)

### Response timeline

| Stage | Target |
|-------|--------|
| Initial acknowledgement | Within 48 hours |
| Triage and severity assessment | Within 7 days |
| Patch for critical issues | Within 30 days |
| Public advisory (after patch ships) | Within 90 days |

We'll keep you in the loop throughout.

## Safe Harbor

We will not pursue legal action against security researchers who:

- Report vulnerabilities in good faith
- Avoid accessing or modifying user data beyond what's necessary to demonstrate the issue
- Give us reasonable time (90 days, or sooner if we ship a patch faster) to respond before public disclosure
- Don't perform automated scanning that disrupts our service

## Scope

In scope:

- The Inkog CLI (`github.com/inkog-io/inkog`)
- The Inkog API (`api.inkog.io`)
- The Inkog Dashboard (`app.inkog.io`)
- The Inkog MCP server (`@inkog-io/mcp` on npm)
- The Inkog GitHub Action (`inkog-io/inkog`)

Out of scope:

- Social engineering and phishing
- Denial of service attacks
- Self-XSS and issues requiring physical access to a user's device
- Issues in third-party dependencies — please report those upstream first
- Vulnerabilities in unsupported versions (see table above)

## Recognition

With your permission, we'll credit you in the public advisory and the [security acknowledgments](https://inkog.io/security/acknowledgments). For high-impact reports we offer swag and, for qualifying reports, a bug bounty — reach out for details.

## Hardening This Repo

This repository runs Inkog against itself in CI, plus Dependabot for dependency updates and CodeQL-style scanning via GitHub's default setup. If you spot anything our own scans missed, we'd love to know — that's exactly the kind of finding we want to fix.
