# Inkog Architecture

## Overview

Inkog is a pre-deployment AI agent security scanner built with a focus on speed, accuracy, and compliance. This document describes the technical architecture.

## Core Components

### 1. Scanner CLI
- **Language:** Go
- **Startup Time:** 0.88ms (significantly faster than Python alternatives)
- **Function:** Analyzes agent code and dependencies for security risks
- **Input:** Agent source code, configuration files
- **Output:** Risk assessment report with mitigation recommendations

### 2. Parser Engine
- **Technology:** tree-sitter
- **Performance:** 36x faster than alternative parsing solutions
- **Capability:** Fast, accurate abstract syntax tree generation
- **Supported Languages:** Python, TypeScript, JavaScript, Go
- **Purpose:** Extract agent structure and dependencies for pattern matching

### 3. Pattern Detection System
- **Approach:** Rule-based behavioral analysis
- **Framework:** Extensible pattern library
- **Accuracy:** 96% on known vulnerability patterns
- **Categories:**
  - Prompt injection attacks
  - Infinite loops and resource exhaustion
  - Data exposure vulnerabilities
  - Unauthorized external service calls
  - Token limit bypasses
  - Unsafe model parameter configurations

### 4. Database
- **Technology:** PostgreSQL with JSONB
- **Purpose:** Store scan results, pattern definitions, and compliance reports
- **Data:** Risk assessments, audit logs, customer usage metrics
- **Scalability:** Horizontal scaling through read replicas

### 5. Isolation Layer
- **Container:** Docker
- **Sandbox:** gVisor for additional security
- **Purpose:** Safely execute pattern analysis without risk to host system
- **Benefit:** Prevents agent code from breaking out during analysis

## Deployment Architecture

### Current Phase: AWS Lambda
```
GitHub/GitLab → GitHub Action → Lambda Function → PostgreSQL
                                ↓
                           Scan Results
```

### Key Benefits
- Serverless scaling
- No infrastructure management
- Cost-efficient for variable workloads
- Fast cold start times (critical for GitHub Actions)

### Future: Kubernetes Support
- On-premise deployments
- Enterprise air-gapped environments
- Custom compliance requirements
- Higher concurrency needs

## Security Scanning Flow

```
1. Code Input
   └─ GitHub repository or artifact

2. Parser
   └─ Extract AST and dependencies using tree-sitter

3. Pattern Matching Engine
   └─ Compare against 50+ security patterns

4. Risk Assessment
   └─ Calculate risk score and severity levels

5. Report Generation
   └─ Create compliance reports (EU AI Act, etc.)

6. Output
   └─ GitHub Actions output, API response, or dashboard view
```

## API Design

### Future REST API Endpoints

```
POST /api/v1/scan
  Input: agent_code, framework, risk_threshold
  Output: risk_assessment, patterns_detected, recommendations

GET /api/v1/reports/:scan_id
  Output: detailed scan report with compliance data

POST /api/v1/patterns/custom
  Input: pattern_definition
  Output: pattern_id (for premium users)
```

## Data Flow

### Scan Submission
```
User Code → GitHub Action → Inkog Service → Parser → Pattern Engine → Assessment
```

### Results Storage
```
Assessment → PostgreSQL (encrypted) → Dashboard/Report Generation → User
```

## Performance Targets

- **Scan Duration:** < 10 seconds for typical agent code
- **Pattern Matching:** < 500ms for 50 patterns
- **Report Generation:** < 1 second
- **API Response Time:** < 500ms p95
- **System Startup:** 0.88ms

## Scalability Considerations

### Current (MVP)
- Single Lambda instance
- PostgreSQL single node
- ~1,000 scans/month capacity

### Phase 2
- Lambda auto-scaling
- PostgreSQL read replicas
- Redis caching for patterns
- ~100,000 scans/month capacity

### Phase 3
- Kubernetes clusters
- Multi-region deployment
- Advanced load balancing
- Enterprise concurrency support

## Security Principles

1. **No Code Execution:** Patterns are matched against AST, never executed
2. **Data Isolation:** Customer code never stored; only analysis results retained
3. **Compliance:** GDPR, SOC 2, EU AI Act ready
4. **Encryption:** All data in transit (TLS) and at rest (PostgreSQL encryption)
5. **Audit Logging:** Full trace of all scans and API calls

## Technology Choices Rationale

| Component | Choice | Why |
|-----------|--------|-----|
| Language | Go | 0.88ms startup, single binary, fast execution |
| Parser | tree-sitter | 36x faster, widely used, accurate ASTs |
| Database | PostgreSQL | JSONB for flexible schema, battle-tested, scalable |
| Isolation | Docker + gVisor | Defense in depth, proven security model |
| Infrastructure | Lambda | Serverless, auto-scaling, GitHub-friendly |

## Future Enhancements

- [ ] Machine learning pattern detection
- [ ] Custom policy framework
- [ ] Real-time monitoring for deployed agents
- [ ] Integration with Kubernetes admission controllers
- [ ] Supply chain security scanning
- [ ] Multi-language agent support expansion

---

For deployment instructions, see [SETUP.md](SETUP.md)
