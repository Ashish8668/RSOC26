# APIGuard Technical Documentation

## 1) Project Objective
APIGuard is an automated API security scanner designed to find high-impact API vulnerabilities before deployment or abuse.  
It supports both:
- Offensive validation on an intentionally vulnerable target (`vulnerable-api`)
- Defensive validation on a hardened target (`safe-api`)

Primary goal in demo and real workflow:
- Discover endpoints quickly
- Run focused security checks
- Produce actionable, explainable findings with severity, CVSS-style score, confidence, and remediation

---

## 2) High-Level Architecture

## 2.1 Components
- `scanner/client` (React): UI for scan input, live progress, findings, filters, diff view, and report export
- `scanner/server` (Node/Express): orchestration, detection engine, parser, scoring, storage, report APIs
- `vulnerable-api` (Node/Express + SQLite): intentionally insecure target for exploitation demos
- `safe-api` (Node/Express + SQLite): hardened target to prove controls work

## 2.2 Data/Control Flow
1. User starts scan from UI or API (`/api/scan/start`)
2. Backend parser converts input into endpoint inventory
3. Scan engine executes detection modules in sequence
4. Findings are normalized (severity, CVSS, confidence, vector, remediation)
5. Findings + scan activity are persisted (Firebase Admin or in-memory fallback)
6. UI polls scan status and streams findings/activity
7. Report APIs build executive summary + detailed evidence

---

## 3) Input Parser (On-Ramp)

APIGuard accepts multiple formats for judge-friendly demos:
- Base URL crawl (auto endpoint discovery)
- OpenAPI/Swagger JSON
- OpenAPI YAML
- Postman collection JSON
- Raw `curl` commands

## 3.1 Detection-Ready Parsing Output
All input types are normalized into a common endpoint schema:
- `method`
- `url`
- `path`
- `name`
- `pathParams`
- `body`
- `headers`

This normalization is critical because every detection module consumes the same endpoint structure.

## 3.2 Why this matters
It removes dependency on a single source format and lets teams scan APIs at any maturity level:
- No docs available -> crawl
- Spec-first teams -> OpenAPI
- QA teams -> Postman
- Manual tester -> raw curl

---

## 4) Security Detection Modules

Each module returns structured findings:
- `type`
- `severity`
- `cvss_score`
- `cvss_vector`
- `confidence`
- `owasp`
- `title/description`
- `evidence`
- `replay` (request + insecure response + expected secure response)
- `remediation`

## 4.1 Module A: BOLA / Broken Object Level Authorization (OWASP API1)

### What is tested
- Horizontal access control: user A accessing user B objects by ID tampering
- Vertical privilege check: normal token reaching admin-like endpoint

### Detection mechanism
1. Find endpoints containing numeric object IDs (`/users/1`, `/orders/1`)
2. Replay same authenticated context with mutated IDs (`1 -> 2 -> 3`)
3. Compare responses
4. Flag if unauthorized object data is returned (`200` + different resource)

### Why a finding is raised
- Ownership check missing or inconsistent
- Role checks missing on privileged routes

### Expected secure behavior
- `403 Forbidden` for unauthorized object

---

## 4.2 Module B: Authentication & JWT Security (OWASP API2)

### What is tested
- Missing token handling
- Expired/malformed token rejection
- JWT `alg:none` acceptance
- JWT algorithm confusion behavior
- Sensitive endpoint exposure without proper auth

### Detection mechanism
1. Probe protected-looking endpoints (`/users`, `/orders`, `/admin`, `/profile`)
2. Send:
- no token
- malformed token
- crafted `alg:none` token
- crafted confusion-style token
3. Validate expected enforcement (`401/403`)
4. Flag endpoints that still return business data

### Why a finding is raised
- Signature validation bypass
- Weak middleware
- Missing auth on critical endpoints

### Expected secure behavior
- Missing/invalid token -> `401`
- Authenticated but unauthorized -> `403`

---

## 4.3 Module C: Rate Limiting (OWASP API4)

### What is tested
- Burst request handling (50-100 requests)
- Login brute-force resilience
- Effective throttle threshold and measured RPS

### Detection mechanism
1. Choose high-risk endpoints (especially login/auth)
2. Fire rapid burst requests
3. Track status code distribution (`200/401/429/503`)
4. Compute:
- accepted count
- blocked count
- measured RPS
- request index where throttling begins

### Why a finding is raised
- No throttling responses despite heavy burst
- Throttling starts too late for real protection

### Expected secure behavior
- `429 Too Many Requests` under abuse

---

## 4.4 Module D: Sensitive Data Exposure (OWASP API3)

### What is tested
- PII/secrets in API responses
- Excessive data returned beyond requested scope

### Detection mechanism
Regex-based response scanning for:
- emails
- phone numbers
- SSNs
- credit card patterns
- AWS key format (`AKIA...`)
- private key blocks (`BEGIN PRIVATE KEY`)
- password-like JSON fields
- internal IP patterns

Additional behavior check:
- request limited fields (`fields=id`) and detect over-returned properties

### Why a finding is raised
- Data minimization not enforced
- serializer/DTO not applied
- internal or secret material exposed

### Expected secure behavior
- strict field whitelisting
- no secret/PII in generic responses

---

## 4.5 Module E: Injection & Misconfiguration (OWASP API8)

### Injection checks
- SQLi payloads (`'`, `1=1--`, union probes)
- Error leakage and query behavior anomalies
- SSRF probes via URL-like parameters (`169.254.169.254`)

### Misconfiguration checks
- Active CORS probe with `Origin: https://evil.com`
- Security header presence checks:
- `X-Content-Type-Options`
- `Strict-Transport-Security`
- `X-Frame-Options`
- `Content-Security-Policy`

### Why a finding is raised
- User input changes SQL behavior or leaks DB errors
- Service attempts internal metadata fetch
- CORS too permissive
- Security headers missing

### Expected secure behavior
- parameterized SQL
- SSRF allowlist + private-range block
- strict CORS allowlist
- baseline security headers

---

## 5) Risk Scoring and Prioritization

## 5.1 Severity
- `critical`, `high`, `medium`, `low`, `info`

## 5.2 CVSS-style score (0-10)
- Modules set scores directly for known patterns
- Engine fallback applies severity-based CVSS defaults if missing

## 5.3 CVSS vector
- Each finding has a vector string (type-based mapping/fallback)
- Example format: `CVSS:3.1/AV:N/AC:L/...`

## 5.4 Confidence
- `Confirmed`, `Likely`, `Possible`
- Assigned using evidence quality and response behavior

## 5.5 Why this helps judges/teams
- Not just “issue found”
- Gives impact + certainty + remediation priority

---

## 6) AI-Powered Remediation

## 6.1 Flow
1. Scanner creates raw finding
2. Finding context is sent to LLM (Groq endpoint)
3. Concise code-focused remediation is generated
4. Fallback to static remediation if LLM unavailable

## 6.2 Output style
- Practical, implementation-ready guidance
- Usually includes exact Node/Express fix direction

---

## 7) Dashboard and Reporting Workflow

## 7.1 Live scanning UX
- Scan progress bar by module
- Live activity feed
- Findings list sorted by severity
- Severity + type filters

## 7.2 Forensic explainability
- Evidence tab: structured evidence object
- Diff tab:
- insecure/actual response
- expected secure response
- triggering request replay details

## 7.3 Report outputs
- Executive summary (risk score, counts, confidence distribution)
- Detailed findings
- Recommendation list
- Export:
- HTML report endpoint
- Browser print/save as PDF

---

## 8) Storage and Persistence

## 8.1 Modes
- `firebase-admin`: persistent scans/findings in Firestore
- `memory`: fallback when admin creds are not configured

## 8.2 Why fallback exists
- Guarantees demo continuity even without cloud setup
- Avoids hard dependency failures during hackathon presentation

---

## 9) Security Standards and Mapping

## 9.1 OWASP API Security Top 10 (2023) mapping
- API1: BOLA
- API2: Broken Authentication/JWT
- API3: Sensitive Data/Property Exposure
- API4: Unrestricted Resource Consumption
- API8: Security Misconfiguration, Injection-adjacent checks

## 9.2 CVSS usage
- Numeric impact scale for prioritization
- Vector shown for technical context

## 9.3 Secure coding patterns demonstrated (safe-api)
- JWT verification with allowed algorithms
- RBAC + ownership checks
- rate limiting
- security headers
- parameterized SQL
- SSRF policy
- response minimization

---

## 10) End-to-End Detection Lifecycle (Per Finding)
1. Endpoint discovered by parser
2. Module executes probe payload/request variant
3. Response observed and compared against expected secure behavior
4. Finding created with evidence/replay
5. Severity + CVSS + vector + confidence normalized
6. AI/static remediation attached
7. Finding persisted and streamed to dashboard
8. Included in final report

---

## 11) Demo-Round “What can be asked” Preparation

## 11.1 Common judge questions and concise answers

### Q: How do you avoid false positives?
- We use behavior-driven checks (status + content + differential comparison), confidence labels, and replay evidence.

### Q: How is this different from static linting?
- We actively execute requests against live endpoints and validate runtime security behavior.

### Q: How do you prove vulnerability impact?
- Diff view shows actual insecure response vs expected secure response for the exact triggering request.

### Q: Can this work in CI/CD?
- Scanner backend already supports programmatic invocation and structured findings. (CLI workflow extension can be layered easily.)

### Q: What if OpenAPI is missing?
- Base URL crawl and raw curl ingestion provide non-spec fallback.

### Q: How do you prioritize fixes?
- Severity + CVSS-style score + confidence + one-line remediation.

---

## 12) Known Limits (Transparent Engineering)
- This is a focused API scanner, not a full dynamic web app pentest suite.
- Some advanced attack classes require environment-specific payload tuning.
- Confidence model is heuristic-based, not human-reviewed triage.
- CVSS vectors are standardized mappings, not complete per-case analyst vectors.

---

## 13) Future Enhancements
- Native CLI (`--fail-on critical`) for strict CI gating
- Scheduled continuous scanning
- Tenant-aware auth flow support (OAuth/OIDC token minting)
- Plugin system for custom org-specific checks
- Full CVSS vector calculator from granular metrics

---

## 14) Practical Demo Flow (Recommended)
1. Start `vulnerable-api`, `safe-api`, scanner backend, scanner frontend
2. Manually prove 2-3 vulnerabilities on vulnerable target (BOLA + admin access + data leak)
3. Run scan on vulnerable target (`http://localhost:3001`)
4. Show live findings + diff + report
5. Run scan on safe target (`http://localhost:3002`)
6. Show improved posture (fewer critical findings, correct status codes)
7. Close with standards mapping and remediation workflow

This gives a complete “problem -> detection -> proof -> fix validation” story.
