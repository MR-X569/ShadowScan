# Backend Architecture Specification

## 1. Overview

The ShadowScan backend is built with **FastAPI** (Python 3.12) following a layered architecture designed to cleanly separate HTTP routing, business logic, persistence, security scanning orchestration, and AI intelligence.

---

## 2. Layered Structure

```text
┌────────────────────────────────────────────────────────┐
│                      API Layer                         │
│   (FastAPI Routers: /auth, /users, /scans, /admin, /ai)│
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│                    Service Layer                       │
│ (AuthService, EmailVerificationService, ScanService,   │
│  AdminService, AIService, PDFReportService)            │
└──────────────┬───────────────────────────┬─────────────┘
               │                           │
┌──────────────▼──────────┐ ┌──────────────▼─────────────┐
│  Persistence / CRUD     │ │   Scanner & AI Engines     │
│ (SQLAlchemy, PostgreSQL,│ │ (ScannerEngine, Browser,   │
│  Alembic, Redis)        │ │  45 Plugins, SSRF, Ollama) │
└─────────────────────────┘ └────────────────────────────┘
```

### 2.1 API Layer (`app/api/v1/`)
Versioned REST endpoints handling request validation, dependency injection, and HTTP status codes:
- `auth.py`: Registration, email OTP verification, resend OTP, login, password reset, and Google OAuth.
- `users.py`: Profile retrieval and password change.
- `scans.py`: Scan initiation, scan listing, detailed findings lookup, and PDF report downloads.
- `admin.py`: Platform statistics, user enable/disable/delete management, global scan audits (gated by `get_current_admin`).
- `ai.py`: Ollama health status, scan risk analysis, individual finding explanations, and scan-scoped security chat.

### 2.2 Service Layer (`app/services/` & `app/ai/service.py`)
Encapsulates business rules and operational workflows:
- `AuthService`: Authentication, password hashing (`bcrypt`), JWT token generation, OAuth profile provisioning.
- `EmailVerificationService`: 6-digit OTP creation, 60s cooldown rate limiting, attempt tracking (max 5), account verification, and unverified account recovery.
- `ScanService`: Coordinates scan lifecycle, delegates execution to `ScannerEngine`, calculates risk scores, and manages findings persistence.
- `AdminService`: Aggregates platform-wide metrics and manages user account states.
- `AIService`: Sanitizes finding evidence, builds scan-scoped prompts, invokes Ollama (`llama3.2`), validates JSON structures, and provides offline fallbacks.
- `PDFReportService`: Compiles branded technical PDF vulnerability reports via ReportLab.

### 2.3 Scanning Layer (`app/scanner/`)
- `ScannerEngine`: Central orchestrator initializing target validation, HTTP client session (`httpx`), Playwright browser observation, and plugin dispatch.
- `BrowserScanner` (`browser.py`): Spawns isolated headless Chromium instances to execute client-side JavaScript, extract dynamic DOM, evaluate cookies/storage, and intercept network requests.
- `Plugins` (`plugins/passive/`): 45 specialized passive detection plugins inspecting static HTTP headers, rendered HTML, SSL certificates, cookies, CORS, and injection patterns.
- `ScanContext`: Shared in-memory data carrier passed sequentially across all plugins.

### 2.4 Security & SSRF Layer (`app/core/ssrf.py`)
Multi-tier pre-flight target validation and runtime route interception:
- Resolves DNS and blocks loopback (`127.0.0.0/8`), `0.0.0.0`, private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`), IPv6 loopback (`::1`), and cloud metadata IP (`169.254.169.254`).
- Intercepts all subresource requests inside the Playwright browser.

---

## 3. Core Execution Flow

```text
User Submits Target URL
         │
         ▼
[1] SSRF Pre-Flight Validation (Protocol & IP filtering)
         │
         ▼
[2] Scan Record Created in PostgreSQL (Status: RUNNING)
         │
         ▼
[3] Static HTTP Fetch (Status code, headers, initial HTML)
         │
         ▼
[4] Playwright Browser Observation (Chromium renders page, extracts DOM/forms)
         │
         ▼
[5] 45 Passive Plugins Executed against ScanContext
         │
         ▼
[6] Findings Persisted in PostgreSQL & Risk Score Computed
         │
         ▼
[7] Scan Status Updated (Status: COMPLETED)
         │
         ▼
[8] Interactive Results, PDF Report & AI Analyst Available
```

---

## 4. Database Schema & Migration Architecture

Managed via **Alembic** (Current head: `682a0b12cd34`):
- `users`: User profiles, hashed credentials, roles (`USER`, `ADMIN`), active and verification flags.
- `email_verifications`: 6-digit OTP codes, purpose (`EMAIL_VERIFICATION`, `PASSWORD_RESET`), attempt counters, expiration, and server defaults.
- `scans`: Target URL, scan status (`PENDING`, `RUNNING`, `COMPLETED`, `FAILED`), risk scores, timestamps, cascading foreign keys.
- `findings`: Vulnerability names, plugins, severities (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), descriptions, remediation steps, and evidence.
