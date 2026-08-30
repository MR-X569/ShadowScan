# ShadowScan — AI-Assisted Web Vulnerability Scanner

ShadowScan is a modern, full-stack web vulnerability scanner that combines static HTTP analysis, headless browser-driven DOM inspection, 45 passive security plugins, SSRF defense-in-depth, and an integrated local AI Security Analyst powered by Ollama (`llama3.2`).

---

## Key Capabilities

- **Hybrid Scanning Pipeline**: Combines raw HTTP client requests with Playwright-based headless Chromium page rendering.
- **45 Passive Security Plugins**: Automated discovery and execution across headers, SSL/TLS, cookies, CORS, SSRF, XSS, prototype pollution, injection patterns, and information disclosure.
- **Runtime Browser Observation**: Renders JavaScript single-page applications, inspects dynamic DOM structures, intercepts network traffic, extracts form inputs, and records client storage.
- **SSRF Defense-in-Depth**: Multi-tier protection preventing unauthorized requests to private IP ranges, loopback addresses, link-local subnets, cloud metadata endpoints (`169.254.169.254`), and non-HTTP protocols.
- **AI Security Analyst (Ollama-backed)**: Scan-scoped interactive security chat and deep finding explanation using local LLM inference (`llama3.2`), featuring automated fallback when Ollama is offline.
- **Authentication & Email OTP Lifecycle**: Secure user registration with 6-digit OTP email verification, 60-second resend rate limiting, unverified account recovery, JWT session management, and optional Google OAuth.
- **Role-Based Admin Console**: Administrative oversight for platform statistics, user management, and global scan audit logs.
- **PDF Report Generation**: Server-side branded executive summaries and detailed technical finding reports using ReportLab.
- **Production-Hardened Deployment**: Multi-stage Dockerfiles, unprivileged non-root execution (`shadowscan`), read-only root filesystems, memory-bounded `tmpfs` mounts, and Docker Compose network isolation.

---

## Architecture Overview

```
                      [ Client Browser / UI ]
                                 │
                                 ▼ (HTTP / Port 80)
                      ┌──────────────────────┐
                      │   Nginx (Frontend)   │  (edge network)
                      └──────────┬───────────┘
                                 │ /api/* (Reverse Proxy)
                                 ▼
                      ┌──────────────────────┐
                      │   FastAPI Backend    │  (edge + data networks)
                      └──────────┬───────────┘
                                 │
         ┌───────────────────────┼───────────────────────┐
         ▼ (data network)        ▼ (data network)        ▼ (private host/network)
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  PostgreSQL 16  │     │    Redis 7.4    │     │  Ollama Server  │
│ (Alembic Head)  │     │ (Cache / Queue) │     │   (llama3.2)    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

### 1. Backend Service (`backend/`)
Built with **FastAPI** (Python 3.12) following a layered architecture:
- `app/api/v1/`: Versioned REST endpoints (`/auth`, `/users`, `/scans`, `/admin`, `/ai`).
- `app/scanner/`: Modular scanning engine orchestrating target validation, HTTP fetching, Playwright browser observation, and plugin execution.
- `app/scanner/plugins/passive/`: 45 specialized passive detection plugins.
- `app/ai/`: Ollama client integration, sanitized prompt engineering, and fail-safe fallbacks.
- `app/services/`: Business logic layer for authentication, email verification, scan coordination, admin reporting, and PDF compilation.
- `app/models/` & `app/schemas/`: SQLAlchemy database models and Pydantic validation schemas.

### 2. Frontend Web Application (`frontend/`)
Single-page application built with **React 19**, **TypeScript**, **Vite**, and **Tailwind CSS**:
- Interactive dashboard for submitting scans, monitoring status, and reviewing vulnerability distributions.
- Real-time finding inspector with severity filtering and remediation guidance.
- AI Security Analyst consultation panel scoped to individual scan contexts.
- Full authentication views: registration, OTP verification with resend cooldown timers, login, password recovery, and admin management.

---

## Playwright Browser Scanning Engine

In ShadowScan, **Playwright is an integral part of the application's runtime scanning engine**, not merely a test runner.

When a scan is initiated:
1. **Isolated Browser Context**: A dedicated headless Chromium process and fresh `BrowserContext` are spawned for the scan.
2. **Dynamic SPA Execution**: Renders client-side JavaScript, waiting for DOM settlement within bounded timeouts.
3. **DOM & Asset Extraction**: Captures the fully rendered DOM, document title, final redirected URL, forms, scripts, links, and cookie security flags.
4. **Context Injection**: The rendered HTML is merged into `ScanContext.html` so that downstream plugins (e.g., DOM-based XSS, Form Action Hijacking, SRI integrity) inspect dynamically generated elements without plugin refactoring.
5. **Runtime Route Interception**: Playwright routes intercept every subresource request (images, fetch, XHR, iframes). Prohibited or internal IP destinations are blocked before execution.
6. **Deterministic Resource Cleanup**: Unconditional `finally` blocks guarantee browser pages, contexts, and Chromium child processes are terminated immediately upon scan completion or timeout.

---

## Defense-in-Depth SSRF Protection

ShadowScan protects internal infrastructure against Server-Side Request Forgery (SSRF) through a two-tiered defense model:

1. **Pre-Flight Target Validation (`app/core/ssrf.py`)**:
   - Resolves target hostnames and verifies IP addresses against prohibited CIDR ranges.
   - Blocks IPv4 loopback (`127.0.0.0/8`), `0.0.0.0`, private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`), IPv6 loopback (`::1`), and cloud provider metadata IPs (`169.254.169.254`).
   - Enforces strict protocol schemes (`http://` and `https://` only; rejects `file://`, `ftp://`, `gopher://`).
2. **Browser Network Interception (`app/scanner/browser.py`)**:
   - Playwright route handlers validate every outbound request generated by the rendered page.
   - Any client-side script attempting to contact private endpoints is aborted before transmission and recorded as a security finding (`Browser request blocked by SSRF protection`).

---

## Authentication & Email Verification Lifecycle

- **Registration**: Creates an unverified user account (`is_verified = False`) and generates a 6-digit cryptographic OTP.
- **Email Delivery**: Dispatches OTP via SMTP (STARTTLS) with a 5-minute expiration.
- **Resend Cooldown**: Rate limits resend requests with a 60-second cooldown (`RESEND_COOLDOWN_SECONDS = 60`), returning `HTTP 429` on spam attempts.
- **Lockout Protection**: Limits incorrect OTP verification attempts to 5 before locking out the code.
- **Unverified Account Recovery**: If registration is repeated with an existing unverified email, the system safely updates account credentials, supersedes old OTPs, and sends a fresh code without throwing duplicate account errors.
- **Duplicate Protection**: Verified accounts are strictly protected from re-registration (`HTTP 400: Email already exists`).
- **Session Security**: Authenticated sessions use signed JWT bearer tokens (`HS256`) with configurable expiration.

---

## AI Security Analyst (Ollama Integration)

ShadowScan integrates local Large Language Models via **Ollama** (`llama3.2` by default):

- **Scan-Scoped Security Chat (`POST /api/v1/scans/{id}/ai/chat`)**: Multi-turn conversational interface providing context-aware remediation roadmaps and technical mitigation advice based on the scan's findings.
- **Finding Explanation (`POST /api/v1/scans/{id}/ai/findings/{fid}/explain`)**: Generates structured explanations of vulnerability impact, severity justification, and code-level fixes.
- **Off-Topic Refusal**: Fast deterministic filters immediately reject non-security queries.
- **Graceful Degradation**: If the Ollama daemon is offline or restarting, the API gracefully falls back to deterministic scanner findings data without interrupting core scanning or PDF generation.

---

## Environment Configuration

### Local Development (`backend/.env`)
```ini
DATABASE_URL=postgresql+psycopg://postgres:postgres@localhost:5432/shadowscan
SECRET_KEY=development-secret-key-change-in-production
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60

# SMTP Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_EMAIL=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM=ShadowScan

# AI Configuration (Ollama)
AI_ENABLED=true
AI_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2
OLLAMA_TIMEOUT=60.0

# Optional Google OAuth
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_REDIRECT_URI=http://localhost:8000/auth/google/callback
```

### Production Environment (`.env.production`)
Reference template available in `.env.production.example`:
```ini
POSTGRES_PASSWORD=replace-with-a-long-random-password
DATABASE_URL=postgresql+psycopg://shadowscan:replace-with-a-long-random-password@postgres:5432/shadowscan
SECRET_KEY=replace-with-a-long-random-secret
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60
FRONTEND_URL=https://scanner.example.com

# SMTP Configuration
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_EMAIL=noreply@example.com
SMTP_PASSWORD=replace-with-smtp-password
SMTP_FROM=ShadowScan

# AI Configuration
AI_ENABLED=true
AI_PROVIDER=ollama
OLLAMA_BASE_URL=http://your-private-ollama-host:11434
OLLAMA_MODEL=llama3.2
OLLAMA_TIMEOUT=60
```

---

## Local Development Quickstart

### Prerequisites
- Python 3.12+
- Node.js 20+ & npm
- PostgreSQL 16
- Redis 7+
- Ollama (optional for local AI features)

### 1. Database Setup
```bash
# PostgreSQL must be running on port 5432
psql -U postgres -c "CREATE DATABASE shadowscan;"
```

### 2. Backend Setup
```bash
cd backend
python -m venv ../venv
# On Windows:
..\venv\Scripts\activate
# On Linux/macOS:
source ../venv/bin/activate

pip install -r requirements.txt
python -m playwright install --with-deps chromium
alembic upgrade head
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### 3. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```
The application will be accessible at `http://localhost:5173`.

### 4. Local AI Setup (Optional)
```bash
# In a separate terminal
ollama serve
ollama pull llama3.2
```

---

## Testing & Quality Assurance

ShadowScan maintains a comprehensive test suite covering plugins, scanner orchestration, browser lifecycle, authentication, rate limiting, and AI fallbacks.

```bash
# Run all backend unit and integration tests (366 tests)
cd backend
python -m pytest tests

# Run specific test suites
python -m pytest tests/test_auth_verification_flow.py  # Authentication & OTP lifecycle
python -m pytest tests/test_browser_scanner.py          # Playwright Chromium scanner
python -m pytest tests/test_ssrf_protection.py         # SSRF validation & route interception
python -m pytest tests/test_ai_module.py               # AI Service & prompt sanitation
python -m pytest tests/test_ai_live_integration.py     # Live Ollama integration (auto-skipped if offline)

# Run frontend type-check & production build
cd frontend
npm run build
```

---

## Production Docker Deployment

Production deployment uses multi-container Docker Compose with network isolation and non-root execution.

### Deployment Steps
1. Copy `.env.production.example` to `.env.production` and populate strong production secrets.
2. Build and start the stack:
   ```bash
   docker compose up --build -d
   ```
3. Inspect running services and health checks:
   ```bash
   docker compose ps
   docker compose logs -f backend
   ```

### Architecture Highlights
- **Pre-baked Chromium**: The backend Docker image installs Playwright and Chromium dependencies at build time (`PLAYWRIGHT_BROWSERS_PATH=/ms-playwright`).
- **Zero Host Exposure for Data**: PostgreSQL and Redis are attached exclusively to the internal `data` network (`internal: true`).
- **Non-Root Containers**: Backend runs under UID `10001` (`shadowscan`); frontend runs on unprivileged Nginx (port `8080`).
- **External TLS**: Production HTTPS should be terminated at an external load balancer or reverse proxy (AWS ALB, Cloudflare, Traefik) routing to Nginx port `80`.

---

## Project Structure

```text
ShadowScan/
├── .dockerignore
├── .env.production.example
├── compose.yaml
├── LICENSE
├── README.md
├── backend/
│   ├── Dockerfile
│   ├── alembic.ini
│   ├── requirements.txt
│   ├── app/
│   │   ├── ai/               # Ollama client, prompts, redaction, and schemas
│   │   ├── api/v1/           # REST endpoints (auth, users, scans, admin, ai)
│   │   ├── core/             # Config, database session, enums, security, SSRF
│   │   ├── crud/             # SQLAlchemy database queries
│   │   ├── models/           # Database entity models
│   │   ├── scanner/          # Core engine, browser runner, and 45 plugins
│   │   ├── schemas/          # Pydantic request/response schemas
│   │   └── services/         # Business logic (auth, email, scans, PDF reports)
│   ├── migrations/           # Alembic database migration scripts
│   └── tests/                # 366 Pytest unit and integration tests
├── deployment/
│   ├── README.md             # Production operator deployment guide
│   └── nginx/
│       └── default.conf      # Nginx reverse proxy configuration
├── docs/                     # Architectural design specifications
└── frontend/
    ├── Dockerfile
    ├── package.json
    ├── tsconfig.json
    ├── vite.config.ts
    └── src/
        ├── components/       # Reusable UI components & modals
        ├── pages/            # View routes (Dashboard, Scans, Result, Admin, Auth)
        ├── routes/           # Protected routing and navigation
        └── services/         # Axios API clients
```

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
