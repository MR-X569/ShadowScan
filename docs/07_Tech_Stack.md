# Technology Stack Specification

## 1. Frontend Layer
- **Framework**: React 19
- **Build Tool**: Vite 6.4.3
- **Language**: TypeScript 5.8
- **Styling**: Tailwind CSS
- **Routing**: React Router 7
- **HTTP Client**: Axios (with JWT interceptors)
- **Icons**: Lucide React

---

## 2. Backend Layer
- **Framework**: FastAPI (Python 3.12, Uvicorn)
- **Data Validation & Settings**: Pydantic 2.x & Pydantic Settings
- **Async Runtime**: AnyIO / AsyncIO
- **HTTP Client**: HTTPX 0.28+ & Requests
- **HTML Parsing**: BeautifulSoup4 & lxml
- **PDF Compilation**: ReportLab 4.4+

---

## 3. Browser & Scanning Engine
- **Headless Browser**: Playwright 1.62.0 + Chromium
- **Execution Model**: Isolated `BrowserContext` with JavaScript rendering, dynamic DOM extraction, and cookie observation
- **Network Defense**: Custom SSRF DNS resolver and Playwright route interception
- **Plugin Architecture**: 45 passive security detection plugins

---

## 4. AI & Intelligence Layer
- **LLM Engine**: Ollama (`llama3.2:latest` / `3.2B parameters`)
- **Integration**: Async REST client (`/api/chat`, `/api/generate`, `/api/tags`) with prompt sanitization, JSON schema enforcement, and offline fallback degradation

---

## 5. Persistence & Caching
- **Primary Database**: PostgreSQL 16
- **Database Driver**: `psycopg` 3.3+ (binary)
- **ORM**: SQLAlchemy 2.0+
- **Migrations**: Alembic (head: `682a0b12cd34`)
- **Cache & Queue**: Redis 7.4 (Alpine)

---

## 6. Authentication & Security
- **Hashing**: Passlib & Bcrypt
- **Token Format**: JWT (JSON Web Tokens via `python-jose`, HS256)
- **Email Delivery**: SMTP with STARTTLS (Port 587)
- **OAuth**: Google Auth OAuthlib
- **Rate Limiting**: 60-second cooldown on OTP resend requests

---

## 7. Containerization & Deployment
- **Container Engine**: Docker & Docker Compose v2.20+
- **Web Server / Reverse Proxy**: Nginx 1.28 Unprivileged (Alpine)
- **Base Images**: `python:3.12-slim-bookworm`, `node:22-bookworm-slim`
- **Security Hardening**: Non-root user (`shadowscan`), read-only rootfs, `tmpfs`, `cap_drop: [ALL]`, `no-new-privileges`
