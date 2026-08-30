# API Design Specification

## 1. Overview

The ShadowScan API is built with **FastAPI** following REST conventions with JSON payloads and Pydantic schema validation.

**Base URLs**:
- Direct backend: `http://localhost:8000/` (prefixed routes under `/auth`, `/users`, `/scans`, `/admin`, `/ai`)
- Production reverse proxy: `https://scanner.example.com/api/`

---

## 2. Authentication & Verification Endpoints (`/auth`)

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :---: |
| `POST` | `/auth/register` | Register a new account or recover unverified account | No |
| `POST` | `/auth/login` | Authenticate user and issue JWT token | No |
| `POST` | `/auth/verify-email` | Verify email with 6-digit OTP code | No |
| `POST` | `/auth/resend-otp` | Request new OTP (enforces 60s cooldown) | No |
| `POST` | `/auth/forgot-password` | Trigger password reset OTP | No |
| `POST` | `/auth/verify-reset-otp`| Verify password reset OTP code | No |
| `POST` | `/auth/reset-password` | Set new password using verified OTP | No |
| `GET` | `/auth/google/login` | Initiate Google OAuth 2.0 flow | No |
| `GET` | `/auth/google/callback` | Google OAuth callback handler | No |

---

## 3. User Endpoints (`/users`)

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :---: |
| `GET` | `/users/me` | Retrieve authenticated user profile | Bearer JWT |
| `POST` | `/users/change-password` | Update account password | Bearer JWT |

---

## 4. Scan Management Endpoints (`/scans`)

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :---: |
| `POST` | `/scans` | Create and execute a new security scan | Bearer JWT |
| `GET` | `/scans` | List authenticated user's scan history | Bearer JWT |
| `GET` | `/scans/{scan_id}` | Retrieve scan details and status | Bearer JWT |
| `DELETE` | `/scans/{scan_id}` | Delete a scan and associated findings | Bearer JWT |
| `GET` | `/scans/{scan_id}/findings` | Retrieve findings for a specific scan | Bearer JWT |
| `GET` | `/scans/{scan_id}/report` | Download compiled PDF vulnerability report | Bearer JWT |

---

## 5. AI Security Analyst Endpoints (`/ai` & `/scans/{id}/ai`)

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :---: |
| `GET` | `/ai/status` | Check operational availability of Ollama | No |
| `GET` | `/scans/{scan_id}/ai/analysis` | Retrieve structured AI scan risk analysis | Bearer JWT |
| `POST` | `/scans/{scan_id}/ai/analysis` | Generate or refresh structured AI scan analysis | Bearer JWT |
| `POST` | `/scans/{scan_id}/ai/findings/{fid}/explain` | Explain finding with AI impact & remediation | Bearer JWT |
| `POST` | `/scans/{scan_id}/ai/chat` | Scan-scoped interactive security chat | Bearer JWT |

---

## 6. Admin Management Endpoints (`/admin`)

*All admin endpoints require an authenticated user with `role = "ADMIN"`.*

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :---: |
| `GET` | `/admin/stats` | Platform-wide user, scan, and finding metrics | Admin JWT |
| `GET` | `/admin/users` | List all platform users | Admin JWT |
| `PUT` | `/admin/users/{user_id}/disable` | Disable user account (`is_active = False`) | Admin JWT |
| `PUT` | `/admin/users/{user_id}/enable` | Enable user account (`is_active = True`) | Admin JWT |
| `DELETE` | `/admin/users/{user_id}` | Delete user account and associated scans | Admin JWT |
| `GET` | `/admin/scans` | List all platform scans | Admin JWT |
| `GET` | `/admin/findings` | List all platform findings | Admin JWT |

---

## 7. Health & Monitoring

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :---: |
| `GET` | `/health` | Container & orchestrator health check (`{"status": "ok"}`) | No |
