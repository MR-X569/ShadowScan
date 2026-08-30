# ShadowScan Production Operator & Deployment Guide

This guide provides operational instructions for deploying and managing ShadowScan in a containerized production environment (such as an AWS EC2 instance, ECS, or self-hosted Linux server).

---

## 1. Architecture Summary

```text
                  [ External TLS / HTTPS Termination ]
                 (AWS ALB / Cloudflare / Traefik / Caddy)
                                    │
                                    ▼ (HTTP / Port 80)
        ┌────────────────────────────────────────────────────────┐
        │  Docker Compose: frontend (Nginx 1.28 Unprivileged)    │  (Network: edge)
        └───────────────────────────┬────────────────────────────┘
                                    │ /api/* (Internal Reverse Proxy)
                                    ▼ (Port 8000)
        ┌────────────────────────────────────────────────────────┐
        │  Docker Compose: backend (FastAPI + Playwright/Chrome) │  (Networks: edge, data)
        └───────────────────────────┬────────────────────────────┘
                                    │
                  ┌─────────────────┴─────────────────┐ (Network: data - internal: true)
                  ▼                                   ▼
        ┌───────────────────┐               ┌───────────────────┐
        │   postgres:16.11  │               │     redis:7.4     │  (No host port bindings)
        └───────────────────┘               └───────────────────┘
```

---

## 2. Prerequisites

- **Operating System**: Linux (Ubuntu 22.04+ / Debian 12 / Amazon Linux 2023).
- **Docker Engine**: Version 24.0+ with Docker Compose v2.20+.
- **Hardware Resources**: Minimum 2 vCPUs, 4 GB RAM, 20 GB SSD (allocated for Chromium rendering and PostgreSQL).
- **External Domain & TLS**: Domain name pointing to the server with HTTPS termination configured.

---

## 3. Production Environment Configuration

1. Copy the production environment template:
   ```bash
   cp .env.production.example .env.production
   ```
2. Populate `.env.production` with secure values:
   - `POSTGRES_PASSWORD`: Strong random password (minimum 32 characters).
   - `DATABASE_URL`: `postgresql+psycopg://shadowscan:<POSTGRES_PASSWORD>@postgres:5432/shadowscan`
   - `SECRET_KEY`: High-entropy cryptographic secret for JWT signing (`openssl rand -hex 32`).
   - `FRONTEND_URL`: Public canonical URL of the application (e.g. `https://scanner.example.com`).
   - `SMTP_*`: Valid SMTP credentials for transactional OTP delivery.
   - `OLLAMA_BASE_URL`: URL of the internal Ollama host (e.g. `http://ai-server.internal:11434` or local container).

> **Important**: Never commit `.env.production` to version control. It is ignored by `.dockerignore` and `.gitignore`.

---

## 4. Building and Starting the Stack

Start all services in detached mode with build:
```bash
docker compose up --build -d
```

### Automatic Startup Sequence:
1. `postgres` and `redis` start on the private `data` network.
2. Health checks confirm PostgreSQL and Redis are ready.
3. `backend` executes database migrations (`alembic upgrade head`) and starts Uvicorn.
4. `backend` health check passes.
5. `frontend` starts Nginx on port 80, proxying `/api/*` to the backend and serving static SPA assets.

---

## 5. Health Checks & Service Verification

Check running status of all containers:
```bash
docker compose ps
```

Expected output:
```text
NAME                  IMAGE                           STATUS                    PORTS
shadowscan-backend-1  shadowscan-backend              Up (healthy)              8000/tcp
shadowscan-frontend-1 shadowscan-frontend             Up (healthy)              0.0.0.0:80->8080/tcp
shadowscan-postgres-1 postgres:16.11-bookworm         Up (healthy)              5432/tcp
shadowscan-redis-1    redis:7.4-alpine                Up (healthy)              6379/tcp
```

Test internal health endpoints:
```bash
# Frontend health
curl -f http://localhost:80/

# Backend health through Nginx reverse proxy
curl -f http://localhost:80/api/health
```

---

## 6. Logs & Monitoring

View aggregated or service-specific logs:
```bash
# Follow all logs
docker compose logs -f

# Follow backend logs only
docker compose logs -f backend

# Follow Nginx proxy logs
docker compose logs -f frontend
```

---

## 7. Playwright & Chromium Runtime Security

- **Pre-installed Browser**: Chromium is installed during image construction into `/ms-playwright`. No browser downloads occur on container startup.
- **Non-Root Execution**: Runs under unprivileged user `shadowscan` (UID 10001).
- **Shared Memory**: Configured with `shm_size: 256m` in `compose.yaml` to prevent browser rendering crashes.
- **Seccomp Profile**: For hardened Linux hosts with restricted user namespaces, apply Playwright's recommended seccomp profile:
  ```bash
  docker compose run --rm \
    --security-opt seccomp=/path/to/playwright-seccomp-profile.json backend \
    python -c "from playwright.sync_api import sync_playwright; p=sync_playwright().start(); b=p.chromium.launch(); b.close(); p.stop()"
  ```

---

## 8. AI / Ollama Configuration Options

ShadowScan's AI Security Analyst connects to Ollama via `OLLAMA_BASE_URL`:

- **Option A: Dedicated Internal AI Host (Recommended for GPU)**:
  Point `OLLAMA_BASE_URL` in `.env.production` to a private host on your internal VPC:
  ```ini
  OLLAMA_BASE_URL=http://10.0.1.50:11434
  OLLAMA_MODEL=llama3.2
  ```
- **Option B: Local Host Daemon**:
  If Ollama runs on the Docker host machine, configure host gateway access:
  ```ini
  OLLAMA_BASE_URL=http://host.docker.internal:11434
  ```
- **Fail-Safe Behavior**: If the AI service is unreachable, the backend logs a warning and returns graceful fallback scan data. The scanning engine and reporting functions continue operating normally.

---

## 9. External TLS & Reverse Proxy Setup

The bundled Nginx container listens on HTTP port 80 and is designed to sit behind an external TLS terminator.

### Example Nginx / Reverse Proxy Host Block (Host Level):
```nginx
server {
    listen 443 ssl http2;
    server_name scanner.example.com;

    ssl_certificate /etc/letsencrypt/live/scanner.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/scanner.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:80;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 75s;
    }
}
```

---

## 10. Database Backup & Management

Persistent data is stored in the Docker volume `postgres_data`.

### Backup PostgreSQL Database:
```bash
docker compose exec -T postgres pg_dump -U shadowscan shadowscan > backup_$(date +%Y%m%d_%H%M%S).sql
```

### Restore Database:
```bash
cat backup.sql | docker compose exec -T postgres psql -U shadowscan -d shadowscan
```

---

## 11. Maintenance, Updates & Teardown

```bash
# Restart the stack
docker compose restart

# Pull updated base images and rebuild
git pull
docker compose up --build -d

# Stop the stack (data volumes preserved)
docker compose down

# Stop and remove volumes (DESTRUCTIVE - deletes database data)
docker compose down -v
```

---

## 12. Troubleshooting

| Issue | Cause | Resolution |
| :--- | :--- | :--- |
| `backend` restarts repeatedly | Database connection failure or unapplied migration | Check `docker compose logs backend`. Verify `POSTGRES_PASSWORD` matches in `DATABASE_URL`. |
| `frontend` returns 502 Bad Gateway | Backend is starting up or unhealthy | Wait 30s for backend health check. Verify backend is healthy with `docker compose ps`. |
| Browser scan fails on dynamic targets | Insufficient `/dev/shm` size | Ensure `shm_size: 256m` is present in `compose.yaml`. |
| AI Analyst returns "AI unavailable" | Ollama daemon not running or model not pulled | Verify Ollama is reachable at `OLLAMA_BASE_URL` and `llama3.2` model is loaded (`ollama list`). |
| OTP emails not received | SMTP configuration error or firewall block | Check `SMTP_HOST`, `SMTP_PORT`, and `SMTP_PASSWORD` in `.env.production`. Ensure port 587 outbound is open. |
