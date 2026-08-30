# Production deployment

1. Copy `.env.production.example` to `.env.production` and replace every
   placeholder. The latter is ignored by Git.
2. Start with `docker compose up --build -d`.
3. Terminate TLS at an external load balancer or a separately managed TLS
   reverse proxy. The bundled nginx only listens on HTTP port 80 and forwards
   `/api/` privately to the backend; no certificate is embedded in the image.

The backend image installs the pinned Python Playwright package and Chromium
with OS dependencies at build time. The process runs as the non-root
`shadowscan` user, does not pass `--no-sandbox`, exposes no browser debugging
port, has a PID limit, memory/CPU limits, and uses Docker init to reap child
processes. For untrusted-target production deployments, use the official
Playwright Chromium seccomp profile (the Docker runtime's default profile may
block user-namespace sandboxing on some hosts):

```sh
docker compose run --rm \
  --security-opt seccomp=/path/to/playwright-seccomp-profile.json backend \
  python -c "from playwright.sync_api import sync_playwright; p=sync_playwright().start(); b=p.chromium.launch(); b.close(); p.stop()"
```

Use Playwright's maintained profile from its Docker guidance, and apply the
same runtime policy in the production orchestrator. Do not replace it with
`--no-sandbox`, `privileged: true`, `network_mode: host`, or `SYS_ADMIN`.
