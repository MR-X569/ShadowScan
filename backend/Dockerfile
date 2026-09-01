# Chromium is installed during image build, never at container startup.
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app

COPY backend/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
    && python -m playwright install --with-deps chromium \
    && rm -rf /root/.cache /tmp/* /var/lib/apt/lists/* \
    && groupadd --gid 10001 shadowscan \
    && useradd --uid 10001 --gid shadowscan --create-home --shell /usr/sbin/nologin shadowscan \
    && chown -R shadowscan:shadowscan /app /home/shadowscan /ms-playwright \
    && chmod -R 755 /ms-playwright


COPY --chown=shadowscan:shadowscan backend/ /app/

USER shadowscan

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=45s --retries=3 \
  CMD python -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:8000/health', timeout=3)" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
