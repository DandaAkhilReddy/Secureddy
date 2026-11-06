# syntax=docker/dockerfile:1.7
# Reddy Security application image. One image, three roles:
#   reddysec web      FastAPI (sign-in, dashboard, Reading Room v1)
#   reddysec worker   mailbox polling, analysis, detonation orchestration
#   reddysec deadman  the dead man's switch
#
# Base: Microsoft's Playwright image for Python. Ubuntu 24.04 (noble),
# Python 3.12, Chromium + system deps baked in at /ms-playwright. The Reading
# Room (v1) drives Chromium from the web process, so the browser must be here.
# Pin the tag to the Playwright version in the project (1.63.0); the pip
# package is pinned to the same version below so it matches the baked browsers.
#
# Build from the repository root:
#   docker build -f docker/Dockerfile.app -t reddysec-app:local .

ARG PLAYWRIGHT_IMAGE=mcr.microsoft.com/playwright/python:v1.63.0-noble

# ---------------------------------------------------------------------------
# build: install the package into a virtualenv
# ---------------------------------------------------------------------------
FROM ${PLAYWRIGHT_IMAGE} AS build

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src

# asyncpg is the PostgreSQL driver for the production RS_DATABASE_URL
# (postgresql+asyncpg://...). It is installed here until it lands in
# pyproject's "azure" extra.
RUN python -m venv /opt/venv \
    && printf 'playwright==1.63.0\n' > /tmp/constraints.txt \
    && /opt/venv/bin/pip install --constraint /tmp/constraints.txt ".[azure]" "asyncpg==0.30.0" \
    && /opt/venv/bin/python -c "import playwright, reddysec; print('playwright', playwright.__version__)"

# ---------------------------------------------------------------------------
# runtime
# ---------------------------------------------------------------------------
FROM ${PLAYWRIGHT_IMAGE} AS runtime

LABEL org.opencontainers.image.title="reddysec-app" \
      org.opencontainers.image.description="Reddy Security web / worker / deadman" \
      org.opencontainers.image.source="https://github.com/dandaakhilreddy/reddy-security"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:${PATH}" \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    HOME=/home/app \
    RS_ARTIFACTS_DIR=/var/lib/reddysec/artifacts

# Non-root user. uid 10000 keeps clear of the base image's pwuser (1000).
RUN groupadd --gid 10000 app \
    && useradd --uid 10000 --gid app --create-home --home-dir /home/app --shell /usr/sbin/nologin app \
    && mkdir -p /var/lib/reddysec/artifacts /app/var \
    && chown -R app:app /var/lib/reddysec /app \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build --chown=app:app /opt/venv /opt/venv
COPY --chown=app:app docker/healthcheck.py /usr/local/bin/reddysec-healthcheck.py

WORKDIR /app
USER 10000:10000

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python", "/usr/local/bin/reddysec-healthcheck.py"]

# Override per role: ["reddysec", "worker"] or ["reddysec", "deadman"].
CMD ["reddysec", "web"]
