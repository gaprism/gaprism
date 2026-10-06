# syntax=docker/dockerfile:1
#
# One image for everything that runs the application: docker-compose.yml starts it as the web app,
# as the scan worker and for one-off commands (migrations, accounts, location data).
# Quickstart and operations: docs/deploy.md.

ARG PYTHON_VERSION=3.13
ARG NODE_VERSION=22
ARG UV_VERSION=0.8

# ---- 1. Styles and htmx, built here so that an image never carries a stale stylesheet ----------
FROM node:${NODE_VERSION}-alpine AS assets
WORKDIR /src
COPY package.json package-lock.json .npmrc ./
RUN npm ci
COPY assets ./assets
COPY scripts/copy-assets.mjs ./scripts/copy-assets.mjs
# Tailwind reads its class names from the templates; the build adds css/, htmx and the licences.
COPY app/templates ./app/templates
COPY app/static ./app/static
RUN npm run build

# ---- 2. Python dependencies, exactly as locked (wheels only: no compiler in the image) ---------
# (A stage of its own: COPY --from cannot expand a build argument.)
FROM ghcr.io/astral-sh/uv:${UV_VERSION} AS uv

FROM python:${PYTHON_VERSION}-slim-bookworm AS deps
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_PYTHON_DOWNLOADS=never \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --group deploy --no-install-project

# ---- 3. The image that runs --------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim-bookworm

# gunicorn: the "deploy" dependency group. One worker process per WEB_CONCURRENCY, threads per
# GUNICORN_CMD_ARGS; compose sets both from WEB_WORKERS and WEB_THREADS in .env.
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    FLASK_APP=app \
    FLASK_ENV=production \
    DATASETS_DIR=/data/datasets \
    WEB_CONCURRENCY=2 \
    GUNICORN_CMD_ARGS="--threads 4"

# An unprivileged user with a fixed id. /data is the only place the application writes to (the IP
# location databases); compose mounts a volume there, which starts out owned by this user.
RUN groupadd --gid 10001 app \
 && useradd --uid 10001 --gid app --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin app \
 && install -d -o app -g app /data /data/datasets

COPY --from=deps /opt/venv /opt/venv
WORKDIR /app
COPY app ./app
COPY runner ./runner
COPY migrations ./migrations
COPY --from=assets /src/app/static ./app/static
RUN python -m compileall -q app runner

USER app
EXPOSE 8000

# The query string stays out of the access log: it can hold the name of a vendor somebody is
# assessing. Behind a proxy the logged address is the proxy's. No control socket: nothing here
# needs gunicorn's remote control, and the user has no home directory to keep it in.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--worker-class", "gthread", \
     "--timeout", "60", "--graceful-timeout", "30", \
     "--max-requests", "2000", "--max-requests-jitter", "200", \
     "--worker-tmp-dir", "/dev/shm", "--no-control-socket", \
     "--access-logfile", "-", "--error-logfile", "-", \
     "--access-logformat", "%(h)s %(t)s \"%(m)s %(U)s\" %(s)s %(b)s %(M)sms", \
     "app:create_app()"]
