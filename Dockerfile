# Production Dockerfile for Thirstys-Waterfall Web Interface
ARG PYTHON_IMAGE=python:3.11-slim@sha256:baf89808ec37adeaab83cec287adb4a2afa4a11c1d51e961c7ec737877e61af6

FROM ${PYTHON_IMAGE} AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1
ARG SOURCE_DATE_EPOCH=315532800
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY requirements-build.lock ./
RUN pip install --no-cache-dir --require-hashes -r requirements-build.lock

COPY pyproject.toml setup.py README.md LICENSE MANIFEST.in ./
COPY thirstys_waterfall ./thirstys_waterfall
RUN python -m build --no-isolation --wheel --outdir /wheels


FROM ${PYTHON_IMAGE} AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    THIRSTYS_ENV=production

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements-deploy.lock ./
RUN pip install --no-cache-dir --require-hashes -r requirements-deploy.lock

COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir --no-deps /wheels/*.whl \
    && pip uninstall --yes setuptools wheel \
    && rm -rf /wheels

COPY web ./web
RUN sed -i 's/\r$//' /app/web/start.sh && chmod +x /app/web/start.sh

RUN useradd -m -u 1000 -s /bin/bash thirsty && \
    mkdir -p /home/thirsty/.thirstys_waterfall && \
    chown -R thirsty:thirsty /home/thirsty /app

USER thirsty
WORKDIR /app/web

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

CMD ["bash", "/app/web/start.sh"]
