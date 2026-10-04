# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG SOURCE_DATE_EPOCH=1764257310
FROM --platform=$BUILDPLATFORM golang:1.26.3-alpine@sha256:91eda9776261207ea25fd06b5b7fed8d397dd2c0a283e77f2ab6e91bfa71079d AS source
ARG TARGETOS
ARG TARGETARCH
ENV CGO_ENABLED=0 GOTOOLCHAIN=local SOURCE_DATE_EPOCH=1764257310
RUN apk add --no-cache git=2.52.0-r0
ADD --checksum=sha256:433fe72ee2d31135730b781ef812d50c2abeaeb1ec217e90d2f6acf0d455f713 \
    https://github.com/splx-ai/agentic-radar/archive/65a7e4bd01e2034c7cb52e9620eeed287688cc53.tar.gz \
    /tmp/agentic-radar-source.tar.gz
RUN mkdir -p /src/agentic-radar \
    && tar -xzf /tmp/agentic-radar-source.tar.gz --strip-components=1 -C /src/agentic-radar
COPY docs/research/patches/agentic-radar-0.14.1-machine-json.patch /tmp/agentic-radar-machine-json.patch
WORKDIR /src/agentic-radar
RUN echo 'd32c61e4c2134141686e950a3f025c1b521a1f0096e5572c6846b65d0afb9d72  /tmp/agentic-radar-machine-json.patch' | sha256sum -c - \
    && git apply --check /tmp/agentic-radar-machine-json.patch \
    && git apply /tmp/agentic-radar-machine-json.patch
WORKDIR /src/launcher
COPY engines/images/agentic-radar/launcher/go.mod engines/images/agentic-radar/launcher/main.go engines/images/agentic-radar/launcher/main_test.go ./
RUN test -z "$(gofmt -d main.go main_test.go)" \
    && go test ./... \
    && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -buildvcs=false -trimpath \
       -ldflags='-s -w -buildid=' -o /out/ai-security-scanner-agentic-radar-entrypoint .

FROM python:3.11.16-slim@sha256:9c900dea9e8fb7e16277c179b555cc72d29a352dbc33cff48ad5a0412fd5bfc7 AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1 PIP_ROOT_USER_ACTION=ignore \
    PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 PYTHON_DOTENV_DISABLED=1 SOURCE_DATE_EPOCH=1764257310
COPY engines/images/agentic-radar/requirements.lock engines/images/agentic-radar/build-requirements.lock /tmp/
COPY --from=source /src/agentic-radar /src/agentic-radar
RUN echo '4345d805c8c9838f27d0f08cdf37a3cbec74a0a75e8bd4bd00f6c20e9b5f7f3c  /tmp/requirements.lock' | sha256sum -c - \
    && echo '59f3ca12dca8a4572c7a84cb443c51140fd7e42dacffc62bc046af2dda4ef4db  /tmp/build-requirements.lock' | sha256sum -c - \
    && python -m pip install --no-compile --only-binary=:all: --require-hashes \
       --prefix=/install --requirement=/tmp/requirements.lock \
    && python -m pip install --no-compile --only-binary=:all: --require-hashes \
       --prefix=/build-deps --requirement=/tmp/build-requirements.lock \
    && PYTHONPATH=/install/lib/python3.11/site-packages:/build-deps/lib/python3.11/site-packages \
       python -m pip wheel --no-deps --no-build-isolation --wheel-dir=/wheels /src/agentic-radar \
    && python -m pip install --no-compile --no-deps --prefix=/install /wheels/agentic_radar-0.14.1-py3-none-any.whl \
    && PYTHONPATH=/install/lib/python3.11/site-packages:/build-deps/lib/python3.11/site-packages \
       python -m pytest -q /src/agentic-radar/tests/graph_json_export_test.py \
    && PYTHONPATH=/install/lib/python3.11/site-packages \
       python -c 'import importlib.util,agentic_radar; assert agentic_radar.__version__ == "0.14.1"; assert all(importlib.util.find_spec(name) is None for name in ("agents", "crewai", "langgraph", "autogen", "torch", "transformers"))' \
    && find /install -exec touch -h -d '@1764257310' '{}' +

FROM python:3.11.16-slim@sha256:9c900dea9e8fb7e16277c179b555cc72d29a352dbc33cff48ad5a0412fd5bfc7
LABEL org.opencontainers.image.title="ai-security-scanner Agentic Radar engine" \
      org.opencontainers.image.description="Pinned-source offline AI workflow inventory from an immutable repository snapshot" \
      org.opencontainers.image.source="https://github.com/splx-ai/agentic-radar" \
      org.opencontainers.image.revision="65a7e4bd01e2034c7cb52e9620eeed287688cc53" \
      org.opencontainers.image.version="0.14.1-1" org.opencontainers.image.licenses="Apache-2.0" \
      io.ai-security-scanner.source-archive-sha256="433fe72ee2d31135730b781ef812d50c2abeaeb1ec217e90d2f6acf0d455f713" \
      io.ai-security-scanner.patch-sha256="d32c61e4c2134141686e950a3f025c1b521a1f0096e5572c6846b65d0afb9d72" \
      io.ai-security-scanner.requirements-sha256="4345d805c8c9838f27d0f08cdf37a3cbec74a0a75e8bd4bd00f6c20e9b5f7f3c"
ENV HOME="/tmp/ai-security-scanner-home" NO_COLOR="1" PYTHONDONTWRITEBYTECODE="1" \
    PYTHONHASHSEED="0" PYTHONNOUSERSITE="1" PYTHONUNBUFFERED="1" \
    PYTHON_DOTENV_DISABLED="1" XDG_CACHE_HOME="/tmp/ai-security-scanner-cache"
COPY --from=build /install /usr/local
COPY --from=source /out/ai-security-scanner-agentic-radar-entrypoint /usr/local/bin/ai-security-scanner-agentic-radar-entrypoint
COPY --from=source /src/agentic-radar/LICENSE /usr/share/licenses/agentic-radar/LICENSE
COPY --from=source /tmp/agentic-radar-machine-json.patch /usr/share/source/agentic-radar-0.14.1-machine-json.patch
COPY engines/images/agentic-radar/requirements.lock engines/images/agentic-radar/build-requirements.lock engines/images/agentic-radar/Dockerfile engines/images/agentic-radar/PATCHES.md /usr/share/source/
COPY LICENSE /usr/share/licenses/ai-security-scanner/LICENSE
RUN mkdir -p /workspace /output /tmp/ai-security-scanner-home /tmp/ai-security-scanner-cache \
    && chmod 1777 /tmp /tmp/ai-security-scanner-home /tmp/ai-security-scanner-cache \
    && find /usr/share/source /usr/share/licenses/agentic-radar /usr/share/licenses/ai-security-scanner \
       -exec touch -h -d '@1764257310' '{}' +
WORKDIR /tmp/ai-security-scanner-home
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/ai-security-scanner-agentic-radar-entrypoint"]
