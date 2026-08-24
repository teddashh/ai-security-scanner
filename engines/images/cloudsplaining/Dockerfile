# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG SOURCE_REVISION=75a67ea9cb6d0fdf35ff185d08dad0d45587e6f7
ARG SOURCE_DATE_EPOCH=1781480779

FROM golang:1.25.0-alpine3.22@sha256:f18a072054848d87a8077455f0ac8a25886f2397f88bfdd222d6fafbb5bba440 AS launcher
WORKDIR /src
COPY engines/images/cloud-launcher/go.mod engines/images/cloud-launcher/main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -buildvcs=false -trimpath \
      -ldflags='-s -w -buildid=' -o /out/ai-security-scanner-cloud-launcher .

FROM ghcr.io/astral-sh/uv:0.11.0@sha256:e49fde5daf002023f0a2e2643861ce9ca8a8da5b73d0e6db83ef82ff99969baf AS uv

FROM python:3.11.13-slim-bookworm@sha256:86adf8dbadc3d6e82ee5dd2c74bec2e1c2467cdad47886280501df722372d2e1 AS build
ARG SOURCE_REVISION
ARG SOURCE_DATE_EPOCH
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
    UV_COMPILE_BYTECODE=0 \
    UV_LINK_MODE=copy \
    UV_NO_CACHE=1 \
    UV_PROJECT_ENVIRONMENT=/opt/cloudsplaining
COPY --from=uv /uv /usr/local/bin/uv
ADD --checksum=sha256:2bf9b7ae71b39ca597c164bd42c8bb3e1a68e4fb5a6e44bdbca9e5cd959b1f5c \
    https://github.com/salesforce/cloudsplaining/archive/75a67ea9cb6d0fdf35ff185d08dad0d45587e6f7.tar.gz \
    /tmp/cloudsplaining-source.tar.gz
RUN mkdir /src \
    && tar --extract --gzip --file=/tmp/cloudsplaining-source.tar.gz \
         --directory=/src --strip-components=1 --no-same-owner \
    && test "$(sha256sum /src/uv.lock | cut -d' ' -f1)" = "2405aeed08011b0662a08248079be8be71a3b0025fc141fba603de309c821261" \
    && cd /src \
    && uv sync --frozen --no-dev --no-editable --python /usr/local/bin/python3.11 \
    && test "$(/opt/cloudsplaining/bin/cloudsplaining --version)" = "cloudsplaining, version 0.9.1" \
    && find /opt/cloudsplaining -exec touch -h -d "@${SOURCE_DATE_EPOCH}" '{}' +

FROM python:3.11.13-slim-bookworm@sha256:86adf8dbadc3d6e82ee5dd2c74bec2e1c2467cdad47886280501df722372d2e1
ARG SOURCE_DATE_EPOCH
LABEL org.opencontainers.image.title="ai-security-scanner Cloudsplaining engine" \
      org.opencontainers.image.description="Pinned-source AWS IAM authorization analysis with a scanner-owned launcher" \
      org.opencontainers.image.source="https://github.com/teddashh/ai-security-scanner" \
      org.opencontainers.image.revision="75a67ea9cb6d0fdf35ff185d08dad0d45587e6f7" \
      org.opencontainers.image.version="0.9.1-1" \
      org.opencontainers.image.licenses="BSD-3-Clause" \
      io.ai-security-scanner.source-archive-sha256="2bf9b7ae71b39ca597c164bd42c8bb3e1a68e4fb5a6e44bdbca9e5cd959b1f5c" \
      io.ai-security-scanner.uv-lock-sha256="2405aeed08011b0662a08248079be8be71a3b0025fc141fba603de309c821261" \
      io.ai-security-scanner.profile="aws-iam-us-east-1"

COPY --from=build /opt/cloudsplaining /opt/cloudsplaining
COPY --from=build --chmod=0444 /src/LICENSE /usr/share/licenses/cloudsplaining/LICENSE
COPY --from=build --chmod=0444 /src/uv.lock /usr/share/licenses/cloudsplaining/uv.lock
COPY --from=launcher --chmod=0555 /out/ai-security-scanner-cloud-launcher /usr/local/bin/ai-security-scanner-cloud-launcher

ENV AWS_EC2_METADATA_DISABLED="true" \
    AWS_DEFAULT_REGION="us-east-1" \
    AWS_REGION="us-east-1" \
    AWS_STS_REGIONAL_ENDPOINTS="regional" \
    HOME="/tmp/ai-security-scanner-home" \
    PATH="/opt/cloudsplaining/bin:/usr/local/bin:/usr/bin:/bin" \
    PYTHONDONTWRITEBYTECODE="1" \
    PYTHONUNBUFFERED="1" \
    XDG_CACHE_HOME="/tmp/ai-security-scanner-cache"

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/ai-security-scanner-cloud-launcher"]
