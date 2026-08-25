# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG SOURCE_REVISION=7909f2fc6186063e5c9e7ddef8c4d7d1072c8f3d
ARG SOURCE_DATE_EPOCH=1715333097

FROM golang:1.25.0-alpine3.22@sha256:f18a072054848d87a8077455f0ac8a25886f2397f88bfdd222d6fafbb5bba440 AS launcher
WORKDIR /src
COPY engines/images/cloud-launcher/go.mod engines/images/cloud-launcher/main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -buildvcs=false -trimpath \
      -ldflags='-s -w -buildid=' -o /out/ai-security-scanner-cloud-launcher .

FROM ghcr.io/astral-sh/uv:0.11.0@sha256:e49fde5daf002023f0a2e2643861ce9ca8a8da5b73d0e6db83ef82ff99969baf AS uv

FROM python:3.11.13-slim-bookworm@sha256:86adf8dbadc3d6e82ee5dd2c74bec2e1c2467cdad47886280501df722372d2e1 AS build
ARG SOURCE_REVISION
ARG SOURCE_DATE_EPOCH
ENV PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=0 \
    UV_LINK_MODE=copy \
    UV_NO_CACHE=1 \
    UV_PYTHON_DOWNLOADS=never
COPY --from=uv /uv /usr/local/bin/uv
COPY engines/images/scoutsuite/requirements.lock /build/requirements.lock
COPY engines/images/scoutsuite/requirements.in /build/requirements.in
COPY engines/images/scoutsuite/scoutsuite-json-only.patch /build/scoutsuite-json-only.patch
COPY engines/images/scoutsuite/prepare_source.py /build/prepare_source.py
COPY engines/images/scoutsuite/scout_entry.py /build/scout_entry.py
ADD --checksum=sha256:f263c09a56f255b55c42dfde4ee4a3e371d121f22e9c9942ff9661a009004bb3 \
    https://github.com/nccgroup/ScoutSuite/archive/7909f2fc6186063e5c9e7ddef8c4d7d1072c8f3d.tar.gz \
    /build/scoutsuite-5.14.0.tar.gz
RUN test "$(sha256sum /build/requirements.lock | cut -d' ' -f1)" = "a5b6365421108d786a563c543375a87979210035a1fa793849840ca2f9fd94c7" \
    && test "$(sha256sum /build/scoutsuite-json-only.patch | cut -d' ' -f1)" = "4f13f6754931203b4564ab6f7e7480428c713315bc05a99eddea4733aff8413b" \
    && mkdir /src \
    && tar --extract --gzip --file=/build/scoutsuite-5.14.0.tar.gz \
         --directory=/src --strip-components=1 --no-same-owner \
    && python /build/prepare_source.py /src "${SOURCE_DATE_EPOCH}" \
    && python -m venv /opt/scoutsuite \
    && uv pip install --python /opt/scoutsuite/bin/python --require-hashes --no-build \
         --no-deps --requirements /build/requirements.lock \
    && cp -a /src/ScoutSuite /opt/scoutsuite/lib/python3.11/site-packages/ScoutSuite \
    && cp /build/scout_entry.py /opt/scoutsuite/bin/scout \
    && chmod 0555 /opt/scoutsuite/bin/scout \
    && test "$(/opt/scoutsuite/bin/scout --version)" = "Scout Suite 5.14.0" \
    && find /opt/scoutsuite -exec touch -h -d "@${SOURCE_DATE_EPOCH}" '{}' +

FROM python:3.11.13-slim-bookworm@sha256:86adf8dbadc3d6e82ee5dd2c74bec2e1c2467cdad47886280501df722372d2e1
ARG SOURCE_DATE_EPOCH
LABEL org.opencontainers.image.title="ai-security-scanner ScoutSuite engine" \
      org.opencontainers.image.description="Pinned-source ScoutSuite AWS IAM JSON profile with a scanner-owned launcher" \
      org.opencontainers.image.source="https://github.com/teddashh/ai-security-scanner" \
      org.opencontainers.image.revision="7909f2fc6186063e5c9e7ddef8c4d7d1072c8f3d" \
      org.opencontainers.image.version="5.14.0-3" \
      org.opencontainers.image.licenses="GPL-2.0-only" \
      io.ai-security-scanner.source-archive-sha256="f263c09a56f255b55c42dfde4ee4a3e371d121f22e9c9942ff9661a009004bb3" \
      io.ai-security-scanner.requirements-lock-sha256="a5b6365421108d786a563c543375a87979210035a1fa793849840ca2f9fd94c7" \
      io.ai-security-scanner.profile="aws-iam-us-east-1-json"

COPY --from=build /opt/scoutsuite /opt/scoutsuite
COPY --from=build --chmod=0444 /src/LICENSE /usr/share/licenses/scoutsuite/LICENSE
COPY --from=build --chmod=0444 /build/scoutsuite-5.14.0.tar.gz /usr/share/source/scoutsuite/scoutsuite-5.14.0.tar.gz
COPY --from=build --chmod=0444 /build/requirements.lock /usr/share/source/scoutsuite/requirements.lock
COPY --from=build --chmod=0444 /build/requirements.in /usr/share/source/scoutsuite/requirements.in
COPY --from=build --chmod=0444 /build/scoutsuite-json-only.patch /usr/share/source/scoutsuite/scoutsuite-json-only.patch
COPY --from=build --chmod=0444 /build/prepare_source.py /usr/share/source/scoutsuite/prepare_source.py
COPY --from=build --chmod=0444 /build/scout_entry.py /usr/share/source/scoutsuite/scout_entry.py
COPY --chmod=0444 engines/images/scoutsuite/SOURCE-OFFER.md /usr/share/source/scoutsuite/SOURCE-OFFER.md
COPY --chmod=0444 engines/images/scoutsuite/Dockerfile /usr/share/source/scoutsuite/build/Dockerfile
COPY --chmod=0444 engines/images/cloud-launcher/go.mod engines/images/cloud-launcher/main.go /usr/share/source/scoutsuite/build/cloud-launcher/
COPY --from=launcher --chmod=0555 /out/ai-security-scanner-cloud-launcher /usr/local/bin/ai-security-scanner-cloud-launcher

ENV AWS_EC2_METADATA_DISABLED="true" \
    AWS_DEFAULT_REGION="us-east-1" \
    AWS_REGION="us-east-1" \
    AWS_STS_REGIONAL_ENDPOINTS="regional" \
    HOME="/tmp/ai-security-scanner-home" \
    PATH="/opt/scoutsuite/bin:/usr/local/bin:/usr/bin:/bin" \
    PYTHONDONTWRITEBYTECODE="1" \
    PYTHONUNBUFFERED="1" \
    XDG_CACHE_HOME="/tmp/ai-security-scanner-cache"

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/ai-security-scanner-cloud-launcher"]
