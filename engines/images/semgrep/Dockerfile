# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM ghcr.io/astral-sh/uv:0.10.9@sha256:10902f58a1606787602f303954cea099626a4adb02acbac4c69920fe9d278f82 AS uv

FROM --platform=$BUILDPLATFORM golang:1.25.10-alpine@sha256:8d22e29d960bc50cd025d93d5b7c7d220b1ee9aa7a239b3c8f55a57e987e8d45 AS launcher

ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0 GOTOOLCHAIN=local SOURCE_DATE_EPOCH=1787250577
WORKDIR /src/launcher
COPY engines/images/local-launcher/go.mod engines/images/local-launcher/main.go engines/images/local-launcher/main_test.go ./
RUN go test ./... && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
    -o /out/ai-security-scanner-engine-entrypoint .

FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40 AS build

ENV OPAMYES=1 \
    OPAMROOT=/root/.opam \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SOURCE_DATE_EPOCH=1787250577 \
    UV_LINK_MODE=copy

RUN apk add --no-cache \
    bash=5.3.3-r1 \
    build-base=0.5-r3 \
    bzip2-dev=1.0.8-r6 \
    bzip2-static=1.0.8-r6 \
    check-jsonschema=0.28.4-r0 \
    curl-dev=8.20.0-r0 \
    elfutils-dev=0.194-r0 \
    git=2.52.0-r0 \
    gmp-dev=6.3.0-r4 \
    gmp-static=6.3.0-r4 \
    libev-dev=4.33-r1 \
    libunwind-dev=1.8.1-r0 \
    libunwind-static=1.8.1-r0 \
    linux-headers=6.16.12-r0 \
    make=4.4.1-r3 \
    opam=2.5.2-r0 \
    pcre2-dev=10.47-r0 \
    pcre2-static=10.47-r0 \
    python3=3.12.14-r0 \
    rsync=3.4.3-r0 \
    xz-static=5.8.3-r0 \
    zstd-dev=1.5.7-r2 \
    zstd-static=1.5.7-r2

COPY --from=uv /uv /usr/local/bin/uv
ADD --checksum=sha256:7c5c5fe27b3b65ba1ac77f121c5d3df4398a1c06ab3d7e39fdef8884ca8494b5 \
    https://github.com/semgrep/semgrep/archive/a0c13f304151e531c7e7c00838076211a07a790c.tar.gz \
    /tmp/semgrep-source.tar.gz

RUN mkdir -p /src/semgrep \
    && tar -xzf /tmp/semgrep-source.tar.gz --strip-components=1 -C /src/semgrep

COPY engines/images/semgrep/submodules.lock /tmp/semgrep-submodules.lock
COPY .engine-cache/offline/semgrep-submodules /tmp/semgrep-submodules
RUN while IFS='|' read -r path repository revision digest size archive; do \
      case "${path}" in ''|'#'*) continue ;; esac; \
      test "$(stat -c '%s' "/tmp/semgrep-submodules/${archive}")" = "${size}"; \
      echo "${digest#sha256:}  /tmp/semgrep-submodules/${archive}" | sha256sum -c -; \
      rm -rf "/src/semgrep/${path}"; \
      mkdir -p "/src/semgrep/${path}"; \
      tar -xzf "/tmp/semgrep-submodules/${archive}" --strip-components=1 -C "/src/semgrep/${path}"; \
    done < /tmp/semgrep-submodules.lock \
    && tar --sort=name --mtime="@${SOURCE_DATE_EPOCH}" --owner=0 --group=0 --numeric-owner \
       -czf /tmp/semgrep-complete-source.tar.gz -C /src semgrep

WORKDIR /src/semgrep

ARG TARGETARCH
RUN test "${TARGETARCH}" = "amd64" -o "${TARGETARCH}" = "arm64" \
    && make opam-init OPAM_INIT_FLAGS=--disable-sandboxing \
    && make switch \
    && make install-deps \
    && SEMGREP_GIT_COMMIT=a0c13f304151e531c7e7c00838076211a07a790c opam exec -- make core \
    && install -D -m 0555 _build/default/src/main/Main.exe cli/src/semgrep/bin/semgrep-core \
    && cd cli \
    && UV_PROJECT_ENVIRONMENT=/opt/semgrep uv sync --frozen --no-dev --no-editable --python /usr/bin/python3 \
    && /opt/semgrep/bin/semgrep --version | grep -Fx '1.174.0'

FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40

LABEL org.opencontainers.image.title="ai-security-scanner Semgrep engine" \
      org.opencontainers.image.description="Pinned open-source Semgrep build with a project-owned offline rule pack" \
      org.opencontainers.image.source="https://github.com/semgrep/semgrep" \
      org.opencontainers.image.revision="a0c13f304151e531c7e7c00838076211a07a790c" \
      org.opencontainers.image.version="1.174.0-1" \
      org.opencontainers.image.licenses="LGPL-2.1-or-later AND Apache-2.0" \
      io.ai-security-scanner.rules-sha256="2081a62359682db1ddd15eda7eed1f3931975870cef8f8dab7120ba86fe2e5f3"

RUN apk add --no-cache \
    git=2.52.0-r0 \
    libgcc=15.2.0-r2 \
    libstdc++=15.2.0-r2 \
    py3-setuptools=80.9.0-r2 \
    python3=3.12.14-r0 \
    && addgroup -g 65532 scanner \
    && adduser -D -H -u 65532 -G scanner scanner \
    && mkdir -p /workspace /output /opt/ai-security-scanner/semgrep /usr/share/source \
    && chown scanner:scanner /output \
    && chmod 0555 /workspace /opt/ai-security-scanner/semgrep

COPY --from=build /opt/semgrep /opt/semgrep
COPY --from=launcher /out/ai-security-scanner-engine-entrypoint /usr/local/bin/ai-security-scanner-engine-entrypoint
COPY engines/images/semgrep/rules.yml /opt/ai-security-scanner/semgrep/rules.yml
COPY --from=build /src/semgrep/LICENSE /usr/share/licenses/semgrep/LICENSE
COPY --from=build /tmp/semgrep-complete-source.tar.gz /usr/share/source/semgrep-source.tar.gz
COPY engines/images/semgrep/submodules.lock /usr/share/source/semgrep-submodules.lock
COPY engines/images/semgrep/SOURCE-OFFER.md /usr/share/source/SEMGREP-SOURCE-OFFER.md
COPY engines/images/semgrep/Dockerfile /usr/share/source/ai-security-scanner-semgrep.Dockerfile
COPY LICENSE /usr/share/licenses/ai-security-scanner/LICENSE

RUN ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep \
    && chmod 0444 /opt/ai-security-scanner/semgrep/rules.yml \
    && /usr/local/bin/semgrep --version | grep -Fx '1.174.0'

ENV HOME="/tmp/ai-security-scanner-home" \
    SEMGREP_ENABLE_VERSION_CHECK="0" \
    SEMGREP_SEND_METRICS="off" \
    XDG_CACHE_HOME="/tmp/ai-security-scanner-cache"

WORKDIR /workspace
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/ai-security-scanner-engine-entrypoint"]
