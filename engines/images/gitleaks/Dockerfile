# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM --platform=$BUILDPLATFORM golang:1.26.3-alpine@sha256:91eda9776261207ea25fd06b5b7fed8d397dd2c0a283e77f2ab6e91bfa71079d AS launcher

ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0 GOTOOLCHAIN=local SOURCE_DATE_EPOCH=1773330037

WORKDIR /src/launcher
COPY engines/images/gitleaks/launcher/go.mod engines/images/gitleaks/launcher/main.go engines/images/gitleaks/launcher/main_test.go ./
RUN test -z "$(gofmt -d main.go main_test.go)" \
    && go test ./... \
    && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
       -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
       -o /out/ai-security-scanner-gitleaks-entrypoint .

FROM --platform=$BUILDPLATFORM golang:1.26.3-alpine@sha256:91eda9776261207ea25fd06b5b7fed8d397dd2c0a283e77f2ab6e91bfa71079d AS build

ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0 GOTOOLCHAIN=local SOURCE_DATE_EPOCH=1773330037

RUN apk add --no-cache git=2.52.0-r0

ADD --checksum=sha256:6b2638a733b85619dc80bdf28e84e4fed7e526a761ab5c148fbf67695aea2115 \
    https://github.com/gitleaks/gitleaks/archive/83d9cd684c87d95d656c1458ef04895a7f1cbd8e.tar.gz \
    /tmp/gitleaks-source.tar.gz
RUN mkdir -p /src/gitleaks \
    && tar -xzf /tmp/gitleaks-source.tar.gz --strip-components=1 -C /src/gitleaks

COPY engines/images/gitleaks/patches/0001-add-scanner-owned-ignore-policy.patch /tmp/0001-add-scanner-owned-ignore-policy.patch
WORKDIR /src/gitleaks
RUN echo '3fd66952713338b561c71c7ed608c5cce41355a7594c4eb8ffb4303abae29ccd  go.sum' | sha256sum -c - \
    && echo 'e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf  config/gitleaks.toml' | sha256sum -c - \
    && echo '9e7e7443fe5b5ee52dfb5ebb458d73fa868c441729e98d98a0453e7dd8cc24a7  /tmp/0001-add-scanner-owned-ignore-policy.patch' | sha256sum -c - \
    && git apply --check /tmp/0001-add-scanner-owned-ignore-policy.patch \
    && git apply /tmp/0001-add-scanner-owned-ignore-policy.patch \
    && go mod verify \
    && go test ./cmd/... \
    && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=readonly -buildvcs=false -trimpath \
       -ldflags='-s -w -buildid= -X github.com/zricethezav/gitleaks/v8/version.Version=8.30.1' \
       -o /out/gitleaks . \
    && mkdir -p /rootfs/output /rootfs/workspace /rootfs/tmp \
       /rootfs/opt/ai-security-scanner/gitleaks /rootfs/usr/share/licenses/gitleaks \
       /rootfs/usr/share/licenses/ai-security-scanner /rootfs/usr/share/source \
    && chmod 1777 /rootfs/tmp \
    && install -m 0444 config/gitleaks.toml /rootfs/opt/ai-security-scanner/gitleaks/gitleaks.toml \
    && install -m 0444 LICENSE /rootfs/usr/share/licenses/gitleaks/LICENSE \
    && install -m 0444 /tmp/gitleaks-source.tar.gz /rootfs/usr/share/source/gitleaks-source.tar.gz \
    && install -m 0444 /tmp/0001-add-scanner-owned-ignore-policy.patch \
       /rootfs/usr/share/source/0001-add-scanner-owned-ignore-policy.patch

FROM scratch

LABEL org.opencontainers.image.title="ai-security-scanner Gitleaks engine" \
      org.opencontainers.image.description="Pinned-source current-project secret scanning with scanner-owned rules and write-time redaction" \
      org.opencontainers.image.source="https://github.com/gitleaks/gitleaks" \
      org.opencontainers.image.revision="83d9cd684c87d95d656c1458ef04895a7f1cbd8e" \
      org.opencontainers.image.version="8.30.1-1" \
      org.opencontainers.image.licenses="MIT AND Apache-2.0" \
      io.ai-security-scanner.gitleaks-config-sha256="e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf" \
      io.ai-security-scanner.patch-sha256="9e7e7443fe5b5ee52dfb5ebb458d73fa868c441729e98d98a0453e7dd8cc24a7"

ENV HOME="/tmp/ai-security-scanner-home" \
    XDG_CACHE_HOME="/tmp/ai-security-scanner-cache"

COPY --from=build /out/gitleaks /usr/local/bin/gitleaks
COPY --from=launcher /out/ai-security-scanner-gitleaks-entrypoint /usr/local/bin/ai-security-scanner-gitleaks-entrypoint
COPY --from=build /rootfs /
COPY engines/images/gitleaks/PATCHES.md /usr/share/source/GITLEAKS-PATCHES.md
COPY engines/images/gitleaks/Dockerfile /usr/share/source/ai-security-scanner-gitleaks.Dockerfile
COPY LICENSE /usr/share/licenses/ai-security-scanner/LICENSE

WORKDIR /workspace
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/ai-security-scanner-gitleaks-entrypoint"]
