# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG SOURCE_DATE_EPOCH=1777994963

FROM --platform=$BUILDPLATFORM golang:1.26.0-alpine@sha256:d4c4845f5d60c6a974c6000ce58ae079328d03ab7f721a0734277e69905473e5 AS build

ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local \
    SOURCE_DATE_EPOCH=1777994963

WORKDIR /src/launcher
COPY engines/images/external-launcher/go.mod engines/images/external-launcher/main.go engines/images/external-launcher/main_test.go ./
RUN go test ./... \
    && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
        -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
        -o /out/ai-security-scanner-engine-entrypoint .

ADD --checksum=sha256:0f2dd95b86692513d0c9a077f8332b33d52e6aba2e5955257aa0b2c74aae1e8b \
    https://github.com/projectdiscovery/naabu/archive/5a0ca8bde91b5bb16213e9e8b5c6871eac954bd8.tar.gz \
    /tmp/naabu-source.tar.gz

RUN mkdir -p /src/naabu \
    && tar -xzf /tmp/naabu-source.tar.gz --strip-components=1 -C /src/naabu \
    && cd /src/naabu \
    && grep -Fq 'const Version = `2.6.1`' pkg/runner/banners.go \
    && echo '7b7604e76aa7692564fb95b76368de214189facb7e8bdd51f3f210531afd46a6  go.sum' | sha256sum -c - \
    && go mod verify \
    && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
        -mod=readonly -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
        -o /out/naabu ./cmd/naabu \
    && go version -m /out/naabu | grep -Fq 'github.com/projectdiscovery/naabu/v2' \
    && mkdir -p /rootfs/run/ai-security-scanner /rootfs/output /rootfs/workspace /rootfs/tmp \
    && chmod 1777 /rootfs/tmp \
    && : > /rootfs/run/ai-security-scanner/.keep \
    && : > /rootfs/output/.keep \
    && : > /rootfs/workspace/.keep \
    && : > /rootfs/tmp/.keep

FROM scratch

LABEL org.opencontainers.image.title="ai-security-scanner Naabu engine" \
      org.opencontainers.image.description="Grant-local, SOCKS-enforced TCP connect discovery for ai-security-scanner" \
      org.opencontainers.image.source="https://github.com/projectdiscovery/naabu" \
      org.opencontainers.image.revision="5a0ca8bde91b5bb16213e9e8b5c6871eac954bd8" \
      org.opencontainers.image.version="2.6.1-2" \
      org.opencontainers.image.licenses="MIT" \
      io.ai-security-scanner.source-archive-sha256="0f2dd95b86692513d0c9a077f8332b33d52e6aba2e5955257aa0b2c74aae1e8b"

ENV HOME="/tmp" \
    SSL_CERT_FILE="/etc/ssl/certs/ca-certificates.crt" \
    XDG_CACHE_HOME="/tmp/cache" \
    XDG_CONFIG_HOME="/tmp/config"

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /lib/ld-musl-*.so.1 /lib/
COPY --from=build /out/naabu /usr/local/bin/naabu
COPY --from=build /out/ai-security-scanner-engine-entrypoint /usr/local/bin/ai-security-scanner-engine-entrypoint
COPY --from=build /src/naabu/LICENSE.md /usr/share/licenses/naabu/LICENSE.md
COPY --from=build /rootfs /

WORKDIR /workspace
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/ai-security-scanner-engine-entrypoint"]
