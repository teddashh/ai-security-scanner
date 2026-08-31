# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG SOURCE_DATE_EPOCH=1783613511

FROM --platform=$BUILDPLATFORM golang:1.26.0-alpine@sha256:d4c4845f5d60c6a974c6000ce58ae079328d03ab7f721a0734277e69905473e5 AS build

ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local \
    SOURCE_DATE_EPOCH=1783613511

WORKDIR /src/launcher
COPY engines/images/external-launcher/go.mod engines/images/external-launcher/main.go engines/images/external-launcher/main_test.go ./
RUN go test ./... \
    && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
        -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
        -o /out/ai-security-scanner-engine-entrypoint .

WORKDIR /src/httpx-patch
COPY engines/images/httpx/patch_live_dns.go engines/images/httpx/patch_live_dns_test.go ./
RUN go test patch_live_dns.go patch_live_dns_test.go \
    && go build -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
        -o /out/patch-httpx-live-dns patch_live_dns.go

ADD --checksum=sha256:94ae90ef3a2551bbc81c0814bd157387ab9c9bda54d1f5e38aaa708b95570946 \
    https://github.com/projectdiscovery/httpx/archive/13037dd08b9715cfbd960a70ae1edfef6686a857.tar.gz \
    /tmp/httpx-source.tar.gz

RUN mkdir -p /src/httpx \
    && tar -xzf /tmp/httpx-source.tar.gz --strip-components=1 -C /src/httpx \
    && cd /src/httpx \
    && grep -Fq 'const Version = `v1.10.0`' runner/banner.go \
    && echo '97ea2eed27767ae6d1e31b4d56b1e2c9a69235cdc76f89cdb79c199e621029b5  go.sum' | sha256sum -c - \
    && go mod verify \
    && echo '748502c7633140c7395d73d3b7d91eaa2efa324a5567cfc7b7a57485a1f9a641  runner/runner.go' | sha256sum -c - \
    && HTTPX_PINNED_RUNNER=/src/httpx/runner/runner.go go test \
        /src/httpx-patch/patch_live_dns.go /src/httpx-patch/patch_live_dns_test.go \
    && /out/patch-httpx-live-dns --source /src/httpx/runner/runner.go \
    && echo '6e8c7c8e59f6f7e574af0ff3b87cf3cd74e8e9d814618108dedeb9620fdbab95  runner/runner.go' | sha256sum -c - \
    && ! grep -Fq 'getDNSData(hp, onlyHost)' runner/runner.go \
    && grep -Fq 'var ips4, ips6, cnames, resolvers []string' runner/runner.go \
    && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
        -mod=readonly -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
        -o /out/httpx ./cmd/httpx \
    && go version -m /out/httpx | grep -Fq 'github.com/projectdiscovery/httpx' \
    && mkdir -p /rootfs/run/ai-security-scanner /rootfs/output /rootfs/workspace /rootfs/tmp \
    && chmod 1777 /rootfs/tmp \
    && : > /rootfs/run/ai-security-scanner/.keep \
    && : > /rootfs/output/.keep \
    && : > /rootfs/workspace/.keep \
    && : > /rootfs/tmp/.keep

FROM scratch

LABEL org.opencontainers.image.title="ai-security-scanner httpx engine" \
      org.opencontainers.image.description="Grant-and-port-local HTTP metadata collection for ai-security-scanner" \
      org.opencontainers.image.source="https://github.com/projectdiscovery/httpx" \
      org.opencontainers.image.revision="13037dd08b9715cfbd960a70ae1edfef6686a857" \
      org.opencontainers.image.version="1.10.0-5" \
      org.opencontainers.image.licenses="Apache-2.0 AND MIT" \
      io.ai-security-scanner.source-archive-sha256="94ae90ef3a2551bbc81c0814bd157387ab9c9bda54d1f5e38aaa708b95570946"

ENV HOME="/tmp" \
    SSL_CERT_FILE="/etc/ssl/certs/ca-certificates.crt" \
    XDG_CACHE_HOME="/tmp/cache" \
    XDG_CONFIG_HOME="/tmp/config"

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /lib/ld-musl-*.so.1 /lib/
COPY --from=build /out/httpx /usr/local/bin/httpx
COPY --from=build /out/ai-security-scanner-engine-entrypoint /usr/local/bin/ai-security-scanner-engine-entrypoint
COPY LICENSE /usr/share/licenses/ai-security-scanner/LICENSE
COPY --from=build /src/httpx/LICENSE.md /usr/share/licenses/httpx/LICENSE.md
COPY --from=build /rootfs /

WORKDIR /workspace
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/ai-security-scanner-engine-entrypoint"]
