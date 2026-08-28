# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG SOURCE_DATE_EPOCH=1787553065

FROM --platform=$BUILDPLATFORM golang:1.26.0-alpine@sha256:d4c4845f5d60c6a974c6000ce58ae079328d03ab7f721a0734277e69905473e5 AS build

ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local \
    SOURCE_DATE_EPOCH=1787553065

WORKDIR /src/launcher
COPY engines/images/external-launcher/go.mod engines/images/external-launcher/main.go engines/images/external-launcher/main_test.go ./
RUN go test ./... \
    && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
        -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
        -o /out/ai-security-scanner-engine-entrypoint .

ADD --checksum=sha256:233fd559f0f2287310709ed0f19613a9e298dbff03ee7f9e0905a0709e8537e4 \
    https://github.com/projectdiscovery/nuclei/archive/a8c88feb4a1c8e961b7902534ce3af97e9d524a4.tar.gz \
    /tmp/nuclei-source.tar.gz
ADD --checksum=sha256:1c651703d2fcd3e4134c548b49576db1e5c95e9522ce01246259b3aa2a50813b \
    https://github.com/projectdiscovery/nuclei-templates/archive/24858b4bfabfa86f0bcfd36aea24fb535152b012.tar.gz \
    /tmp/nuclei-templates-source.tar.gz

RUN mkdir -p /src/nuclei /src/nuclei-templates \
    && tar -xzf /tmp/nuclei-source.tar.gz --strip-components=1 -C /src/nuclei \
    && tar -xzf /tmp/nuclei-templates-source.tar.gz --strip-components=1 -C /src/nuclei-templates \
    && cd /src/nuclei \
    && grep -Fq 'Version = `v3.11.1`' pkg/catalog/config/constants.go \
    && echo 'c9be45a7baa2b3fda7d9ecdea91865b9caf78a733c70d1133d346bcc7dba501b  go.sum' | sha256sum -c - \
    && go mod verify \
    && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
        -mod=readonly -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
        -o /out/nuclei ./cmd/nuclei \
    && go version -m /out/nuclei | grep -Fq 'github.com/projectdiscovery/nuclei/v3' \
    && printf '%s\n' '24858b4bfabfa86f0bcfd36aea24fb535152b012' > /src/nuclei-templates/AI_SECURITY_SCANNER_REVISION \
    && mkdir -p /rootfs/run/ai-security-scanner /rootfs/output /rootfs/workspace /rootfs/tmp \
    && chmod 1777 /rootfs/tmp \
    && : > /rootfs/run/ai-security-scanner/.keep \
    && : > /rootfs/output/.keep \
    && : > /rootfs/workspace/.keep \
    && : > /rootfs/tmp/.keep

FROM scratch

LABEL org.opencontainers.image.title="ai-security-scanner Nuclei engine" \
      org.opencontainers.image.description="Exact-allowlist, read-only HTTP template execution for ai-security-scanner" \
      org.opencontainers.image.source="https://github.com/projectdiscovery/nuclei" \
      org.opencontainers.image.revision="a8c88feb4a1c8e961b7902534ce3af97e9d524a4" \
      org.opencontainers.image.version="3.11.1-4" \
      org.opencontainers.image.licenses="Apache-2.0 AND MIT" \
      io.ai-security-scanner.source-archive-sha256="233fd559f0f2287310709ed0f19613a9e298dbff03ee7f9e0905a0709e8537e4" \
      io.ai-security-scanner.templates-revision="24858b4bfabfa86f0bcfd36aea24fb535152b012" \
      io.ai-security-scanner.templates-archive-sha256="1c651703d2fcd3e4134c548b49576db1e5c95e9522ce01246259b3aa2a50813b"

ENV HOME="/tmp" \
    SSL_CERT_FILE="/etc/ssl/certs/ca-certificates.crt" \
    XDG_CACHE_HOME="/tmp/cache" \
    XDG_CONFIG_HOME="/tmp/config"

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /lib/ld-musl-*.so.1 /lib/
COPY --from=build /out/nuclei /usr/local/bin/nuclei
COPY --from=build /out/ai-security-scanner-engine-entrypoint /usr/local/bin/ai-security-scanner-engine-entrypoint
COPY LICENSE /usr/share/licenses/ai-security-scanner/LICENSE
COPY --from=build /src/nuclei/LICENSE.md /usr/share/licenses/nuclei/LICENSE.md
COPY --from=build /src/nuclei-templates/LICENSE.md /usr/share/licenses/nuclei-templates/LICENSE.md
COPY --from=build /src/nuclei-templates/http /opt/nuclei-templates/http
COPY --from=build /src/nuclei-templates/AI_SECURITY_SCANNER_REVISION /opt/nuclei-templates/AI_SECURITY_SCANNER_REVISION
COPY --from=build /rootfs /

WORKDIR /workspace
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/ai-security-scanner-engine-entrypoint"]
