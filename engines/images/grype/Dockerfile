# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM --platform=$BUILDPLATFORM golang:1.26.3-alpine@sha256:91eda9776261207ea25fd06b5b7fed8d397dd2c0a283e77f2ab6e91bfa71079d AS launcher

ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0 GOTOOLCHAIN=local SOURCE_DATE_EPOCH=1786377915

WORKDIR /src/launcher
COPY engines/images/local-launcher/go.mod engines/images/local-launcher/main.go engines/images/local-launcher/main_test.go ./
RUN go test ./... && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
    -o /out/ai-security-scanner-engine-entrypoint .

FROM --platform=$BUILDPLATFORM golang:1.26.3-alpine@sha256:91eda9776261207ea25fd06b5b7fed8d397dd2c0a283e77f2ab6e91bfa71079d AS build

ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0 GOTOOLCHAIN=local SOURCE_DATE_EPOCH=1786377915

RUN apk add --no-cache zstd=1.5.7-r2

ADD --checksum=sha256:3289f706c9a73485655f17cc9f82c46361512791f3b0b7bcb587125323429fcc \
    https://github.com/anchore/grype/archive/b5fa92bbcbef655497e3be840a2f718380e2cdd3.tar.gz \
    /tmp/grype-source.tar.gz
RUN mkdir -p /src/grype \
    && tar -xzf /tmp/grype-source.tar.gz --strip-components=1 -C /src/grype \
    && cd /src/grype \
    && echo 'eef40fe9f4880913b399dc4b2a728287f11d5a4014adf331ad77b5ecd7cda1d8  go.sum' | sha256sum -c - \
    && go mod verify \
    && cd /src/grype/cmd/grype \
    && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=readonly -buildvcs=false -trimpath \
       -ldflags='-s -w -buildid= -extldflags=-static -X main.version=0.117.0 -X main.gitCommit=b5fa92bbcbef655497e3be840a2f718380e2cdd3 -X main.buildDate=2026-08-10T16:05:15Z -X main.gitDescription=v0.117.0' \
       -o /out/grype . \
    && mkdir -p /rootfs/opt/ai-security-scanner/grype-db/6 /rootfs/output /rootfs/workspace /rootfs/tmp \
    && chmod 1777 /rootfs/tmp

COPY .engine-cache/offline/grype/db.tar.zst /tmp/grype-db.tar.zst
COPY engines/images/grype/import.json /tmp/grype-import.json
RUN echo '20a7315860b2d07231103a73bedec01de31e7a7f3d590aedfc61709dc9e117f9  /tmp/grype-db.tar.zst' | sha256sum -c - \
    && zstd --decompress --stdout /tmp/grype-db.tar.zst > /tmp/grype-db.tar \
    && tar -xf /tmp/grype-db.tar -C /rootfs/opt/ai-security-scanner/grype-db/6 \
    && echo 'db6f590412955f6b58cec12bfa4b712b2626eef9a030bffd8f32b9ebce074ff8  /rootfs/opt/ai-security-scanner/grype-db/6/vulnerability.db' | sha256sum -c - \
    && cp /tmp/grype-import.json /rootfs/opt/ai-security-scanner/grype-db/6/import.json \
    && chmod -R a-w /rootfs/opt/ai-security-scanner/grype-db

FROM scratch

LABEL org.opencontainers.image.title="ai-security-scanner Grype engine" \
      org.opencontainers.image.description="Pinned-source Grype with a checksum-verified offline vulnerability database" \
      org.opencontainers.image.source="https://github.com/anchore/grype" \
      org.opencontainers.image.revision="b5fa92bbcbef655497e3be840a2f718380e2cdd3" \
      org.opencontainers.image.version="0.117.0-3" \
      org.opencontainers.image.licenses="Apache-2.0" \
      io.ai-security-scanner.database-archive="sha256:20a7315860b2d07231103a73bedec01de31e7a7f3d590aedfc61709dc9e117f9"

ENV GRYPE_CHECK_FOR_APP_UPDATE="false" GRYPE_DB_AUTO_UPDATE="false" GRYPE_DB_CACHE_DIR="/opt/ai-security-scanner/grype-db" HOME="/tmp/ai-security-scanner-home" XDG_CACHE_HOME="/tmp/ai-security-scanner-cache"

COPY --from=build /out/grype /usr/local/bin/grype
COPY --from=launcher /out/ai-security-scanner-engine-entrypoint /usr/local/bin/ai-security-scanner-engine-entrypoint
COPY --from=build /src/grype/LICENSE /usr/share/licenses/grype/LICENSE
COPY engines/images/grype/DATABASE-NOTICE.md /usr/share/licenses/grype/DATABASE-NOTICE.md
COPY LICENSE /usr/share/licenses/ai-security-scanner/LICENSE
COPY --from=build /rootfs /

WORKDIR /workspace
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/ai-security-scanner-engine-entrypoint"]
