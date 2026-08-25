# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM --platform=$BUILDPLATFORM golang:1.26.3-alpine@sha256:91eda9776261207ea25fd06b5b7fed8d397dd2c0a283e77f2ab6e91bfa71079d AS launcher

ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOEXPERIMENT=jsonv2 SOURCE_DATE_EPOCH=1786703098

WORKDIR /src/launcher
COPY engines/images/local-launcher/go.mod engines/images/local-launcher/main.go engines/images/local-launcher/main_test.go ./
RUN go test ./... && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
    -o /out/ai-security-scanner-engine-entrypoint .

FROM --platform=$BUILDPLATFORM golang:1.26.3-alpine@sha256:91eda9776261207ea25fd06b5b7fed8d397dd2c0a283e77f2ab6e91bfa71079d AS build

ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOEXPERIMENT=jsonv2 SOURCE_DATE_EPOCH=1786703098

ADD --checksum=sha256:285594b257470eb444fd2836be95a835565ee600382320c977b3993d8efbb767 \
    https://github.com/aquasecurity/trivy/archive/e1fd17a0ea4a8cf24bc4b4dd7e2cfbf4bb31b994.tar.gz \
    /tmp/trivy-source.tar.gz
RUN --mount=type=cache,id=ai-security-scanner-trivy-go-mod,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,id=ai-security-scanner-trivy-go-build,target=/root/.cache/go-build,sharing=locked \
    mkdir -p /src/trivy \
    && tar -xzf /tmp/trivy-source.tar.gz --strip-components=1 -C /src/trivy \
    && cd /src/trivy \
    && echo 'b0727b3c85888f77163ac9f6164869e9e8fc11cc6b8b6bafabbed92cf3288b9a  go.sum' | sha256sum -c - \
    && go mod verify \
    && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=readonly -buildvcs=false -trimpath \
       -ldflags='-s -w -buildid= -X=github.com/aquasecurity/trivy/pkg/version/app.ver=0.74.0' \
       -o /out/trivy ./cmd/trivy \
    && mkdir -p /rootfs/opt/ai-security-scanner/trivy-cache/db /rootfs/output /rootfs/workspace /rootfs/tmp \
    && chmod 1777 /rootfs/tmp

COPY .engine-cache/offline/trivy/db.tar.gz /tmp/trivy-db.tar.gz
RUN echo '8cf3aaad2dde16ff1529445dab19c2e2a9adc457dbe8d2b02fdbce06b0f638dc  /tmp/trivy-db.tar.gz' | sha256sum -c - \
    && tar -xzf /tmp/trivy-db.tar.gz -C /rootfs/opt/ai-security-scanner/trivy-cache/db \
    && echo 'e58db9fad4ce26f9ad77f4116f7a3b52527eb3a75718484903d930d110dee431  /rootfs/opt/ai-security-scanner/trivy-cache/db/trivy.db' | sha256sum -c - \
    && echo 'b253a6f5e90d91bf0e0e4b6f07a6f26cb9169155d0af68309728d9d853ded143  /rootfs/opt/ai-security-scanner/trivy-cache/db/metadata.json' | sha256sum -c - \
    && chmod -R a-w /rootfs/opt/ai-security-scanner/trivy-cache

FROM scratch

LABEL org.opencontainers.image.title="ai-security-scanner Trivy engine" \
      org.opencontainers.image.description="Pinned-source Trivy OS-package profile with a checksum-verified offline vulnerability database" \
      org.opencontainers.image.source="https://github.com/aquasecurity/trivy" \
      org.opencontainers.image.revision="e1fd17a0ea4a8cf24bc4b4dd7e2cfbf4bb31b994" \
      org.opencontainers.image.version="0.74.0-2" \
      org.opencontainers.image.licenses="Apache-2.0" \
      io.ai-security-scanner.database-manifest="sha256:a61aa42edc534843230ca24ef72ef322a2da18d717c3de4b6277f4aac43926a1"

ENV HOME="/tmp/ai-security-scanner-home" TRIVY_CACHE_DIR="/opt/ai-security-scanner/trivy-cache" XDG_CACHE_HOME="/tmp/ai-security-scanner-cache"

COPY --from=build /out/trivy /usr/local/bin/trivy
COPY --from=launcher /out/ai-security-scanner-engine-entrypoint /usr/local/bin/ai-security-scanner-engine-entrypoint
COPY --from=build /src/trivy/LICENSE /usr/share/licenses/trivy/LICENSE
COPY engines/images/trivy/DATABASE-NOTICE.md /usr/share/licenses/trivy/DATABASE-NOTICE.md
COPY LICENSE /usr/share/licenses/ai-security-scanner/LICENSE
COPY --from=build /rootfs /

WORKDIR /workspace
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/ai-security-scanner-engine-entrypoint"]
