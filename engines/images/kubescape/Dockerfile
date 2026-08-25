# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM --platform=$BUILDPLATFORM golang:1.26.3-alpine@sha256:91eda9776261207ea25fd06b5b7fed8d397dd2c0a283e77f2ab6e91bfa71079d AS launcher

ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0 GOTOOLCHAIN=local SOURCE_DATE_EPOCH=1786522719

WORKDIR /src/launcher
COPY engines/images/local-launcher/go.mod engines/images/local-launcher/main.go engines/images/local-launcher/main_test.go ./
RUN go test ./... && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
    -o /out/ai-security-scanner-engine-entrypoint .

FROM --platform=$BUILDPLATFORM golang:1.26.3-alpine@sha256:91eda9776261207ea25fd06b5b7fed8d397dd2c0a283e77f2ab6e91bfa71079d AS build

ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0 GOTOOLCHAIN=local SOURCE_DATE_EPOCH=1786522719

ADD --checksum=sha256:d2844a14352bdeacd6f70edd5acaddfdb0bf388ccc78c5ef1dacea2095bdd090 \
    https://github.com/kubescape/kubescape/archive/469969f6bebf46bef5e808b91a4bb46fb2bbf4ed.tar.gz \
    /tmp/kubescape-source.tar.gz
RUN mkdir -p /src/kubescape \
    && tar -xzf /tmp/kubescape-source.tar.gz --strip-components=1 -C /src/kubescape \
    && cd /src/kubescape \
    && echo '634f23d02eefc421460a79036829b2b4ba3210be947fc7fce413024b01d58517  go.sum' | sha256sum -c - \
    && go mod verify \
    && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=readonly -buildvcs=false -trimpath \
       -ldflags='-s -w -buildid= -X main.version=v4.0.12 -X main.commit=469969f6bebf46bef5e808b91a4bb46fb2bbf4ed -X main.date=2026-08-12T08:18:39Z' \
       -o /out/kubescape . \
    && mkdir -p /rootfs/opt/ai-security-scanner/kubescape-artifacts /rootfs/output /rootfs/workspace /rootfs/tmp \
    && chmod 1777 /rootfs/tmp

ADD --checksum=sha256:7f7d7bbc6908b9872fd71751dc8d5dd5f543cdd6a684a24d1fb15b686e8344db \
    https://github.com/kubescape/regolibrary/releases/download/v2/nsa \
    /rootfs/opt/ai-security-scanner/kubescape-artifacts/nsa.json
ADD --checksum=sha256:df4e2431e8f560961ce56aa06e022caf9b2f82f98752de78df1cd0706b42cf3a \
    https://github.com/kubescape/regolibrary/releases/download/v2/default_config_inputs \
    /rootfs/opt/ai-security-scanner/kubescape-artifacts/controls-inputs.json
ADD --checksum=sha256:bf44e01e6b212c8e8c0ca0686d1bd84488e3f9ce5375cd36511c8faef3a44e7b \
    https://github.com/kubescape/regolibrary/releases/download/v2/exceptions \
    /rootfs/opt/ai-security-scanner/kubescape-artifacts/exceptions.json
RUN chmod -R a+rX,a-w /rootfs/opt/ai-security-scanner/kubescape-artifacts

FROM scratch

LABEL org.opencontainers.image.title="ai-security-scanner Kubescape engine" \
      org.opencontainers.image.description="Pinned-source, offline NSA policy scan for explicit local Kubernetes manifests" \
      org.opencontainers.image.source="https://github.com/kubescape/kubescape" \
      org.opencontainers.image.revision="469969f6bebf46bef5e808b91a4bb46fb2bbf4ed" \
      org.opencontainers.image.version="4.0.12-2" \
      org.opencontainers.image.licenses="Apache-2.0" \
      io.ai-security-scanner.regolibrary-revision="a12188c49147bb6ec379b42a4159d3d5852634b8"

ENV HOME="/tmp/ai-security-scanner-home" KS_SUBMIT="false" OTEL_SDK_DISABLED="true" XDG_CACHE_HOME="/tmp/ai-security-scanner-cache"

COPY --from=build /out/kubescape /usr/local/bin/kubescape
COPY --from=launcher /out/ai-security-scanner-engine-entrypoint /usr/local/bin/ai-security-scanner-engine-entrypoint
COPY --from=build /src/kubescape/LICENSE /usr/share/licenses/kubescape/LICENSE
COPY engines/images/kubescape/ARTIFACT-NOTICE.md /usr/share/licenses/kubescape/ARTIFACT-NOTICE.md
COPY LICENSE /usr/share/licenses/ai-security-scanner/LICENSE
COPY --from=build /rootfs /

WORKDIR /workspace
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/ai-security-scanner-engine-entrypoint"]
