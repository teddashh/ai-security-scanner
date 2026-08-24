FROM anchore/syft@sha256:678bfa565b60f747aac0f8e964fe5588a24445b8d0a480e91f6efd70020dfbb0

LABEL org.opencontainers.image.title="ai-security-scanner managed Syft"
LABEL org.opencontainers.image.description="Offline, non-root Syft runtime for immutable assessment-case repository snapshots"
LABEL org.opencontainers.image.source="https://github.com/teddashh/ai-security-scanner"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.version="1.51.0-1"
LABEL ai.security-scanner.upstream.repository="https://github.com/anchore/syft"
LABEL ai.security-scanner.upstream.revision="2293641e3bd628a01bb37639318d62c0ebe89b39"
LABEL ai.security-scanner.upstream.image="anchore/syft@sha256:678bfa565b60f747aac0f8e964fe5588a24445b8d0a480e91f6efd70020dfbb0"

ENV HOME="/tmp/ai-security-scanner-home" \
    XDG_CACHE_HOME="/tmp/ai-security-scanner-cache" \
    SYFT_CACHE_DIR="/tmp/ai-security-scanner-cache/syft" \
    SYFT_CHECK_FOR_APP_UPDATE="false"

USER 65532:65532
ENTRYPOINT ["/syft"]
