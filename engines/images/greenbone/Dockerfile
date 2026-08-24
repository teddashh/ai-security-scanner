# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG SOURCE_DATE_EPOCH=1787573675
FROM --platform=$TARGETPLATFORM golang:1.26.0-alpine@sha256:d4c4845f5d60c6a974c6000ce58ae079328d03ab7f721a0734277e69905473e5 AS launcher

ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local \
    SOURCE_DATE_EPOCH=1787573675

WORKDIR /src/launcher
COPY engines/images/greenbone-launcher/go.mod engines/images/greenbone-launcher/main.go engines/images/greenbone-launcher/main_test.go ./
RUN test -z "$(gofmt -d main.go main_test.go)" \
    && go test ./... \
    && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
        -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
        -o /out/ai-security-scanner-engine-entrypoint .

FROM registry.community.greenbone.net/community/vulnerability-tests@sha256:419438986cc4bc88c9a9c7960b519033c9ef1827241457c9acaca3b497a0183c AS feed
RUN grep -Fqx 'FEED_COMMIT = "b26d7237d56b7cf85e6ace2b9351e7851461b3a8";' /var/lib/openvas/24.10/vt-data/nasl/plugin_feed_info.inc \
    && test -s /var/lib/openvas/24.10/vt-data/nasl/vt-metadata.json \
    && test -s /var/lib/openvas/24.10/vt-data/nasl/sha256sums \
    && test -s /var/lib/openvas/24.10/vt-data/nasl/sha256sums.asc

FROM registry.community.greenbone.net/community/notus-data@sha256:73a309ed3dab7a5646952664434b425e2162909c7f92ed55f0abcfc37e211def AS notus
RUN mkdir -p /prepared \
    && tar -xzf /var/lib/notus/notus-data.tar.gz -C /prepared \
    && test -s /prepared/advisories/sha256sums \
    && test -s /prepared/advisories/sha256sums.asc \
    && test -s /prepared/products/sha256sums

FROM scratch AS source
ADD --checksum=sha256:47cbc7fbff0e19c4533f48c6e7287298f1466d1556f0fc4a7177c37506a3d5e8 \
    https://github.com/greenbone/openvas-scanner/archive/c3ae607ef632393b7919fb179d30b940d929f713.tar.gz \
    /openvas-scanner-c3ae607ef632393b7919fb179d30b940d929f713.tar.gz

FROM rust:1.98.0-bookworm@sha256:94e9efa4033213dbb70d4f665527e7ece3944ddb7ba1dd2e43f6fd6e2490af58 AS scanner-source
COPY --from=source /openvas-scanner-c3ae607ef632393b7919fb179d30b940d929f713.tar.gz /tmp/openvas-scanner.tar.gz
RUN mkdir -p /source \
    && tar -xzf /tmp/openvas-scanner.tar.gz --strip-components=1 -C /source \
    && test -f /source/rust/Cargo.lock \
    && test -d /source/.docker/vendor/krb5-1.22.2 \
    && test -d /source/.docker/vendor/libpcap-1.10.6

FROM scanner-source AS krb5-build
RUN apt-get update \
    && apt-get install --no-install-recommends --no-install-suggests -y \
        bison ca-certificates make \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /source/.docker/vendor/krb5-1.22.2/src
RUN ./configure --prefix=/opt/krb5-static \
        --enable-static \
        --disable-shared \
        --without-system-verto \
        --without-libedit \
        --disable-rpath \
    && make -C util/support -j"$(nproc)" \
    && make -C util/et -j"$(nproc)" \
    && make -C util/profile -j"$(nproc)" \
    && make -C include -j"$(nproc)" \
    && make -C lib/crypto -j"$(nproc)" \
    && make -C lib/krb5 -j"$(nproc)" \
    && make -C lib/gssapi -j"$(nproc)" \
    && make install-mkdirs \
    && make -C util/support install \
    && make -C util/et install \
    && make -C util/profile install \
    && make -C include install \
    && make -C lib/crypto install \
    && make -C lib/krb5 install \
    && make -C lib/gssapi install \
    && test -f /opt/krb5-static/lib/libgssapi_krb5.a \
    && test -f /opt/krb5-static/lib/libkrb5.a \
    && test -f /opt/krb5-static/lib/libk5crypto.a \
    && test -f /opt/krb5-static/lib/libcom_err.a \
    && test -f /opt/krb5-static/lib/libkrb5support.a

FROM scanner-source AS pcap-build
RUN apt-get update \
    && apt-get install --no-install-recommends --no-install-suggests -y \
        bison ca-certificates flex make \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /source/.docker/vendor/libpcap-1.10.6
RUN ./configure --prefix=/opt/libpcap-static --disable-shared --disable-dbus \
    && make -j"$(nproc)" \
    && make install \
    && test -f /opt/libpcap-static/lib/libpcap.a \
    && test -f /opt/libpcap-static/include/pcap.h

FROM rust:1.98.0-bookworm@sha256:94e9efa4033213dbb70d4f665527e7ece3944ddb7ba1dd2e43f6fd6e2490af58 AS build-archives
COPY --from=krb5-build /opt/krb5-static /opt/krb5-static
COPY --from=pcap-build /opt/libpcap-static /opt/libpcap-static
RUN mkdir -p /archives/include/gssapi /archives/include/krb5 \
    && install -m 644 /opt/libpcap-static/lib/libpcap.a /archives/libpcap.a \
    && install -m 644 /opt/krb5-static/lib/libgssapi_krb5.a /archives/libgssapi_krb5.a \
    && install -m 644 /opt/krb5-static/lib/libkrb5.a /archives/libkrb5.a \
    && install -m 644 /opt/krb5-static/lib/libk5crypto.a /archives/libk5crypto.a \
    && install -m 644 /opt/krb5-static/lib/libcom_err.a /archives/libcom_err.a \
    && install -m 644 /opt/krb5-static/lib/libkrb5support.a /archives/libkrb5support.a \
    && install -m 644 /opt/libpcap-static/include/pcap.h /archives/include/pcap.h \
    && install -m 644 /opt/krb5-static/include/krb5.h /archives/include/krb5.h \
    && install -m 644 /opt/krb5-static/include/com_err.h /archives/include/com_err.h \
    && install -m 644 /opt/krb5-static/include/profile.h /archives/include/profile.h \
    && install -m 644 /opt/krb5-static/include/gssapi/gssapi.h /archives/include/gssapi/gssapi.h \
    && install -m 644 /opt/krb5-static/include/gssapi/gssapi_alloc.h /archives/include/gssapi/gssapi_alloc.h \
    && install -m 644 /opt/krb5-static/include/gssapi/gssapi_ext.h /archives/include/gssapi/gssapi_ext.h \
    && install -m 644 /opt/krb5-static/include/gssapi/gssapi_generic.h /archives/include/gssapi/gssapi_generic.h \
    && install -m 644 /opt/krb5-static/include/gssapi/gssapi_krb5.h /archives/include/gssapi/gssapi_krb5.h \
    && install -m 644 /opt/krb5-static/include/gssapi/mechglue.h /archives/include/gssapi/mechglue.h \
    && install -m 644 /opt/krb5-static/include/krb5/krb5.h /archives/include/krb5/krb5.h

FROM scanner-source AS scanner-build
ARG SOURCE_DATE_EPOCH
ENV BIN_VERSION="c3ae607ef632393b7919fb179d30b940d929f713" \
    CARGO_INCREMENTAL="0" \
    OPENVAS_ARCHIVES="/archives" \
    LIBPCAP_LIBDIR="/archives" \
    SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}"
COPY --from=build-archives /archives /archives
RUN apt-get update \
    && apt-get install --no-install-recommends --no-install-suggests -y \
        capnproto ca-certificates libclang-dev libsnmp-dev make patch \
    && rm -rf /var/lib/apt/lists/*
COPY engines/images/greenbone/openvasd-rustls-provider.patch /tmp/openvasd-rustls-provider.patch
COPY engines/images/greenbone/openvasd-service-port.patch /tmp/openvasd-service-port.patch
COPY engines/images/greenbone/openvasd-http-compat.patch /tmp/openvasd-http-compat.patch
COPY engines/images/greenbone/openvasd-nasl-array-compat.patch /tmp/openvasd-nasl-array-compat.patch
COPY engines/images/greenbone/openvasd-eregmatch-captures.patch /tmp/openvasd-eregmatch-captures.patch
COPY engines/images/greenbone/openvasd-report-port.patch /tmp/openvasd-report-port.patch
RUN patch --batch --fuzz=0 -p1 -d /source < /tmp/openvasd-rustls-provider.patch \
    && patch --batch --fuzz=0 -p1 -d /source < /tmp/openvasd-service-port.patch \
    && patch --batch --fuzz=0 -p1 -d /source < /tmp/openvasd-http-compat.patch \
    && patch --batch --fuzz=0 -p1 -d /source < /tmp/openvasd-nasl-array-compat.patch \
    && patch --batch --fuzz=0 -p1 -d /source < /tmp/openvasd-eregmatch-captures.patch \
    && patch --batch --fuzz=0 -p1 -d /source < /tmp/openvasd-report-port.patch
WORKDIR /source/rust
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/source/rust/target \
    cargo test --locked --lib scanner::vt_runner::tests \
    && cargo test --locked --lib nasl::builtin::find_service::tests \
    && cargo test --locked --lib nasl::builtin::http::tests \
    && cargo test --locked --lib nasl::builtin::regex::tests \
    && cargo test --locked --lib nasl::builtin::report::tests \
    && cargo test --locked --bin openvasd database::sqlite::results::tests \
    && cargo test --locked --lib nasl::builtin::string::tests \
    && cargo test --locked --lib nasl::interpreter::declare::tests \
    && cargo test --locked --lib nasl::interpreter::tests::missing_dict_key \
    && cargo test --locked --lib nasl::interpreter::tests::array_out_of_range \
    && cargo test --locked --lib nasl::utils::function::from_nasl_value::tests \
    && cargo build --locked --release --bin openvasd \
    && install -Dm755 target/release/openvasd /out/openvasd \
    && /out/openvasd --version 2>&1 | grep -Fq 'c3ae607ef632393b7919fb179d30b940d929f713'

FROM registry.community.greenbone.net/community/openvas-scanner@sha256:ff7a14572583cc0e83ae0398a6c462f0c6d180c1bae6d54acbdd0df94f5446c6

ARG SOURCE_DATE_EPOCH

LABEL org.opencontainers.image.title="ai-security-scanner Greenbone engine" \
      org.opencontainers.image.description="Signed-feed Greenbone scanner with exact per-grant loopback relays to the managed SOCKS gateway" \
      org.opencontainers.image.source="https://github.com/greenbone/openvas-scanner" \
      org.opencontainers.image.revision="c3ae607ef632393b7919fb179d30b940d929f713" \
      org.opencontainers.image.version="23.50.21-feed202608240615-1" \
      org.opencontainers.image.licenses="GPL-2.0-only AND ODbL-1.0 AND Apache-2.0" \
      io.ai-security-scanner.openvas-revision="c3ae607ef632393b7919fb179d30b940d929f713" \
      io.ai-security-scanner.openvas-source-sha256="47cbc7fbff0e19c4533f48c6e7287298f1466d1556f0fc4a7177c37506a3d5e8" \
      io.ai-security-scanner.openvas-patch="rustls-provider:f401a3a174b6fe20fa187a1b74f53d1f9563a22c7a32bfc9aa122268d10e03c3;service-port:fd6409227338da73344657b5686c65bdf23a737da04f8bb3f7434eeb98da3424;http-compat:0aa8b07e43f2b21f32f7f2fa8181957b456248f0986de2723940809047a35eff;nasl-array-compat:affe3266602aade09416b68f2d085d1f390931d921a78eb7bb526451e1eeb891;eregmatch-captures:8e9ce5794e51abf78d77ea3c11931f50cf54f44be0d15becdd0a06c4f7b95d20;report-port:f9440c30d1c13a0fc13165ae2cdece6faab39409b2656db61d781d1e0865ca1c" \
      io.ai-security-scanner.feed-revision="b26d7237d56b7cf85e6ace2b9351e7851461b3a8" \
      io.ai-security-scanner.feed-version="202608240615-community" \
      io.ai-security-scanner.feed-image-digest="sha256:419438986cc4bc88c9a9c7960b519033c9ef1827241457c9acaca3b497a0183c" \
      io.ai-security-scanner.notus-revision="4635b37aecd2d968680c7609a7fb61e5d780ce93" \
      io.ai-security-scanner.notus-image-digest="sha256:73a309ed3dab7a5646952664434b425e2162909c7f92ed55f0abcfc37e211def"

ENV HOME="/tmp" \
    LANG="C.UTF-8" \
    LC_ALL="C.UTF-8" \
    NMAP_PRIVILEGED="0" \
    SSL_CERT_FILE="/etc/ssl/certs/ca-certificates.crt" \
    TMPDIR="/tmp"

COPY --from=launcher --chmod=0555 /out/ai-security-scanner-engine-entrypoint /usr/local/bin/ai-security-scanner-engine-entrypoint
COPY --from=scanner-build --chmod=0555 /out/openvasd /usr/local/bin/openvasd
COPY --from=feed /var/lib/openvas/24.10/vt-data/nasl/ /opt/greenbone/feed/
COPY --from=notus /prepared/ /opt/greenbone/notus/

COPY --chmod=0444 LICENSE /usr/share/licenses/ai-security-scanner/LICENSE
COPY --chmod=0444 engines/images/greenbone/SOURCE-OFFER.md /usr/share/source/greenbone/SOURCE-OFFER.md
COPY --chmod=0444 engines/images/greenbone/THIRD-PARTY-NOTICES.md /usr/share/licenses/greenbone/THIRD-PARTY-NOTICES.md
COPY --from=source --chmod=0444 /openvas-scanner-c3ae607ef632393b7919fb179d30b940d929f713.tar.gz /usr/share/source/openvas-scanner/openvas-scanner-c3ae607ef632393b7919fb179d30b940d929f713.tar.gz
COPY --chmod=0444 engines/images/greenbone/Dockerfile /usr/share/source/ai-security-scanner-greenbone/build/Dockerfile
COPY --chmod=0444 engines/images/greenbone/openvasd-rustls-provider.patch /usr/share/source/ai-security-scanner-greenbone/patches/openvasd-rustls-provider.patch
COPY --chmod=0444 engines/images/greenbone/openvasd-service-port.patch /usr/share/source/ai-security-scanner-greenbone/patches/openvasd-service-port.patch
COPY --chmod=0444 engines/images/greenbone/openvasd-http-compat.patch /usr/share/source/ai-security-scanner-greenbone/patches/openvasd-http-compat.patch
COPY --chmod=0444 engines/images/greenbone/openvasd-nasl-array-compat.patch /usr/share/source/ai-security-scanner-greenbone/patches/openvasd-nasl-array-compat.patch
COPY --chmod=0444 engines/images/greenbone/openvasd-eregmatch-captures.patch /usr/share/source/ai-security-scanner-greenbone/patches/openvasd-eregmatch-captures.patch
COPY --chmod=0444 engines/images/greenbone/openvasd-report-port.patch /usr/share/source/ai-security-scanner-greenbone/patches/openvasd-report-port.patch
COPY --chmod=0444 engines/images/greenbone-launcher/go.mod engines/images/greenbone-launcher/main.go engines/images/greenbone-launcher/main_test.go /usr/share/source/ai-security-scanner-greenbone/launcher/

RUN setcap -r /usr/bin/nmap \
    && setcap -r /usr/local/sbin/openvas \
    && rm -f /usr/bin/nmap /usr/local/sbin/openvas \
    && mkdir -p /run/ai-security-scanner /output /workspace /tmp \
    && chmod 1777 /tmp \
    && test -z "$(getcap -r /usr/bin /usr/local 2>/dev/null)" \
	&& /usr/local/bin/openvasd --version 2>&1 | grep -Fq 'c3ae607ef632393b7919fb179d30b940d929f713'

WORKDIR /workspace
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/ai-security-scanner-engine-entrypoint"]
