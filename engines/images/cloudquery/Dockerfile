# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG SOURCE_REVISION=e27e4ab61ad85479a5d53dae9b08440bc63e72b3
ARG AWS_SOURCE_REVISION=804be3a90d6f15d3e6c662c0eb7afa88a9596180
ARG FILE_SOURCE_REVISION=05f02334b9d6ed5de344fd9a9cf7ddead31ce453

FROM --platform=$BUILDPLATFORM golang:1.25.0-alpine3.22@sha256:f18a072054848d87a8077455f0ac8a25886f2397f88bfdd222d6fafbb5bba440 AS launcher
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY engines/images/cloud-launcher/go.mod engines/images/cloud-launcher/main.go ./
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
      go build -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
      -o /out/ai-security-scanner-cloud-launcher .

FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40 AS artifacts
ARG TARGETARCH

ADD --checksum=sha256:61d8304180f2cd1139d74db4185a5b1c99437cceb97bdb8acf0d1abd875106b1 \
    https://github.com/cloudquery/cloudquery/releases/download/cli-v2.0.31/cloudquery_linux_amd64 \
    /downloads/cloudquery-linux-amd64
ADD --checksum=sha256:51f1e24bc05fbae03ebd45f55c456a522d62d55413ebd0a4d728cf1b36ec938d \
    https://github.com/cloudquery/cloudquery/releases/download/cli-v2.0.31/cloudquery_linux_arm64 \
    /downloads/cloudquery-linux-arm64
ADD --checksum=sha256:138cb293cc691725914bd59ab452fb29b13b32e1c92f3da1410720349ba9004d \
    https://github.com/cloudquery/cloudquery/releases/download/plugins-source-aws-v9.2.0/aws_linux_amd64.zip \
    /downloads/aws-linux-amd64.zip
ADD --checksum=sha256:d9dd75752cf6f2f7cd5d9ba9639927e4ce00ddce3acb2af4d05dd2af6fa9fc9c \
    https://github.com/cloudquery/cloudquery/releases/download/plugins-source-aws-v9.2.0/aws_linux_arm64.zip \
    /downloads/aws-linux-arm64.zip
ADD --checksum=sha256:10c7278be4e365e7b6263fd3c2fef871d1559f3c65f6115728d8d5d13e307257 \
    https://github.com/cloudquery/cloudquery/releases/download/plugins-destination-file-v1.0.2/file_linux_amd64.zip \
    /downloads/file-linux-amd64.zip
ADD --checksum=sha256:68688cd89c3a8c8fd0332463c7039a9a14443d382a01ee7cb74e57d0234a8b85 \
    https://github.com/cloudquery/cloudquery/releases/download/plugins-destination-file-v1.0.2/file_linux_arm64.zip \
    /downloads/file-linux-arm64.zip
ADD --checksum=sha256:a4788989f99ab02144605539ab552e86c076405ac7516fb673e73ba6bda40c6b \
    https://github.com/cloudquery/cloudquery/archive/804be3a90d6f15d3e6c662c0eb7afa88a9596180.tar.gz \
    /downloads/aws-source.tar.gz
ADD --checksum=sha256:21e18c3d1348243273231e72a39febd9d7429ac4f1ec36c5bf18c32d509e5996 \
    https://github.com/cloudquery/cloudquery/archive/e27e4ab61ad85479a5d53dae9b08440bc63e72b3.tar.gz \
    /downloads/cli-source.tar.gz
ADD --checksum=sha256:21f4b826b9ad4830854130674023b97e443abba17b66a3557cd0805b3083b2d1 \
    https://github.com/cloudquery/cloudquery/archive/05f02334b9d6ed5de344fd9a9cf7ddead31ce453.tar.gz \
    /downloads/file-source.tar.gz

RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) \
        cli=/downloads/cloudquery-linux-amd64; \
        aws=/downloads/aws-linux-amd64.zip; \
        file=/downloads/file-linux-amd64.zip; \
        aws_sha=c7460b15d200d606e1d339889acb5482c15cbf6346e278943492808a4b2cbc90; \
        file_sha=73f24531aeb686db87e38624f71fa8e0e5ce876d5dc36458dcb554d400f17387 ;; \
      arm64) \
        cli=/downloads/cloudquery-linux-arm64; \
        aws=/downloads/aws-linux-arm64.zip; \
        file=/downloads/file-linux-arm64.zip; \
        aws_sha=5d1b00b1dac8701d9ace39ed21bd927e6fe499637df09b0635405a58c578e998; \
        file_sha=e3708d162c6dbb429185d5295edcfd1324ed459252f794eca5a805e1ab5d3122 ;; \
      *) echo "unsupported CloudQuery target architecture" >&2; exit 64 ;; \
    esac; \
    mkdir -p /out /extract/aws /extract/file /source/aws /source/cli /source/file; \
    cp "${cli}" /out/cloudquery; \
    unzip -q "${aws}" plugins/source/aws -d /extract/aws; \
    unzip -q "${file}" plugins/destination/file -d /extract/file; \
    cp /extract/aws/plugins/source/aws /out/cloudquery-source-aws; \
    cp /extract/file/plugins/destination/file /out/cloudquery-destination-file; \
    test "$(sha256sum /out/cloudquery-source-aws | cut -d' ' -f1)" = "${aws_sha}"; \
    test "$(sha256sum /out/cloudquery-destination-file | cut -d' ' -f1)" = "${file_sha}"; \
    tar --extract --gzip --file=/downloads/aws-source.tar.gz \
      --directory=/source/aws --strip-components=1 --no-same-owner; \
    tar --extract --gzip --file=/downloads/cli-source.tar.gz \
      --directory=/source/cli --strip-components=1 --no-same-owner; \
    tar --extract --gzip --file=/downloads/file-source.tar.gz \
      --directory=/source/file --strip-components=1 --no-same-owner; \
    test -f /source/aws/plugins/source/aws/go.sum; \
    test -f /source/cli/cli/go.sum; \
    test -f /source/file/plugins/destination/file/go.sum; \
    cp /source/aws/LICENSE /out/LICENSE; \
    chmod 0555 /out/cloudquery /out/cloudquery-source-aws /out/cloudquery-destination-file; \
    chmod 0444 /out/LICENSE /downloads/aws-source.tar.gz /downloads/cli-source.tar.gz /downloads/file-source.tar.gz

FROM scratch
ARG SOURCE_REVISION
ARG AWS_SOURCE_REVISION
ARG FILE_SOURCE_REVISION
LABEL org.opencontainers.image.title="ai-security-scanner CloudQuery engine" \
      org.opencontainers.image.description="Anonymous public CloudQuery AWS IAM inventory source closure with scanner-owned launcher" \
      org.opencontainers.image.source="https://github.com/teddashh/ai-security-scanner" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.version="2.0.31-aws9.2.0-4" \
      org.opencontainers.image.licenses="MPL-2.0" \
      io.ai-security-scanner.cloudquery-cli.version="2.0.31" \
      io.ai-security-scanner.cloudquery-aws.version="9.2.0" \
      io.ai-security-scanner.cloudquery-file.version="1.0.2" \
      io.ai-security-scanner.cloudquery-cli.source-revision="${SOURCE_REVISION}" \
      io.ai-security-scanner.cloudquery-aws.source-revision="${AWS_SOURCE_REVISION}" \
      io.ai-security-scanner.cloudquery-file.source-revision="${FILE_SOURCE_REVISION}" \
      io.ai-security-scanner.cloudquery-cli.source-archive-sha256="21e18c3d1348243273231e72a39febd9d7429ac4f1ec36c5bf18c32d509e5996" \
      io.ai-security-scanner.cloudquery-aws.source-archive-sha256="a4788989f99ab02144605539ab552e86c076405ac7516fb673e73ba6bda40c6b" \
      io.ai-security-scanner.cloudquery-file.source-archive-sha256="21f4b826b9ad4830854130674023b97e443abba17b66a3557cd0805b3083b2d1" \
      io.ai-security-scanner.profile="aws-iam-us-east-1"

COPY --from=launcher /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=launcher --chmod=0555 /out/ai-security-scanner-cloud-launcher /usr/local/bin/ai-security-scanner-cloud-launcher
COPY --from=artifacts --chmod=0555 /out/cloudquery /app/cloudquery
COPY --from=artifacts --chmod=0555 /out/cloudquery-source-aws /usr/local/libexec/cloudquery-source-aws
COPY --from=artifacts --chmod=0555 /out/cloudquery-destination-file /usr/local/libexec/cloudquery-destination-file
COPY --from=artifacts /out/LICENSE /usr/share/licenses/cloudquery/LICENSE
COPY --from=artifacts /downloads/cli-source.tar.gz /usr/share/source/cloudquery/cli-e27e4ab.tar.gz
COPY --from=artifacts /downloads/aws-source.tar.gz /usr/share/source/cloudquery/aws-804be3a.tar.gz
COPY --from=artifacts /downloads/file-source.tar.gz /usr/share/source/cloudquery/file-05f0233.tar.gz
COPY engines/images/cloudquery/SOURCE-OFFER.md /usr/share/source/cloudquery/SOURCE-OFFER.md
COPY engines/images/cloudquery/dependencies.lock.json /usr/share/source/cloudquery/build/dependencies.lock.json
COPY engines/images/cloudquery/plugins.yml /usr/share/source/cloudquery/build/plugins.yml
COPY engines/images/cloudquery/Dockerfile /usr/share/source/cloudquery/build/Dockerfile
COPY engines/images/cloud-launcher/go.mod /usr/share/source/cloudquery/build/cloud-launcher/go.mod
COPY engines/images/cloud-launcher/main.go /usr/share/source/cloudquery/build/cloud-launcher/main.go

ENV AWS_EC2_METADATA_DISABLED="true" \
    AWS_DEFAULT_REGION="us-east-1" \
    AWS_REGION="us-east-1" \
    AWS_STS_REGIONAL_ENDPOINTS="regional" \
    CQ_TELEMETRY_LEVEL="none" \
    HOME="/tmp/ai-security-scanner-home" \
    PATH="/app:/usr/local/bin:/usr/local/libexec" \
    SSL_CERT_FILE="/etc/ssl/certs/ca-certificates.crt"

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/ai-security-scanner-cloud-launcher"]
