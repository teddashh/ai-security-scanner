# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG SOURCE_DATE_EPOCH=1787252378

FROM --platform=$BUILDPLATFORM golang:1.25.0-alpine3.22@sha256:f18a072054848d87a8077455f0ac8a25886f2397f88bfdd222d6fafbb5bba440 AS launcher
ARG TARGETARCH
WORKDIR /src
COPY engines/images/m365-launcher/go.mod engines/images/m365-launcher/main.go ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -buildvcs=false -trimpath \
      -ldflags='-s -w -buildid=' -o /out/ai-security-scanner-m365-launcher .

FROM --platform=$BUILDPLATFORM python:3.11.13-slim-bookworm@sha256:86adf8dbadc3d6e82ee5dd2c74bec2e1c2467cdad47886280501df722372d2e1 AS prepare
COPY engines/images/m365-launcher/prepare_source.py /opt/prepare_source.py
COPY engines/images/scubagear/dependencies.lock.json /input/dependencies.lock.json
ADD --checksum=sha256:8b1f109d65bf145d7d36370e1ca6db841e82208776a04d79855d33b960d3c444 \
    https://github.com/cisagov/ScubaGear/archive/4d34e9a48e38ce5c2e14c0fdfbaee53e57594ae2.tar.gz \
    /input/scubagear.tar.gz
ADD --checksum=sha256:c9596cd06539ea898d8f0bc3569bdd2fdbab931390fc5747548cfed75b10cc9d \
    https://www.powershellgallery.com/api/v2/package/Microsoft.Graph.Authentication/2.25.0 \
    /input/Microsoft.Graph.Authentication.2.25.0.nupkg
ADD --checksum=sha256:d4602bc7a4a093766520422d53ca8b09acde162286fae11e2ee6c8edfea07810 \
    https://www.powershellgallery.com/api/v2/package/powershell-yaml/0.4.12 \
    /input/powershell-yaml.0.4.12.nupkg
ADD --checksum=sha256:4a8c3c98b9976aad4fd04308c7b1711ce6578a6a8be2ef172b0f28d79d7e62f7 \
    https://raw.githubusercontent.com/microsoftgraph/msgraph-sdk-powershell/eedb5e8e801bb4263630d2bef3194907655e2838/LICENSE.txt \
    /third-party/Microsoft.Graph.Authentication-LICENSE.txt
ADD --checksum=sha256:c6596eb7be8581c18be736c846fb9173b69eccf6ef94c5135893ec56bd92ba08 \
    https://raw.githubusercontent.com/open-policy-agent/opa/1e32c796e8979b1bda2f768138500b1deb95ff24/LICENSE \
    /third-party/Open-Policy-Agent-LICENSE
RUN python3 /opt/prepare_source.py \
      --engine scubagear \
      --source /input/scubagear.tar.gz \
      --lock /input/dependencies.lock.json \
      --output /prepared \
      --package Microsoft.Graph.Authentication=/input/Microsoft.Graph.Authentication.2.25.0.nupkg \
      --package powershell-yaml=/input/powershell-yaml.0.4.12.nupkg

FROM scratch AS opa-amd64
ADD --chmod=0555 --checksum=sha256:1dd5c5591ff856f5e20a1d66bafae9511ddf3c5552ed3b5070c70b2b6580ee3f \
    https://github.com/open-policy-agent/opa/releases/download/v1.19.0/opa_linux_amd64_static /opa

FROM scratch AS opa-arm64
ADD --chmod=0555 --checksum=sha256:06680087ed236c8c6aaa021660d83178db829a2ad30bdb3482481fada6791b2a \
    https://github.com/open-policy-agent/opa/releases/download/v1.19.0/opa_linux_arm64_static /opa

FROM opa-${TARGETARCH} AS opa

FROM mcr.microsoft.com/powershell:7.5-azurelinux-3.0@sha256:74b9b9d43da4d04c349bd358dd2db14ee01f0ab17769e402cf0ae4bd9fdd2f2b AS powershell-amd64
FROM mcr.microsoft.com/powershell:7.5-azurelinux-3.0-arm64@sha256:60d31793816646c4dd80b719b350ca68c8a53c000cbb2740655ddafe5e127903 AS powershell-arm64
FROM powershell-${TARGETARCH}

ARG SOURCE_DATE_EPOCH
LABEL org.opencontainers.image.title="ai-security-scanner ScubaGear engine" \
      org.opencontainers.image.description="Pinned-source Microsoft Entra ID assessment through one protected Graph token" \
      org.opencontainers.image.source="https://github.com/teddashh/ai-security-scanner" \
      org.opencontainers.image.revision="4d34e9a48e38ce5c2e14c0fdfbaee53e57594ae2" \
      org.opencontainers.image.version="1.8.0-5" \
      org.opencontainers.image.licenses="CC0-1.0 AND MIT AND Apache-2.0" \
      io.ai-security-scanner.source-archive-sha256="8b1f109d65bf145d7d36370e1ca6db841e82208776a04d79855d33b960d3c444" \
      io.ai-security-scanner.profile="aad-commercial-graph-token" \
      io.ai-security-scanner.opa-version="1.19.0"

COPY --from=prepare /prepared/engine/ScubaGear /opt/ai-security-scanner/ScubaGear
COPY --from=prepare /prepared/modules /opt/ai-security-scanner/modules
COPY --from=prepare --chmod=0444 /prepared/dependencies.lock.json /opt/ai-security-scanner/dependencies.lock.json
COPY --from=opa --chmod=0555 /opa /opt/ai-security-scanner/opa/opa
COPY --from=launcher --chmod=0555 /out/ai-security-scanner-m365-launcher /usr/local/bin/ai-security-scanner-m365-launcher
COPY --chmod=0444 engines/images/scubagear/run-scubagear.ps1 /opt/ai-security-scanner/run-scubagear.ps1

COPY --from=prepare --chmod=0444 /prepared/licenses/ScubaGear-LICENSE /usr/share/licenses/scubagear/LICENSE
COPY --from=prepare --chmod=0444 /prepared/modules/Microsoft.Graph.Authentication/2.25.0/Microsoft.Graph.Authentication.nuspec /usr/share/licenses/scubagear/Microsoft.Graph.Authentication.nuspec
COPY --from=prepare --chmod=0444 /prepared/modules/powershell-yaml/0.4.12/powershell-yaml.nuspec /usr/share/licenses/scubagear/powershell-yaml.nuspec
COPY --from=prepare --chmod=0444 /prepared/modules/powershell-yaml/0.4.12/LICENSE /usr/share/licenses/scubagear/powershell-yaml-LICENSE
COPY --from=prepare --chmod=0444 /prepared/modules/powershell-yaml/0.4.12/lib/netstandard2.1/LICENSE.txt /usr/share/licenses/scubagear/YamlDotNet-LICENSE
COPY --from=prepare --chmod=0444 /third-party/Microsoft.Graph.Authentication-LICENSE.txt /usr/share/licenses/scubagear/Microsoft.Graph.Authentication-LICENSE.txt
COPY --from=prepare --chmod=0444 /third-party/Open-Policy-Agent-LICENSE /usr/share/licenses/scubagear/Open-Policy-Agent-LICENSE
COPY --chmod=0444 engines/images/scubagear/THIRD-PARTY-NOTICES.md /usr/share/licenses/scubagear/THIRD-PARTY-NOTICES.md

ENV DOTNET_CLI_TELEMETRY_OPTOUT="1" \
    DOTNET_NOLOGO="1" \
    HOME="/tmp/ai-security-scanner-home" \
    NUGET_XMLDOC_MODE="skip" \
    PATH="/opt/microsoft/powershell/7:/usr/local/bin:/usr/bin:/bin" \
    POWERSHELL_TELEMETRY_OPTOUT="1" \
    POWERSHELL_UPDATECHECK="Off" \
    PSModulePath="/opt/ai-security-scanner/modules:/opt/microsoft/powershell/7/Modules" \
    SCUBAGEAR_SKIP_VERSION_CHECK="1" \
    XDG_CACHE_HOME="/tmp/ai-security-scanner-cache" \
    XDG_CONFIG_HOME="/tmp/ai-security-scanner-config" \
    XDG_DATA_HOME="/tmp/ai-security-scanner-data"

RUN chmod 0555 /usr/share/licenses/scubagear

USER 65532:65532
RUN pwsh -NoLogo -NoProfile -NonInteractive -Command \
      '$ErrorActionPreference="Stop"; Import-Module Microsoft.Graph.Authentication -RequiredVersion 2.25.0; Import-Module powershell-yaml -RequiredVersion 0.4.12; Import-Module /opt/ai-security-scanner/ScubaGear/ScubaGear.psd1 -SkipEditionCheck; if ((Get-Module ScubaGear).Version -ne [version]"1.8.0") { throw "ScubaGear version mismatch" }; $tokens=$null; $errors=$null; [void][System.Management.Automation.Language.Parser]::ParseFile("/opt/ai-security-scanner/run-scubagear.ps1",[ref]$tokens,[ref]$errors); if ($errors.Count) { throw ($errors | Out-String) }' \
    && test "$(/opt/ai-security-scanner/opa/opa version | sed -n 's/^Version: //p')" = "1.19.0"

ENTRYPOINT ["/usr/local/bin/ai-security-scanner-m365-launcher"]
