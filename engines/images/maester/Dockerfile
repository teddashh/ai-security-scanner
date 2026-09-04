# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG SOURCE_DATE_EPOCH=1787030409

FROM --platform=$BUILDPLATFORM golang:1.25.0-alpine3.22@sha256:f18a072054848d87a8077455f0ac8a25886f2397f88bfdd222d6fafbb5bba440 AS launcher
ARG TARGETARCH
WORKDIR /src
COPY engines/images/m365-launcher/go.mod engines/images/m365-launcher/main.go ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -buildvcs=false -trimpath \
      -ldflags='-s -w -buildid=' -o /out/ai-security-scanner-m365-launcher .

FROM --platform=$BUILDPLATFORM python:3.11.13-slim-bookworm@sha256:86adf8dbadc3d6e82ee5dd2c74bec2e1c2467cdad47886280501df722372d2e1 AS prepare
COPY engines/images/m365-launcher/prepare_source.py /opt/prepare_source.py
COPY engines/images/maester/dependencies.lock.json /input/dependencies.lock.json
ADD --checksum=sha256:e634e9bc5521e27adf2fd766ddf34f993a492e5ab8a5c49499c76d7bac69e43f \
    https://github.com/maester365/maester/archive/6bf1d98f094fc7a68e449d2f40f73ef820b72ee3.tar.gz \
    /input/maester.tar.gz
ADD --checksum=sha256:7ac68868f2e12afb6c35df19542b1dfdd07b848bc69f6b45eca3a618e2143f78 \
    https://www.powershellgallery.com/api/v2/package/Microsoft.Graph.Authentication/2.27.0 \
    /input/Microsoft.Graph.Authentication.2.27.0.nupkg
ADD --checksum=sha256:4a27904c6814a5fbe4758f8e49861f6a1994aee77b71165a5c43c0371ba6c580 \
    https://www.powershellgallery.com/api/v2/package/Pester/5.7.1 \
    /input/Pester.5.7.1.nupkg
ADD --checksum=sha256:4a8c3c98b9976aad4fd04308c7b1711ce6578a6a8be2ef172b0f28d79d7e62f7 \
    https://raw.githubusercontent.com/microsoftgraph/msgraph-sdk-powershell/b339b370f7b3b23fe7a0e359f029ca68ab1ebdb1/LICENSE.txt \
    /third-party/Microsoft.Graph.Authentication-LICENSE.txt
ADD --checksum=sha256:6a2fc73db70e674162600052e12a6537e93b51d5dfcf2340c4ed08cdb174debb \
    https://raw.githubusercontent.com/Pester/Pester/dc45b7481fffc4f6c2ff1a74edebaad03ce1efcb/LICENSE \
    /third-party/Pester-LICENSE
RUN python3 /opt/prepare_source.py \
      --engine maester \
      --source /input/maester.tar.gz \
      --lock /input/dependencies.lock.json \
      --output /prepared \
      --package Microsoft.Graph.Authentication=/input/Microsoft.Graph.Authentication.2.27.0.nupkg \
      --package Pester=/input/Pester.5.7.1.nupkg

FROM mcr.microsoft.com/powershell:7.5-azurelinux-3.0@sha256:74b9b9d43da4d04c349bd358dd2db14ee01f0ab17769e402cf0ae4bd9fdd2f2b AS powershell-amd64
FROM mcr.microsoft.com/powershell:7.5-azurelinux-3.0-arm64@sha256:60d31793816646c4dd80b719b350ca68c8a53c000cbb2740655ddafe5e127903 AS powershell-arm64
FROM powershell-${TARGETARCH}

ARG SOURCE_DATE_EPOCH
LABEL org.opencontainers.image.title="ai-security-scanner Maester engine" \
      org.opencontainers.image.description="Pinned-source Microsoft Entra ID test suite through one protected Graph token" \
      org.opencontainers.image.source="https://github.com/teddashh/ai-security-scanner" \
      org.opencontainers.image.revision="6bf1d98f094fc7a68e449d2f40f73ef820b72ee3" \
      org.opencontainers.image.version="2.0.0-3" \
      org.opencontainers.image.licenses="MIT AND Apache-2.0" \
      io.ai-security-scanner.source-archive-sha256="e634e9bc5521e27adf2fd766ddf34f993a492e5ab8a5c49499c76d7bac69e43f" \
      io.ai-security-scanner.profile="entra-graph-token"

COPY --from=prepare /prepared/engine/Maester /opt/ai-security-scanner/Maester
COPY --from=prepare /prepared/tests /opt/ai-security-scanner/maester-tests
COPY --from=prepare /prepared/modules /opt/ai-security-scanner/modules
COPY --from=prepare --chmod=0444 /prepared/dependencies.lock.json /opt/ai-security-scanner/dependencies.lock.json
COPY --from=launcher --chmod=0555 /out/ai-security-scanner-m365-launcher /usr/local/bin/ai-security-scanner-m365-launcher
COPY --chmod=0444 engines/images/maester/run-maester.ps1 /opt/ai-security-scanner/run-maester.ps1

COPY --from=prepare --chmod=0444 /prepared/licenses/Maester-LICENSE /usr/share/licenses/maester/LICENSE
COPY --from=prepare --chmod=0444 /prepared/modules/Microsoft.Graph.Authentication/2.27.0/Microsoft.Graph.Authentication.nuspec /usr/share/licenses/maester/Microsoft.Graph.Authentication.nuspec
COPY --from=prepare --chmod=0444 /prepared/modules/Pester/5.7.1/Pester.nuspec /usr/share/licenses/maester/Pester.nuspec
COPY --from=prepare --chmod=0444 /third-party/Microsoft.Graph.Authentication-LICENSE.txt /usr/share/licenses/maester/Microsoft.Graph.Authentication-LICENSE.txt
COPY --from=prepare --chmod=0444 /third-party/Pester-LICENSE /usr/share/licenses/maester/Pester-LICENSE
COPY --chmod=0444 engines/images/maester/THIRD-PARTY-NOTICES.md /usr/share/licenses/maester/THIRD-PARTY-NOTICES.md

ENV DOTNET_CLI_TELEMETRY_OPTOUT="1" \
    DOTNET_NOLOGO="1" \
    HOME="/tmp/ai-security-scanner-home" \
    NUGET_XMLDOC_MODE="skip" \
    PATH="/opt/microsoft/powershell/7:/usr/local/bin:/usr/bin:/bin" \
    POWERSHELL_TELEMETRY_OPTOUT="1" \
    POWERSHELL_UPDATECHECK="Off" \
    PSModulePath="/opt/ai-security-scanner/modules:/opt/microsoft/powershell/7/Modules" \
    XDG_CACHE_HOME="/tmp/ai-security-scanner-cache" \
    XDG_CONFIG_HOME="/tmp/ai-security-scanner-config" \
    XDG_DATA_HOME="/tmp/ai-security-scanner-data"

RUN chmod 0555 /usr/share/licenses/maester

USER 65532:65532
RUN pwsh -NoLogo -NoProfile -NonInteractive -Command \
      '$ErrorActionPreference="Stop"; Import-Module Microsoft.Graph.Authentication -RequiredVersion 2.27.0; Import-Module Pester -RequiredVersion 5.7.1; Import-Module /opt/ai-security-scanner/Maester/Maester.psd1; if ((Get-Module Maester).Version -ne [version]"2.0.0") { throw "Maester version mismatch" }; if (-not (Test-Path -LiteralPath /opt/ai-security-scanner/maester-tests/Maester/Entra/Test-MtDomainsDmarcRecordMaturity.Tests.ps1 -PathType Leaf)) { throw "Pinned Entra test tree is incomplete" }; $tokens=$null; $errors=$null; [void][System.Management.Automation.Language.Parser]::ParseFile("/opt/ai-security-scanner/run-maester.ps1",[ref]$tokens,[ref]$errors); if ($errors.Count) { throw ($errors | Out-String) }'

ENTRYPOINT ["/usr/local/bin/ai-security-scanner-m365-launcher"]
