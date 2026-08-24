# Complete corresponding source and notices

The managed Steampipe image contains the exact Steampipe v2.4.5 source archive at
`/usr/share/source/steampipe/steampipe-v2.4.5.tar.gz`. That archive corresponds to
commit `71fa72fc9ce33897bcb0bd0c9ebf09b867b881cf` and the AGPL-3.0-only executable in
the image. The public ai-security-scanner repository supplies the exact Dockerfile,
scanner-owned launcher, install preparation program, build arguments, and workflow
needed to rebuild it.

The image also carries the exact AWS plugin v1.32.0 source archive (Apache-2.0), the
Steampipe FDW v2.2.5 source archive and license (Apache-2.0), and the PostgreSQL
14.19 copyright notice. OCI content is locked to these release digests:

- embedded PostgreSQL: `sha256:84264ef41853178707bccb091f5450c22e835f8a98f9961592c75690321093d9`
- Steampipe FDW: `sha256:62b654db44ca6f7f6894e8f53e5dcad9530d356253273ebf05f92109d5ca7457`

No plugin registry, update service, or telemetry endpoint is contacted at runtime.
For the AGPL source-request path, open a public issue in
`https://github.com/teddashh/ai-security-scanner`; the in-image source remains the
immediate, version-matched offer.
