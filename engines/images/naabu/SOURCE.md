# Naabu source record

This image is built from the upstream Naabu source at commit
`5a0ca8bde91b5bb16213e9e8b5c6871eac954bd8` (release `v2.6.1`).

- Repository: <https://github.com/projectdiscovery/naabu>
- Source archive: <https://github.com/projectdiscovery/naabu/archive/5a0ca8bde91b5bb16213e9e8b5c6871eac954bd8.tar.gz>
- Source archive SHA-256: `0f2dd95b86692513d0c9a077f8332b33d52e6aba2e5955257aa0b2c74aae1e8b`
- `go.sum` SHA-256: `7b7604e76aa7692564fb95b76368de214189facb7e8bdd51f3f210531afd46a6`
- License: MIT; the image carries `/usr/share/licenses/naabu/LICENSE.md`.

The project-owned launcher source is in `engines/images/external-launcher`.
Build from the repository root with `docker build -f engines/images/naabu/Dockerfile .`.
