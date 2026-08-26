# httpx source record

This image is built from the upstream httpx source at commit
`13037dd08b9715cfbd960a70ae1edfef6686a857` (release `v1.10.0`).

- Repository: <https://github.com/projectdiscovery/httpx>
- Source archive: <https://github.com/projectdiscovery/httpx/archive/13037dd08b9715cfbd960a70ae1edfef6686a857.tar.gz>
- Source archive SHA-256: `94ae90ef3a2551bbc81c0814bd157387ab9c9bda54d1f5e38aaa708b95570946`
- `go.sum` SHA-256: `97ea2eed27767ae6d1e31b4d56b1e2c9a69235cdc76f89cdb79c199e621029b5`
- Reviewed managed-image source helper: `patch_live_dns.go`
- `runner/runner.go` before helper SHA-256: `748502c7633140c7395d73d3b7d91eaa2efa324a5567cfc7b7a57485a1f9a641`
- `runner/runner.go` after helper SHA-256: `6e8c7c8e59f6f7e574af0ff3b87cf3cd74e8e9d814618108dedeb9620fdbab95`
- Licenses: upstream httpx is MIT and the project launcher is Apache-2.0; the
  image carries both license texts below `/usr/share/licenses`.

The reviewed helper removes httpx's unconditional post-request DNS enrichment.
The actual request still uses the authorized hostname through the managed
remote-name SOCKS proxy, preserving HTTP Host and TLS SNI without giving the
scanner a second live DNS path. The image build checks the exact source hash
both before and after this single replacement.

The project-owned launcher source is in `engines/images/external-launcher`.
Build from the repository root with `docker build -f engines/images/httpx/Dockerfile .`.
