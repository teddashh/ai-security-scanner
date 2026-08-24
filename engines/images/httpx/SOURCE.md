# httpx source record

This image is built from the upstream httpx source at commit
`13037dd08b9715cfbd960a70ae1edfef6686a857` (release `v1.10.0`).

- Repository: <https://github.com/projectdiscovery/httpx>
- Source archive: <https://github.com/projectdiscovery/httpx/archive/13037dd08b9715cfbd960a70ae1edfef6686a857.tar.gz>
- Source archive SHA-256: `94ae90ef3a2551bbc81c0814bd157387ab9c9bda54d1f5e38aaa708b95570946`
- `go.sum` SHA-256: `97ea2eed27767ae6d1e31b4d56b1e2c9a69235cdc76f89cdb79c199e621029b5`
- Licenses: upstream httpx is MIT and the project launcher is Apache-2.0; the
  image carries both license texts below `/usr/share/licenses`.

The project-owned launcher source is in `engines/images/external-launcher`.
Build from the repository root with `docker build -f engines/images/httpx/Dockerfile .`.
