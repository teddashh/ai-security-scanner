# Grype vulnerability database notice

The managed image embeds Anchore Grype DB schema `v6.1.9`, built
`2026-08-24T06:22:13Z`, from the checksum-pinned archive
`vulnerability-db_v6.1.9_2026-08-24T00:17:18Z_1787552533.tar.zst`.
The archive digest is
`sha256:20a7315860b2d07231103a73bedec01de31e7a7f3d590aedfc61709dc9e117f9`
and the extracted SQLite database digest is
`sha256:db6f590412955f6b58cec12bfa4b712b2626eef9a030bffd8f32b9ebce074ff8`.
The required Grype import metadata records the independently calculated
`xxh64:a30ef08fe392f331` database digest, client schema `v6.1.9`, and fixed
archive URL; its SHA-256 is
`sha256:b1382ad7455d20f5af33ac4a9dacb2376d35321c353f078bdafe69a533661afc`.

Grype is Apache-2.0. The database aggregates upstream advisory providers whose
attribution and use conditions remain applicable. The scanner records the
exact database digest and build time with every run and never updates it in
place.
