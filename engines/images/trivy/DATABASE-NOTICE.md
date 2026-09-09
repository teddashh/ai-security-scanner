# Trivy package-vulnerability database notice

The managed image embeds Trivy DB schema 2 from the immutable OCI manifest
`ghcr.io/aquasecurity/trivy-db@sha256:a61aa42edc534843230ca24ef72ef322a2da18d717c3de4b6277f4aac43926a1`.
Its database layer is
`sha256:8cf3aaad2dde16ff1529445dab19c2e2a9adc457dbe8d2b02fdbce06b0f638dc`
and reports `UpdatedAt` `2026-08-24T06:55:32.451220873Z`.

The image also embeds Trivy Java DB schema 1 from the immutable OCI manifest
`ghcr.io/aquasecurity/trivy-java-db@sha256:0a8596207372125cf30d5625d2ecbd05a5656d6b4463a455d85fac2c84778829`.
Its `application/vnd.aquasec.trivy.javadb.layer.v1.tar+gzip` layer is
`sha256:9077545235eeea3da457263c10255e7d1bf0a748f21f4f9ef5e49135c79a4de4`,
contains only `trivy-java.db` and `metadata.json`, and reports `UpdatedAt`
`2026-09-09T01:11:59.619689416Z`. This separate index lets upstream Trivy
resolve otherwise unidentified JAR contents; vulnerability matching still uses
the standard database above.

The project-owned launcher fixes every managed Trivy invocation to `--scanners
vuln`. Repository and IaC snapshots receive two non-overlapping upstream
profiles: Trivy `filesystem` with `--pkg-types library` for lockfiles, followed
by Trivy `rootfs` with `--pkg-types library` for individual package archives and
binaries such as JARs. Single-image OCI layout snapshots receive only
`--pkg-types os`. All profiles use an in-memory scan cache and disable
standard-database, Java-database, VEX-repository, version, and telemetry update
paths. Consequently, OCI image runs remain deliberately limited to recognized
OS packages. This image does not perform IaC misconfiguration checks. The
complementary managed Grype container profile retains offline OCI-image
language-package and JAR-archive coverage.

Trivy, trivy-db, and trivy-java-db are Apache-2.0. The vulnerability database
aggregates upstream security advisories; attribution and use conditions remain
those of the named advisory providers represented in the database. The scanner
records immutable database provenance and never updates either database in
place.
