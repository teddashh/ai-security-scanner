# Trivy OS-package vulnerability database notice

The managed image embeds Trivy DB schema 2 from the immutable OCI manifest
`ghcr.io/aquasecurity/trivy-db@sha256:a61aa42edc534843230ca24ef72ef322a2da18d717c3de4b6277f4aac43926a1`.
Its database layer is
`sha256:8cf3aaad2dde16ff1529445dab19c2e2a9adc457dbe8d2b02fdbce06b0f638dc`
and reports `UpdatedAt` `2026-08-24T06:55:32.451220873Z`.

This image intentionally does not embed Trivy's separate Java vulnerability
database. The project-owned launcher fixes every managed Trivy invocation to
`--scanners vuln --pkg-types os`, uses an in-memory scan cache, and disables
standard-database, Java-database, VEX-repository, version, and telemetry update
paths. Consequently, this integration reports vulnerabilities only for OS
packages recognized in the supplied snapshot. It does not analyze language
packages or JAR dependencies and does not perform IaC misconfiguration checks.
The complementary managed Grype profile retains offline container
language-package and JAR coverage.

Trivy and the trivy-db build software are Apache-2.0. The database aggregates
upstream security advisories; attribution and use conditions remain those of
the named advisory providers represented in the database. The scanner records
the exact database digest and date with every run and never updates it in place.
