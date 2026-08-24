# Trivy vulnerability database notice

The managed image embeds Trivy DB schema 2 from the immutable OCI manifest
`ghcr.io/aquasecurity/trivy-db@sha256:a61aa42edc534843230ca24ef72ef322a2da18d717c3de4b6277f4aac43926a1`.
Its database layer is
`sha256:8cf3aaad2dde16ff1529445dab19c2e2a9adc457dbe8d2b02fdbce06b0f638dc`
and reports `UpdatedAt` `2026-08-24T06:55:32.451220873Z`.

Trivy and the trivy-db build software are Apache-2.0. The database aggregates
upstream security advisories; attribution and use conditions remain those of
the named advisory providers represented in the database. The scanner records
the exact database digest and date with every run and never updates it in place.
