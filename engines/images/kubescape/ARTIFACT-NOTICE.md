# Kubescape offline policy notice

The managed image scans explicit local Kubernetes manifests only and embeds
three checksum-pinned assets from the Apache-2.0 Kubescape regolibrary `v2`
release, annotated tag object `844c0de2436a45c58bdb669052ac20ca53c8a327`
and source commit `a12188c49147bb6ec379b42a4159d3d5852634b8`:

- `nsa`: `sha256:7f7d7bbc6908b9872fd71751dc8d5dd5f543cdd6a684a24d1fb15b686e8344db`
- `default_config_inputs`: `sha256:df4e2431e8f560961ce56aa06e022caf9b2f82f98752de78df1cd0706b42cf3a`
- `exceptions`: `sha256:bf44e01e6b212c8e8c0ca0686d1bd84488e3f9ce5375cd36511c8faef3a44e7b`

The fixed launcher verifies all three files before execution, explicitly opts
out of submission and host scanning, and supplies no network route.
