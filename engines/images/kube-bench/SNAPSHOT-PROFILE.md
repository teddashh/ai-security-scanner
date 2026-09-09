# Immutable kube-bench node-facts snapshot

Live kube-bench normally needs privileged host namespace access and broad
mounts. The managed integration intentionally does not provide that access.
Instead, a case may contain an explicit, immutable directory at
`node-snapshot/` with a `profile.json` inventory and these five files:

- `kubelet-config.yaml`
- `kubelet.service`
- `kubelet.conf`
- `kube-proxy.yaml`
- `ca.crt`

`profile.json` uses schema `2.0.0`, profile
`cis-kubernetes-node-facts`, benchmark `cis-1.11`, and an ISO-8601
`captured_at`. Its `files` array has exactly one entry for each file above. An
entry records the snapshot `path`, original absolute `source_path`,
`sha256:<64 lowercase hex>`, original octal `mode`, and original `owner` and
`group`. Its `processes` array records exactly one single-line `command` for
each of `kubelet` and `kube-proxy`.

Every file digest and every bounded fact is validated; unlisted files,
symlinks, devices, directories, unknown fields, and unapproved process names
are rejected. The runtime does not execute captured command lines. It only
replays them as immutable `ps` output and replays recorded ownership and mode
as immutable `stat` output. Original file paths in process facts are
mechanically mapped to their verified snapshot copies.

Only `kubelet-config.yaml` and `kube-proxy.yaml` are parsed for configuration
values by this upstream profile. The other three files exist so kube-bench can
evaluate their recorded mode and ownership; use a non-empty redacted
placeholder for their content. Do not attach tokens, private keys, kubeconfig
credentials, or a real certificate. Captured process lines must likewise omit
unrelated secret-bearing arguments. A complete non-secret example is kept in
[`testdata/node-snapshot/profile.json`](testdata/node-snapshot/profile.json).

The scanner then runs kube-bench's pinned, unmodified upstream
`cis-1.11/node.yaml` profile. All 26 upstream node checks, identifiers,
severity-neutral verdicts, evidence, and remediation remain owned by
kube-bench; the product overlay only maps the user-selected snapshot facts to
the paths and process names that profile reads. This is a point-in-time
offline assessment of the exported facts, not a live-node or Kubernetes API
scan.
