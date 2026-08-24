# Immutable kube-bench node snapshot profile

Live kube-bench normally needs privileged host namespace access and broad
mounts. The managed integration intentionally does not provide that access.
Instead, a case may contain an explicit, immutable directory at
`node-snapshot/` with a `profile.json` inventory and one or more of these
narrow files:

- `kubelet-config.yaml`
- `kubelet.service`
- `kubelet.conf`
- `kube-proxy.yaml`
- `ca.crt`

`profile.json` uses schema `1.0.0`, profile
`cis-kubernetes-node-config`, an ISO-8601 `captured_at`, and a `files` array of
`path` plus `sha256:<64 lowercase hex>` entries. Every listed digest is verified
and unlisted files, symlinks, devices, and directories are rejected.

This profile provides configuration-file coverage only. It cannot truthfully
claim live process, host ownership, host permission, runtime flag, or API
coverage; those checks remain absent rather than inferred.
