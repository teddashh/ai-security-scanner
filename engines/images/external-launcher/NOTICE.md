# Managed external-engine launcher

`main.go` is the project-owned, non-shell entrypoint used by the managed Naabu,
httpx, and Nuclei images. It consumes only the runtime-owned frozen scope file,
turns each grant into an isolated scanner invocation, and writes normalized
JSONL evidence attributed to the exact asset and grant.

The launcher intentionally denies ambient scanner arguments, direct network
access, unapproved targets and ports, expired grants, updates, stdin, redirects,
Nuclei OAST, and Nuclei templates outside the exact embedded allowlist. All
scanner traffic must use the runtime-provided literal-IP SOCKS5h bridge.
