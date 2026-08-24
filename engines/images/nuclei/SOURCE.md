# Nuclei source record

This image is built from upstream Nuclei commit
`a8c88feb4a1c8e961b7902534ce3af97e9d524a4` (release `v3.11.1`) and embeds only
the HTTP subtree of the exact Nuclei templates commit
`24858b4bfabfa86f0bcfd36aea24fb535152b012`.

- Nuclei repository: <https://github.com/projectdiscovery/nuclei>
- Nuclei source archive SHA-256: `233fd559f0f2287310709ed0f19613a9e298dbff03ee7f9e0905a0709e8537e4`
- Nuclei `go.sum` SHA-256: `c9be45a7baa2b3fda7d9ecdea91865b9caf78a733c70d1133d346bcc7dba501b`
- Template repository: <https://github.com/projectdiscovery/nuclei-templates>
- Template source archive SHA-256: `1c651703d2fcd3e4134c548b49576db1e5c95e9522ce01246259b3aa2a50813b`
- Licenses: MIT; both upstream license texts are carried below `/usr/share/licenses`.

The project-owned launcher source is in `engines/images/external-launcher`. It
validates every selected template against the conservative read-only HTTP
policy before invoking Nuclei. Build from the repository root with
`docker build -f engines/images/nuclei/Dockerfile .`.
