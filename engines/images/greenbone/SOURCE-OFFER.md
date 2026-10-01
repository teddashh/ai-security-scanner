# Greenbone engine corresponding source

The `ai-security-scanner` Greenbone engine image redistributes GPL-covered
software and the source-form Greenbone Community Feed. This notice identifies
the exact corresponding-source material shipped in the image.

| Component | Distributed revision | Corresponding source in the image |
| --- | --- | --- |
| Greenbone OpenVAS Scanner / `openvasd` | `26465a11ff0e6a98d60a253265fab5974fc757b6` (`23.50.24`) | `/usr/share/source/openvas-scanner/openvas-scanner-23.50.24.tar.gz` |
| Greenbone Community Feed | `816c24126e0375d32c667b78d20342ce7c58ec58` (`202610010558-community`) | The executable NASL source, metadata, checksums, signature, and licenses are installed directly at `/opt/greenbone/feed` |
| Greenbone Notus data | `202610010540` | The source-form advisory/product data and licenses are installed at `/opt/greenbone/notus` |
| ai-security-scanner Greenbone launcher and build recipe | image source revision | `/usr/share/source/ai-security-scanner-greenbone/` |

The upstream source archives are checksum-locked in the included Dockerfile.
The scanner archive SHA-256 is
`af8b1e0175dfc57f38bdecc08607dbac294459e684e2f3e7d69c85101fa13517`.
The Greenbone launcher contains the bounded SOCKS5 relay implementation used
by the image, so no opaque or preloaded network shim is part of the runtime.

For at least three years after the last distribution of this image, any third
party may request any additional machine-readable Corresponding Source needed
for a GPL-covered binary in this image by opening a public issue at
<https://github.com/teddashh/ai-security-scanner/issues>. It will be provided
for no more than the reasonable physical cost of conveying the source.
