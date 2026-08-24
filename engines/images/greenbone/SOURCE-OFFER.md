# Greenbone engine corresponding source

The `ai-security-scanner` Greenbone engine image redistributes GPL-covered
software and the source-form Greenbone Community Feed. This notice identifies
the exact corresponding-source material shipped in the image.

| Component | Distributed revision | Corresponding source in the image |
| --- | --- | --- |
| Greenbone OpenVAS Scanner / `openvasd` | `c3ae607ef632393b7919fb179d30b940d929f713` (`23.50.21`) | `/usr/share/source/openvas-scanner/openvas-scanner-c3ae607ef632393b7919fb179d30b940d929f713.tar.gz` |
| Greenbone Community Feed | `b26d7237d56b7cf85e6ace2b9351e7851461b3a8` (`202608240615-community`) | The executable NASL source, metadata, checksums, signature, and licenses are installed directly at `/opt/greenbone/feed` |
| Greenbone Notus data | `4635b37aecd2d968680c7609a7fb61e5d780ce93` | The source-form advisory/product data and licenses are installed at `/opt/greenbone/notus` |
| ai-security-scanner Greenbone launcher and build recipe | image source revision | `/usr/share/source/ai-security-scanner-greenbone/` |

The upstream source archives are checksum-locked in the included Dockerfile.
The scanner archive SHA-256 is
`47cbc7fbff0e19c4533f48c6e7287298f1466d1556f0fc4a7177c37506a3d5e8`.
The Greenbone launcher contains the bounded SOCKS5 relay implementation used
by the image, so no opaque or preloaded network shim is part of the runtime.

For at least three years after the last distribution of this image, any third
party may request any additional machine-readable Corresponding Source needed
for a GPL-covered binary in this image by opening a public issue at
<https://github.com/teddashh/ai-security-scanner/issues>. It will be provided
for no more than the reasonable physical cost of conveying the source.
