# Third-party notices: Greenbone managed engine

This image contains these principal third-party works:

- Greenbone OpenVAS Scanner 23.50.21, revision
  `c3ae607ef632393b7919fb179d30b940d929f713`, under GPL-2.0. Its license and
  complete pinned source archive are shipped in the image.
- Greenbone Community Feed snapshot `202608240615-community`, revision
  `b26d7237d56b7cf85e6ace2b9351e7851461b3a8`. The feed declares
  `(GPL-2.0-only or GPL-2.0-or-later or GPL-3.0-only) AND ODbL-1.0`; its NASL
  source, database, license texts, signed checksum manifest, and signature are
  included at `/opt/greenbone/feed`.
- Greenbone Notus generated data, revision
  `4635b37aecd2d968680c7609a7fb61e5d780ce93`. The distributed data includes
  its GPL-2.0 and ODbL-1.0 license notices at `/opt/greenbone/notus`.
- Debian and other system packages retained from the pinned official
  Greenbone scanner image. Their package copyright notices remain under
  `/usr/share/doc`.

The wrapper source is part of ai-security-scanner and is distributed under the
repository's Apache-2.0 license. This notice is informational and does not
replace any component's license text.
