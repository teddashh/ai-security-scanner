# Third-party notices: Greenbone managed engine

This image contains these principal third-party works:

- Greenbone OpenVAS Scanner 23.50.24, revision
  `26465a11ff0e6a98d60a253265fab5974fc757b6`, under GPL-2.0. Its license and
  complete pinned source archive are shipped in the image.
- Greenbone Community Feed snapshot `202610010558-community`, revision
  `816c24126e0375d32c667b78d20342ce7c58ec58`. The feed declares
  `(GPL-2.0-only or GPL-2.0-or-later or GPL-3.0-only) AND ODbL-1.0`; its NASL
  source, database, license texts, signed checksum manifest, and signature are
  included at `/opt/greenbone/feed`.
- Greenbone Notus generated data, revision `202610010540`. The distributed data includes
  its GPL-2.0 and ODbL-1.0 license notices at `/opt/greenbone/notus`.
- Debian and other system packages retained from the pinned official
  Greenbone scanner image. Their package copyright notices remain under
  `/usr/share/doc`.

The wrapper source is part of ai-security-scanner and is distributed under the
repository's Apache-2.0 license. This notice is informational and does not
replace any component's license text.
