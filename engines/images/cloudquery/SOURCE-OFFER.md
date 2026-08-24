# CloudQuery corresponding source and reproducible inputs

The managed image intentionally uses the last complete, anonymously available
AWS source-plugin generation in CloudQuery's public monorepo. It does not use
the newer authenticated CloudQuery plugin registry.

The complete corresponding source comes from the exact public release commits
in <https://github.com/cloudquery/cloudquery>. Copies of all three commit
archives are included in the image as:

```text
/usr/share/source/cloudquery/cli-e27e4ab.tar.gz
/usr/share/source/cloudquery/aws-804be3a.tar.gz
/usr/share/source/cloudquery/file-05f0233.tar.gz
```

The source associations and archive SHA-256 values are:

- CLI `v2.0.31`: commit `e27e4ab61ad85479a5d53dae9b08440bc63e72b3`,
  `21e18c3d1348243273231e72a39febd9d7429ac4f1ec36c5bf18c32d509e5996`;
- AWS source plugin `v9.2.0`: commit
  `804be3a90d6f15d3e6c662c0eb7afa88a9596180`,
  `a4788989f99ab02144605539ab552e86c076405ac7516fb673e73ba6bda40c6b`;
- file destination plugin `v1.0.2`: commit
  `05f02334b9d6ed5de344fd9a9cf7ddead31ce453`,
  `21f4b826b9ad4830854130674023b97e443abba17b66a3557cd0805b3083b2d1`.

Together the archives contain the exact component source, their Go module
locks, and the upstream MPL-2.0 license.

The runtime binaries are the upstream public release artifacts for:

- CloudQuery CLI `v2.0.31`;
- CloudQuery AWS source plugin `v9.2.0`;
- CloudQuery file destination plugin `v1.0.2`.

Both Linux architectures are selected from exact SHA-256-locked artifacts in
the adjacent Dockerfile. `dependencies.lock.json`, the fixed local-plugin
configuration, the scanner-owned launcher source, and the Dockerfile are also
copied into `/usr/share/source/cloudquery/build/`.

This older open-source closure has a 2023 knowledge date. The application must
show that age and must not imply that it is the current commercial CloudQuery
AWS plugin. The file plugin emits one newline-delimited JSON file per selected
table under `/output`. Live AWS inventory remains attributable to the case's
short-lived read-only authorization and the exact table set emitted by the
launcher.
