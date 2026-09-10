# glib 0.18.5 backport provenance

This directory is the published `glib 0.18.5` crate with one upstream fix
backported for the Tauri Linux GTK3 dependency chain.

| Field | Value |
| --- | --- |
| Source artifact | `https://static.crates.io/crates/glib/glib-0.18.5.crate` |
| Artifact SHA-256 | `233daaf6e83ae6a12a52055f568f9d7cf4671dabb78ff9560ab6da230ce00ee5` |
| License | MIT |
| Backported fix | `gtk-rs/gtk-rs-core#1343` |
| Advisory | `GHSA-wrw7-89jp-8q8g` / `RUSTSEC-2024-0429` |

The only change to the published crate is in `src/variant_iter.rs`:

```diff
-            let p: *mut libc::c_char = std::ptr::null_mut();
+            let mut p: *mut libc::c_char = std::ptr::null_mut();
...
-                &p,
+                &mut p,
```

`scripts/verify-vendored-glib.sh` downloads the checksum-pinned crate and
proves that the vendored tree contains exactly those two changed lines plus
this provenance file.

Remove the override and this directory when Tauri's supported Linux graph
uses `glib >= 0.20.0`, or when gtk-rs publishes a compatible fixed 0.18 release.
