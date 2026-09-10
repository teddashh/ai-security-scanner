#!/usr/bin/env bash

set -euo pipefail

readonly upstream_url="https://static.crates.io/crates/glib/glib-0.18.5.crate"
readonly upstream_sha256="233daaf6e83ae6a12a52055f568f9d7cf4671dabb78ff9560ab6da230ce00ee5"
readonly vendored_dir="vendor/glib-0.18.5"
readonly patched_file="src/variant_iter.rs"

for tool in curl tar sha256sum cmp sed find; do
  command -v "${tool}" >/dev/null || {
    printf 'Missing required command: %s\n' "${tool}" >&2
    exit 2
  }
done

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/ass-glib-verify.XXXXXX")"
cleanup() {
  case "${work_dir}" in
    "${TMPDIR:-/tmp}"/ass-glib-verify.*) rm -rf -- "${work_dir}" ;;
    *) printf 'Refusing unexpected temporary path: %s\n' "${work_dir}" >&2 ;;
  esac
}
trap cleanup EXIT

curl --fail --silent --show-error --location --retry 3 \
  --output "${work_dir}/glib.crate" "${upstream_url}"
printf '%s  %s\n' "${upstream_sha256}" "${work_dir}/glib.crate" | sha256sum --check --status
tar -xzf "${work_dir}/glib.crate" -C "${work_dir}"
readonly upstream_dir="${work_dir}/glib-0.18.5"

failed=0
while IFS= read -r -d '' upstream_file; do
  relative_path="${upstream_file#"${upstream_dir}/"}"
  vendored_file="${vendored_dir}/${relative_path}"
  if [[ ! -f "${vendored_file}" ]]; then
    printf 'Vendored glib is missing %s\n' "${relative_path}" >&2
    failed=1
    continue
  fi

  if [[ "${relative_path}" == "${patched_file}" ]]; then
    sed \
      -e 's/            let p: \*mut libc::c_char = std::ptr::null_mut();/            let mut p: *mut libc::c_char = std::ptr::null_mut();/' \
      -e 's/                &p,/                \&mut p,/' \
      "${upstream_file}" > "${work_dir}/expected-variant-iter.rs"
    if ! cmp --silent "${work_dir}/expected-variant-iter.rs" "${vendored_file}"; then
      printf 'Vendored glib patch differs from gtk-rs/gtk-rs-core#1343\n' >&2
      failed=1
    fi
  elif ! cmp --silent "${upstream_file}" "${vendored_file}"; then
    printf 'Vendored glib file differs from the published crate: %s\n' "${relative_path}" >&2
    failed=1
  fi
done < <(find "${upstream_dir}" -type f -print0)

while IFS= read -r -d '' vendored_file; do
  relative_path="${vendored_file#"${vendored_dir}/"}"
  if [[ "${relative_path}" != "PROVENANCE.md" && ! -f "${upstream_dir}/${relative_path}" ]]; then
    printf 'Unexpected file in vendored glib: %s\n' "${relative_path}" >&2
    failed=1
  fi
done < <(find "${vendored_dir}" -type f -print0)

if [[ "${failed}" -ne 0 ]]; then
  exit 1
fi

printf 'Vendored glib matches crates.io 0.18.5 plus the exact upstream security fix.\n'
