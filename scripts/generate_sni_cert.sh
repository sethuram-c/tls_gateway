#!/usr/bin/env bash
# Phase 27: issue an additional development certificate for api.test.
# Requires an existing disposable CA from scripts/generate_dev_certs.sh.
set -euo pipefail

if [[ $# -gt 1 || ${1:-} == '--help' ]]; then
  echo 'Usage: bash scripts/generate_sni_cert.sh [certs_directory]'
  exit 0
fi

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cert_dir=${1:-"$repo_root/certs"}
if [[ ! -f "$cert_dir/ca.crt" || ! -f "$cert_dir/ca.key" ]]; then
  echo 'Missing CA. Run make certs first.' >&2
  exit 1
fi
if [[ -e "$cert_dir/api.test.key" || -L "$cert_dir/api.test.key" ||
      -e "$cert_dir/api.test.crt" || -L "$cert_dir/api.test.crt" ]]; then
  echo 'Refusing to overwrite existing api.test certificate/key' >&2
  exit 1
fi
umask 077
work_dir=$(mktemp -d "$cert_dir/.sni-cert.XXXXXXXX")
cleanup() { rm -rf -- "$work_dir"; }
trap cleanup EXIT

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "$work_dir/api.test.key" >/dev/null 2>&1
openssl req -new -sha256 -key "$work_dir/api.test.key" \
  -out "$work_dir/api.test.csr" -subj '/CN=api.test' >/dev/null 2>&1
cat > "$work_dir/api.test.ext" <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:api.test
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EXT
# Supply our own random serial; do not change ca.srl in the existing cert directory.
serial="0x$(openssl rand -hex 16)"
openssl x509 -req -sha256 -days 30 \
  -in "$work_dir/api.test.csr" \
  -CA "$cert_dir/ca.crt" -CAkey "$cert_dir/ca.key" \
  -set_serial "$serial" -extfile "$work_dir/api.test.ext" \
  -out "$work_dir/api.test.crt" >/dev/null 2>&1
openssl verify -purpose sslserver -verify_hostname api.test \
  -CAfile "$cert_dir/ca.crt" "$work_dir/api.test.crt" >/dev/null

# Certificates/keys stay out of Git. Do not replace existing files.
mv -n -- "$work_dir/api.test.key" "$cert_dir/api.test.key"
mv -n -- "$work_dir/api.test.crt" "$cert_dir/api.test.crt"
printf 'Created api.test.key and api.test.crt in %s\n' "$cert_dir"
printf 'Pass api.test.crt and api.test.key as optional proxy arguments to enable SNI selection.\n'
