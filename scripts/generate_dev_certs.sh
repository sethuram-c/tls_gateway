#!/usr/bin/env bash
# Generate a disposable local CA and TLS server certificate for study only.
set -euo pipefail

if [[ ${1:-} == "--help" || $# -gt 1 ]]; then
  echo "Usage: bash scripts/generate_dev_certs.sh [output_directory]"
  exit 0
fi

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
out_dir=${1:-"$repo_root/certs"}
parent_dir=$(dirname -- "$out_dir")

if [[ -e "$out_dir" || -L "$out_dir" ]]; then
  echo "Refusing to overwrite existing path: $out_dir" >&2
  exit 1
fi
if [[ ! -d "$parent_dir" ]]; then
  echo "Parent directory does not exist: $parent_dir" >&2
  exit 1
fi
if ! command -v openssl >/dev/null 2>&1; then
  echo "OpenSSL is required (sudo dnf install openssl)" >&2
  exit 1
fi

# Files made by this script, including private keys, are readable only by you.
umask 077
work_dir=$(mktemp -d "$parent_dir/.tls-gateway-certs.XXXXXXXX")
cleanup() { if [[ -n "${work_dir:-}" && -d "$work_dir" ]]; then rm -rf -- "$work_dir"; fi; }
trap cleanup EXIT

# 1) A self-signed development Certificate Authority (CA).
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "$work_dir/ca.key" >/dev/null 2>&1
openssl req -new -x509 -sha256 -days 30 \
  -key "$work_dir/ca.key" -out "$work_dir/ca.crt" \
  -subj '/CN=TLS Gateway Lab CA' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  >/dev/null 2>&1

# 2) An independent server key and Certificate Signing Request (CSR).
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "$work_dir/server.key" >/dev/null 2>&1
openssl req -new -sha256 -key "$work_dir/server.key" \
  -out "$work_dir/server.csr" -subj '/CN=localhost' \
  >/dev/null 2>&1

# 3) The CA signs a server certificate, including DNS and IP SAN entries.
cat > "$work_dir/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
openssl x509 -req -sha256 -days 30 \
  -in "$work_dir/server.csr" \
  -CA "$work_dir/ca.crt" -CAkey "$work_dir/ca.key" -CAcreateserial \
  -extfile "$work_dir/server.ext" -out "$work_dir/server.crt" \
  >/dev/null 2>&1

# 4) Fail early if the issued certificate is not valid for our lab hostname/IP.
openssl verify -CAfile "$work_dir/ca.crt" -purpose sslserver \
  -verify_hostname localhost "$work_dir/server.crt" >/dev/null
openssl verify -CAfile "$work_dir/ca.crt" -purpose sslserver \
  -verify_ip 127.0.0.1 "$work_dir/server.crt" >/dev/null

# The CSR, extension file and generated serial are intermediate materials.
rm -f -- "$work_dir/server.csr" "$work_dir/server.ext" "$work_dir/ca.srl"

# Atomic directory rename: no half-written certs/ in the successful case.
mv -T -- "$work_dir" "$out_dir"
trap - EXIT
printf 'Local development certificates generated in: %s\n' "$out_dir"
printf 'CA: ca.crt, ca.key | server: server.crt, server.key\n'
printf 'Do NOT commit private keys or trust this CA system-wide.\n'
