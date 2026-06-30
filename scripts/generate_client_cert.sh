#!/usr/bin/env bash
# Phase 30: issue a disposable TLS *client* certificate under the lab CA.
# Never commit certs/ or install the development CA system-wide.
set -euo pipefail

if [[ $# -gt 1 || ${1:-} == '--help' ]]; then
  echo 'Usage: bash scripts/generate_client_cert.sh [certs_directory]'
  exit 0
fi

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cert_dir=${1:-"$repo_root/certs"}
if [[ ! -f "$cert_dir/ca.crt" || ! -f "$cert_dir/ca.key" ]]; then
  echo 'Missing local CA. Run make certs first.' >&2
  exit 1
fi
for path in "$cert_dir/client.key" "$cert_dir/client.crt"; do
  if [[ -e "$path" || -L "$path" ]]; then
    echo "Refusing to overwrite: $path" >&2
    exit 1
  fi
done
if ! command -v openssl >/dev/null 2>&1; then
  echo 'OpenSSL is required.' >&2
  exit 1
fi

umask 077
work_dir=$(mktemp -d "$cert_dir/.mtls-client.XXXXXXXX")
trap 'rm -rf -- "$work_dir"' EXIT

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "$work_dir/client.key" >/dev/null 2>&1
openssl req -new -sha256 -key "$work_dir/client.key" \
  -out "$work_dir/client.csr" -subj '/CN=tls-gateway-lab-client' >/dev/null 2>&1
cat > "$work_dir/client.ext" <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EXT
serial="0x$(openssl rand -hex 16)"
openssl x509 -req -sha256 -days 30 \
  -in "$work_dir/client.csr" \
  -CA "$cert_dir/ca.crt" -CAkey "$cert_dir/ca.key" \
  -set_serial "$serial" -extfile "$work_dir/client.ext" \
  -out "$work_dir/client.crt" >/dev/null 2>&1
openssl verify -CAfile "$cert_dir/ca.crt" \
  -purpose sslclient "$work_dir/client.crt" >/dev/null

# Avoid changing existing CA files or the previously issued server certificate.
mv -n -- "$work_dir/client.key" "$cert_dir/client.key"
mv -n -- "$work_dir/client.crt" "$cert_dir/client.crt"
printf 'Generated client.crt and client.key in %s\n' "$cert_dir"
printf 'Development client certificate: extendedKeyUsage=clientAuth\n'
printf 'Keep ca.key and client.key private; never commit certs/.\n'
