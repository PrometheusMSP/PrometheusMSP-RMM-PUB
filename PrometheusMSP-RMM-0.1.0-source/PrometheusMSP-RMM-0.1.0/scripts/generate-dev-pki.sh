#!/usr/bin/env sh
set -eu

umask 077
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
out="$root/deploy/pki"
mkdir -p "$out"

if [ -e "$out/ca.key" ] || [ -e "$out/server.key" ]; then
  echo "Refusing to overwrite existing PKI in $out" >&2
  exit 1
fi

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$out/ca.key"
openssl req -x509 -new -sha256 -days 30 -key "$out/ca.key" -out "$out/ca.crt" \
  -subj "/CN=Prometheus RMM Development CA"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$out/server.key"
openssl req -new -sha256 -key "$out/server.key" -out "$out/server.csr" \
  -subj "/CN=localhost"
printf '%s\n' 'subjectAltName=DNS:localhost,IP:127.0.0.1' 'extendedKeyUsage=serverAuth' > "$out/server.ext"
openssl x509 -req -sha256 -days 30 -in "$out/server.csr" -CA "$out/ca.crt" \
  -CAkey "$out/ca.key" -CAcreateserial -extfile "$out/server.ext" -out "$out/server.crt"
openssl genpkey -algorithm ED25519 -out "$out/job-signing-private.pem"
openssl pkey -in "$out/job-signing-private.pem" -pubout -out "$out/job-signing-public.pem"
rm -f "$out/server.csr" "$out/server.ext" "$out/ca.srl"
chmod 600 "$out"/*.key "$out"/*private.pem
chmod 644 "$out"/*.crt "$out"/*public.pem
echo "Development-only PKI written to $out (30-day certificates)."
