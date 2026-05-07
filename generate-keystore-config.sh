#!/bin/bash
set -euo pipefail

if [[ -z "${KEYSTORE:-}" || -z "${STORE_PASSWORD:-}" || -z "${KEY_PASSWORD:-}" ]]; then
  echo "Missing KEYSTORE, STORE_PASSWORD, or KEY_PASSWORD environment variable" >&2
  exit 1
fi

echo "${KEYSTORE}" | base64 -d > app/secret.keystore

echo "storePassword=${STORE_PASSWORD}" > keystore.properties
echo "keyPassword=${KEY_PASSWORD}" >> keystore.properties
echo "keyAlias=release" >> keystore.properties
echo "storeFile=secret.keystore" >> keystore.properties
