#!/bin/sh
set -e

# Register the relayer key and testnet config on first boot
stellar network add testnet \
  --rpc-url https://soroban-testnet.stellar.org \
  --network-passphrase "Test SDF Network ; September 2015" 2>/dev/null || true

if [ -z "$RELAYER_SECRET" ]; then
  echo "ERROR: RELAYER_SECRET env var not set"
  exit 1
fi

echo "$RELAYER_SECRET" | stellar keys add relayer --secret-key 2>/dev/null || true

exec node server.js
