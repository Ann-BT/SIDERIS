#!/bin/bash
# ──────────────────────────────────────────────────────────
# scripts/tunnel.sh
# SIDERIS — ngrok Tunnel Helper
# ──────────────────────────────────────────────────────────

NGROK_BIN="/home/merlin/.gemini/antigravity/scratch/ngrok"

# Check if ngrok binary exists
if [ ! -f "$NGROK_BIN" ]; then
  echo "Error: ngrok binary not found at $NGROK_BIN"
  exit 1
fi

if [ "$1" == "auth" ]; then
  if [ -z "$2" ]; then
    echo "Error: Please provide your ngrok authtoken."
    echo "Usage: npm run tunnel-auth <YOUR_TOKEN>"
    exit 1
  fi
  echo "Setting ngrok authtoken..."
  $NGROK_BIN config add-authtoken "$2"
  exit $?
fi

echo "Starting ngrok tunnel for Sideris WAF Proxy (port 4000)..."
echo "Press Ctrl+C to stop the tunnel."
$NGROK_BIN http --domain=setting-cadillac-harmonica.ngrok-free.dev 4000
