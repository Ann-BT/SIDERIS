#!/bin/bash
# scripts/tunnel.sh
# Entry point for tunneling, delegates to Node.js scripts/tunnel.js

# Find project directory path
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
node "$DIR/tunnel.js" "$@"
