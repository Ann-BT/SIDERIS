FROM node:20-alpine

# Install system dependencies
RUN apk add --no-cache git python3 make g++

WORKDIR /app

# ── Install root dependencies ──────────────────────────────────
COPY package.json package-lock.json ./
RUN npm ci

# ── Install dashboard UI dependencies ─────────────────────────
COPY src/dashboard/ui/package.json src/dashboard/ui/package-lock.json ./src/dashboard/ui/
RUN cd src/dashboard/ui && npm ci

# ── Install terser for agent.js obfuscation ───────────────────
# terser minifies + obfuscates the client-side agent so the telemetry
# collection logic is not human-readable even if someone inspects the
# page source or downloads the Docker image.
RUN npm install -g terser

# ── Copy all project files ────────────────────────────────────
COPY . .

# ── Obfuscate agent.js ────────────────────────────────────────
# Replaces the readable source with a minified + mangled version.
# The original source stays in your repo (for development) but
# the deployed image only ships the obfuscated build.
RUN terser src/agent/agent.js \
      --compress \
      --mangle \
      --mangle-props "regex=/^_sideris/" \
      --output src/agent/agent.js \
  && echo "[build] agent.js obfuscated successfully"

# ── Expose SIDERIS ports ──────────────────────────────────────
# 4000 : WAF Proxy        (user-facing — monitored website)
# 5000 : Telemetry Ingest (internal only)
# 6001 : Dashboard API    (internal only)
# 5173 : Dashboard UI     (internal only — SOC analysts)
EXPOSE 4000 5000 6001 5173

CMD ["npm", "run", "start-all"]
