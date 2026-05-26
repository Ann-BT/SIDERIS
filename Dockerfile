FROM node:20-alpine

# Install system dependencies (e.g., git and python/make if any native dependencies exist)
RUN apk add --no-cache git python3 make g++

WORKDIR /app

# Copy package descriptors for root
COPY package.json package-lock.json ./
RUN npm ci

# Copy package descriptors for dashboard UI and install its dependencies
COPY src/dashboard/ui/package.json src/dashboard/ui/package-lock.json ./src/dashboard/ui/
RUN cd src/dashboard/ui && npm ci

# Copy all project files
COPY . .

# Expose SIDERIS ports:
# 4000: WAF Proxy
# 5000: Telemetry Ingest
# 6001: Dashboard API
# 5173: Dashboard UI (Vite dev server)
EXPOSE 4000 5000 6001 5173

# Start all services concurrently
CMD ["npm", "run", "start-all"]
