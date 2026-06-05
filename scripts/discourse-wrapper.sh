#!/bin/bash
# Modify pnpm version constraint in all package.json files to allow pnpm v11
echo "Overriding pnpm engines constraint in package.json files..."
find /opt/bitnami/discourse -name "package.json" -maxdepth 5 -exec sed -i 's/"pnpm": "\^10"/"pnpm": ">=10"/g' {} \;

# Disable strict peer dependencies and approve builds in pnpm-workspace.yaml
echo "Configuring pnpm workspace options..."
sed -i 's/strictPeerDependencies: true/strictPeerDependencies: false/g' /opt/bitnami/discourse/pnpm-workspace.yaml
sed -i "s/set this to true or false/true/g" /opt/bitnami/discourse/pnpm-workspace.yaml

# Patch esbuild node shims in asset-processor build.js
echo "Patching esbuild config in asset-processor/build.js..."
sed -i 's/assert: "\.\/noop",/assert: ".\/noop",\n      os: ".\/noop",\n      http: ".\/noop",\n      https: ".\/noop",\n      zlib: ".\/noop",/g' /opt/bitnami/discourse/frontend/asset-processor/build.js

# Bypass the redundant full Ember core build to avoid Embroider workspace symlinking errors
echo "Bypassing core Ember build..."
sed -i '/def existing_core_build_usable?/,/^end/c\def existing_core_build_usable?\n  true\nend' /opt/bitnami/discourse/script/assemble_ember_build.rb

# Run pnpm install as the discourse user to initialize workspace and generate .pnpm/lock.yaml
echo "Running pnpm install..."
su discourse -c "export CI=true && export pnpm_config_engine_strict=false && pnpm install --dir /opt/bitnami/discourse --no-strict-peer-dependencies --no-frozen-lockfile"

# Execute the original entrypoint
exec /opt/bitnami/scripts/discourse/entrypoint.sh /opt/bitnami/scripts/discourse/run.sh
