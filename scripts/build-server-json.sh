#!/usr/bin/env bash
# Build dist/server.json, the MCP Registry entry of the release, from the
# template packaging/mcp/server.json.
#
# Fills in the version (from dist/npm/version, written by build-npm.sh), the
# npm package version, and the URL and SHA-256 of the MCPB bundle attached to
# the GitHub release (dist/retyc-<version>.mcpb, built by build-mcpb.sh).
#
# Usage: scripts/build-server-json.sh
# Requirements: jq, sha256sum.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="${ROOT}/dist"
TEMPLATE="${ROOT}/packaging/mcp/server.json"
REPO_URL="https://github.com/retyc/retyc-cli"

for tool in jq sha256sum; do
  command -v "$tool" >/dev/null || { echo "Error: '$tool' is required" >&2; exit 1; }
done
[ -f "${DIST}/npm/version" ] || { echo "Error: dist/npm/version not found. Run scripts/build-npm.sh first." >&2; exit 1; }
VERSION=$(cat "${DIST}/npm/version")
MCPB="${DIST}/retyc-${VERSION}.mcpb"
[ -f "${MCPB}" ] || { echo "Error: ${MCPB#"${ROOT}"/} not found. Run scripts/build-mcpb.sh first." >&2; exit 1; }

SHA=$(sha256sum "${MCPB}" | cut -d' ' -f1)
URL="${REPO_URL}/releases/download/v${VERSION}/retyc-${VERSION}.mcpb"

jq --arg v "${VERSION}" --arg url "${URL}" --arg sha "${SHA}" '
  .version = $v
  | .packages |= map(
      if .registryType == "npm" then .version = $v
      elif .registryType == "mcpb" then .identifier = $url | .fileSha256 = $sha
      else . end)
' "${TEMPLATE}" >"${DIST}/server.json"

echo "OK  dist/server.json (version ${VERSION}, mcpb sha256 ${SHA:0:12}…)"
