#!/usr/bin/env bash
# Build the npm packages of the MCP server from a populated goreleaser dist/.
#
#   dist/npm/mcp/                 @retyc/mcp: Node launcher (bin/retyc-mcp.js)
#   dist/npm/mcp-<os>-<cpu>/      @retyc/mcp-<os>-<cpu>: the Go binary of one platform
#
# The launcher lists every platform package as an optional dependency; npm
# installs only the one whose `os` / `cpu` match the host (esbuild model).
# Every package gets the goreleaser version, also written to dist/npm/version.
#
# Usage:
#   scripts/build-npm.sh [--expect-version X.Y.Z] [--host-only]
#
# --host-only builds only the platform package of this host (local tests and
# PR CI, where goreleaser builds linux/amd64 only).
# Requirements: jq, goreleaser dist/ (make goreleaser-quick or the release CI).
set -euo pipefail

EXPECT_VERSION=""
HOST_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --expect-version) EXPECT_VERSION="$2"; shift 2 ;;
    --host-only) HOST_ONLY=1; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="${ROOT}/dist"
ARTIFACTS="${DIST}/artifacts.json"
METADATA="${DIST}/metadata.json"
TEMPLATES="${ROOT}/packaging/npm"
OUT="${DIST}/npm"

command -v jq >/dev/null || { echo "Error: 'jq' is required" >&2; exit 1; }
for f in "${ARTIFACTS}" "${METADATA}"; do
  [ -f "$f" ] || { echo "Error: $f not found. Run goreleaser first (make goreleaser-quick)." >&2; exit 1; }
done

VERSION=$(jq -r '.version' "${METADATA}")
[ -n "${VERSION}" ] && [ "${VERSION}" != "null" ] || { echo "Error: no version in ${METADATA}" >&2; exit 1; }
if [ -n "${EXPECT_VERSION}" ] && [ "${VERSION}" != "${EXPECT_VERSION}" ]; then
  echo "Error: goreleaser version '${VERSION}' != expected '${EXPECT_VERSION}' (tag mismatch)" >&2
  exit 1
fi

# Same lookup as scripts/build-mcpb.sh.
find_binary() {
  local goos="$1" goarch="$2"
  local rel
  rel=$(jq -r --arg os "$goos" --arg arch "$goarch" \
    'first(.[] | select(.type == "Binary" and .goos == $os and .goarch == $arch)) | .path // empty' \
    "${ARTIFACTS}")
  [ -n "$rel" ] || { echo "Error: no Binary artifact for ${goos}/${goarch} in artifacts.json" >&2; exit 1; }
  echo "${ROOT}/${rel#"${ROOT}/"}"
}

# goos/goarch -> npm os/cpu.
PLATFORMS="linux/amd64:linux/x64 linux/arm64:linux/arm64 darwin/amd64:darwin/x64 darwin/arm64:darwin/arm64 windows/amd64:win32/x64"

host_target() {
  local os arch
  case "$(uname -s)" in Linux) os=linux ;; Darwin) os=darwin ;; *) os=unsupported ;; esac
  case "$(uname -m)" in x86_64|amd64) arch=x64 ;; aarch64|arm64) arch=arm64 ;; *) arch=unsupported ;; esac
  echo "${os}/${arch}"
}

rm -rf "${OUT}"
mkdir -p "${OUT}"

OPTIONAL_DEPS='{}'
BUILT=0
for entry in ${PLATFORMS}; do
  go_target="${entry%%:*}"
  npm_target="${entry##*:}"
  npm_os="${npm_target%%/*}"
  npm_cpu="${npm_target##*/}"
  name="@retyc/mcp-${npm_os}-${npm_cpu}"
  OPTIONAL_DEPS=$(jq --arg n "$name" --arg v "$VERSION" '. + {($n): $v}' <<<"${OPTIONAL_DEPS}")

  if [ "${HOST_ONLY}" = 1 ] && [ "${npm_target}" != "$(host_target)" ]; then
    continue
  fi

  dir="${OUT}/mcp-${npm_os}-${npm_cpu}"
  exe="retyc"
  [ "${npm_os}" = win32 ] && exe="retyc.exe"
  mkdir -p "${dir}/bin"
  cp "$(find_binary "${go_target%%/*}" "${go_target##*/}")" "${dir}/bin/${exe}"
  chmod 755 "${dir}/bin/${exe}"
  cp "${ROOT}/LICENSE" "${dir}/LICENSE"
  jq --arg n "$name" --arg v "$VERSION" --arg os "$npm_os" --arg cpu "$npm_cpu" \
    '.name = $n | .version = $v | .os = [$os] | .cpu = [$cpu]' \
    "${TEMPLATES}/platform.package.json" >"${dir}/package.json"
  BUILT=$((BUILT + 1))
done
[ "${BUILT}" -gt 0 ] || { echo "Error: no platform package built (host $(host_target) not supported?)" >&2; exit 1; }

mkdir -p "${OUT}/mcp/bin"
cp "${TEMPLATES}/mcp/bin/retyc-mcp.js" "${OUT}/mcp/bin/retyc-mcp.js"
chmod 755 "${OUT}/mcp/bin/retyc-mcp.js"
cp "${TEMPLATES}/mcp/README.md" "${OUT}/mcp/README.md"
cp "${ROOT}/LICENSE" "${OUT}/mcp/LICENSE"
jq --arg v "$VERSION" --argjson deps "${OPTIONAL_DEPS}" \
  '.version = $v | .optionalDependencies = $deps' \
  "${TEMPLATES}/mcp/package.json" >"${OUT}/mcp/package.json"

echo "${VERSION}" >"${OUT}/version"
echo "OK  dist/npm: @retyc/mcp + ${BUILT} platform package(s), version ${VERSION}"
