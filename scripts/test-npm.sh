#!/usr/bin/env bash
# Smoke-test the npm packages built by scripts/build-npm.sh (dist/npm/).
#
# Packs every package, installs them into a throwaway prefix and checks the
# launcher contract: stdout stays clean for the MCP stdio protocol, the `mcp`
# prefix and `serve` default are applied, exit codes and signals pass through,
# and an unsupported platform fails loudly on stderr only.
#
# Usage: scripts/test-npm.sh            (after scripts/build-npm.sh [--host-only])
# Requirements: node, npm, jq.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NPM_DIST="${ROOT}/dist/npm"

for tool in node npm jq; do
  command -v "$tool" >/dev/null || { echo "Error: '$tool' is required" >&2; exit 1; }
done
[ -f "${NPM_DIST}/version" ] || { echo "Error: ${NPM_DIST}/version not found. Run scripts/build-npm.sh first." >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

FAILED=0
pass() { echo "ok    $1"; }
fail() { echo "FAIL  $1" >&2; FAILED=1; }

# Pack every built package (a packing error fails here), then install the
# launcher with the platform package of this host only: npm refuses the
# others (EBADPLATFORM). The platform package satisfies the launcher's
# optional dependency without any registry.
VERSION=$(cat "${NPM_DIST}/version")
HOST="$(node -p 'process.platform + "-" + process.arch')"
mkdir -p "${TMP}/tgz" "${TMP}/prefix"
for dir in "${NPM_DIST}"/*/; do
  (cd "${dir}" && npm pack --silent --pack-destination "${TMP}/tgz" >/dev/null)
done
for tgz in "retyc-mcp-${VERSION}.tgz" "retyc-mcp-${HOST}-${VERSION}.tgz"; do
  [ -f "${TMP}/tgz/${tgz}" ] || { echo "Error: ${tgz} not built (host ${HOST})" >&2; exit 1; }
done
# 0. Every package ships the license of the binary or script it carries.
for tgz in "${TMP}"/tgz/*.tgz; do
  if tar -tzf "${tgz}" | grep -x 'package/LICENSE' >/dev/null; then
    pass "LICENSE in $(basename "${tgz}")"
  else
    fail "no LICENSE in $(basename "${tgz}")"
  fi
done

(cd "${TMP}/prefix" && npm init -y >/dev/null && \
  npm install --silent --no-audit --no-fund --offline \
    "${TMP}/tgz/retyc-mcp-${VERSION}.tgz" "${TMP}/tgz/retyc-mcp-${HOST}-${VERSION}.tgz" >/dev/null)
LAUNCHER="${TMP}/prefix/node_modules/.bin/retyc-mcp"
[ -x "${LAUNCHER}" ] || { echo "Error: launcher not installed at ${LAUNCHER}" >&2; exit 1; }

# 1. No argument: `mcp serve`, and stdout carries only protocol messages.
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}'
first_line=$(printf '%s\n' "${INIT}" | RETYC_CONFIG_DIR="${TMP}/cfg" timeout 5 "${LAUNCHER}" 2>/dev/null | head -n 1 || true)
if printf '%s' "${first_line}" | jq -e '.id == 1 and .result.serverInfo.name == "retyc"' >/dev/null 2>&1; then
  pass "initialize answered on a clean stdout"
else
  fail "initialize: unexpected first stdout line: ${first_line}"
fi

# 2. Arguments get the `mcp` prefix.
if "${LAUNCHER}" serve --help >/dev/null 2>&1; then
  pass "'serve --help' runs 'retyc mcp serve --help'"
else
  fail "'serve --help' did not exit 0"
fi

# 3. Exit codes pass through unchanged (77 = login, 78 = config).
for code in 77 78; do
  fake="${TMP}/exit${code}"
  printf '#!/bin/sh\nexit %s\n' "${code}" >"${fake}" && chmod +x "${fake}"
  set +e; RETYC_NPM_TEST_BIN="${fake}" "${LAUNCHER}" >/dev/null 2>&1; got=$?; set -e
  [ "${got}" = "${code}" ] && pass "exit code ${code} propagated" || fail "exit code ${code}: got ${got}"
done

# 4. SIGTERM to the launcher reaches the child: no orphan left behind.
sleeper="${TMP}/sleeper"
printf '#!/bin/sh\necho $$ > "%s/child.pid"\nexec sleep 30\n' "${TMP}" >"${sleeper}" && chmod +x "${sleeper}"
RETYC_NPM_TEST_BIN="${sleeper}" "${LAUNCHER}" >/dev/null 2>&1 &
launcher_pid=$!
for _ in $(seq 1 50); do [ -s "${TMP}/child.pid" ] && break; sleep 0.1; done
child_pid=$(cat "${TMP}/child.pid" 2>/dev/null || echo "")
kill -TERM "${launcher_pid}" 2>/dev/null || true
wait "${launcher_pid}" 2>/dev/null || true
sleep 2
if [ -n "${child_pid}" ] && ! kill -0 "${child_pid}" 2>/dev/null; then
  pass "SIGTERM forwarded to the child"
else
  fail "child ${child_pid:-<none>} still alive after SIGTERM"
  [ -n "${child_pid}" ] && kill -KILL "${child_pid}" 2>/dev/null || true
fi

# 5. Unsupported platform: exit 1, nothing on stdout, a reason on stderr.
set +e
out=$(RETYC_NPM_TEST_PLATFORM=freebsd "${LAUNCHER}" 2>"${TMP}/err"); got=$?
set -e
if [ "${got}" = 1 ] && [ -z "${out}" ] && grep -q "not supported" "${TMP}/err"; then
  pass "unsupported platform rejected on stderr"
else
  fail "unsupported platform: exit=${got} stdout='${out}' stderr='$(cat "${TMP}/err")'"
fi

exit "${FAILED}"
