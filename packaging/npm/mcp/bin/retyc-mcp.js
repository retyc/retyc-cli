#!/usr/bin/env node
// Launcher of the Retyc MCP server published as @retyc/mcp.
//
// The Go binary ships in one optional dependency per platform
// (@retyc/mcp-<platform>-<arch>); npm installs only the one matching the host.
// This script resolves it and runs `retyc mcp <args>`, `serve` by default:
//   npx -y @retyc/mcp         -> retyc mcp serve
//   npx -y @retyc/mcp setup   -> retyc mcp setup
//
// It must never write to stdout: in `serve` mode stdout carries the MCP
// protocol. Exit codes (77 login, 78 config…) and signals pass through.
//
// Test seams, read by this script only: RETYC_NPM_TEST_BIN replaces the
// resolved binary, RETYC_NPM_TEST_PLATFORM replaces process.platform.
'use strict';

const { spawn } = require('child_process');

const SUPPORTED = ['linux-x64', 'linux-arm64', 'darwin-x64', 'darwin-arm64', 'win32-x64'];

function resolveBinary() {
  if (process.env.RETYC_NPM_TEST_BIN) {
    return process.env.RETYC_NPM_TEST_BIN;
  }
  const platform = process.env.RETYC_NPM_TEST_PLATFORM || process.platform;
  const target = `${platform}-${process.arch}`;
  if (!SUPPORTED.includes(target)) {
    fail(`retyc-mcp: platform ${target} is not supported (supported: ${SUPPORTED.join(', ')}).`);
  }
  const exe = platform === 'win32' ? 'retyc.exe' : 'retyc';
  try {
    return require.resolve(`@retyc/mcp-${target}/bin/${exe}`);
  } catch {
    fail(
      `retyc-mcp: the binary package @retyc/mcp-${target} is not installed.\n` +
        'It is an optional dependency: reinstall without --omit=optional / --no-optional.'
    );
  }
}

function fail(message) {
  process.stderr.write(message + '\n');
  process.exit(1);
}

const args = process.argv.slice(2);
const child = spawn(resolveBinary(), ['mcp', ...(args.length ? args : ['serve'])], {
  stdio: 'inherit',
  windowsHide: true,
});

// Forward termination signals so an MCP client stopping the launcher stops
// the server too; the child's own exit then ends this process.
for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
  process.on(sig, () => {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill(sig);
    }
  });
}

child.on('error', (err) => fail(`retyc-mcp: cannot start the Retyc binary: ${err.message}`));

child.on('exit', (code, signal) => {
  if (signal) {
    // Die from the same signal so the parent sees the real cause.
    process.removeAllListeners(signal);
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code === null ? 1 : code);
});
