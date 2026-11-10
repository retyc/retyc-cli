#!/bin/sh
# Generates the manual pages shipped in the Linux packages (goreleaser
# `before` hook) into ./manpages: one page per command, from the cobra
# command tree (scripts/genman), compressed as Debian policy requires
# (gzip -9n: no name nor timestamp).
#
# Usage: scripts/manpages.sh [version]
#
# Runs the prod build with an empty environment: flag defaults derived from
# the environment (the config file path) must not show the build machine's.
set -eu

cd "$(dirname "$0")/.."

version=${1:-dev}
date=$(git log -1 --format=%cs 2>/dev/null || date -u +%Y-%m-%d)

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

go build -tags prod -o "$tmp/genman" ./scripts/genman

rm -rf manpages
mkdir manpages
# HOME="~" makes the config path read ~/.config/retyc/config.yaml.
env -i PATH="$PATH" HOME="~" "$tmp/genman" manpages "$version" "$date"
gzip -9n manpages/*.1
