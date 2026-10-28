#!/bin/sh
# Generates the shell completion scripts shipped in the Linux packages
# (goreleaser `before` hook) into ./completions.
#
# Runs the prod build with a throwaway config dir, so that nothing is read
# from or written to the config of the machine that builds the release.
set -eu

cd "$(dirname "$0")/.."

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

go build -tags prod -o "$tmp/retyc" .

rm -rf completions
mkdir completions
for sh in bash zsh fish; do
	RETYC_CONFIG_DIR="$tmp/config" "$tmp/retyc" completion "$sh" >"completions/retyc.$sh"
done
