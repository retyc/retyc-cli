#!/bin/sh
# Generates the shell completion scripts shipped in the Linux packages
# (goreleaser `before` hook) into ./completions.
#
# Runs the prod build with an empty environment and a throwaway config dir:
# `completion` goes through the root PersistentPreRunE, so a RETYC_* variable,
# an env file or SSL_CERT_* of the build machine must not reach it.
set -eu

cd "$(dirname "$0")/.."

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

go build -tags prod -o "$tmp/retyc" .

rm -rf completions
mkdir completions
for sh in bash zsh fish; do
	env -i PATH="$PATH" HOME="$tmp" RETYC_CONFIG_DIR="$tmp/config" \
		"$tmp/retyc" completion "$sh" >"completions/retyc.$sh"
done
