#!/usr/bin/env bash
# Create <count> empty files under [dir] (default: .), never more than 99
# entries (files or sub-folders) in any folder.
# Usage: make-files.sh <count> [dir]
set -euo pipefail

n=${1:?usage: $0 <count> [dir]}
root=${2:-.}
max=99

# Folder levels needed so that no level holds more than $max sub-folders.
leaves=$(((n + max - 1) / max))
depth=1
cap=$max
while ((cap < leaves)); do
	cap=$((cap * max))
	depth=$((depth + 1))
done

for ((i = 0; i < n; i++)); do
	if ((i % max == 0)); then
		d=$((i / max))
		dir=
		for ((l = 0; l < depth; l++)); do
			printf -v part 'd%02d' $((d % max))
			dir=$part/$dir
			d=$((d / max))
		done
		dir=$root/${dir%/}
		mkdir -p "$dir"
	fi
	printf -v name 'f%02d' $((i % max))
	: >"$dir/$name"
done
