#!/usr/bin/env bash
# Benchmark small-file writes through `retyc webdav serve`, with and without a
# WebDAV client in the path.
#
# Upload cost over WebDAV is dominated by the number of sequential API
# round-trips, so the numbers only mean something next to the API latency of the
# same run. Phase 1 drives the server directly with curl; phase 2 drives it
# through the mounted filesystem. Comparing the two separates the server from
# the WebDAV client, and the trend line (first files vs last) shows whether the
# per-file cost grows as the folder fills.
#
# Prerequisites: the server is already running (ideally with RETYC_TRACE=1 and
# its stderr redirected to a file) and the WebDAV mount is active.
#
# - retyc dataroom create --title bench1
# - RETYC_TRACE=1 retyc webdav serve --addr 127.0.0.1 --port 8888 2> /tmp/trace3.log
# - sudo mkdir -p /mnt/a && sudo mount -t davfs -o dir_mode=0777,file_mode=0666 http://127.0.0.1:8888/dataroom/bench1 /mnt/a
#
#
# Usage:
#   N=30 MOUNT=/mnt/a BASE_URL=http://127.0.0.1:8888/dataroom/bench1 \
#   API_URL=https://api.retyc.com scripts/webdav-bench.sh
#
# Environment:
#   N         files per phase (default 30)
#   SRC       source file, created as 4KB of random data if missing
#   MOUNT     WebDAV mount point for phase 2
#   BASE_URL  same dataroom over HTTP, for phase 1
#   API_URL   REST API, to measure its latency; read from config.yaml if unset
#   OUT       output directory (default /tmp/retyc-bench-<timestamp>)
set -uo pipefail

N=${N:-30}
SRC=${SRC:-/tmp/4k}
MOUNT=${MOUNT:-/mnt/a}
BASE_URL=${BASE_URL:-http://127.0.0.1:8888/dataroom/bench1}
OUT=${OUT:-/tmp/retyc-bench-$(date +%Y%m%d-%H%M%S)}
TAG=b$(date +%H%M%S)

mkdir -p "$OUT"
exec > >(tee "$OUT/bench.log") 2>&1

ts()      { date +%H:%M:%S.%3N; }
section() { printf '\n════ %s ════ %s\n' "$1" "$(ts)"; }

# ─────────────────────────────────────────────────────────────────────────────
section "ENVIRONMENT"

echo "host           : $(hostname)"
echo "retyc binary   : $(command -v retyc || echo '<not in PATH>')"
retyc version 2>&1 | sed 's/^/version        : /'
echo "RETYC_CONFIG_DIR : ${RETYC_CONFIG_DIR:-<unset>}"

for cfg in "$PWD/.retyc/config.yaml" "$HOME/.config/retyc/config.yaml"; do
    [ -f "$cfg" ] && { echo "--- config $cfg"; sed 's/^/    /' "$cfg"; }
done

# Which binary is actually serving, and which API it talks to: a dev build and a
# prod build differ only in their default API URL, and mixing them up silently
# changes the latency the whole benchmark measures.
pid=$(pgrep -f 'webdav serve' | head -1)
if [ -n "$pid" ]; then
    echo "--- webdav server (PID $pid)"
    echo "    exe     : $(readlink -f /proc/"$pid"/exe 2>/dev/null || echo '<permission denied, rerun with sudo>')"
    echo "    cmdline : $(tr '\0' ' ' < /proc/"$pid"/cmdline 2>/dev/null)"
    # Strict allow-list: anything not known to be safe is masked. RETYC_TOKEN in
    # particular is a usable refresh token.
    tr '\0' '\n' < /proc/"$pid"/environ 2>/dev/null \
        | grep -E '^(RETYC_|HTTPS?_PROXY|SSL_CERT)' \
        | awk -F= '{
              safe = ($1 == "RETYC_TRACE" || $1 == "RETYC_CONFIG_DIR" || $1 == "RETYC_API_BASE_URL")
              print "    env     : " $1 "=" (safe ? substr($0, index($0, "=") + 1) : "<set, masked>")
          }'
else
    echo "!! no 'webdav serve' process found"
fi

echo "--- davfs2 mount"
mount | grep -i davfs | sed 's/^/    /' || echo "    <no davfs2 mount>"
[ -f /etc/davfs2/davfs2.conf ] && grep -Ev '^\s*(#|$)' /etc/davfs2/davfs2.conf | sed 's/^/    /'

# ─────────────────────────────────────────────────────────────────────────────
section "LATENCY"

api_url=$(grep -hEo 'https?://[^ "]*' "$PWD/.retyc/config.yaml" "$HOME/.config/retyc/config.yaml" 2>/dev/null \
          | grep -i api | head -1)
api_url=${API_URL:-$api_url}
if [ -n "$api_url" ]; then
    echo "API: $api_url"
    for _ in 1 2 3; do
        curl -sk -o /dev/null -w "    API round-trip : %{time_total}s\n" --max-time 10 "$api_url" || true
    done
else
    echo "API not detected: no config.yaml, the binary uses its build-mode default."
    echo "  dev  -> https://api.triplesfer.traefik.me     prod -> https://api.retyc.com"
    echo "  rerun with API_URL=<url> to measure the API latency itself"
fi
# Only a cold dataroom cache makes this a proxy for one API round-trip; a warm
# one answers locally in well under a millisecond.
curl -s -o /dev/null -w "    webdav server round-trip : %{time_total}s\n" -X OPTIONS "$BASE_URL/" || true

# ─────────────────────────────────────────────────────────────────────────────
[ -f "$SRC" ] || { echo "creating $SRC (4KB)"; dd if=/dev/urandom of="$SRC" bs=4096 count=1 status=none; }

stats() {  # stats <label> <file of durations in ms>
    local label=$1 f=$2
    [ -s "$f" ] || { printf "  %-8s no measurements\n" "$label"; return; }
    # Sorted externally: asort() is a gawk extension, and mawk is the default awk
    # on Debian/Ubuntu.
    sort -n "$f" | awk -v label="$label" '
        { d[NR] = $1; sum += $1 }
        END {
            printf "  %-8s n=%d  total=%.2fs  mean=%.0fms  min=%.0fms  median=%.0fms  max=%.0fms\n", \
                   label, NR, sum/1000, sum/NR, d[1], d[int((NR+1)/2)], d[NR]
        }'
    # Trend: chronological order (unsorted), first five against last five.
    awk -v label="$label" '
        { d[NR] = $1 }
        END {
            if (NR < 10) exit
            k = 5; head = 0; tail = 0
            for (i = 1; i <= k; i++)           head += d[i]
            for (i = NR - k + 1; i <= NR; i++) tail += d[i]
            if (head <= 0) exit
            printf "  %-8s trend: first 5=%.0fms  ->  last 5=%.0fms  (x%.1f)\n", \
                   label, head/k, tail/k, (tail/k)/(head/k)
        }' "$f"
}

propfind_ms() {  # cost of one Depth:1 PROPFIND on a folder
    curl -s -o /dev/null -w '%{time_total}' -X PROPFIND -H 'Depth: 1' "$1" \
        | awk '{ printf "%.0f", $1 * 1000 }'
}

# Each phase writes into a fresh folder, so what is measured is a directory
# filling from 0 to N rather than one that is already loaded.
section "PHASE 1 — server only (curl, no WebDAV client)"
d_curl="$BASE_URL/curl-$TAG"
curl -s -o /dev/null -X MKCOL "$d_curl/"
echo "  PROPFIND on empty folder : $(propfind_ms "$d_curl/") ms"
: > "$OUT/curl.ms"
t0=$(date +%s%N)
for i in $(seq "$N"); do
    s=$(date +%s%N)
    curl -s -o /dev/null -T "$SRC" "$d_curl/f$i"
    echo "$(( ($(date +%s%N) - s) / 1000000 ))" >> "$OUT/curl.ms"
done
echo "  wall-clock : $(( ($(date +%s%N) - t0) / 1000000 )) ms"
echo "  PROPFIND on $N files : $(propfind_ms "$d_curl/") ms"
stats curl "$OUT/curl.ms"

section "PHASE 2 — WebDAV client (cp)"
d_dav="$MOUNT/dav-$TAG"
mkdir -p "$d_dav"
: > "$OUT/davfs.ms"
t0=$(date +%s%N)
for i in $(seq "$N"); do
    s=$(date +%s%N)
    cp "$SRC" "$d_dav/f$i"
    echo "$(( ($(date +%s%N) - s) / 1000000 ))" >> "$OUT/davfs.ms"
done
echo "  wall-clock : $(( ($(date +%s%N) - t0) / 1000000 )) ms"
stats davfs "$OUT/davfs.ms"

# ─────────────────────────────────────────────────────────────────────────────
section "SUMMARY"
stats curl  "$OUT/curl.ms"
stats davfs "$OUT/davfs.ms"
echo
echo "per-file durations : $OUT/curl.ms  $OUT/davfs.ms"
echo "full log           : $OUT/bench.log"
echo
echo "attach: this directory plus the server trace (RETYC_TRACE=1) covering $(ts)"
