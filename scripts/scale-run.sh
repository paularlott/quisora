#!/usr/bin/env bash
# Starts `quisora serve` with a seeded store and runs every loadtest scenario at several concurrencies, recording the
# server's RSS and CPU. Output: <outdir>/results.jsonl (one JSON report per run), <outdir>/summary.txt.
#
#   scripts/scale-run.sh CONFIG.toml DATA.json OUTDIR [scenarios] [concurrencies] [duration]
#
# Environment: QUISORA (binary, default bin/quisora), LOADTEST (default bin/loadtest, built by `task loadtest`), URL (default https://127.0.0.1:38443), DISK_CMD (prints the data size).
set -euo pipefail

CONFIG=$1 DATA=$2 OUT=$3
SCENARIOS=${4:-"discovery client_credentials refresh refresh_groups introspect scim_list scim_filter mgmt_list password_login"}
CONCS=${5:-"16 64 256"}
DUR=${6:-30s}
QUISORA=${QUISORA:-$(cd "$(dirname "$0")/.." && pwd)/bin/quisora}
LOADTEST=${LOADTEST:-$(cd "$(dirname "$0")/.." && pwd)/bin/loadtest}
URL=${URL:-https://127.0.0.1:38443}
mkdir -p "$OUT"
: >"$OUT/summary.txt"
: >"$OUT/rss.log"
if curl -sk -m 2 "$URL/readyz" >/dev/null 2>&1; then echo "something already answers on $URL" >&2; exit 1; fi

"$QUISORA" -c "$CONFIG" serve >"$OUT/server.log" 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null || true; kill ${SAMPLER:-0} 2>/dev/null || true' EXIT
for _ in $(seq 1 600); do
	curl -sk "$URL/readyz" >/dev/null 2>&1 && break
	kill -0 $PID 2>/dev/null || { echo "server exited"; tail "$OUT/server.log"; exit 1; }
	sleep 0.5
done

cputime() { ps -o cputime= -p $PID | awk -F'[:.]' '{ if (NF==3) print $1*60+$2+$3/100; else print $1*3600+$2*60+$3+$4/100 }'; }
rss_mb() { ps -o rss= -p $PID | awk '{printf "%.0f", $1/1024}'; }
# Physical footprint (anonymous memory: Go heap, goroutine stacks, argon2 blocks; excludes clean file mappings such
# as Badger tables). macOS only; prints 0 elsewhere.
fp_mb() { footprint -p $PID 2>/dev/null | awk '/Footprint:/ {for(i=1;i<=NF;i++) if($i=="Footprint:"){v=$(i+1);u=$(i+2)}; if (u=="GB") v*=1024; else if (u=="KB") v/=1024; printf "%.0f", v; found=1} END {if (!found) print 0}'; }

( while kill -0 $PID 2>/dev/null; do echo "$(date +%s) $(ps -o rss= -p $PID) $(($(fp_mb) * 1024))" >>"$OUT/rss.log"; sleep 1; done ) &
SAMPLER=$!

say() { echo "$*" | tee -a "$OUT/summary.txt"; }
say "idle after start: RSS $(rss_mb) MB, footprint $(fp_mb) MB"
[ -n "${DISK_CMD:-}" ] && say "data size: $(eval "$DISK_CMD")"

for sc in $SCENARIOS; do
	for c in $CONCS; do
		t0=$(date +%s); cpu0=$(cputime)
		"$LOADTEST" run --url "$URL" --insecure --data "$DATA" --scenario "$sc" --concurrency "$c" \
			--duration "$DUR" --warmup 3s --json "$OUT/results.jsonl" --label "$sc/$c" | tee -a "$OUT/summary.txt"
		t1=$(date +%s); cpu1=$(cputime)
		peak=$(awk -v a="$t0" -v b="$t1" '$1>=a && $1<=b && $2>m {m=$2} END {printf "%.0f", m/1024}' "$OUT/rss.log")
		fpk=$(awk -v a="$t0" -v b="$t1" '$1>=a && $1<=b && $3>m {m=$3} END {printf "%.0f", m/1024}' "$OUT/rss.log")
		cores=$(awk -v a="$cpu0" -v b="$cpu1" -v t0="$t0" -v t1="$t1" 'BEGIN {printf "%.1f", (b-a)/(t1-t0)}')
		say "  server: peak RSS ${peak} MB, peak footprint ${fpk} MB, avg CPU ${cores} cores"
	done
done
[ -n "${DISK_CMD:-}" ] && say "data size at end: $(eval "$DISK_CMD")"
say "final RSS $(rss_mb) MB, footprint $(fp_mb) MB"
