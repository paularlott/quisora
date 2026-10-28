#!/usr/bin/env bash
# 3-node replicated BadgerDB cluster on localhost: seed node 1, start it with nodes 2 and 3 empty, time until each serves
# the seeded data, then run load round-robin across all three nodes.
#
#   scripts/scale-cluster.sh WORKDIR [orgs] [duration]
#
# Environment: QUISORA (binary, default bin/quisora), LOADTEST (default bin/loadtest, built by `task loadtest`), BASE_PORT (default 38450: HTTPS on +1..+3, gossip on +11..+13).
set -euo pipefail

WORK=$1 ORGS=${2:-500} DUR=${3:-30s}
QUISORA=${QUISORA:-$(cd "$(dirname "$0")/.." && pwd)/bin/quisora}
LOADTEST=${LOADTEST:-$(cd "$(dirname "$0")/.." && pwd)/bin/loadtest}
BASE=${BASE_PORT:-38450}
mkdir -p "$WORK"
MASTER=$("$QUISORA" genkey) CKEY=$("$QUISORA" genkey)
PUBLIC=https://127.0.0.1:$((BASE + 1))

cfg() { # n
	local n=$1 f="$WORK/node$1.toml"
	cat >"$f" <<TOML
[server]
listen = "127.0.0.1:$((BASE + n))"
public_url = "$PUBLIC"
data_dir = "$WORK/node$n"
master_key = "$MASTER"
[storage]
backend = "badgerdb"
[cluster]
bind = "127.0.0.1:$((BASE + 10 + n))"
advertise = "127.0.0.1:$((BASE + 10 + n))"
key = "$CKEY"
peers = ["127.0.0.1:$((BASE + 11))", "127.0.0.1:$((BASE + 12))", "127.0.0.1:$((BASE + 13))"]
size = 3
[limits]
login_per_ip_min = 0
max_in_flight = 8192
[log]
level = "warn"
TOML
}
for n in 1 2 3; do cfg $n; done

PIDS=()
trap 'kill "${PIDS[@]}" 2>/dev/null || true' EXIT
say() { echo "$*" | tee -a "$WORK/summary.txt"; }
: >"$WORK/summary.txt"

# Seed node 1 offline with its own settings (a gossip node keeps sync writes on): the seeded records become the first
# writes of their partitions, which nodes 2 and 3 copy.
QUISORA_LOADTEST=1 "$LOADTEST" -c "$WORK/node1.toml" seed --orgs "$ORGS" --users 1000 --data "$WORK/seed.json" | tee "$WORK/seed.out" | tail -3

LAST=$(python3 - "$WORK/seed.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))["grants"][-1]["token"], end="")
PY
)
LASTCLIENT=$(python3 - "$WORK/seed.json" <<'PY'
import json, sys
g = json.load(open(sys.argv[1]))["grants"][-1]
print(g["org"] + " " + g["client_id"] + " " + g["client_secret"], end="")
PY
)
read -r LASTORG CID CSEC <<<"$LASTCLIENT"

have_last() { # url -> 0 when the last seeded refresh token works there
	curl -sk -o /dev/null -w '%{http_code}' -d "grant_type=refresh_token&client_id=$CID&client_secret=$CSEC&refresh_token=$LAST" "$1/o/$LASTORG/oauth/token" | grep -q 200
}
# All three start together: a write needs two of the three nodes, so node 1 cannot serve on its own.
T0=$(python3 -c 'import time; print(time.time())')
for n in 1 2 3; do "$QUISORA" -c "$WORK/node$n.toml" serve >"$WORK/node$n.log" 2>&1 & PIDS+=($!); done
declare -A DONE
for _ in $(seq 1 7200); do
	for n in 1 2 3; do
		[ -n "${DONE[$n]:-}" ] && continue
		if have_last "https://127.0.0.1:$((BASE + n))"; then
			DONE[$n]=$(python3 -c "import time; print(round(time.time()-$T0,1))")
			say "node $n converged (last grant readable) after ${DONE[$n]} s"
		fi
	done
	[ -n "${DONE[1]:-}" ] && [ -n "${DONE[2]:-}" ] && [ -n "${DONE[3]:-}" ] && break
	sleep 0.5
done
sleep 10 # let the tail of the feed drain, then verify user counts
for n in 1 2 3; do
	tok=$(python3 -c "import json; print(json.load(open('$WORK/seed.json'))['api_token'])")
	for o in $(printf 'org-%05d ' 1 $(((ORGS + 1) / 2)) "$ORGS"); do
		t=$(curl -sk -H "Authorization: Bearer $tok" -H 'Api-Version: 2026-10-20' "https://127.0.0.1:$((BASE + n))/api/orgs/$o/users?limit=1" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("total"))')
		say "node $n $o users: $t"
	done
done

URLS=(--url "https://127.0.0.1:$((BASE + 1))" --url "https://127.0.0.1:$((BASE + 2))" --url "https://127.0.0.1:$((BASE + 3))")
for sc in refresh password_login; do
	for c in 64 256; do
		"$LOADTEST" run "${URLS[@]}" --insecure --data "$WORK/seed.json" --scenario "$sc" --concurrency "$c" \
			--duration "$DUR" --warmup 3s --json "$WORK/results.jsonl" --label "cluster3/$sc/$c" | tee -a "$WORK/summary.txt"
	done
done
for n in 1 2 3; do say "node $n final RSS $(ps -o rss= -p "${PIDS[$((n - 1))]}" | awk '{printf "%.0f MB", $1/1024}')"; done
