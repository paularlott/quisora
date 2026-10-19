#!/usr/bin/env bash
# 3-node replicated BadgerDB cluster on localhost: seed node 1, start nodes 2 and 3 empty, time their catch-up, then run
# load round-robin across all three nodes.
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
$([ "$n" != 1 ] && echo "peers = [\"127.0.0.1:$((BASE + 11))\"]")
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

# Seed node 1 offline (sync writes off, as for the single-node seeds).
sed 's/^backend = "badgerdb"/backend = "badgerdb"\n[storage.badgerdb]\nsync_writes = false/' "$WORK/node1.toml" >"$WORK/node1-seed.toml"
QUISORA_LOADTEST=1 "$LOADTEST" -c "$WORK/node1-seed.toml" seed --orgs "$ORGS" --users 1000 --data "$WORK/seed.json" | tee "$WORK/seed.out" | tail -3

"$QUISORA" -c "$WORK/node1.toml" serve >"$WORK/node1.log" 2>&1 & PIDS+=($!)
for _ in $(seq 1 120); do curl -sk "$PUBLIC/readyz" >/dev/null 2>&1 && break; sleep 0.5; done

LAST=$(python3 - "$WORK/seed.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))["grants"][-1]["token"], end="")
PY
)
LASTCLIENT=$(python3 - "$WORK/seed.json" <<'PY'
import json, sys
g = json.load(open(sys.argv[1]))["grants"][-1]
print(g["client_id"] + " " + g["client_secret"], end="")
PY
)
read -r CID CSEC <<<"$LASTCLIENT"

have_last() { # url -> 0 when the last seeded refresh token works there
	curl -sk -o /dev/null -w '%{http_code}' -d "grant_type=refresh_token&client_id=$CID&client_secret=$CSEC&refresh_token=$LAST" "$1/oauth/token" | grep -q 200
}
have_last "$PUBLIC" && say "node 1 serves the seeded data" || { say "node 1 cannot refresh the last grant"; exit 1; }

T0=$(python3 -c 'import time; print(time.time())')
"$QUISORA" -c "$WORK/node2.toml" serve >"$WORK/node2.log" 2>&1 & PIDS+=($!)
"$QUISORA" -c "$WORK/node3.toml" serve >"$WORK/node3.log" 2>&1 & PIDS+=($!)
declare -A DONE
for _ in $(seq 1 7200); do
	for n in 2 3; do
		[ -n "${DONE[$n]:-}" ] && continue
		if have_last "https://127.0.0.1:$((BASE + n))"; then
			DONE[$n]=$(python3 -c "import time; print(round(time.time()-$T0,1))")
			say "node $n converged (last grant readable) after ${DONE[$n]} s"
		fi
	done
	[ -n "${DONE[2]:-}" ] && [ -n "${DONE[3]:-}" ] && break
	sleep 0.5
done
sleep 10 # let the tail of the feed drain, then verify user counts
for n in 1 2 3; do
	tok=$(python3 -c "import json; print(json.load(open('$WORK/seed.json'))['api_token'])")
	for o in org-00001 org-00250 org-00500; do
		t=$(curl -sk -H "Authorization: Bearer $tok" -H 'Api-Version: 1' "https://127.0.0.1:$((BASE + n))/api/v1/orgs/$o/users?limit=1" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("total"))')
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
