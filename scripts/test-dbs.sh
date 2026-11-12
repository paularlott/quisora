#!/usr/bin/env bash
# Starts/stops the database containers used by the store conformance tests and benchmarks.
#
# The servers run with relaxed durability (no fsync per commit) so tests and benchmarks are not disk bound.
#
#   scripts/test-dbs.sh up        start postgres, mysql and mariadb (idempotent)
#   scripts/test-dbs.sh down      stop and remove every container
#   scripts/test-dbs.sh env       print export lines (use: eval "$(scripts/test-dbs.sh env)")
set -euo pipefail

PASS=quisora-test-pass
PG_PORT=55432
MYSQL_PORT=53306
MARIADB_PORT=53307

dsns() {
	echo "export QUISORA_TEST_POSTGRES_DSN='postgres://postgres:${PASS}@127.0.0.1:${PG_PORT}/postgres?sslmode=disable'"
	echo "export QUISORA_TEST_MYSQL_DSN='root:${PASS}@tcp(127.0.0.1:${MYSQL_PORT})/mysql'"
	echo "export QUISORA_TEST_MARIADB_DSN='root:${PASS}@tcp(127.0.0.1:${MARIADB_PORT})/mysql'"
}

# run NAME PORT:CONTAINER_PORT IMAGE [docker flags...] [-- command args...]; (re)starts the container if it is not
# running. A container made with other settings than these (an older copy of this script) is made again, so a changed
# setting (such as max_connections) takes effect rather than the old container being started as it was.
run() {
	local name=$1 ports=$2 image=$3
	local flags=() cmd=()
	shift 3
	while [ $# -gt 0 ] && [ "$1" != "--" ]; do flags+=("$1"); shift; done
	[ $# -gt 0 ] && shift
	[ $# -gt 0 ] && cmd=("$@")
	local want
	want=$(printf '%s\n' "$ports" "$image" ${flags[@]+"${flags[@]}"} -- ${cmd[@]+"${cmd[@]}"} | shasum | cut -c1-16)
	local have
	have=$(docker inspect -f '{{index .Config.Labels "quisora.settings"}}' "$name" 2>/dev/null || true)
	if docker inspect "$name" >/dev/null 2>&1; then
		if [ "$have" != "$want" ]; then
			docker rm -f "$name" >/dev/null
			echo "removed $name (its settings changed)"
		elif [ "$(docker inspect -f '{{.State.Running}}' "$name")" = "true" ]; then
			return
		else
			docker start "$name" >/dev/null
			echo "restarted $name"
			return
		fi
	fi
	docker run -d --name "$name" --label "quisora.settings=$want" -p "127.0.0.1:${ports}" ${flags[@]+"${flags[@]}"} \
		"$image" ${cmd[@]+"${cmd[@]}"} >/dev/null
	echo "started $name"
}

wait_for() {
	local name=$1 cmd=$2
	for _ in $(seq 1 90); do
		if docker exec "$name" sh -c "$cmd" >/dev/null 2>&1; then return; fi
		sleep 1
	done
	echo "$name did not become ready" >&2
	exit 1
}

case "${1:-up}" in
up)
	run quisora-test-postgres "${PG_PORT}:5432" paularlott/knot-postgres:18 -e POSTGRES_PASSWORD="$PASS" -- \
		-c fsync=off -c synchronous_commit=off -c full_page_writes=off -c max_connections=200
	# max_connections: the cluster tests run several nodes' stores at once (each pool up to 32 connections), more than
	# the servers' default 151 allows.
	run quisora-test-mysql "${MYSQL_PORT}:3306" paularlott/knot-mysql:9.7 -e MYSQL_ROOT_PASSWORD="$PASS" -- --innodb-flush-log-at-trx-commit=2 --max-connections=500
	run quisora-test-mariadb "${MARIADB_PORT}:3306" paularlott/knot-mariadb:11.8 -e MARIADB_ROOT_PASSWORD="$PASS" -- --innodb-flush-log-at-trx-commit=2 --max-connections=500
	wait_for quisora-test-postgres "pg_isready -U postgres -h 127.0.0.1"
	wait_for quisora-test-mysql "mysqladmin ping -h 127.0.0.1 -uroot -p${PASS}"
	wait_for quisora-test-mariadb "mariadb-admin ping -h 127.0.0.1 -uroot -p${PASS} || mysqladmin ping -h 127.0.0.1 -uroot -p${PASS}"
	dsns
	;;
down)
	docker rm -f quisora-test-postgres quisora-test-mysql quisora-test-mariadb >/dev/null 2>&1 || true
	;;
env)
	dsns
	;;
*)
	echo "usage: $0 up | down | env" >&2
	exit 2
	;;
esac
