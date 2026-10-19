#!/bin/sh
# node.sh start|stop|seed|idp-start|idp-stop: the Quisora node under test and the fake sign-in provider. Everything
# they write lives in conformance/.run (ignored by git): master key, data directory, certificates, pids and logs.
set -e
C=$(cd "$(dirname "$0")" && pwd)
ROOT=$C/..
R=$C/.run
URL=https://host.docker.internal:8090 # how the suite's container (and its browser) reach this machine
mkdir -p "$R"
[ -f "$R/masterkey" ] || "$ROOT/bin/quisora" genkey > "$R/masterkey"
K=$(tr -d '\n' < "$R/masterkey")
case "$1" in
start)
  nohup "$ROOT/bin/quisora" serve --listen 0.0.0.0:8090 --public-url "$URL" --data-dir "$R/data" --master-key "$K" \
    --extra-ca-file "$R/fakeidp.pem" --allow-private-networks --log-level debug >> "$R/node.log" 2>&1 &
  echo $! > "$R/node.pid"
  for i in $(seq 1 40); do curl -skf https://127.0.0.1:8090/healthz > /dev/null && break; sleep 0.5; done
  curl -sk https://127.0.0.1:8090/healthz; echo;;
stop)
  [ -f "$R/node.pid" ] && kill "$(cat "$R/node.pid")" 2> /dev/null || true
  sleep 1.5; rm -f "$R/node.pid";;
seed)
  rm -rf "$R/data"
  (cd "$ROOT" && bin/seed --data "$R/data" --master-key "$K" --public-url "$URL");;
idp-start)
  nohup "$ROOT/bin/fakeidp" --cert-out "$R/fakeidp.pem" >> "$R/fakeidp.log" 2>&1 &
  echo $! > "$R/fakeidp.pid"; sleep 0.7
  curl -skf https://127.0.0.1:8095/.well-known/openid-configuration > /dev/null && echo "fakeidp up";;
idp-stop)
  [ -f "$R/fakeidp.pid" ] && kill "$(cat "$R/fakeidp.pid")" 2> /dev/null || true
  rm -f "$R/fakeidp.pid";;
*)
  echo "usage: node.sh start|stop|seed|idp-start|idp-stop" >&2; exit 2;;
esac
