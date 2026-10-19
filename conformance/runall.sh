#!/bin/bash
# runall.sh <tag>: the four certification plans; logs in conformance/.run/logs/<plan>-<tag>.log, the suite's exports
# in conformance/.run/results/<plan>-<tag>/, then a one-line result per module.
C=$(cd "$(dirname "$0")" && pwd)
L=$C/.run/logs
mkdir -p "$L"
T=${1:-run}
"$C/run.sh" "oidcc-config-certification-test-plan" "config-$T" > "$L/config-$T.log" 2>&1
"$C/run.sh" "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]" "basic-$T" > "$L/basic-$T.log" 2>&1
"$C/run.sh" "oidcc-rp-initiated-logout-certification-test-plan[client_registration=static_client][response_type=code]" "rpl-$T" > "$L/rpl-$T.log" 2>&1
CONFIG=backchannel.json "$C/run.sh" "oidcc-backchannel-rp-initiated-logout-certification-test-plan[client_registration=static_client][response_type=code]" "bcl-$T" > "$L/bcl-$T.log" 2>&1
for p in config basic rpl bcl; do echo "== $p"; python3 "$C/summ.py" "$L/$p-$T.log" brief; done
