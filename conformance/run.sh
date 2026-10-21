#!/bin/bash
# run.sh <plan[variants]> <export-subdir> [extra run-test-plan.py args]: one plan against the suite at
# https://localhost.emobix.co.uk:8453 (its development host name, which resolves to 127.0.0.1), with the seeded
# configuration conformance/.run/config/$CONFIG (default basic.json). It runs the suite's run-test-plan.py through
# run-plan.py, which rotates Quisora's signing key where oidcc-server-rotate-keys needs it. Append
# ":oidcc-server-rotate-keys" (or any module names, comma separated) to the plan to run only those modules.
set -e
C=$(cd "$(dirname "$0")" && pwd)
R=$C/.run
export CONFORMANCE_SERVER=https://localhost.emobix.co.uk:8453/ CONFORMANCE_DEV_MODE=1
mkdir -p "$R/results/$2"
cd "$R/suite/scripts" && "$R/venv/bin/python" "$C/run-plan.py" --export-dir "$R/results/$2" "${@:3}" "$1" "$R/config/${CONFIG:-basic.json}"
