#!/bin/bash
# run.sh <plan[variants]> <export-subdir> [extra run-test-plan.py args]: one plan against the suite at
# https://localhost.emobix.co.uk:8453 (its development host name, which resolves to 127.0.0.1), with the seeded
# configuration conformance/.run/config/$CONFIG (default basic.json).
set -e
C=$(cd "$(dirname "$0")" && pwd)
R=$C/.run
export CONFORMANCE_SERVER=https://localhost.emobix.co.uk:8453/ CONFORMANCE_DEV_MODE=1
mkdir -p "$R/results/$2"
cd "$R/suite/scripts" && "$R/venv/bin/python" run-test-plan.py --export-dir "$R/results/$2" "${@:3}" "$1" "$R/config/${CONFIG:-basic.json}"
