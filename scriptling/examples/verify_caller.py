# Verify a caller from the command line (or a CRM's button): find the person, start a verification, print the code to
# read to them, and wait for their answer.
#
#   scriptling -L lib examples/verify_caller.py <org> <name or email> <in|out> [reason] [--org <their organization>] [--no-wait]
#
# in: they called you; out: you called them (only ever on the number held for their account). Run it as the agent:
# QUISORA_TOKEN is your personal API token with the call_verify scope (you must be in one of your organization's agent
# groups). The person enters the code under Verify a call in their own account menu.

import sys
import time
import quisora

args = sys.argv[1:]
wait = "--no-wait" not in args
customer_org = None
if "--org" in args:
    i = args.index("--org")
    if i + 1 < len(args):
        customer_org = args[i + 1]
        args = args[:i] + args[i + 2:]
args = [a for a in args if not a.startswith("--")]
if len(args) < 3 or args[2] not in ("in", "out"):
    print("usage: verify_caller.py <org> <name or email> <in|out> [reason] [--org <their organization>] [--no-wait]")
    sys.exit(2)
org, who, direction = args[0], args[1], ("inbound" if args[2] == "in" else "outbound")
reason = args[3] if len(args) > 3 else None

qs = quisora.from_env()
try:
    people = qs.verify_users(org, who, customer_org)
    if len(people) != 1:
        print(f"{len(people)} people match {who}: be more precise")
        for p in people:
            print(f"  {p['name']} <{p['email']}>")
        sys.exit(1)
    person = people[0]
    started = qs.start_verification(org, person["id"], direction, reason, customer_org)
    v = started["verification"]
    code = started["code"]
    print(f"Verifying {person['name']} <{person['email']}>")
    print(f"Read them the code: {code[:3]} {code[3:]}")
    print(f"They enter it under Verify a call in their account menu ({v['verify_path']}). It works for 5 minutes.")
    if not wait:
        sys.exit(0)
    while True:
        time.sleep(3)
        v = qs.verification(org, v["id"])
        if v["state"] != "pending":
            break
    if v["state"] == "confirmed":
        how = "with a passkey or second factor" if v.get("second_factor") else "with their password only"
        print(f"Confirmed: it is them ({how})")
    elif v["state"] == "denied":
        print("Not them: they said it was not them")
        sys.exit(1)
    else:
        print(f"Not verified: {v['state']}")
        sys.exit(1)
except quisora.QuisoraError as e:
    print(f"Could not verify: {e}")
    sys.exit(1)
