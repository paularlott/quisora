# An approval bot: decide the access requests waiting for this service account. Requests whose reason starts with one
# of the given prefixes (ticket numbers, say) are approved; the others are left for a person, or denied with --deny.
#
#   scriptling -L lib examples/approve_requests.py <org> <prefix>[,<prefix>...] [--deny] [--dry-run]
#
# Needs a service account of the organization with the access_requests:approve scope, and requester groups whose
# settings let service accounts approve (Service accounts can approve). Run it from cron, or a chat bot's command.

import sys
import quisora

args = sys.argv[1:]
deny = "--deny" in args
dry = "--dry-run" in args
args = [a for a in args if not a.startswith("--")]
if len(args) != 2:
    print("usage: approve_requests.py <org> <prefix>[,<prefix>...] [--deny] [--dry-run]")
    sys.exit(2)
org, prefixes = args[0], [p for p in args[1].split(",") if p]

qs = quisora.from_env()
try:
    waiting = qs.pending_access_requests(org)
    if not waiting:
        print("Nothing is waiting")
    for r in waiting:
        who = f"{r['user_name']} for {r['tenant_display_name']} ({r['length_text']}): {r['reason']}"
        matched = any(r["reason"].startswith(p) for p in prefixes)
        if matched:
            if not dry:
                qs.approve_access_request(org, r["id"], note="Approved automatically: the reason names a ticket")
            print(f"Approved {who}")
        elif deny:
            if not dry:
                qs.deny_access_request(org, r["id"], note="Denied automatically: give a ticket number as the reason")
            print(f"Denied {who}")
        else:
            print(f"Left for a person: {who}")
except quisora.QuisoraError as e:
    print(f"Could not decide: {e}")
    sys.exit(1)
