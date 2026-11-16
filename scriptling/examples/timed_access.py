# Give a user access to a members-only tenant for a few hours, list who has access, or take it away: what an external
# tool that approves access requests does once it has approved one. Quisora ends the access by itself and signs the
# person out of the tenant's applications.
#
#   scriptling -L lib examples/timed_access.py <org> give <tenant> <user> <hours> <reason> [--roles r1,r2]
#   scriptling -L lib examples/timed_access.py <org> list <tenant>
#   scriptling -L lib examples/timed_access.py <org> remove <tenant> <user>
#
# <tenant> is a tenant's name or id, <user> a username or email address. Needs an administrator's token, or a service
# account of the organization with the access, tenants and users scopes.

import sys
import quisora

USAGE = ("usage: timed_access.py <org> give <tenant> <user> <hours> <reason> [--roles r1,r2]\n"
         "       timed_access.py <org> list <tenant>\n"
         "       timed_access.py <org> remove <tenant> <user>")

args = sys.argv[1:]
if len(args) < 3:
    print(USAGE)
    sys.exit(2)
org, action, rest = args[0], args[1], args[2:]
roles = None
positional = []
while rest:
    arg = rest.pop(0)
    if arg == "--roles" and rest:
        roles = [r for r in rest.pop(0).split(",") if r]
    else:
        positional.append(arg)

qs = quisora.from_env()


def need(value, what):
    if value is None:
        print(f"No {what} in {org}")
        sys.exit(1)
    return value


try:
    tenant = need(qs.find_tenant(org, positional[0]), "tenant " + positional[0])
    if action == "give" and len(positional) == 4:
        _, login, hours, reason = positional
        u = need(qs.find_user(org, login), "user " + login)
        e = qs.give_access(org, tenant["id"], u["id"], hours=float(hours), roles=roles, reason=reason)
        print(f"{u['username']} has access to {tenant['name']} until {e['expires']} (UTC)")
    elif action == "list" and len(positional) == 1:
        for e in qs.iter_access(org, tenant["id"]):
            end = e.get("expires") or "no end"
            print(f"{e['subject_type']:<6} {e['name']:<30} {end}")
    elif action == "remove" and len(positional) == 2:
        u = need(qs.find_user(org, positional[1]), "user " + positional[1])
        qs.remove_access(org, tenant["id"], tenant["id"] + ":" + u["id"])
        print(f"Removed {u['username']}'s access to {tenant['name']}")
    else:
        print(USAGE)
        sys.exit(2)
except quisora.QuisoraError as e:
    print(f"Could not {action}: {e}")
    sys.exit(1)
