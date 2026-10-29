# List the users of an organization, optionally only those matching a search.
#
#   scriptling -L lib examples/list_users.py <org> [search] [--role admin] [--inactive]

import sys
import quisora

args = sys.argv[1:]
if not args or args[0].startswith("-"):
    print("usage: list_users.py <org> [search] [--role user|manager|admin] [--inactive]")
    sys.exit(2)

org = args.pop(0)
search = None
role = None
active = None
while args:
    arg = args.pop(0)
    if arg == "--role":
        role = args.pop(0)
    elif arg == "--inactive":
        active = False
    else:
        search = arg

qs = quisora.from_env()

count = 0
print("%-24s %-22s %-34s %-8s %s" % ("ID", "USERNAME", "EMAIL", "ROLE", "ACTIVE"))
for user in qs.iter_users(org, q=search, role=role, active=active, sort="username"):
    print("%-24s %-22s %-34s %-8s %s" % (user["id"], user.get("username", ""), user.get("email", ""),
                                         user.get("role", ""), "yes" if user.get("active") else "no"))
    count += 1
print(f"\n{count} user(s)")
