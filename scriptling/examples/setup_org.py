# Create a customer organization and set it up, as the service account that owns it.
#
#   scriptling -L lib examples/setup_org.py <name> [display name] --admin <email> <given name>
#       [--guests <primary org> <group id,group id,...>] [--color #rrggbb]
#
# Needs a service account of the primary organization with orgs:create and orgs:manage (QUISORA_CLIENT_ID,
# QUISORA_CLIENT_SECRET, QUISORA_ORG set to the primary organization). The account owns what it creates: it acts as
# a super admin of that organization, and of no other. --guests lets the members of those groups of the primary
# organization sign in to the new one as guests (an organization provider).

import sys
import quisora

args = sys.argv[1:]
positional = []
admin = None
guests = None
color = None
while args:
    arg = args.pop(0)
    if arg == "--admin":
        if len(args) < 2:
            print("--admin needs an email address and a given name")
            sys.exit(2)
        admin = (args.pop(0), args.pop(0))
    elif arg == "--guests":
        if len(args) < 2:
            print("--guests needs the primary organization's name and a comma-separated list of its group ids")
            sys.exit(2)
        guests = (args.pop(0), [g for g in args.pop(0).split(",") if g])
    elif arg == "--color":
        if not args:
            print("--color needs a colour, #rrggbb")
            sys.exit(2)
        color = args.pop(0)
    else:
        positional.append(arg)

if not positional or admin is None:
    print("usage: setup_org.py <name> [display name] --admin <email> <given name> "
          "[--guests <primary org> <group,group,...>] [--color #rrggbb]")
    sys.exit(2)

name = positional[0]
display_name = positional[1] if len(positional) > 1 else None

qs = quisora.from_env()

try:
    org = qs.create_org(name, display_name=display_name)
    print(f"Created organization {org['name']} with id {org['id']}")
    if color:
        qs.update_branding(name, primary_color=color)
        print(f"  branding: {color}")
    user = qs.create_user(name, admin[0], admin[1], role="admin", invite={"email": True})
    print(f"  administrator {user['email']} invited")
    if guests:
        p = qs.create_provider(name, "organization", source_org=guests[0], source_groups=guests[1],
                               auto_provision=True)
        print(f"  guests from {guests[0]} through provider {p['name']} ({p['id']})")
except quisora.QuisoraError as e:
    print(f"Could not set up {name}: {e}")
    sys.exit(1)
