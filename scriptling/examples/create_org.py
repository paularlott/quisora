# Create an organization, optionally with its first service account.
#
#   scriptling -L lib examples/create_org.py <name> [display name] [--service-account setup users,groups,...]
#
# Needs a super admin's token, or a service account of the primary organization with orgs:create.
# The service account's secret is printed once: store it straight away.

import sys
import quisora

args = sys.argv[1:]
positional = []
service_account = None
while args:
    arg = args.pop(0)
    if arg == "--service-account":
        if len(args) < 2:
            print("--service-account needs a name and a comma-separated list of scopes")
            sys.exit(2)
        service_account = {"name": args.pop(0), "scopes": args.pop(0).split(",")}
    else:
        positional.append(arg)

if not positional:
    print("usage: create_org.py <name> [display name] [--service-account <name> <scope,scope,...>]")
    sys.exit(2)

name = positional[0]
display_name = positional[1] if len(positional) > 1 else None

qs = quisora.from_env()

try:
    org = qs.create_org(name, display_name=display_name, service_account=service_account)
except quisora.QuisoraError as e:
    print(f"Could not create {name}: {e}")
    sys.exit(1)

print(f"Created organization {org['name']} ({org.get('display_name', '')}) with id {org['id']}")
sa = org.get("service_account")
if sa:
    print(f"Service account {sa['name']}: client_id {sa['id']}")
    print(f"  token endpoint: {sa.get('token_endpoint')}")
    if sa.get("secret"):
        print(f"  secret (shown once): {sa['secret']}")
