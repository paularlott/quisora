# Create a user and, with --invite, issue them an invitation link to set up their sign-in.
#
#   scriptling -L lib examples/create_user.py <org> <email> <given name> [family name]
#       [--username grace] [--role user|manager|admin] [--tag dept:eng ...] [--invite] [--mail]
#
# --invite prints the single-use link; --mail also emails it to the user.
# A service account needs the users scope, and manage_admins as well to create an admin.

import sys
import quisora

args = sys.argv[1:]
positional = []
fields = {}
tags = []
invite = None
while args:
    arg = args.pop(0)
    if arg == "--username":
        fields["username"] = args.pop(0)
    elif arg == "--role":
        fields["role"] = args.pop(0)
    elif arg == "--tag":
        tags.append(args.pop(0))
    elif arg == "--invite":
        invite = invite or {"email": False}
    elif arg == "--mail":
        invite = {"email": True}
    else:
        positional.append(arg)

if len(positional) < 3:
    print("usage: create_user.py <org> <email> <given name> [family name] [--username u] [--role r] [--tag t] [--invite] [--mail]")
    sys.exit(2)

org, email, given_name = positional[0], positional[1], positional[2]
if len(positional) > 3:
    fields["family_name"] = positional[3]
if tags:
    fields["tags"] = tags

qs = quisora.from_env()

try:
    user = qs.create_user(org, email, given_name, invite=invite, **fields)
except quisora.QuisoraError as e:
    print(f"Could not create {email}: {e}")
    sys.exit(1)

print(f"Created {user.get('username')} <{user.get('email')}> with id {user['id']}")
link = user.get("invite")
if link:
    print(f"Invitation link (valid until {link['expires']}): {link['url']}")
    if link.get("emailed"):
        print("The link was emailed to the user.")
    elif link.get("email_warning"):
        print("Not emailed: " + link["email_warning"])
