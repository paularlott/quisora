# Who is this access token for, and are they a guest from another organization? What an application does with a token
# it was given: ask Quisora (introspection, as the application), then label a guest with where they came from.
#
#   scriptling -L lib examples/guest_token.py <org> <access token>
#
# <org> is the application's organization (name or id). The application's own credentials come from
# QUISORA_APP_CLIENT_ID and QUISORA_APP_CLIENT_SECRET: a confidential client of that organization, not a service
# account. A guest's home organization and tenant are in the token only when the application asked for the idp scope.

import os
import sys
import quisora

if len(sys.argv) != 3:
    print("usage: guest_token.py <org> <access token>")
    sys.exit(2)
org, token = sys.argv[1], sys.argv[2]
url = os.environ.get("QUISORA_URL")
client_id, secret = os.environ.get("QUISORA_APP_CLIENT_ID"), os.environ.get("QUISORA_APP_CLIENT_SECRET")
if not url or not client_id or not secret:
    print("QUISORA_URL, QUISORA_APP_CLIENT_ID and QUISORA_APP_CLIENT_SECRET are needed")
    sys.exit(2)

try:
    claims = quisora.introspect(url, org, token, client_id, secret,
                                verify=os.environ.get("QUISORA_INSECURE", "") not in ("1", "true", "yes"))
except quisora.QuisoraError as e:
    print(f"Could not ask: {e}")
    sys.exit(1)
if not claims.get("active"):
    print("Not an active token for this application")
    sys.exit(1)
who = claims.get("username") or claims.get("sub")
guest = quisora.guest_of(claims)
if guest is None:
    print(f"{who}, of {claims.get('org_name')}")
else:
    home = guest["org_name"] or guest["org"]
    if guest["tenant_name"]:
        home += ", " + guest["tenant_name"]
    print(f"{who}, a guest from {home} (their id there {guest['user']}, organization {guest['org']})")
