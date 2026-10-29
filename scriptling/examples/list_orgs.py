# List the organizations the token can see (a super admin's sees them all).
#
#   scriptling -L lib examples/list_orgs.py [search]

import sys
import quisora

search = sys.argv[1] if len(sys.argv) > 1 else None

qs = quisora.from_env()

print("%-24s %-20s %-30s %s" % ("ID", "NAME", "DISPLAY NAME", "USERS"))
for org in qs.iter_orgs(q=search, sort="name"):
    name = org["name"] + (" *" if org.get("primary") else "")
    print("%-24s %-20s %-30s %s" % (org["id"], name, org.get("display_name", ""), org.get("users", "")))
