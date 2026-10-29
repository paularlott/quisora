# Add users to a group, creating the group first if there is none of that name.
#
#   scriptling -L lib examples/add_to_group.py <org> <group name> <username or email> [...]

import sys
import quisora

if len(sys.argv) < 4:
    print("usage: add_to_group.py <org> <group name> <username or email> [...]")
    sys.exit(2)

org, group_name, logins = sys.argv[1], sys.argv[2], sys.argv[3:]

qs = quisora.from_env()

group = None
for g in qs.iter_groups(org, q=group_name):
    if g["display_name"].lower() == group_name.lower():
        group = g
        break
if group is None:
    group = qs.create_group(org, group_name)
    print(f"Created group {group['display_name']} ({group['id']})")

failed = 0
for login in logins:
    user = qs.find_user(org, login)
    if user is None:
        print(f"No user {login}")
        failed += 1
        continue
    qs.add_group_member(org, group["id"], user["id"])
    print(f"Added {user.get('username') or user['email']} to {group['display_name']}")

if failed:
    sys.exit(1)
