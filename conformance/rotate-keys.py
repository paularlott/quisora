#!/usr/bin/env python3
"""rotate-keys.py <config.json> <plan[variants]>: runs oidcc-server-rotate-keys, which compares the JWKS before and
after a key rotation that the tester triggers between the module's setup and its start (run-test-plan.py starts
modules at once, so it cannot). This creates the module, rotates Quisora's signing key through the management API,
then starts the module and prints its result. Rotating keys takes a recently re-authenticated admin console session
(a token cannot), so it signs in as the super admin seed set up (.run/admin-login.json: password, then TOTP code)."""
import asyncio, base64, hashlib, hmac, http.cookiejar, json, os, re, ssl, struct, sys, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".run", "suite", "scripts"))
from conformance import Conformance  # noqa: E402

NODE = "https://127.0.0.1:8090"


def totp(secret):
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    mac = hmac.new(key, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
    o = mac[-1] & 0x0F
    return "%06d" % ((struct.unpack(">I", mac[o:o + 4])[0] & 0x7FFFFFFF) % 1000000)


def rotate():
    login = json.load(open(os.path.join(HERE, ".run", "admin-login.json")))
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE  # the node's self-signed certificate
    web = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
                                      urllib.request.HTTPSHandler(context=ctx))

    def csrf(path):
        page = web.open(NODE + path).read().decode()
        return re.search(r'<meta name="csrf-token" content="([^"]*)"', page).group(1)

    def post(path, body, token, extra=None):
        h = {"Content-Type": "application/json", "Accept": "application/json", "X-CSRF-Token": token}
        h.update(extra or {})
        with web.open(urllib.request.Request(NODE + path, data=json.dumps(body).encode(), method="POST", headers=h)) as r:
            return r.status, r.read().decode()

    tok = csrf("/login/primary")
    _, out = post("/api-internal/login/password", {"org": "primary", "email": login["email"], "password": login["password"]}, tok)
    ticket = json.loads(out)["ticket"]
    post("/api-internal/login/totp", {"ticket": ticket, "code": totp(login["totp_secret"])}, tok)
    status, out = post("/api/keys/rotate", {}, csrf("/account"), {"Api-Version": "1"})
    print("rotated:", status, out)


async def main(config_file, plan):
    name, _, rest = plan.partition("[")
    variant = dict(v.split("=", 1) for v in rest.rstrip("]").split("][")) if rest else None
    conf = Conformance(os.environ.get("CONFORMANCE_SERVER", "https://localhost.emobix.co.uk:8453/"), None, False)
    created = await conf.create_test_plan(name, open(config_file).read(), variant)
    mod = await conf.create_test_from_plan_with_variant(created["id"], "oidcc-server-rotate-keys", None)
    mid = mod["id"]
    await conf.wait_for_state(mid, ["CONFIGURED"])
    rotate()
    await conf.start_test(mid)
    await conf.wait_for_state(mid, ["FINISHED"])
    info = await conf.get_module_info(mid)
    print("oidcc-server-rotate-keys", info["status"], info.get("result"))
    for entry in await conf.get_test_log(mid):
        if entry.get("result") in ("FAILURE", "WARNING"):
            print("  -", entry.get("src"), entry.get("result"), entry.get("msg"))
    return 0 if info.get("result") in ("PASSED", "WARNING") else 1


sys.exit(asyncio.run(main(sys.argv[1], sys.argv[2])))
