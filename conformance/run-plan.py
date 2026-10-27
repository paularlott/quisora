#!/usr/bin/env python3
"""run-plan.py [run-test-plan.py arguments]: the suite's own runner (scripts/run-test-plan.py, unmodified), with a real
signing key rotation where oidcc-server-rotate-keys needs one.

That module compares the JWKS fetched at its set-up with the JWKS after a rotation the tester triggers before starting
it; the runner starts it at once, so on its own it always fails. Here the runner's suite client is wrapped: when the
runner starts that module, the rotation happens first (the seeded super admin signs in, password then TOTP, and calls
POST /api/keys/rotate: rotating takes a re-authenticated console session, not a token). It waits until no other module
of the plan is in flight, since one that fetched the JWKS before the rotation would get a token signed with the new
key. Everything else (plan creation, every module, the export) is the runner's, so the exported plan carries the
module's real result."""
import asyncio, base64, hashlib, hmac, http.cookiejar, importlib.util, json, os, re, ssl, struct, sys, time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(HERE, ".run", "suite", "scripts")
NODE = os.environ.get("QUISORA_NODE", "https://127.0.0.1:8090")
ROTATE_MODULE = "oidcc-server-rotate-keys"


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

    tok = csrf("/o/primary/login")
    _, out = post("/o/primary/api-internal/login/password", {"email": login["email"], "password": login["password"]}, tok)
    ticket = json.loads(out)["ticket"]
    post("/o/primary/api-internal/login/totp", {"ticket": ticket, "code": totp(login["totp_secret"])}, tok)
    status, out = post("/api/keys/rotate", {}, csrf("/o/primary/account"), {"Api-Version": "2026-10-20"})
    if status != 200:
        raise SystemExit("key rotation failed: %d %s" % (status, out))
    print("Rotated Quisora's signing key:", out)


def load_runner():
    sys.path.insert(0, SCRIPTS)
    spec = importlib.util.spec_from_file_location("run_test_plan", os.path.join(SCRIPTS, "run-test-plan.py"))
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    return runner


def wrap(client):
    created, start, info = client.create_test_from_plan_with_variant, client.start_test, client.get_module_info
    live, rotating = set(), set()  # module ids not known to be over; those of the rotation module

    async def create_test_from_plan_with_variant(self, plan_id, test_name, variant):
        out = await created(self, plan_id, test_name, variant)
        live.add(out["id"])
        if test_name == ROTATE_MODULE:
            rotating.add(out["id"])
        return out

    async def start_test(self, module_id):
        if module_id in rotating:
            while True:
                for mid in [m for m in live if m != module_id]:
                    if (await info(self, mid)).get("status") in ("FINISHED", "INTERRUPTED"):
                        live.discard(mid)
                if live <= {module_id}:
                    break
                await asyncio.sleep(2)
            rotate()
        return await start(self, module_id)

    client.create_test_from_plan_with_variant = create_test_from_plan_with_variant
    client.start_test = start_test


if __name__ == "__main__":
    runner = load_runner()
    wrap(runner.Conformance)
    sys.argv = [os.path.join(SCRIPTS, "run-test-plan.py")] + sys.argv[1:]
    asyncio.run(runner.main())
