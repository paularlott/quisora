# summ.py <runlog>: per-module result and the FAILURE/WARNING conditions with messages, from the suite API.
import json, re, ssl, sys, urllib.request
ctx = ssl._create_unverified_context()
B = "https://localhost.emobix.co.uk:8453"
def get(p): return json.load(urllib.request.urlopen(B + p, context=ctx))
log = open(sys.argv[1]).read()
ids = re.findall(r"Running test module: (\S+)\n.*?new id: (\w+)", log)
detail = len(sys.argv) < 3 or sys.argv[2] != "brief"
for name, mid in ids:
    info = get("/api/info/" + mid)
    res, st = info.get("result"), info.get("status")
    short = name.split("[")[0]
    print(f"{short:60s} {st:12s} {res}")
    if detail and res not in ("PASSED",):
        for e in get("/api/log/" + mid):
            r = e.get("result")
            if r in ("FAILURE", "WARNING", "INTERRUPTED", "REVIEW", "SKIPPED") or (st == "INTERRUPTED" and e.get("src") in ("WebRunner",) and "rror" in str(e.get("msg"))):
                extra = {k: str(v)[:250] for k, v in e.items() if k in ("error", "expected", "actual", "claim", "url", "error_description", "missing", "unexpected", "status", "content", "value", "required", "found")}
                print(f"     - {e.get('src')} {r}: {str(e.get('msg'))[:300]} {extra if extra else ''}")
