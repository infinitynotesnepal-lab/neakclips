"""Each person's own Gemini API key, with sign-in on: used only for them, never for anyone else, never shown, kept
encrypted. The network is replaced, so no key is needed and nothing leaves this machine."""
import json
import os
import stat
import sys
import tempfile
import threading

os.environ["PEAKCUT_DATA"] = tempfile.mkdtemp(prefix="pc-keys-")
os.environ.update(DATABASE_URL="", PEAKCUT_ACCOUNTS="1", PEAKCUT_PUBLIC_URL="http://127.0.0.1:8765", PEAKCUT_VERIFY_EMAIL="0",
                  PEAKCUT_AI_PROVIDER="gemini", PEAKCUT_AI_MODELS="", PEAKCUT_AI_BASE_URL="",
                  PEAKCUT_AI_KEY="AIzaSERVERENVKEY000000000000000000000",          # must never be used for anyone
                  PEAKCUT_SECRET_KEY="", PEAKCUT_SECRET_KEY_FILE=os.path.join(os.environ["PEAKCUT_DATA"], "keys", "secret.key"))
sys.path.insert(0, ".")
sys.path.insert(0, "tests")
import sqlalchemy as sa  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from _people import add_csrf  # noqa: E402
from studio import ai, auth, brain, config, ctx, db, migrate, server, usage, vault  # noqa: E402

db.init()
fails = []
BASE = "http://127.0.0.1:8765"
ORIGIN = {"Origin": BASE}
KA, KB, KT = "AIzaSyALICE" + "a" * 28, "AIzaSyBOB00" + "b" * 28, "AIzaSyTYPED" + "t" * 28
LEGACY = "AIzaSyLEGACY" + "l" * 27


def check(name, got, want=True):
    ok = want(got) if callable(want) else got == want
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"   got {got!r}"))
    ok or fails.append(name)


class Reply:
    def __init__(self, status, data):
        self.status_code, self._d, self.text, self.headers = status, data, json.dumps(data), {}

    def json(self):
        return self._d


sent = []           # the key each request to Google carried
GOOD = {KA, KB, KT, LEGACY}


def fake_post(url, json=None, headers=None, timeout=None, **_k):  # noqa: A002
    k = (headers or {}).get("x-goog-api-key", "")
    sent.append(k)
    if k not in GOOD:
        return Reply(400, {"error": {"message": f"API key not valid: {k}"}})   # a service that repeats the key back
    return Reply(200, {"candidates": [{"content": {"parts": [{"text": '["ok"]'}]}}],
                       "usageMetadata": {"promptTokenCount": 5, "totalTokenCount": 7}})


def fake_get(url, params=None, headers=None, timeout=None, **_k):
    sent.append((headers or {}).get("x-goog-api-key", ""))
    return Reply(200, {"models": [{"name": "models/gemini-2.5-flash", "supportedGenerationMethods": ["generateContent"]}]})


ai.httpx.post, ai.httpx.get = fake_post, fake_get


def person(email, admin=False):
    u, _ = auth._create(email, email.split("@")[0], password_hash="x")
    if admin:
        with db.engine.begin() as c:
            c.execute(db.users.update().where(db.users.c.id == u.id).values(is_admin=True))
    cl = TestClient(server.app, base_url=BASE, follow_redirects=False)
    cl.cookies.set(auth.COOKIE, auth.start_session(u.id))
    add_csrf(cl).get("/api/public")
    return u, cl


boss, admin = person("boss@example.com", admin=True)
alice, a = person("alice@example.com")
bob, b = person("bob@example.com")
carol, c = person("carol@example.com")

# ---- an older version's key in ai.json (plain text) goes to its owner, encrypted, and nowhere else
(config.DATA_DIR / "ai.json").write_text(json.dumps({"provider": "gemini", "models": ["gemini-2.5-flash"], "base_url": "", "key": LEGACY}))
migrate.run(apply=True, quiet=True)
left = json.loads((config.DATA_DIR / "ai.json").read_text())
check("the plain-text key is gone from ai.json, the model choice stays", ("key" in left, left.get("models")), (False, ["gemini-2.5-flash"]))
with ctx.as_user(boss.id):
    check("it now belongs to the admin who saved it", ai.key(), LEGACY)
with ctx.as_user(carol.id):
    check("nobody else gets it", ai.key(), "")
check("running the migration again changes nothing", migrate.run(apply=True, quiet=True)["ai_key"], "no plain-text key")
f = config.SECRET_KEY_FILE
check("the secret key file was made, readable by the app only", (f.is_file(), stat.S_IMODE(f.stat().st_mode)), (True, 0o600))
check("...in a folder of its own", stat.S_IMODE(f.parent.stat().st_mode), 0o700)

# ---- someone without a key: no AI, and no one else's key, the server's .env key or an old ai.json key
(config.DATA_DIR / "ai.json").write_text(json.dumps({"provider": "gemini", "models": ["m"], "key": LEGACY}))   # as if left behind
ai._saved["at"] = None
r = c.get("/api/ai").json()
check("no key: not ready, and nothing borrowed", (r["ready"], r["has_key"], r["key_mask"]), (False, False, ""))
check("only Gemini is offered", [p["id"] for p in r["providers"]], ["gemini"])
check("the page says the AI is off for them", c.get("/api/status").json()["ai"]["ready"], False)
check("testing without a key says to add one", c.post("/api/ai/test", json={}).status_code, 400)
sent.clear()
with ctx.as_user(carol.id):
    try:
        brain.ask_ai("hello", purpose="test")
        got = "answered"
    except RuntimeError as e:
        got = str(e)
check("an AI call for them is not made at all", (got, sent), ("The AI is not set up on this server.", []))
(config.DATA_DIR / "ai.json").unlink()
ai._saved["at"] = None

# ---- two people, two keys
r = a.put("/api/ai", json={"provider": "gemini", "models": "gemini-2.5-flash", "key": KA})
check("alice saves her key", (r.status_code, r.json()["ready"]), (200, True))
check("...only a masked form comes back", (KA in r.text, r.json()["key_mask"]), (False, KA[:4] + "•" * 8 + KA[-4:]))
r = b.put("/api/ai", json={"models": "", "key": KB})
check("bob saves his, with the usual model", (r.status_code, r.json()["models"]), (200, ["gemini-2.5-flash"]))
check("each sees only their own mask", (a.get("/api/ai").json()["key_mask"][-4:], b.get("/api/ai").json()["key_mask"][-4:]), (KA[-4:], KB[-4:]))
for who, cl in (("alice", a), ("bob", b), ("carol", c), ("the admin", admin)):
    texts = [cl.get(p).text for p in ("/api/ai", "/api/status", "/api/sync", "/api/usage")]
    check(f"{who}: no key in any page data", any(k in t for t in texts for k in (KA, KB, LEGACY)), False)
adm = admin.get("/api/admin/overview")
check("admins see who has a key, and nothing of the key", (next(u for u in adm.json()["users"] if u["id"] == bob.id)["has_ai_key"],
                                                            any(k in adm.text for k in (KA, KB, KA[-4:] + '"', "key_enc"))), (True, False))
check("...not on an account's page either", any(k in admin.get(f"/api/admin/users/{alice.id}").text for k in (KA, KB, "key_mask", "key_enc")), False)

# ---- kept encrypted, and bound to its owner
with db.engine.connect() as cn:
    rows = {r.user_id: r for r in cn.execute(sa.select(db.ai_keys))}
check("the database holds no key as plain text", any(k in (r.key_enc or "") for r in rows.values() for k in (KA, KB, LEGACY)), False)
check("each is AES-256-GCM, versioned", rows[alice.id].key_enc.startswith("v1:"), True)
check("it opens for its owner", vault.unlock(rows[alice.id].key_enc, f"ai_key:{alice.id}"), KA)
try:
    vault.unlock(rows[alice.id].key_enc, f"ai_key:{bob.id}")
    moved = "opened"
except vault.VaultError:
    moved = "refused"
check("...and not as anyone else's", moved, "refused")
with db.engine.begin() as cn:                                 # someone with database access copies alice's key onto bob
    cn.execute(db.ai_keys.update().where(db.ai_keys.c.user_id == bob.id).values(key_enc=rows[alice.id].key_enc))
ai.forget()
pub = b.get("/api/ai").json()
check("a key moved to another account is not used there", (pub["has_key"], pub["ready"], pub["unreadable"]), (False, False, True))
with db.engine.begin() as cn:
    cn.execute(db.ai_keys.update().where(db.ai_keys.c.user_id == bob.id).values(key_enc=rows[bob.id].key_enc))
ai.forget()

# ---- every AI request uses the asking person's own key
sent.clear()
check("alice's test uses her key", (a.post("/api/ai/test", json={}).status_code, sent[-1]), (200, KA))
check("bob's test uses his", (b.post("/api/ai/test", json={}).status_code, sent[-1]), (200, KB))
check("a key can be tested before saving", (a.post("/api/ai/test", json={"key": KT}).status_code, sent[-1], a.get("/api/ai").json()["key_mask"][-4:]),
      (200, KT, KA[-4:]))
sent.clear()
with ctx.as_user(alice.id):
    brain.ask_ai("hello", purpose="test")
out = {}
with ctx.as_user(bob.id):
    t = threading.Thread(target=ctx.bind(lambda: out.update(r=brain.ask_ai("hi", purpose="test")[1])))   # how jobs and recordings run
t.start(); t.join()                                                                                       # noqa: E702
check("video work and live recording use their owner's key, even on other threads", sent, [KA, KB])
with ctx.as_user(alice.id):
    check("alice's calls are in her usage", usage.summary({})["calls_total"], 1)
with ctx.as_user(carol.id):
    check("...and not in carol's", usage.summary({})["calls_total"], 0)

# ---- a key that is refused is explained without repeating it
bad = "AIzaSyWRONG0" + "w" * 27
r = a.post("/api/ai/test", json={"key": bad})
check("a refused key is explained without echoing it", (r.status_code, bad in r.text, "refused the key" in r.text), (502, False, True))
check("a pasted key that can't be a key is refused", a.put("/api/ai", json={"key": "short"}).status_code, 400)

# ---- only Gemini, only Google's address: a key can never be sent somewhere else
check("another service is refused", a.put("/api/ai", json={"provider": "openai", "models": "m", "key": KA}).status_code, 400)
check("another address is refused", a.put("/api/ai", json={"provider": "gemini", "models": "m", "base_url": "http://10.0.0.5/v1", "key": KA}).status_code, 400)
check("finding models at another address is refused", a.post("/api/ai/models", json={"provider": "gemini", "base_url": "http://10.0.0.5"}).status_code, 400)
check("finding models with the saved key works", a.post("/api/ai/models", json={"provider": "gemini"}).json()["models"], ["gemini-2.5-flash"])

# ---- CSRF and who may change it
plain = TestClient(server.app, base_url=BASE, follow_redirects=False)
plain.cookies.set(auth.COOKIE, a.cookies.get(auth.COOKIE))
check("changing a key needs the page's CSRF token", plain.put("/api/ai", json={"key": KT}, headers=ORIGIN).status_code, 403)
check("...removing it too", plain.delete("/api/ai/key", headers=ORIGIN).status_code, 403)
anon = add_csrf(TestClient(server.app, base_url=BASE, follow_redirects=False))
anon.get("/api/public")
check("signed out, nothing can be read or changed", (anon.get("/api/ai").status_code, anon.put("/api/ai", json={"key": KT}).status_code), (401, 401))

# ---- removing a key
r = a.delete("/api/ai/key")
check("alice removes her key", (r.status_code, r.json()["has_key"], r.json()["ready"]), (200, False, False))
sent.clear()
with ctx.as_user(alice.id):
    try:
        brain.ask_ai("hello", purpose="test")
    except RuntimeError:
        pass
check("after that no call is made for her, with anyone's key", sent, [])
check("bob's key is untouched", b.get("/api/ai").json()["ready"], True)
with db.engine.connect() as cn:
    kinds = [r.kind for r in cn.execute(sa.select(db.activity).where(db.activity.c.user_id == alice.id))]
check("saving and removing are in her activity", {"api_key_saved", "api_key_removed"} <= set(kinds), True)

# ---- guessing invitation links is stopped (here, where the limits are this test's own)
from studio import invites  # noqa: E402
real = invites.create(boss.id, "guessed@example.com", 24)["link"].rsplit("/", 1)[1]
g = add_csrf(TestClient(server.app, base_url=BASE, follow_redirects=False))
g.get("/api/public")
body = lambda t: {"token": t, "name": "G", "password": "good-pass-123", "confirm": "good-pass-123"}  # noqa: E731
codes = [g.post("/api/auth/invite/accept", json=body("C" * 40 + f"{i:03d}"), headers=ORIGIN).status_code for i in range(22)]
check("trying many made-up links is rate limited", (codes[0], codes[-1]), (404, 429))
same = [g.post("/api/auth/invite/check", json={"token": "D" * 43}, headers=ORIGIN).status_code for _ in range(2)]
check("...one link tried over and over is limited on its own too", same[-1], 429)
check("...even the real one waits, from there", g.post("/api/auth/invite/accept", json=body(real), headers=ORIGIN).status_code, 429)
check("...and the invitation itself is still unused", invites.check(real)["email"], "guessed@example.com")

print("ALL PASSED" if not fails else f"{len(fails)} failed")
import shutil  # noqa: E402
db.engine.dispose()
shutil.rmtree(os.environ["PEAKCUT_DATA"], ignore_errors=True)
sys.exit(1 if fails else 0)
