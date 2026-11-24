"""Invitations, admin account management, CSRF and keeping each person's data to themselves, against a throwaway
NeakClips server. Usage: test_invites.py <base url> <project root>"""
import concurrent.futures
import hashlib
import os
import subprocess
import sys
import time

import sqlalchemy as sa

from _people import client, invite_token, join

BASE, ROOT = sys.argv[1], sys.argv[2]
ORIGIN = {"Origin": BASE}
sys.path.insert(0, ROOT)
from studio import db  # noqa: E402  (the test server's own database: same PEAKCUT_DATA)

fails = []


def check(name, got, want=True):
    ok = want(got) if callable(want) else got == want
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"   got {got!r}"))
    ok or fails.append(name)


def accept(c, token, password="good-pass-123", confirm=None, name="New Person", **extra):
    return c.post("/api/auth/invite/accept", json={"token": token, "name": name, "password": password,
                                                   "confirm": password if confirm is None else confirm, **extra}, headers=ORIGIN)


# ---- an admin, made the way the first admin is made on a real server
boss, boss_u = join(BASE, "boss@example.com", name="Boss", root=ROOT)
subprocess.run([sys.executable, "-m", "studio.admin", "grant", "boss@example.com"], cwd=ROOT, env=os.environ, check=True,
               capture_output=True)
user, user_u = join(BASE, "plain@example.com", name="Plain", root=ROOT)
anon = client(BASE)

# ---- nobody can sign themselves up
check("sign-up is closed", anon.post("/api/auth/signup", json={"email": "self@example.com", "password": "test-pass-123"}, headers=ORIGIN).status_code, 403)
check("the old sign-up page sends people to sign in", (anon.get("/signup").status_code, anon.get("/signup").headers.get("location")), (303, "/login?invite_only=1"))
check("the server says it is invitation only", anon.get("/api/public").json().get("invite_only"), True)

# ---- CSRF: a change without the page's token is refused, even when signed in
nocsrf = client(BASE, csrf=False)
nocsrf.cookies.update({k: v for k, v in user.cookies.items()})
check("a change without the CSRF header is refused", nocsrf.put("/api/settings", json={}, headers=ORIGIN).status_code, 403)
check("...with a wrong one too", nocsrf.put("/api/settings", json={}, headers={**ORIGIN, "X-CSRF-Token": "x" * 43}).status_code, 403)
check("...and with it, it works", user.put("/api/settings", json={}, headers=ORIGIN).status_code, 200)
import httpx  # noqa: E402
check("the CSRF cookie is SameSite=Strict", "samesite=strict" in httpx.get(BASE + "/login").headers.get("set-cookie", "").lower(), True)
check("reading needs no token", nocsrf.get("/api/status").status_code, 200)

# ---- only admins can invite, revoke, or see invitations, activity or reset links
for path, method in (("/api/admin/invitations", "get"), ("/api/admin/invitations", "post"), ("/api/admin/activity", "get"),
                     ("/api/admin/invitations/inv_0000000000000000/revoke", "post"),
                     ("/api/admin/invitations/inv_0000000000000000/renew", "post"),
                     (f"/api/admin/users/{boss_u['id']}/reset-password", "post")):
    for who, c in (("a user", user), ("someone signed out", anon)):
        r = getattr(c, method)(path, **({"json": {"email": "x@example.com", "hours": 24}, "headers": ORIGIN} if method == "post" else {}))
        check(f"{who}: {method.upper()} {path} -> 404", r.status_code, 404)

# ---- making invitations
mk = lambda email, hours=24: boss.post("/api/admin/invitations", json={"email": email, "hours": hours}, headers=ORIGIN)  # noqa: E731
check("a bad email is refused", mk("not-an-email").status_code, 400)
check("an email that can carry extra addresses is refused", mk("a@example.com,b@example.com").status_code, 400)
check("only 24 hours, 3 days or 7 days", (mk("t@example.com", 5).status_code, mk("t@example.com", "abc").status_code), (400, 400))
check("someone who already has an account can't be invited", mk("plain@example.com").status_code, 409)
r = mk("New.Person@Example.com", 72)
check("an admin invites someone", r.status_code, 200)
inv = r.json()
token = inv["link"].rsplit("/", 1)[1]
check("the link is on this server, under /invite/", inv["link"].startswith(BASE + "/invite/"), True)
check("the email is kept in lower case", inv["email"], "new.person@example.com")
check("it lasts what was chosen", round((inv["expires_at"] - inv["created_at"]) / 3600), 72)
check("the token is long and random", len(token) >= 40, True)
with db.engine.connect() as cn:
    row = cn.execute(sa.select(db.invitations).where(db.invitations.c.id == inv["id"])).first()
check("only the token's SHA-256 is stored, never the token", (row.token_hash == hashlib.sha256(token.encode()).hexdigest(),
                                                              token in str(tuple(row))), (True, False))
listing = boss.get("/api/admin/invitations")
check("the list shows it as pending", next(x["status"] for x in listing.json()["items"] if x["id"] == inv["id"]), "pending")
check("the list never contains a token or link", token in listing.text or "/invite/" in listing.text, False)

# ---- the invitation page and its form
check("the invitation page opens", anon.get(f"/invite/{token}").status_code, 200)
check("...is never cached or passed on", (anon.get(f"/invite/{token}").headers.get("cache-control"),
                                         anon.get(f"/invite/{token}").headers.get("referrer-policy")), ("private, no-store", "no-referrer"))
check("...and the token is not written into it", token in anon.get(f"/invite/{token}").text, False)
chk = anon.post("/api/auth/invite/check", json={"token": token}, headers=ORIGIN)
check("the page is told which email the invitation is for", (chk.status_code, chk.json().get("email")), (200, "new.person@example.com"))
check("a made-up token is refused", anon.post("/api/auth/invite/check", json={"token": "A" * 43}, headers=ORIGIN).status_code, 404)
c1 = client(BASE)
check("the passwords must match", accept(c1, token, confirm="different-123").status_code, 400)
check("a name is needed", accept(c1, token, name="  ").status_code, 400)
check("a short password is refused", accept(c1, token, password="short").status_code, 400)
check("it can't be used for another email", accept(c1, token, email="someone.else@example.com").status_code, 403)
r = accept(c1, token, email="new.person@example.com", is_admin=True, role="admin")
check("the account is made", r.status_code, 200)
newbie = r.json()["user"]
check("...for the invited email, as a normal user", (newbie["email"], newbie["is_admin"]), ("new.person@example.com", False))
check("...and they are signed in straight away", c1.get("/api/auth/me").json()["user"]["email"], "new.person@example.com")
check("...and can open their dashboard", c1.get("/app").status_code, 200)
check("the invitation can't be used again", accept(client(BASE), token).status_code, 410)
check("...or even looked at", anon.post("/api/auth/invite/check", json={"token": token}, headers=ORIGIN).status_code, 410)
st = next(x for x in boss.get("/api/admin/invitations").json()["items"] if x["id"] == inv["id"])
check("the history shows it accepted, by that account", (st["status"], st["accepted_user"]), ("accepted", newbie["id"]))
check("an accepted invitation can't be revoked", boss.post(f"/api/admin/invitations/{inv['id']}/revoke", headers=ORIGIN).status_code, 409)

# ---- expired
t2 = invite_token("late@example.com", ROOT)
with db.engine.begin() as cn:
    cn.execute(db.invitations.update().where(db.invitations.c.token_hash == hashlib.sha256(t2.encode()).hexdigest())
               .values(expires_at=time.time() - 1))
check("an expired invitation is refused", (accept(client(BASE), t2).status_code, "expired" in accept(client(BASE), t2).text), (410, True))
exp = next(x for x in boss.get("/api/admin/invitations").json()["items"] if x["email"] == "late@example.com")
check("the history shows it expired", exp["status"], "expired")
r = boss.post(f"/api/admin/invitations/{exp['id']}/renew", json={"hours": 168}, headers=ORIGIN)
check("an admin can make a new link for it", (r.status_code, r.json().get("status")), (200, "pending"))
t2b = r.json()["link"].rsplit("/", 1)[1]
check("the old link still doesn't work", accept(client(BASE), t2).status_code, 404)
check("the new one does", accept(client(BASE), t2b).status_code, 200)

# ---- revoked
r = mk("gone@example.com")
t3, i3 = r.json()["link"].rsplit("/", 1)[1], r.json()["id"]
check("an admin revokes an invitation", boss.post(f"/api/admin/invitations/{i3}/revoke", headers=ORIGIN).json()["status"], "revoked")
check("a revoked invitation is refused", accept(client(BASE), t3).status_code, 410)
r = mk("gone@example.com")
check("inviting the same email again replaces the older link", r.status_code, 200)
t4 = r.json()["link"].rsplit("/", 1)[1]
r = mk("gone@example.com")
check("...so only the newest link works", (accept(client(BASE), t4).status_code), 410)
check("a malformed invitation id is not found", boss.post("/api/admin/invitations/../x/revoke", headers=ORIGIN).status_code, 404)

# ---- the same link used twice at the same moment makes exactly one account
t5 = invite_token("race@example.com", ROOT)
with concurrent.futures.ThreadPoolExecutor(6) as ex:
    codes = sorted(ex.map(lambda _: accept(client(BASE), t5).status_code, range(6)))
check("one link, used six times at once, makes one account", (codes.count(200), sum(1 for x in codes if x in (409, 410, 429))), (1, 5))
with db.engine.connect() as cn:
    check("...and there is one row for it", cn.execute(sa.select(sa.func.count()).select_from(db.users).where(db.users.c.email == "race@example.com")).scalar(), 1)

# ---- what admins see: status and activity, never a password or key
ov = boss.get("/api/admin/overview")
check("the overview counts accepted invitations", ov.json()["totals"]["invites_accepted"] >= 3, True)
row = next(u for u in ov.json()["users"] if u["id"] == newbie["id"])
check("each account shows its status and whether it has a key", (row["disabled"], row["has_ai_key"], row["has_password"]), (False, False, True))
check("no password hash anywhere in the admin pages", any(x in ov.text for x in ("argon2", "scrypt", "password_hash")), False)
det = boss.get(f"/api/admin/users/{newbie['id']}").json()
check("an account's page shows who invited them", det["invited_by"], "boss@example.com")
check("...and that they joined and signed in", {a["kind"] for a in det["activity"]} >= {"joined", "login"}, True)
client(BASE).post("/api/auth/login", json={"email": "new.person@example.com", "password": "wrong-pass-1"}, headers=ORIGIN)
acts = boss.get("/api/admin/activity").json()["items"]
check("a wrong password shows in user activity", any(a["kind"] == "login_failed" and a["email"] == "new.person@example.com" for a in acts), True)
check("activity never holds what was typed", "wrong-pass-1" in boss.get("/api/admin/activity").text, False)

# ---- account management: disable, enable, reset the password with a link
dis = f"/api/admin/users/{newbie['id']}/disabled"
check("an admin disables the account", boss.post(dis, json={"disabled": True}, headers=ORIGIN).status_code, 200)
check("...they are signed out at once", c1.get("/api/status").status_code, 401)
check("...and can't sign in", client(BASE).post("/api/auth/login", json={"email": "new.person@example.com", "password": "good-pass-123"}, headers=ORIGIN).status_code, 400)
early = boss.post(f"/api/admin/users/{user_u['id']}/reset-password", json={}, headers=ORIGIN).json()["link"].split("t=", 1)[1]
boss.post(f"/api/admin/users/{user_u['id']}/disabled", json={"disabled": True}, headers=ORIGIN)
check("disabling an account cancels a reset link made before", client(BASE).post("/api/auth/reset", json={"token": early, "password": "sneaky-pass-123"}, headers=ORIGIN).status_code, 400)
boss.post(f"/api/admin/users/{user_u['id']}/disabled", json={"disabled": False}, headers=ORIGIN)
check("a disabled account gets no reset link", boss.post(f"/api/admin/users/{newbie['id']}/reset-password", json={}, headers=ORIGIN).status_code, 400)
check("an admin enables it again", boss.post(dis, json={"disabled": False}, headers=ORIGIN).status_code, 200)
r = boss.post(f"/api/admin/users/{newbie['id']}/reset-password", json={"hours": 24}, headers=ORIGIN)
check("an admin makes a one-time reset link", (r.status_code, "/reset?t=" in r.json().get("link", "")), (200, True))
check("...which holds no password", any(k in r.json() for k in ("password", "new_password")), False)
check("an admin can't reset their own password this way", boss.post(f"/api/admin/users/{boss_u['id']}/reset-password", json={}, headers=ORIGIN).status_code, 400)
rt = r.json()["link"].split("t=", 1)[1]
c2 = client(BASE)
check("the person chooses a new password with it", c2.post("/api/auth/reset", json={"token": rt, "password": "brand-new-pass-9"}, headers=ORIGIN).status_code, 200)
check("the link works only once", client(BASE).post("/api/auth/reset", json={"token": rt, "password": "another-pass-99"}, headers=ORIGIN).status_code, 400)
check("the old password no longer works", client(BASE).post("/api/auth/login", json={"email": "new.person@example.com", "password": "good-pass-123"}, headers=ORIGIN).status_code, 400)
fresh = client(BASE)
check("the new one does", fresh.post("/api/auth/login", json={"email": "new.person@example.com", "password": "brand-new-pass-9"}, headers=ORIGIN).status_code, 200)
with db.engine.connect() as cn:
    h = cn.execute(sa.select(db.users.c.password_hash).where(db.users.c.id == newbie["id"])).scalar()
check("passwords are stored as Argon2id hashes", h.startswith("$argon2id$"), True)
log = [x["action"] for x in boss.get("/api/admin/overview").json()["log"]]
check("invitations and resets are in the admin log", {"invite", "invite:revoke", "invite:renew", "reset-link"} <= set(log), True)

# ---- one person's things are invisible to everyone else, whatever they ask for
alice, _a = join(BASE, "alice.iso@example.com", name="Alice", root=ROOT)
bob, _b = join(BASE, "bob.iso@example.com", name="Bob", root=ROOT)
cr = alice.post("/api/creators", json={"name": "Alice Only"}, headers=ORIGIN).json()
s = alice.post("/api/upload/start", json={"name": "mine.mp4", "size": 2000, "options": {}, "creator": ""}, headers=ORIGIN).json()
alice.put(f"/api/upload/{s['id']}/0", content=os.urandom(2000), headers={"Content-Type": "application/octet-stream", **ORIGIN})
job = alice.post(f"/api/upload/{s['id']}/finish", json={}, headers=ORIGIN).json()
jid = job.get("id", "")
check("alice has a video", bool(jid) and any(j["id"] == jid for j in alice.get("/api/jobs").json()), True)
check("bob's video list doesn't include it", any(j["id"] == jid for j in bob.get("/api/jobs").json()), False)
check("bob can't open it", bob.get(f"/api/jobs/{jid}").status_code, 404)
check("bob can't fetch its files", (bob.get(f"/media/{jid}/clip01.mp4").status_code, bob.get(f"/media/{jid}/source.mp4").status_code), (404, 404))
check("bob can't delete it", bob.delete(f"/api/jobs/{jid}", headers=ORIGIN).status_code, 404)
check("bob can't delete it in bulk", bob.post("/api/bulk/delete", json={"videos": [jid], "clips": [[jid, "clip01"]]}, headers=ORIGIN).json().get("videos", 0), 0)
check("bob can't re-make or edit its clips", (bob.post(f"/api/jobs/{jid}/clips/clip01/render", json={}, headers=ORIGIN).status_code,
                                              bob.put(f"/api/jobs/{jid}/clips/clip01/text", json={"title": "x"}, headers=ORIGIN).status_code), (404, 404))
check("bob can't download its clips", bob.get("/api/clips.zip", params={"ids": f"{jid}.clip01"}).status_code, lambda s: s in (400, 404))
check("bob can't post its clips", bob.post("/api/posts", json={"job": jid, "clip": "clip01", "accounts": []}, headers=ORIGIN).status_code, 404)
check("bob can't see or change alice's creator", (bob.get("/api/creators").json(), bob.put(f"/api/creators/{cr['id']}", json={"name": "x"}, headers=ORIGIN).status_code), ([], 404))
check("bob's usage is his own", bob.get("/api/usage").json()["calls_total"], 0)
check("alice's video is still there", alice.get(f"/api/jobs/{jid}").status_code, 200)
check("a new account sees nothing made before it joined", (bob.get("/api/jobs").json(), bob.get("/api/overview").json()["creators"]), ([], []))
check("the user list is admins only", (bob.get("/api/admin/overview").status_code, bob.get(f"/api/admin/users/{_a['id']}").status_code), (404, 404))

print("\n%d failed" % len(fails) if fails else "\nALL PASSED")
sys.exit(1 if fails else 0)
