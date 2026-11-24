"""Everything only an admin may do: the numbers on /admin, invitations, and switching accounts off.

Who is an admin is the `is_admin` value on their row in the users table and nothing else. No web request can
change it, and no email address is special in the code. It is set by hand, on the server:

    python -m studio.admin list
    python -m studio.admin grant someone@example.com
    python -m studio.admin revoke someone@example.com
    python -m studio.admin invite someone@example.com [24|72|168]    print an invitation link (hours it works)
    python -m studio.admin password someone@example.com             set a password (asked for, never shown)
    python -m studio.admin email old@example.com new@example.com    change the email an account signs in with

Admins see accounts, invitations, sign-ins and AI use. They never see anyone's password or AI key, nor their videos,
clips or connected accounts."""
import getpass
import shutil
import sys
import time
from collections import defaultdict

import sqlalchemy as sa

from . import config, db

class Refused(ValueError):
    """Something an admin asked for that is not allowed. `status` is the HTTP status to answer with."""
    def __init__(self, msg, status=400):
        super().__init__(msg)
        self.status = status


def _day(t):
    return time.strftime("%Y-%m-%d", time.localtime(t))


def _log(c, admin_id: str, action: str, target_id: str = None, detail: str = ""):
    c.execute(db.admin_log.insert().values(t=time.time(), admin_id=admin_id, action=action[:30], target_id=target_id,
                                           detail=detail[:300]))


# ---------------------------------------------------------------- the dashboard
def overview() -> dict:
    from . import ai, auth, fetch_model, jobs, live, load, mailer, transcribe
    now = time.time()
    midnight = time.mktime(time.localtime(now)[:3] + (0, 0, 0, 0, 0, -1))
    d7, d30 = now - 7 * 86400, now - 30 * 86400
    u, g = db.users.c, db.usage.c
    tok = g.tokens_in + g.tokens_out
    with db.engine.connect() as c:
        rows = c.execute(sa.select(db.users).order_by(u.created_at.desc()).limit(2000)).all()
        n_users = c.execute(sa.select(sa.func.count()).select_from(db.users)).scalar()
        verified = {r[0] for r in c.execute(sa.select(db.email_ok.c.user_id))}
        used = {r[0]: (r[1], int(r[2] or 0)) for r in c.execute(sa.select(g.user_id, sa.func.count(), sa.func.sum(tok)).group_by(g.user_id))}
        with_key = {r[0] for r in c.execute(sa.select(db.ai_keys.c.user_id).where(db.ai_keys.c.key_enc.is_not(None)))}
        devices = {r[0]: int(r[1]) for r in c.execute(sa.select(db.sessions.c.user_id, sa.func.count()).where(
            db.sessions.c.expires_at > now).group_by(db.sessions.c.user_id))}
        inv = {r[0]: int(r[1]) for r in c.execute(sa.select(db.invitations.c.status, sa.func.count()).group_by(db.invitations.c.status))}
        inv_waiting = c.execute(sa.select(sa.func.count()).select_from(db.invitations).where(
            db.invitations.c.status == "pending", db.invitations.c.expires_at > now)).scalar()
        calls_today = c.execute(sa.select(sa.func.count()).select_from(db.usage).where(g.t >= midnight)).scalar()

        days = [_day(now - 86400 * i) for i in range(29, -1, -1)]
        daily = {d: {"day": d, "signups": 0, "tokens": 0, "calls": 0} for d in days}
        for (created,) in c.execute(sa.select(u.created_at).where(u.created_at >= now - 31 * 86400)):
            if _day(created) in daily:
                daily[_day(created)]["signups"] += 1
        # one grouped query, not every call of the month pulled into Python: each day is a [start, next start) window
        starts = [time.mktime(time.strptime(d, "%Y-%m-%d")) for d in days]
        windows = [(sa.and_(g.t >= s, g.t < e) if e else g.t >= s, d) for s, e, d in zip(starts, starts[1:] + [None], days)]
        day_of = sa.case(*windows, else_="")
        for d, n_calls, n_tok in c.execute(sa.select(day_of, sa.func.count(), sa.func.sum(tok)).where(g.t >= starts[0])
                                           .group_by(sa.literal_column("1"))):
            if d in daily:
                daily[d]["tokens"] += int(n_tok or 0); daily[d]["calls"] += int(n_calls)          # noqa: E702
        by_purpose = [[r[0], r[1], int(r[2] or 0)] for r in c.execute(
            sa.select(g.purpose, sa.func.count(), sa.func.sum(tok)).group_by(g.purpose).order_by(sa.func.sum(tok).desc()).limit(12))]
        emails = {r.id: r.email for r in rows}
        log = [{"t": r._mapping["t"], "admin": emails.get(r.admin_id, ""), "action": r.action, "target": emails.get(r.target_id, ""),
                "detail": r.detail} for r in c.execute(sa.select(db.admin_log).order_by(db.admin_log.c.t.desc()).limit(40))]

    all_jobs = jobs.all_jobs()
    vids, clips = defaultdict(int), defaultdict(int)
    for j in all_jobs:
        vids[j["user"]] += 1
        clips[j["user"]] += sum(1 for k in j["clips"] if k.get("status") == "done")
    verify_on = config.VERIFY_EMAIL
    users = [{"id": r.id, "email": r.email, "name": r.name, "role": "admin" if r.is_admin else "user", "disabled": bool(r.disabled),
              "verified": (not verify_on) or r.id in verified, "google": bool(r.google_sub),
              "created_at": r.created_at, "last_seen": r.last_seen, "has_password": bool(r.password_hash),
              "has_ai_key": r.id in with_key, "devices": devices.get(r.id, 0),
              "ai_calls": used.get(r.id, (0, 0))[0], "tokens": used.get(r.id, (0, 0))[1],
              "videos": vids[r.id], "clips": clips[r.id]} for r in rows]
    return {
        "totals": {"users": int(n_users), "verified": sum(1 for x in users if x["verified"]),
                   "disabled": sum(1 for x in users if x["disabled"]), "admins": sum(1 for x in users if x["role"] == "admin"),
                   "signups_today": sum(1 for x in users if x["created_at"] >= midnight),
                   "signups_7d": sum(1 for x in users if x["created_at"] >= d7),
                   "signups_30d": sum(1 for x in users if x["created_at"] >= d30),
                   "active_7d": sum(1 for x in users if (x["last_seen"] or 0) >= d7),
                   "ai_calls": sum(v[0] for v in used.values()), "ai_calls_today": int(calls_today),
                   "tokens": sum(v[1] for v in used.values()),
                   "videos": len(all_jobs), "clips": sum(clips.values()), "recording": len(live.active()),
                   "working": sum(1 for j in all_jobs if j["status"] in ("queued", "running")),
                   "with_ai_key": sum(1 for x in users if x["has_ai_key"]),
                   "invites_waiting": int(inv_waiting or 0), "invites_accepted": inv.get("accepted", 0)},
        "daily": list(daily.values()), "by_purpose": by_purpose, "users": users, "log": log,
        "server": {"speech_model": transcribe.model_ready(),
                   "speech_more": {m[0]: fetch_model.ready(k) for k, m in fetch_model.MODELS.items() if k != fetch_model.DEFAULT},
                   "ai_key": ai.ready(), "ai_provider": ai.label(), "own_keys": config.ACCOUNTS,
                   "ai_model": (ai.models() or [""])[0], "google": auth.google_ready(), "mail": mailer.ready(),
                   "free_gb": round(shutil.disk_usage(config.DATA_DIR).free / 1e9, 1),
                   "load": load.state(), "running": jobs.running_now(), "waiting": jobs.waiting_total(),
                   "database": config.DATABASE_URL.split(":", 1)[0].split("+")[0]}}


def user_detail(uid: str) -> dict:
    """One account's AI use. Not their videos, clips or connected accounts."""
    g = db.usage.c
    tok = g.tokens_in + g.tokens_out
    with db.engine.connect() as c:
        r = c.execute(sa.select(db.users).where(db.users.c.id == uid)).first()
        if not r:
            raise Refused("No such account", 404)
        recent = [{"t": x._mapping["t"], "tokens": int(x.tokens_in) + int(x.tokens_out), "purpose": x.purpose}
                  for x in c.execute(sa.select(db.usage).where(g.user_id == uid).order_by(g.t.desc()).limit(40))]
        by_purpose = [[x[0], int(x[1] or 0), x[2]] for x in c.execute(
            sa.select(g.purpose, sa.func.sum(tok), sa.func.count()).where(g.user_id == uid)
            .group_by(g.purpose).order_by(sa.func.sum(tok).desc()))]
        devices = c.execute(sa.select(sa.func.count()).select_from(db.sessions).where(
            db.sessions.c.user_id == uid, db.sessions.c.expires_at > time.time())).scalar()
        has_key = bool(c.execute(sa.select(db.ai_keys.c.user_id).where(db.ai_keys.c.user_id == uid,
                                                                       db.ai_keys.c.key_enc.is_not(None))).first())
        invited = c.execute(sa.select(db.invitations).where(db.invitations.c.accepted_user == uid)).first()
        inviter = c.execute(sa.select(db.users.c.email).where(db.users.c.id == invited.created_by)).scalar() if invited else None
    return {"id": r.id, "email": r.email, "name": r.name, "role": "admin" if r.is_admin else "user", "disabled": bool(r.disabled),
            "created_at": r.created_at, "last_seen": r.last_seen, "has_password": bool(r.password_hash),
            "google": bool(r.google_sub), "has_ai_key": has_key,
            "invited_by": inviter or ("Server" if invited else None), "invited_at": invited.created_at if invited else None,
            "signed_in_devices": int(devices), "recent": recent, "by_purpose": by_purpose,
            "activity": activity(uid, 30)["items"]}


# ---------------------------------------------------------------- actions
def set_disabled(admin, uid: str, off) -> dict:
    if not isinstance(off, bool):
        raise Refused("Bad request.")
    with db.engine.begin() as c:
        target = c.execute(sa.select(db.users).where(db.users.c.id == uid)).first()
        if not target:
            raise Refused("No such account", 404)
        if target.id == admin.id:
            raise Refused("You can't disable your own account.")
        if target.is_admin:
            raise Refused("Admin accounts can't be disabled from here.")
        c.execute(db.users.update().where(db.users.c.id == uid).values(disabled=off))
        if off:
            c.execute(db.sessions.delete().where(db.sessions.c.user_id == uid))   # signed out everywhere, at once
            c.execute(db.email_tokens.delete().where(db.email_tokens.c.user_id == uid))   # and any reset link stops working
        _log(c, admin.id, "disable" if off else "enable", uid)
    from . import auth
    auth.forget(uid)
    auth.note(uid, "disabled" if off else "enabled", "", f"by {admin.email}")
    return {"ok": True, "disabled": off}


KINDS = {"login": "Signed in", "login_failed": "Wrong password", "logout": "Signed out", "joined": "Joined from an invitation",
         "password_changed": "Changed their password", "password_reset": "Reset their password with a link",
         "reset_link": "An admin made a password reset link", "api_key_saved": "Saved a Gemini API key",
         "api_key_removed": "Removed their Gemini API key", "disabled": "Account disabled", "enabled": "Account enabled"}


def activity(uid: str = None, limit: int = 200) -> dict:
    """Sign-ins and account changes, newest first: for everyone, or one account."""
    a = db.activity.c
    q = sa.select(db.activity).order_by(a.t.desc()).limit(max(1, min(int(limit), 1000)))
    if uid:
        q = q.where(a.user_id == uid)
    with db.engine.connect() as c:
        rows = c.execute(q).all()
        emails = {r.id: (r.email, r.name) for r in c.execute(sa.select(db.users.c.id, db.users.c.email, db.users.c.name).where(
            db.users.c.id.in_({r.user_id for r in rows})))} if rows else {}
    return {"items": [{"t": r._mapping["t"], "user": r.user_id, "email": emails.get(r.user_id, ("", ""))[0],
                       "name": emails.get(r.user_id, ("", ""))[1], "kind": r.kind, "what": KINDS.get(r.kind, r.kind),
                       "ip": r.ip, "detail": r.detail} for r in rows]}


def reset_link(admin, uid: str, hours: int = 24) -> dict:
    """A one-time link the person uses to choose a new password. The admin never sees or sets the password itself.
    The link works once, for `hours`, and making a new one stops the older one working. When it is used, the account
    is signed out everywhere."""
    from . import auth, mailer
    with db.engine.connect() as c:
        target = c.execute(sa.select(db.users).where(db.users.c.id == uid)).first()
    if not target:
        raise Refused("No such account", 404)
    if target.id == admin.id:
        raise Refused("Change your own password under Settings, Security.")
    if target.disabled:
        raise Refused("Enable the account first.")
    hours = hours if hours in (1, 24, 72) else 24
    url = f"{config.PUBLIC_URL}/reset?t={auth._make_link(uid, 'reset', hours * 3600)}"
    emailed = mailer.ready() and mailer.send(
        target.email, "Reset your NeakClips password", "Reset your password",
        "An admin of this NeakClips server sent you a link to choose a new password.", "Choose a new password", url,
        f"The link works once, for {hours} hours. If you weren't expecting this, tell your admin.")
    with db.engine.begin() as c:
        _log(c, admin.id, "reset-link", uid, f"works for {hours} hours")
    auth.note(uid, "reset_link", "", f"by {admin.email}")
    return {"ok": True, "link": url, "hours": hours, "emailed": bool(emailed), "email": target.email}


# ---------------------------------------------------------------- by hand, on the server
def set_admin(email: str, on: bool) -> bool:
    email = email.strip().lower()
    with db.engine.begin() as c:
        r = c.execute(sa.select(db.users).where(db.users.c.email == email)).first()
        if not r:
            return False
        c.execute(db.users.update().where(db.users.c.id == r.id).values(is_admin=on))
        if not on:
            c.execute(db.sessions.delete().where(db.sessions.c.user_id == r.id))
        _log(c, r.id, "role:admin" if on else "role:user", r.id, "set from the server command line")
    return True


def _cli(argv):
    db.init()
    if argv[:1] == ["list"]:
        with db.engine.connect() as c:
            for r in c.execute(sa.select(db.users).order_by(db.users.c.created_at)):
                print(f"{'admin' if r.is_admin else 'user ':5}  {'disabled' if r.disabled else '        '}  {r.email}")
        return 0
    if argv[:1] == ["invite"] and len(argv) in (2, 3):
        from . import invites
        try:
            got = invites.create(None, argv[1], int(argv[2]) if len(argv) == 3 else 72)
        except (invites.InviteError, ValueError) as e:
            print(e)
            return 1
        print(f"Invitation for {got['email']}, works until {time.strftime('%Y-%m-%d %H:%M', time.localtime(got['expires_at']))}:\n"
              f"  {got['link']}\nSend it to them yourself. It works once, and only for that email.")
        return 0
    if argv[:1] == ["password"] and len(argv) == 2:
        from . import auth
        u = auth.user_by_email(argv[1])
        if not u:
            print(f"No account with the email {argv[1]}.")
            return 1
        if sys.stdin.isatty():
            pw, again = getpass.getpass("New password: "), getpass.getpass("Type it again: ")
        else:                                       # piped in: the first two lines
            lines = sys.stdin.read().splitlines() + ["", ""]
            pw, again = lines[0], lines[1]
        if pw != again:
            print("The two passwords don't match. Nothing was changed.")
            return 1
        try:
            auth._check_password_rules(pw)
        except auth.AuthError as e:
            print(e)
            return 1
        with db.engine.begin() as c:
            c.execute(db.users.update().where(db.users.c.id == u.id).values(password_hash=auth.hash_password(pw)))
            c.execute(db.sessions.delete().where(db.sessions.c.user_id == u.id))
            _log(c, u.id, "password", u.id, "set from the server command line")
        auth.mark_verified(u.id)
        print(f"Password set for {u.email}. They are signed out everywhere and can sign in with it now.")
        return 0
    if argv[:1] == ["email"] and len(argv) == 3:
        from . import auth
        u, new = auth.user_by_email(argv[1]), argv[2].strip().lower()
        if not u:
            print(f"No account with the email {argv[1]}.")
            return 1
        if not auth.EMAIL_RE.match(new):
            print(f"{argv[2]} is not a valid email address.")
            return 1
        with db.engine.begin() as c:
            if c.execute(sa.select(db.users.c.id).where(db.users.c.email == new)).first():
                print(f"There is already an account with the email {new}.")
                return 1
            c.execute(db.users.update().where(db.users.c.id == u.id).values(email=new))
            c.execute(db.sessions.delete().where(db.sessions.c.user_id == u.id))
            _log(c, u.id, "email", u.id, f"{u.email} -> {new}, from the server command line")
        print(f"{u.email} now signs in as {new}. Everything in the account stays as it was.")
        return 0
    if len(argv) == 2 and argv[0] in ("grant", "revoke"):
        if not set_admin(argv[1], argv[0] == "grant"):
            print(f"No account with the email {argv[1]}. They need to sign up first.")
            return 1
        print(f"{argv[1]} is now {'an admin' if argv[0] == 'grant' else 'a normal user'}.")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
