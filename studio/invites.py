"""Invitations: with sign-in on, the only way a new account is made.

An admin types the person's email and how long the link should work (24 hours, 3 days or 7 days). NeakClips makes a
long random token and keeps only its SHA-256 fingerprint, so the database never holds a working link. The link is
shown to the admin once, to copy and send. A lost link cannot be shown again; the admin makes a new one instead,
which stops the old one working.

Each link works once, only for the email it was made for, and only until it expires or is revoked. Using it makes
the account, marks the invitation used and signs the person in, all in one database transaction: if two people try
the same link at the same moment, exactly one of them gets the account."""
import hashlib
import re
import secrets
import threading
import time

import sqlalchemy as sa

from . import auth, config, db

HOURS = {24: "24 hours", 72: "3 days", 168: "7 days"}
_lock = threading.Lock()
_ID = re.compile(r"inv_[0-9a-f]{16}")


class InviteError(ValueError):
    """Why an invitation can't be made, changed or used. `status` is the HTTP status to answer with."""
    def __init__(self, msg, status=400):
        super().__init__(msg)
        self.status = status


def _h(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def link(token: str) -> str:
    return f"{config.PUBLIC_URL}/invite/{token}"


def valid_id(iid: str) -> bool:
    return bool(_ID.fullmatch(iid or ""))


def state(row, now=None) -> str:
    """pending | accepted | revoked | expired"""
    if row.status in ("accepted", "revoked"):
        return row.status
    return "expired" if row.expires_at <= (now or time.time()) else "pending"


def clean_email(email) -> str:
    email = str(email or "").strip().lower()
    if len(email) > 254 or not auth.EMAIL_RE.match(email):
        raise InviteError("Enter a valid email address.")
    return email


def _hours(hours) -> int:
    try:
        h = int(hours)
    except (TypeError, ValueError):
        h = 0
    if h not in HOURS:
        raise InviteError("Choose how long the link works: 24 hours, 3 days or 7 days.")
    return h


def _log(c, admin_id, action, detail):
    c.execute(db.admin_log.insert().values(t=time.time(), admin_id=admin_id or "server", action=action[:30],
                                           target_id=None, detail=detail[:300]))


def _retire_others(c, email, admin_id, keep=None):
    """One working link per email: any other link still waiting for this address stops working."""
    q = db.invitations.update().where(db.invitations.c.email == email, db.invitations.c.status == "pending")
    if keep:
        q = q.where(db.invitations.c.id != keep)
    c.execute(q.values(status="revoked", revoked_at=time.time(), revoked_by=admin_id or "server"))


# ---------------------------------------------------------------- what admins do
def create(admin_id, email, hours) -> dict:
    """A new invitation. Returns it, with the link: the only time the link exists outside the person's inbox."""
    email, h = clean_email(email), _hours(hours)
    token, iid, now = secrets.token_urlsafe(32), "inv_" + secrets.token_hex(8), time.time()
    with db.engine.begin() as c:
        if c.execute(sa.select(db.users.c.id).where(db.users.c.email == email)).first():
            raise InviteError("There is already an account with that email.", 409)
        _retire_others(c, email, admin_id)
        c.execute(db.invitations.insert().values(id=iid, token_hash=_h(token), email=email, created_by=admin_id or "server",
                                                 created_at=now, expires_at=now + h * 3600, status="pending"))
        _log(c, admin_id, "invite", f"{email}, works for {HOURS[h]}")
    return {**get(iid), "link": link(token)}


def renew(admin_id, iid: str, hours) -> dict:
    """A fresh link for an invitation that was not used yet (lost, expired or revoked). The old link stops working."""
    h = _hours(hours)
    token, now = secrets.token_urlsafe(32), time.time()
    with db.engine.begin() as c:
        row = c.execute(sa.select(db.invitations).where(db.invitations.c.id == iid)).first()
        if not row:
            raise InviteError("No such invitation.", 404)
        if row.status == "accepted":
            raise InviteError("This invitation has already been used.", 409)
        if c.execute(sa.select(db.users.c.id).where(db.users.c.email == row.email)).first():
            raise InviteError("There is already an account with that email.", 409)
        _retire_others(c, row.email, admin_id, keep=iid)
        c.execute(db.invitations.update().where(db.invitations.c.id == iid).values(
            token_hash=_h(token), status="pending", expires_at=now + h * 3600, revoked_at=None, revoked_by=None))
        _log(c, admin_id, "invite:renew", f"{row.email}, works for {HOURS[h]}")
    return {**get(iid), "link": link(token)}


def revoke(admin_id, iid: str) -> dict:
    with db.engine.begin() as c:
        row = c.execute(sa.select(db.invitations).where(db.invitations.c.id == iid)).first()
        if not row:
            raise InviteError("No such invitation.", 404)
        if row.status == "accepted":
            raise InviteError("This invitation has already been used. Disable the account instead.", 409)
        if row.status != "revoked":
            c.execute(db.invitations.update().where(db.invitations.c.id == iid, db.invitations.c.status != "accepted")
                      .values(status="revoked", revoked_at=time.time(), revoked_by=admin_id or "server"))
            _log(c, admin_id, "invite:revoke", row.email)
    return get(iid)


def _public(row, names: dict, now: float) -> dict:
    return {"id": row.id, "email": row.email, "status": state(row, now), "created_at": row.created_at,
            "expires_at": row.expires_at, "accepted_at": row.accepted_at, "revoked_at": row.revoked_at,
            "created_by": names.get(row.created_by, "Server" if row.created_by == "server" else ""),
            "revoked_by": names.get(row.revoked_by, "Server" if row.revoked_by == "server" else ""),
            "accepted_user": row.accepted_user}


def get(iid: str) -> dict:
    with db.engine.connect() as c:
        row = c.execute(sa.select(db.invitations).where(db.invitations.c.id == iid)).first()
        names = {r.id: r.email for r in c.execute(sa.select(db.users.c.id, db.users.c.email).where(
            db.users.c.id.in_([x for x in (row.created_by, row.revoked_by) if x]) if row else sa.false()))}
    if not row:
        raise InviteError("No such invitation.", 404)
    return _public(row, names, time.time())


def list_all(limit: int = 1000) -> dict:
    """Every invitation, newest first, with how many are in each state. Never a token or a link."""
    now = time.time()
    with db.engine.connect() as c:
        rows = c.execute(sa.select(db.invitations).order_by(db.invitations.c.created_at.desc()).limit(limit)).all()
        names = {r.id: r.email for r in c.execute(sa.select(db.users.c.id, db.users.c.email))}
    items = [_public(r, names, now) for r in rows]
    counts = {k: sum(1 for x in items if x["status"] == k) for k in ("pending", "accepted", "expired", "revoked")}
    return {"items": items, "counts": counts, "hours": [{"hours": k, "label": v} for k, v in HOURS.items()]}


# ---------------------------------------------------------------- the person who was invited
def _find(c, token: str):
    if not token or len(token) > 200 or not re.fullmatch(r"[A-Za-z0-9_\-]+", token):
        raise InviteError("This invitation link isn't valid. Check you copied all of it, or ask for a new one.", 404)
    row = c.execute(sa.select(db.invitations).where(db.invitations.c.token_hash == _h(token))).first()
    if not row:
        raise InviteError("This invitation link isn't valid. Check you copied all of it, or ask for a new one.", 404)
    st = state(row)
    if st == "accepted":
        raise InviteError("This invitation has already been used. Sign in instead.", 410)
    if st == "revoked":
        raise InviteError("This invitation has been cancelled. Ask an admin for a new one.", 410)
    if st == "expired":
        raise InviteError("This invitation has expired. Ask an admin for a new one.", 410)
    return row


def check(token: str) -> dict:
    """What the invitation page shows: the email it is for, and until when it works."""
    with db.engine.connect() as c:
        row = _find(c, token)
    return {"email": row.email, "expires_at": row.expires_at}


def _clean_name(name) -> str:
    name = re.sub(r"[\x00-\x1f\x7f]", "", str(name or "")).strip()
    if not name:
        raise InviteError("Enter your full name.")
    if len(name) > 120:
        raise InviteError("That name is too long.")
    return name


def accept(token: str, name, password, confirm, email_claim=None, ip: str = ""):
    """Make the account the invitation is for. Returns the new user. Everything is checked first; the invitation is
    marked used and the account made in one transaction, so a link can never make two accounts."""
    name = _clean_name(name)
    password, confirm = str(password or ""), str(confirm if confirm is not None else "")
    if password != confirm:
        raise InviteError("The two passwords don't match.")
    try:
        auth._check_password_rules(password)
    except auth.AuthError as e:
        raise InviteError(str(e))
    pw_hash = auth.hash_password(password)                 # slow on purpose, so it is done before anything is locked
    uid, now = "u_" + secrets.token_hex(8), time.time()
    with _lock, db.engine.begin() as c:
        row = _find(c, token)
        if email_claim is not None and str(email_claim).strip().lower() != row.email:
            raise InviteError("This invitation is for a different email address.", 403)
        if c.execute(sa.select(db.users.c.id).where(db.users.c.email == row.email)).first():
            raise InviteError("There is already an account with that email. Sign in instead.", 409)
        took = c.execute(db.invitations.update().where(
            db.invitations.c.id == row.id, db.invitations.c.status == "pending", db.invitations.c.expires_at > now,
            db.invitations.c.token_hash == row.token_hash).values(status="accepted", accepted_at=now, accepted_user=uid))
        if took.rowcount != 1:                              # someone else used it a moment ago
            raise InviteError("This invitation has already been used. Sign in instead.", 410)
        c.execute(db.users.insert().values(id=uid, email=row.email, name=name, password_hash=pw_hash,
                                           is_admin=False, created_at=now))
        c.execute(db.email_ok.insert().values(user_id=uid, verified_at=now))   # the link reached them at that address
        c.execute(db.activity.insert().values(t=now, user_id=uid, kind="joined", ip=(ip or "")[:64],
                                              detail="Accepted an invitation"))
    config.user_dir(uid).mkdir(parents=True, exist_ok=True)
    return auth.get_user(uid)
