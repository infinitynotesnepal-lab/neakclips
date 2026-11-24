"""Bring an existing NeakClips' data up to date, without losing anything.  Run:  python -m studio.migrate

Safe to run any number of times, and it runs by itself each time NeakClips starts. It:

  1. Looks at the database as it is and says what is there.
  2. Adds the tables this version needs (invitations, each person's encrypted AI key, sign-in activity). Tables
     that already exist are never changed, emptied or dropped, so every account, setting and record stays.
  3. Checks that every video on disk belongs to the account whose folder it is in. Nothing is moved or changed:
     each account's videos and clips are already kept in that account's own folder, so a newly invited person
     starts with an empty account and never sees anything made before they joined.
  4. Moves an AI key saved by an older version (as plain text in ai.json) into the encrypted store, for the admin
     who owned it (the oldest admin account), and removes the plain-text copy. The service and model stay in ai.json.

  --check    only look and report; change nothing."""
import json
import sys
import time

import sqlalchemy as sa

from . import config, db

NAME = "2026-11-invitations-and-own-ai-keys"


def _say(quiet, *a):
    if not quiet:
        print(*a, flush=True)


def inspect() -> dict:
    """The tables and columns that are there now, and how many rows each has."""
    insp = sa.inspect(db.engine)
    out = {}
    with db.engine.connect() as c:
        for t in insp.get_table_names():
            n = c.execute(sa.text(f'SELECT COUNT(*) FROM "{t}"')).scalar()     # names come from the database itself
            out[t] = {"columns": [col["name"] for col in insp.get_columns(t)], "rows": int(n)}
    return out


def _owners(quiet) -> list:
    """Every video's owner as recorded in it, against the folder it is in. Returns the ones that do not match."""
    problems = []
    known = set()
    with db.engine.connect() as c:
        known = {r[0] for r in c.execute(sa.select(db.users.c.id))}
    if not config.USERS_DIR.is_dir():
        return problems
    for d in sorted(p for p in config.USERS_DIR.iterdir() if p.is_dir()):
        files = list((d / "jobs").glob("*/job.json")) + list((d / "creators").glob("*/*/*/job.json"))
        bad = 0
        for f in files:
            try:
                owner = json.loads(f.read_text(encoding="utf-8")).get("user")
            except (OSError, ValueError):
                continue
            if owner != d.name:
                bad += 1
                problems.append(str(f))
        state = "account exists" if d.name in known else "NO ACCOUNT (kept, visible to nobody)"
        _say(quiet, f"    {d.name}: {len(files)} video(s), {state}" + (f", {bad} recorded for another owner" if bad else ""))
    return problems


def _move_legacy_key(apply: bool, quiet: bool) -> str:
    """ai.json from an older version may hold the key as plain text. It goes to the oldest admin, encrypted."""
    from . import ai, vault
    f = ai._file()
    try:
        data = json.loads(f.read_text(encoding="utf-8")) if f.is_file() else {}
    except (OSError, ValueError):
        data = {}
    if not isinstance(data, dict) or not data.get("key"):
        return "no plain-text key"
    with db.engine.connect() as c:
        owner = c.execute(sa.select(db.users).where(db.users.c.is_admin == sa.true()).order_by(db.users.c.created_at)).first()
        if not owner:
            owner = c.execute(sa.select(db.users).order_by(db.users.c.created_at)).first()
        table = db.ai_keys.name in sa.inspect(db.engine).get_table_names()
        has = owner and table and c.execute(sa.select(db.ai_keys.c.user_id).where(db.ai_keys.c.user_id == owner.id)).first()
    if not owner:
        return "a plain-text key, but no account to give it to yet (left as it is)"
    if not apply:
        return f"a plain-text key, which would be moved to {owner.email} (encrypted)"
    p = ai.ALIASES.get(str(data.get("provider") or "gemini").lower(), str(data.get("provider") or "gemini").lower())
    if not has:
        k = str(data["key"])
        with db.engine.begin() as c:
            c.execute(db.ai_keys.insert().values(
                user_id=owner.id, provider=p if p in ai.PROVIDERS else "gemini",
                models=",".join(str(m) for m in (data.get("models") or []))[:700], base_url=str(data.get("base_url") or "")[:300],
                key_enc=vault.lock(k, ai._purpose(owner.id)), key_mask=ai.mask(k), updated_at=time.time()))
    rest = {k: v for k, v in data.items() if k != "key"}
    tmp = f.with_suffix(".tmp")
    tmp.write_text(json.dumps(rest), encoding="utf-8")
    tmp.replace(f)
    ai._saved["at"] = None
    ai.forget()
    return (f"moved the key to {owner.email}, encrypted" if not has else
            f"{owner.email} already had a key saved; removed the plain-text copy") + ", and removed it from ai.json"


def run(apply: bool = True, quiet: bool = False) -> dict:
    before = inspect()
    _say(quiet, "\n  NeakClips data check" + ("" if apply else " (looking only, nothing will change)"))
    _say(quiet, f"  Database: {config.DATABASE_URL.split(':', 1)[0]}")
    for t, info in sorted(before.items()):
        _say(quiet, f"    {t}: {info['rows']} row(s)")
    missing = [t.name for t in db.meta.sorted_tables if t.name not in before]
    _say(quiet, "  Tables to add: " + (", ".join(missing) if missing else "none"))
    if apply:
        db.init()
    for t in db.meta.sorted_tables:          # a table that is there but older than this code: say so, change nothing
        if t.name in before:
            lacking = [c.name for c in t.columns if c.name not in before[t.name]["columns"]]
            if lacking:
                _say(quiet, f"  NOTE: {t.name} has no column {', '.join(lacking)}. Nothing was changed; see DEPLOY.md.")
    _say(quiet, "  Videos and who owns them:")
    problems = _owners(quiet)
    if problems:
        _say(quiet, f"  NOTE: {len(problems)} video(s) say they belong to another account than the folder they are in. "
                    "They were left exactly as they are and stay visible only to the folder's owner.")
    key_note = _move_legacy_key(apply, quiet)
    _say(quiet, f"  Old AI settings: {key_note}")
    if config.ACCOUNTS and (config.env("PEAKCUT_AI_KEY") or config.env("PEAKCUT_AI_KEY_FILE")):
        _say(quiet, "  NOTE: PEAKCUT_AI_KEY is set in .env. With sign-in on it is not used for anyone: every person adds "
                    "their own key. You can remove it from .env.")
    if apply:
        with db.engine.begin() as c:
            if not c.execute(sa.select(db.migrations.c.name).where(db.migrations.c.name == NAME)).first():
                c.execute(db.migrations.insert().values(name=NAME, applied_at=time.time()))
                _say(quiet, f"  Recorded: {NAME}")
        after = inspect()
        lost = [t for t, info in before.items() if after.get(t, {}).get("rows", 0) < info["rows"] and t not in ("sessions", "email_tokens")]
        if lost:
            _say(quiet, f"  WARNING: fewer rows than before in {', '.join(lost)}")
    _say(quiet, "  Done.\n")
    return {"added": missing, "ownership_problems": problems, "ai_key": key_note}


if __name__ == "__main__":
    sys.exit(0 if run(apply="--check" not in sys.argv[1:]) else 1)
