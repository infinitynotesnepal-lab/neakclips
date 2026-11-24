"""Talking to the AI service. You bring your own key, and choose the service and model in the dashboard
(Settings, API settings). With sign-in on, every person uses their own Gemini key and nobody else's. Keys are kept
encrypted in the database (see vault.py), never as plain text. With sign-in off, .env still works as a starting point:

    PEAKCUT_AI_PROVIDER   gemini | openai | xai | groq | openrouter | anthropic | ollama | custom
    PEAKCUT_AI_MODELS     one or more model ids, comma separated, tried in this order
    PEAKCUT_AI_KEY        your key (or PEAKCUT_AI_KEY_FILE, a file holding it)
    PEAKCUT_AI_BASE_URL   only for "custom" (any service that speaks the OpenAI chat format), or to override

Every service is asked for the same thing: JSON that follows a small schema. Gemini takes the schema directly.
The others are told the schema in the prompt and asked for a JSON object, which works with any chat model.

One picture can also be shown (`see`), which is how the webcam is looked for on a gaming stream. A model that
cannot look at pictures answers with something else, and that is simply taken as "it did not look"."""
import base64
import json
import re
import threading
import time

import httpx

from . import config

# name -> (label shown on the pages, address, how it is spoken to, where to get a key, an example model id)
PROVIDERS = {
    "gemini": ("Gemini", "https://generativelanguage.googleapis.com/v1beta/models", "gemini", "https://aistudio.google.com/apikey", "gemini-2.5-flash"),
    "openai": ("OpenAI", "https://api.openai.com/v1", "openai", "https://platform.openai.com/api-keys", "gpt-4o-mini"),
    "xai": ("Grok", "https://api.x.ai/v1", "openai", "https://console.x.ai", "grok-4"),
    "groq": ("Groq", "https://api.groq.com/openai/v1", "openai", "https://console.groq.com/keys", "llama-3.3-70b-versatile"),
    "openrouter": ("OpenRouter", "https://openrouter.ai/api/v1", "openai", "https://openrouter.ai/keys", "google/gemini-2.5-flash"),
    "anthropic": ("Claude", "https://api.anthropic.com/v1", "anthropic", "https://console.anthropic.com", ""),
    "ollama": ("Ollama (on this machine)", "http://127.0.0.1:11434/v1", "openai", "https://ollama.com", "llama3.1"),
    "custom": ("Custom (OpenAI-compatible)", "", "openai", "", ""),
}
ALIASES = {"google": "gemini", "grok": "xai", "claude": "anthropic", "local": "ollama"}
NO_KEY = {"ollama", "custom"}       # a model running on your own machine needs no key
WHERE = "Settings, API settings"     # where the key is added, for messages

# ---------------------------------------------------------------- the settings in use
# With sign-in on, every person brings their own key. It is kept encrypted in the ai_keys table (vault.py), and an AI
# call only ever uses the key of the person it is made for: the user the code is running as (ctx). There is no
# fallback: not another person's key, not the server's .env, not ai.json. Someone without a key gets clips picked by
# loudness, the same as before any key was added.
#
# With sign-in off there is one owner. Their key is kept the same way; if they have not saved one, the older settings
# still work (ai.json from an earlier version, then .env), so nothing changes for people running NeakClips at home.
_lock = threading.Lock()
_saved = {"at": None, "data": {}}
_mine: dict = {}            # user -> (looked at, settings with the key opened). Forgotten the moment they change.
_KEEP_FOR = 30              # seconds
DEFAULT_GEMINI = "gemini-2.5-flash"


def _file():
    return config.DATA_DIR / "ai.json"


def _from_dashboard() -> dict:
    """What an older version saved from the dashboard, read again only when the file changes."""
    f = _file()
    try:
        at = f.stat().st_mtime_ns
    except OSError:
        at = 0
    if _saved["at"] != at:
        try:
            data = json.loads(f.read_text(encoding="utf-8")) if at else {}
        except (OSError, ValueError):
            data = {}
        _saved.update(at=at, data=data if isinstance(data, dict) else {})
    return _saved["data"]


def _owner():
    """Whose settings these are: the person the code runs for, or with sign-in off, the one owner."""
    from . import ctx
    uid = ctx.uid_or_none()
    if uid or config.ACCOUNTS:
        return uid
    from . import auth
    return auth.local_user().id


def _purpose(uid: str) -> str:
    return f"ai_key:{uid}"


def _row(uid):
    """This person's saved settings with the key opened, or None. Kept in memory for a few seconds."""
    if not uid:
        return None
    got = _mine.get(uid)
    if got and time.time() - got[0] < _KEEP_FOR:
        return got[1]
    from . import db, vault
    import sqlalchemy as sa
    with db.engine.connect() as c:
        r = c.execute(sa.select(db.ai_keys).where(db.ai_keys.c.user_id == uid)).first()
    out = None
    if r:
        k, broken = "", False
        if r.key_enc:
            try:
                k = vault.unlock(r.key_enc, _purpose(uid))
            except vault.VaultError:
                broken = True       # changed, moved from another account, or the secret key file was replaced
        out = {"provider": r.provider, "models": [m for m in (r.models or "").split(",") if m],
               "base_url": r.base_url or "", "key": k, "mask": r.key_mask if k else "", "broken": broken,
               "updated_at": r.updated_at}
    if len(_mine) > 20000:
        _mine.clear()
    _mine[uid] = (time.time(), out)
    return out


def forget(uid=None):
    """Someone's settings changed: read them again next time."""
    if uid:
        _mine.pop(uid, None)
    else:
        _mine.clear()


def default_models() -> list:
    """The model a new key starts with: the one chosen for the server before, if it was a Gemini model."""
    d = _from_dashboard()
    if str(d.get("provider") or "").lower() == "gemini" and d.get("models"):
        return list(d["models"])
    if config.AI_PROVIDER == "gemini" and config.AI_MODELS:
        return list(config.AI_MODELS)
    return [DEFAULT_GEMINI]


def current() -> dict:
    """Provider, models, address and key for the person the code is running for."""
    uid = _owner()
    mine = _row(uid)
    if mine:
        return {"provider": mine["provider"], "models": mine["models"] or default_models(),
                "base_url": mine["base_url"], "key": mine["key"]}
    if config.ACCOUNTS:
        return {"provider": "gemini", "models": default_models(), "base_url": "", "key": ""}
    d = _from_dashboard()             # sign-in off, nothing saved the new way yet: the older settings
    p = str(d.get("provider") or config.AI_PROVIDER or "").strip().lower()
    return {"provider": ALIASES.get(p, p),
            "models": list(d["models"]) if d.get("provider") else list(config.AI_MODELS),
            "base_url": (str(d.get("base_url") or "") if d.get("provider") else config.AI_BASE_URL).rstrip("/"),
            "key": str(d["key"]) if d.get("provider") and "key" in d else config.ai_key()}


def provider() -> str:
    return current()["provider"]


def models() -> list:
    return current()["models"]


def key() -> str:
    return current()["key"]


def label() -> str:
    return PROVIDERS.get(provider(), ("",))[0]


def base_url() -> str:
    c = current()
    return c["base_url"] or PROVIDERS.get(c["provider"], ("", ""))[1]


def ready() -> bool:
    c = current()
    return bool(c["provider"] in PROVIDERS and c["models"] and base_url() and (c["key"] or c["provider"] in NO_KEY))


def mask(k: str) -> str:
    """What the page may show of a key: the first and last four characters at most."""
    k = str(k or "")
    if len(k) >= 16:
        return k[:4] + "•" * 8 + k[-4:]
    return "•" * 8 if k else ""


def allowed() -> dict:
    """The services people may choose here. With sign-in on, each person brings a Gemini key."""
    return {"gemini": PROVIDERS["gemini"]} if config.ACCOUNTS else PROVIDERS


def public() -> dict:
    """What the settings page may see. The key itself never leaves the server: only whether there is one, and a
    masked form (first and last four characters) so the owner can tell which key it is."""
    c, mine = current(), _row(_owner())
    return {"provider": c["provider"], "models": c["models"], "base_url": c["base_url"], "has_key": bool(c["key"]),
            "key_hint": c["key"][-4:] if len(c["key"]) >= 12 else "", "key_mask": mask(c["key"]), "ready": ready(),
            "label": label(), "saved_here": bool(mine or _from_dashboard().get("provider")), "own_key": config.ACCOUNTS,
            "updated_at": (mine or {}).get("updated_at"), "unreadable": bool((mine or {}).get("broken")),
            "providers": [{"id": k, "label": v[0], "address": v[1], "needs_key": k not in NO_KEY, "key_url": v[3], "example": v[4]}
                          for k, v in allowed().items()]}


def _check_key(k: str):
    if len(k) < 8 or len(k) > 400 or not re.fullmatch(r"[\x21-\x7e]+", k):
        raise ValueError("That doesn't look like an API key. Paste it exactly as the service shows it.")


def save(provider_id: str, model_ids, address: str = "", new_key=None) -> dict:
    """Save the choice made in the dashboard, for the person making it. `new_key` None keeps the key that is already
    there (the page never has it to send back); an empty string removes it. The key is encrypted before it is
    written anywhere."""
    p = ALIASES.get(str(provider_id or "").strip().lower(), str(provider_id or "").strip().lower())
    if p not in allowed():
        raise ValueError("Only Gemini keys can be used on this server." if config.ACCOUNTS else "Choose one of the AI services in the list.")
    if isinstance(model_ids, str):
        model_ids = model_ids.split(",")
    ms = [str(m).strip()[:120] for m in (model_ids or []) if str(m).strip()][:5]
    if not ms:
        if not config.ACCOUNTS:
            raise ValueError("Enter the model to use.")
        ms = default_models()
    if any(not re.fullmatch(r"[\w.\-:/@]+", m) for m in ms):
        raise ValueError("A model id has letters, digits and . - : / only.")
    address = str(address or "").strip().rstrip("/")[:300]
    if address and config.ACCOUNTS:
        raise ValueError("The service's address can't be changed here.")   # a key must only ever go to Google
    if address and not re.fullmatch(r"https?://[^\s]+", address):
        raise ValueError("The address has to start with http:// or https://")
    if p == "custom" and not address:
        raise ValueError("A custom service needs its address, for example http://127.0.0.1:1234/v1")
    uid = _owner()
    if not uid:
        raise ValueError("Sign in first.")
    old = current()
    k = old["key"] if new_key is None and old["provider"] == p else str(new_key or "").strip()
    if not k and p not in NO_KEY:
        raise ValueError("Paste the key for this service.")
    if k and new_key is not None:
        _check_key(k)
    from . import db, vault
    import sqlalchemy as sa
    values = {"provider": p, "models": ",".join(ms), "base_url": address,
              "key_enc": vault.lock(k, _purpose(uid)) if k else None, "key_mask": mask(k), "updated_at": time.time()}
    with _lock, db.engine.begin() as c:
        if c.execute(sa.select(db.ai_keys.c.user_id).where(db.ai_keys.c.user_id == uid)).first():
            c.execute(db.ai_keys.update().where(db.ai_keys.c.user_id == uid).values(**values))
        else:
            c.execute(db.ai_keys.insert().values(user_id=uid, **values))
    forget(uid)
    clear_problem()
    return public()


def remove_key() -> dict:
    """Forget this person's key (and their choice of model). Their AI stops until they add one again."""
    uid = _owner()
    if not uid:
        raise ValueError("Sign in first.")
    from . import db
    with _lock, db.engine.begin() as c:
        c.execute(db.ai_keys.delete().where(db.ai_keys.c.user_id == uid))
    forget(uid)
    clear_problem()
    return public()


def list_models(provider_id=None, address=None, with_key=None) -> list:
    """The model ids a service offers, so the settings page can show a list to pick from."""
    c = current()
    p = ALIASES.get(str(provider_id or c["provider"]).lower(), str(provider_id or c["provider"]).lower())
    if p not in allowed():
        raise ValueError("Choose one of the AI services in the list.")
    if address and config.ACCOUNTS:
        raise ValueError("The service's address can't be changed here.")
    k = str(with_key or "").strip() or (c["key"] if c["provider"] == p else "")
    base = str(address or "").strip().rstrip("/") or (c["base_url"] if c["provider"] == p else "") or PROVIDERS[p][1]
    if not base:
        raise ValueError("Enter the service's address first.")
    how = PROVIDERS[p][2]
    if how == "gemini":
        r = httpx.get(base, params={"pageSize": 200}, headers={"x-goog-api-key": k}, timeout=20)
    elif how == "anthropic":
        r = httpx.get(f"{base}/models", params={"limit": 200}, headers={"x-api-key": k, "anthropic-version": "2023-06-01"}, timeout=20)
    else:
        r = httpx.get(f"{base}/models", headers={"Authorization": f"Bearer {k}"} if k else {}, timeout=20)
    if r.status_code != 200:
        raise AIError(f"HTTP {r.status_code} {_hide(r.text[:200], k)}")
    data = r.json()
    if how == "gemini":
        found = []
        for m in data.get("models", []):
            if "generateContent" not in (m.get("supportedGenerationMethods") or []):
                continue
            mid = m.get("name", "").split("/")[-1]
            low_id = mid.lower()
            if mid and low_id != "aqa" and not any(t in low_id for t in ("-tts", "-image", "imagen-", "veo-", "lyria-", "embedding")):
                found.append(mid)
    else:
        found = [m.get("id", "") for m in data.get("data", []) if isinstance(m, dict)]
    return sorted({m for m in found if m})[:400]


def test(with_key=None) -> dict:
    """One tiny request with the settings in use, to prove the key, the address and the model all work.
    `with_key` tests a key that was typed but not saved yet (only for Gemini, with the usual model)."""
    if with_key:
        k = str(with_key).strip()
        _check_key(k)
        model = (models() if provider() == "gemini" else None) or default_models()
        out, sent, wrote = _gemini(model[0], 'Answer with a JSON array that holds the single string "ok".',
                                   {"type": "ARRAY", "items": {"type": "STRING"}}, None, use_key=k)
        return {"ok": True, "model": model[0], "tokens": sent + wrote, "answer": str(out)[:80]}
    ms = models()
    if not ready():
        raise ValueError("Add your Gemini API key first." if config.ACCOUNTS else "Save a service, a model and a key first.")
    out, sent, wrote = call(ms[0], 'Answer with a JSON array that holds the single string "ok".', {"type": "ARRAY", "items": {"type": "STRING"}})
    return {"ok": True, "model": ms[0], "tokens": sent + wrote, "answer": str(out)[:80]}


def _hide(text: str, *keys) -> str:
    """The text with any key in it replaced, so a service that repeats the key back never puts it on a page or in a log."""
    text = str(text or "")
    for k in keys:
        if k and len(k) >= 6:
            text = text.replace(k, "<key>")
    return text


class AIError(RuntimeError):
    """A failed AI call. `wait` is how many seconds the service asked us to wait before trying again, when it
    said so (a Retry-After header, or Gemini's retryDelay)."""
    def __init__(self, message, wait=None, daily=False):
        super().__init__(message)
        self.wait = wait
        self.daily = daily        # the limit is for the whole day, so waiting a minute won't help


_problems: dict = {}      # user -> (why their AI last failed, when): shown on their own page, cleared when it answers again


def explain(e) -> str:
    """What went wrong with an AI call, in words the owner can act on."""
    text, low = str(e), str(e).lower()
    name = (models() or ["?"])[0]
    m = re.match(r"HTTP (\d{3})\b", text)
    status = m.group(1) if m else ""
    if status in ("401", "403") or "api key" in low or "api_key" in low or "unauthorized" in low or "permission" in low:
        return f"{label()} refused the key. Paste a working key under {WHERE}."
    if "no longer available" in low or "deprecated" in low or "retired" in low or "discontinued" in low:
        return f"{label()} has retired \"{name}\" (or it isn't available to new keys). Open Settings, AI, press Find models and pick a newer model."
    # Only a 404 that is about a model says the model is unknown. A 400 like "API key not found" or a stray
    # "404" inside some other message must not be reported as an unknown model.
    if (status == "404" and "model" in low) or (not status and ("404" in text or "not found" in low or "does not exist" in low or "unknown model" in low or "not_found" in low)) \
            or (status and "is not found for api version" in low):
        return f"{label()} doesn't know the model \"{name}\". Open Settings, AI, press Find models and pick one from the list."
    if "429" in text or "quota" in low or "rate limit" in low or "exhausted" in low:
        return f"{label()} says the key has hit its limit or has no credit left. Check the account with {label()}, or try again later."
    if "connect" in low or "timed out" in low or "timeout" in low or "getaddrinfo" in low or "refused" in low or "nodename" in low or "servname" in low or "nameresolutionerror" in low or "name resolution" in low:
        return f"NeakClips couldn't reach {label()}. Check the internet connection" + (" and that Ollama is running." if provider() == "ollama" else ".")
    return ""


def _problem_key():
    from . import ctx
    return ctx.uid_or_none() or ""


def note_problem(e):
    why = explain(e)
    if why:
        if len(_problems) > 20000:
            _problems.clear()
        _problems[_problem_key()] = (why, time.time())


def clear_problem():
    _problems.pop(_problem_key(), None)


def problem_text(max_age: float = 6 * 3600) -> str:
    """Why this person's AI last failed, if it did lately. Never someone else's."""
    why, at = _problems.get(_problem_key(), ("", 0.0))
    return why if why and time.time() - at < max_age else ""


def asked_wait(r) -> float | None:
    """How long the service asked us to wait, in seconds, or None when it didn't say."""
    try:
        v = (r.headers.get("retry-after") or "").strip()
        if v:
            return max(0.0, float(v))
    except (ValueError, AttributeError):
        pass
    m = re.search(r'"retryDelay"\s*:\s*"(\d+(?:\.\d+)?)s"', getattr(r, "text", "") or "")
    return float(m.group(1)) if m else None


def _fail(r, model, used_key=None):
    text = _hide(r.text[:300], key(), used_key)
    limited = r.status_code in (429, 503)
    raise AIError(f"HTTP {r.status_code} {text}", wait=asked_wait(r) if limited else None,
                  daily=limited and bool(re.search(r"PerDay|per day|daily", r.text or "", re.I)))


# ---------------------------------------------------------------- the schema, said in words for chat models
def _json_schema(s):
    """Gemini's schema spelling (ARRAY, OBJECT...) as ordinary JSON Schema."""
    if isinstance(s, dict):
        return {k: (v.lower() if k == "type" and isinstance(v, str) else _json_schema(v)) for k, v in s.items()}
    if isinstance(s, list):
        return [_json_schema(x) for x in s]
    return s


def _wrapped(prompt, schema):
    return (prompt + "\n\nAnswer with JSON only, no other text and no code fences: one object with a single key "
            "\"items\", whose value follows this JSON Schema:\n" + json.dumps(_json_schema(schema)))


def _json_chunks(text: str):
    """Every balanced {...} or [...] in the text, in the order they appear."""
    out, depth, start, in_str, esc = [], 0, None, False, False
    for i, ch in enumerate(text):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "{[":
            if depth == 0:
                start = i
            depth += 1
        elif ch in "}]":
            depth -= 1
            if depth == 0 and start is not None:
                out.append(text[start:i + 1])
                start = None
            elif depth < 0:
                depth = 0
    return out


def _parse(text):
    """The JSON in an answer, even if the model wrapped it in a code fence or a sentence.

    A model that is not careful sometimes puts a sentence in front of the JSON,
    or a second object after it, or forgets a comma. The JSON is looked for
    inside the answer rather than demanded of it."""
    text = (text or "").strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text)
    out = None
    try:
        out = json.loads(text)
    except ValueError:
        for chunk in _json_chunks(text):
            try:
                out = json.loads(chunk)
                break
            except ValueError:
                continue
        if out is None:
            m = re.search(r"[\[{].*[\]}]", text, re.S)
            if not m:
                raise AIError("The AI did not answer with JSON.")
            try:
                out = json.loads(m.group(0))
            except ValueError:
                raise AIError("The AI did not answer with JSON.")
    if isinstance(out, dict) and "items" in out:
        out = out["items"]
    return out


# ---------------------------------------------------------------- one call
def call(model: str, prompt: str, schema: dict, timeout: float | None = None):
    """Ask one model. Returns (the parsed JSON answer, tokens sent, tokens written back).

    `timeout` is how long one answer may take. A live stream passes a short one, because a slow
    answer must not stop the recording."""
    how = PROVIDERS[provider()][2]
    return {"gemini": _gemini, "openai": _openai, "anthropic": _anthropic}[how](model, prompt, schema, timeout)


def see(prompt: str, image: bytes, timeout: float | None = None) -> tuple[str, int, int]:
    """Ask one model about one picture: (the answer as text, tokens in, tokens out).

    Nothing is broken by a service that cannot look at pictures, or a model that is only text: the answer
    comes back empty, or says something the caller does not understand, and the caller carries on without
    it. The picture is a JPEG, passed as base64 inside the ordinary message."""
    if not ready() or not image or not models():
        return "", 0, 0
    model = models()[0]
    b64 = base64.b64encode(image).decode()
    how = PROVIDERS[provider()][2]
    if how == "gemini":
        body = {"contents": [{"role": "user", "parts": [
            {"text": prompt},
            {"inline_data": {"mimeType": "image/jpeg", "data": b64}}]}]}
        r = httpx.post(f"{base_url()}/{_gem(model)}:generateContent", json=body,
                       headers={"x-goog-api-key": key()}, timeout=timeout or 120)
        if r.status_code != 200:
            _fail(r, model)
        data = r.json()
        text = "".join(p.get("text", "") for p in data["candidates"][0]["content"]["parts"])
        u = data.get("usageMetadata", {})
        sent = int(u.get("promptTokenCount") or 0)
        return text, sent, max(0, int(u.get("totalTokenCount") or 0) - sent)
    if how == "anthropic":
        body = {"model": model, "max_tokens": 300, "messages": [{"role": "user", "content": [
            {"type": "image", "source": {"type": "base64", "media_type": "image/jpeg", "data": b64}},
            {"type": "text", "text": prompt}]}]}
        r = httpx.post(f"{base_url()}/messages", json=body, timeout=timeout or 120,
                       headers={"x-api-key": key(), "anthropic-version": "2023-06-01"})
        if r.status_code != 200:
            _fail(r, model)
        data = r.json()
        text = "".join(p.get("text", "") for p in data.get("content") or [] if p.get("type") == "text")
        u = data.get("usage") or {}
        return text, int(u.get("input_tokens") or 0), int(u.get("output_tokens") or 0)
    headers = {"Authorization": f"Bearer {key()}"} if key() else {}
    body = {"model": model, "stream": False, "messages": [{"role": "user", "content": [
        {"type": "text", "text": prompt},
        {"type": "image_url", "image_url": {"url": "data:image/jpeg;base64," + b64}}]}]}
    r = httpx.post(f"{base_url()}/chat/completions", json=body, headers=headers, timeout=timeout or 120)
    if r.status_code != 200:
        _fail(r, model)
    data = _openai_body(r)
    text = (data["choices"][0]["message"].get("content") or "")
    u = data.get("usage") or {}
    return text, int(u.get("prompt_tokens") or 0), int(u.get("completion_tokens") or 0)


def _gem(model: str) -> str:
    """Gemini names models "models/gemini-2.5-flash"; the address already ends in /models, so only the bare id is used."""
    return model.removeprefix("models/")


def _gemini(model, prompt, schema, timeout=None, use_key=None):
    url = f"{(PROVIDERS['gemini'][1] if use_key else base_url())}/{_gem(model)}:generateContent"
    headers = {"x-goog-api-key": use_key or key()}
    body = {"contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.4, "responseMimeType": "application/json", "responseSchema": schema}}
    r = httpx.post(url, json=body, headers=headers, timeout=timeout or 120)
    used_plain = False
    if r.status_code in (400, 422) and "api key" not in r.text.lower() and "api_key" not in r.text.lower():
        # Models like Gemma in the Gemini list support generateContent without responseSchema.
        plain = {"contents": [{"role": "user", "parts": [{"text": _wrapped(prompt, schema)}]}]}
        r = httpx.post(url, json=plain, headers=headers, timeout=timeout or 120)
        used_plain = True
    if r.status_code != 200:
        _fail(r, model, use_key)
    data = r.json()
    text = "".join(p.get("text", "") for p in data["candidates"][0]["content"]["parts"])
    u = data.get("usageMetadata", {})
    sent = int(u.get("promptTokenCount") or 0)
    parsed = _parse(text) if used_plain else json.loads(text)
    return parsed, sent, max(0, int(u.get("totalTokenCount") or 0) - sent)   # the answer, and any thinking billed with it


def _openai_body(r):
    """The answer, whether the service sent plain JSON or an event stream.

    Some OpenAI-compatible servers answer with a stream of events unless the
    request says otherwise, so the answer is read from whichever shape arrived.
    A model that answers with a tool call instead of a message leaves the JSON in
    the call's arguments, so that is used too."""
    try:
        data = r.json()
    except ValueError:
        data = _from_events(r.text)
    for ch in data.get("choices") or []:
        msg = ch.get("message") or {}
        if (msg.get("content") or "").strip():
            continue
        for call in msg.get("tool_calls") or []:
            args = (call.get("function") or {}).get("arguments")
            if args:
                msg["content"] = args
                break
    return data


def _from_events(text: str) -> dict:
    """Read an answer out of a server-sent event stream."""
    parts, usage, calls = [], {}, {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        chunk = line[5:].strip()
        if not chunk or chunk == "[DONE]":
            continue
        try:
            d = json.loads(chunk)
        except ValueError:
            continue
        usage = d.get("usage") or usage
        for ch in d.get("choices") or []:
            for piece in ((ch.get("message") or {}), (ch.get("delta") or {})):
                if piece.get("content"):
                    parts.append(piece["content"])
                for call in piece.get("tool_calls") or []:
                    i = call.get("index", 0)
                    calls[i] = calls.get(i, "") + ((call.get("function") or {}).get("arguments") or "")
    message = {"content": "".join(parts)}
    if not message["content"] and calls:
        message["content"] = "".join(calls.values())
    return {"choices": [{"message": message}], "usage": usage}


def _openai(model, prompt, schema, timeout=None):
    headers = {"Authorization": f"Bearer {key()}"} if key() else {}
    body = {"model": model, "messages": [{"role": "user", "content": _wrapped(prompt, schema)}], "stream": False}
    # Most services accept these two extras; a few models refuse one of them, so they are dropped on a refusal.
    extras = [{"temperature": 0.4, "response_format": {"type": "json_object"}}, {"response_format": {"type": "json_object"}}, {}]
    r = None
    for extra in extras:
        r = httpx.post(f"{base_url()}/chat/completions", json={**body, **extra}, headers=headers, timeout=timeout or 180)
        if r.status_code not in (400, 422):
            break
    if r.status_code != 200:
        _fail(r, model)
    data = _openai_body(r)
    u = data.get("usage") or {}
    return _parse(data["choices"][0]["message"].get("content")), int(u.get("prompt_tokens") or 0), int(u.get("completion_tokens") or 0)


def _anthropic(model, prompt, schema, timeout=None):
    body = {"model": model, "max_tokens": 8192, "messages": [{"role": "user", "content": _wrapped(prompt, schema)}]}
    r = httpx.post(f"{base_url()}/messages", json=body, timeout=timeout or 180,
                   headers={"x-api-key": key(), "anthropic-version": "2023-06-01"})
    if r.status_code != 200:
        _fail(r, model)
    data = r.json()
    text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
    u = data.get("usage") or {}
    return _parse(text), int(u.get("input_tokens") or 0), int(u.get("output_tokens") or 0)
