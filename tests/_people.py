"""Helpers for tests that talk to a running test server: a web client that behaves like NeakClips' own pages (it sends
the CSRF cookie back in a header), and making an account the only way there is, from an invitation."""
import os
import re
import subprocess
import sys

import httpx

CSRF = "peakcut_csrf"


def client(base: str, csrf: bool = True, **kw):
    """A browser-like client. With csrf=False it behaves like another website: no CSRF header."""
    kw.setdefault("timeout", 60)
    kw.setdefault("follow_redirects", False)
    c = httpx.Client(base_url=base, **kw)
    if csrf:
        add_csrf(c)
    c.get("/api/public")                  # any page hands out the CSRF cookie
    return c


def add_csrf(c):
    def hook(request):
        if request.method not in ("GET", "HEAD", "OPTIONS") and "x-csrf-token" not in request.headers:
            token = next((ck.value for ck in c.cookies.jar if ck.name == CSRF), "")
            if token:
                request.headers["X-CSRF-Token"] = token
    c.event_hooks["request"].append(hook)
    return c


def invite_token(email: str, root: str = None, hours: int = 72) -> str:
    """An invitation made on the server's command line, the way the first admin is invited."""
    r = subprocess.run([sys.executable, "-m", "studio.admin", "invite", email, str(hours)], cwd=root or os.getcwd(),
                       env=os.environ, capture_output=True, text=True)
    m = re.search(r"/invite/([A-Za-z0-9_\-]+)", r.stdout)
    assert m, r.stdout + r.stderr
    return m.group(1)


def join(base: str, email: str, password: str = "test-pass-123", name: str = "Test Person", root: str = None, **kw):
    """(client signed in as a new account, the account) made from an invitation."""
    c = client(base, **kw)
    token = invite_token(email, root)
    r = c.post("/api/auth/invite/accept", json={"token": token, "name": name, "password": password, "confirm": password},
               headers={"Origin": base})
    assert r.status_code == 200, r.text
    return c, r.json()["user"]
