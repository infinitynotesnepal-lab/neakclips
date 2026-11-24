# Working on NeakClips

A short map for contributors and AI coding assistants.

## Installing or updating NeakClips for someone

**Before installing, ask the person where to put it**, and suggest a short, permanent folder: `C:\peakcut` on
Windows, `~/peakcut` on a Mac or Linux. Do not just clone into the folder you happen to be running in: AI assistants
often run in a temporary, scratch or session workspace, which gets deleted, and whose path is long enough that
Windows cannot load the speech library (Windows can't open files whose full path is over 260 characters; the error
is "DLL load failed ... The filename or extension is too long"). Tell the person where you put it.

**When updating**, look at where NeakClips is first. If its folder path is long (roughly over 100 characters) or inside
a temporary or assistant workspace, ask the person whether to move it to `C:\peakcut` (or `~/peakcut`) as part of the
update. Moving is safe when done like this: clone the latest version into the new folder, copy over `.env`,
`storage.json` and the `data` folder if there is one (the videos and clips; `storage.json` may point to a data folder
elsewhere, which then stays where it is), install the requirements, start it from the new folder, check the clips
are there, and only then offer to delete the old folder. Never delete anything without asking.

## Run and test

- Run: `python -m studio.server` (settings from `.env`; see `.env.example`). Needs Python 3.10+ and `ffmpeg`.
- The English speech model (about 480 MB) downloads by itself on first start; `python -m studio.fetch_model` gets it
  ahead of time. Other spoken languages (Arabic, about 107 MB) download only when asked for, in Settings → Speech
  models or with `python -m studio.fetch_model ar`.
- Tests: `python tests/run.py`. It starts a throwaway copy on a spare port with an empty data folder. Run it
  before and after any change to `studio/`. No keys needed.
- To try a risky change by hand without touching real data:
  `PEAKCUT_DATA=<temp folder> PEAKCUT_PORT=8766 python -m studio.server`.

## Where things are

| File | What it does |
|---|---|
| `studio/server.py` | Every web route, and the gate that runs before each request (who is asking, limits, headers) |
| `studio/config.py` | Every setting, read from environment variables |
| `studio/ai.py` | The only code that talks to an AI service, and each person's own AI settings and key (the `ai_keys` table, encrypted) |
| `studio/vault.py` | AES-256-GCM encryption for saved secrets; the key lives in `PEAKCUT_SECRET_KEY_FILE`, outside the database |
| `studio/invites.py` | Invitations: the only way a new account is made when sign-in is on |
| `studio/migrate.py` | Brings older data up to date (`python -m studio.migrate`); also runs at each start, and never changes or drops existing tables |
| `studio/brain.py` | The prompts: finding clips, live judging, hooks and titles, caption fixes |
| `studio/usage.py` | The record of AI calls and tokens shown on the AI usage page |
| `studio/jobs.py` | The video pipeline and the fair queue |
| `studio/live.py` | Live recording and clipping |
| `studio/transcribe.py`, `studio/asr_worker.py` | Speech to text, here or on a second machine, one model per spoken language |
| `studio/fetch_model.py` | The speech models (`MODELS`: one row per spoken language) and downloading them |
| `tools/export_arabic_model.py` | How the Arabic model was converted for sherpa-onnx (run once, on Google Colab) |
| `studio/render.py` | Cutting, layouts and captions (ffmpeg and Pillow) |
| `studio/media.py` | Downloading (yt-dlp), probing, audio |
| `studio/auth.py`, `studio/account.py`, `studio/admin.py` | Sign-in (Argon2id passwords), deleting things, the admin dashboard and its server commands |
| `studio/db.py` | Database tables (SQLAlchemy core; SQLite or PostgreSQL) |
| `web/index.html` | The whole signed-in app, one file, no build step |
| `web/csrf.js` | Loaded first on every page: copies the CSRF cookie into a header on every change the page asks for |
| `web/invite.html` | The page an invitation link opens |

## Rules worth knowing

- **Sign-in is off by default** (`config.ACCOUNTS`): every request then belongs to one built-in owner
  (`auth.local_user()`). With `PEAKCUT_ACCOUNTS=1` it is an invitation-only multi-user site: there is no sign-up, and
  Google sign-in never makes a new account. Both paths are tested. Tests make accounts with `tests/_people.py`.
- **Each person's own AI key**: with sign-in on, `ai.current()` returns the key of the user the code runs for
  (`ctx`), and nothing else: never another user's, `.env`'s or `ai.json`'s. Keys are stored only through
  `vault.lock(key, "ai_key:<uid>")`; the page and admins only ever get `ai.mask(key)`. Pass any key-bearing text
  through `ai._hide` before it can reach a page or a log.
- **CSRF**: with sign-in on, every request that is not GET/HEAD/OPTIONS must carry the `peakcut_csrf` cookie's value
  in `X-CSRF-Token` (the gate in `server.py` checks it). Pages get it by loading `/assets/csrf.js` first.
- **Who is asking** always comes from the session (`ctx.uid()`), never from the request body. Background threads
  set it themselves with `ctx.as_user(...)`.
- **Anything that changes what a user sees must call `ctx.bump()`**. The page polls `/api/sync`, which answers
  from memory when that user's counter has not moved.
- **Text from videos is untrusted**: it goes into prompts through `brain._safe` and out through `brain._text`.
- **Adding an AI provider**: add a row to `PROVIDERS` in `studio/ai.py`. If it speaks the OpenAI chat format that
  is all; otherwise add one function that returns `(parsed JSON, tokens in, tokens out)`.
- **Adding a spoken language**: add a row to `MODELS` in `studio/fetch_model.py`. Any NVIDIA NeMo transducer model
  exported for sherpa-onnx works; its word pieces must mark word starts with `▁`. The language a video is in comes
  from `options["lang"]` (or a creator's `lang`) and is passed to `transcribe.transcribe(..., lang=...)`.
- **Clips are rendered in a short temporary folder** and moved into place (`render.render_clip`): ffmpeg's caption
  step cannot open paths longer than 260 characters on Windows.
- **Secrets** are read from the environment or from files named by `*_FILE` settings. Never write a key, a real
  address or a personal path into a tracked file.
- **Pages** are plain HTML, CSS and JavaScript. Keep the existing palette, no shadows, and hover states that
  change colour only.
- Comments and messages are written in plain language for people who do not program. Keep that tone.
