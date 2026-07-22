# Ticket Tagging CMS — Setup Guide

## What this is

`cms_app.py` is a small Flask web app that turns the manual "tag tickets in a spreadsheet" process into a real shared workflow, on top of the same `tickets.db` the read-only tagging dashboard already reads:

- **Login** is real Google Sign-In — each teammate signs in with their own Google account. The backend verifies the signed ID token with Google (not just trusting the browser), then checks the verified email against a hardcoded allow-list.
- **Perugu Govardhan, Ajitesh Das, Mansi Gupta** each see *only their own* tickets, fill in Module / Feature / Ticket Type / Case / Status, and either save a draft or submit for approval.
- **Admin (vidharv.b@meritto.com)** sees every submitted ticket across all three, can edit any field, and clicks **Approve** — that's the only action that writes into the final `tag_module` / `tag_feature` / etc. columns (the "Confirmed" columns the tagging dashboard reads). Nothing is final until approved. There's deliberately no "reject with a note" step — the admin fixes things directly instead of bouncing a ticket back.
- Every ticket carries `workflow_status` (`Untagged` → `Draft` → `Submitted` → `Approved`) plus `submitted_by` / `approved_by` / timestamps.
- **SPOCs never see the approval process.** For them a ticket's journey is just Untagged → Draft → **Tagged** — the moment they submit, it's out of their hands. Their browser is never even sent `approved_by`, `approved_at`, `accuracy_flag`, or whether a ticket is `Submitted` vs `Approved` — that's stripped server-side before the response is built, not just hidden in the UI, so it isn't recoverable via dev tools either.
- Scope: the 1,291 tickets already covered by the tagging dashboard, assigned to those three SPOCs. 66 of them already had a taxonomy someone was confident in — those are seeded in pre-approved, labeled `System` in accuracy tracking, and excluded from the accuracy rate. The other 1,225 start `Untagged`, with best-guess suggested values shown as greyed placeholder text in each field — flagged explicitly in the UI as a starting point to check, not a confirmed answer.
- **Admin Dashboard tab.** Split into two sections: **Ticket overview** (total / open / in-progress / clarity-or-reopened / completed / high-priority-and-still-open counts, plus status/priority/ticket-type/created-by-month charts) and **Tagging progress** (tagged / approved / awaiting-review / accuracy KPIs, a per-SPOC tagged-vs-total bar chart, and the accuracy donut).
- **View conversation.** Every ticket row (both SPOC and admin views) has a "View conversation" link next to "Open in Zoho" that opens an in-app modal with that ticket's full comment thread — commenter, role, timestamp, text — pulled live from the `comments` table via `/api/comments/<ticket_id>`. No need to leave the CMS to read ticket history.

## The one real limitation

A hosted-artifact environment can't run this — it needs an actual server process and a domain that Google's OAuth recognizes for the sign-in widget. Two ways to run it:

**Option A — quick, local only.** Run it on your own machine with `python3 cms_app.py`; only reachable by you via `localhost`. Good for testing the workflow first.

**Option B — actually shared with the team.** Deploy `cms_app.py` to a real host everyone can reach (a company VM, Render, Railway, Fly.io, PythonAnywhere, etc.), add that exact origin to the OAuth client's **Authorized JavaScript origins** in Google Cloud Console, and keep `tickets.db` on that same server. SQLite doesn't handle concurrent writes from multiple machines over a network share, so the app and the database need to live together.

## Running it locally

```bash
cd Tickets
pip install flask google-auth --break-system-packages   # if not already installed
python3 cms_app.py
```

Open **http://localhost:5051**. Sign in with one of the 4 allow-listed Google accounts.

## Allow-list

| Email | Role | Maps to SPOC |
|---|---|---|
| vidharv.b@meritto.com | admin | — |
| perugu@meritto.com | spoc | Perugu Govardhan |
| ajitesh.d@meritto.com | spoc | Ajitesh Das |
| mansi.g@meritto.com | spoc | Mansi Gupta |

To add/remove people later, just edit the `ALLOWLIST` dict at the top of `cms_app.py` — no redeploy of anything else needed.

## A note on the secret key

`cms_app.py` reads `CMS_SECRET_KEY` from the environment, falling back to a freshly generated random value if it isn't set:

```python
app.secret_key = os.environ.get("CMS_SECRET_KEY", secrets.token_hex(32))
```

That fallback is fine for a process that stays running. But on hosts that recycle idle processes (e.g. PythonAnywhere's free tier), every restart generates a brand-new secret key — which invalidates every logged-in session, silently signing everyone out. If you deploy anywhere that can restart the process, **pin `CMS_SECRET_KEY` to a fixed value via a real environment variable** (see the PythonAnywhere steps below). Generate one yourself with:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Treat that value like a password — don't paste it into a doc or commit it to git.

## Deploying to PythonAnywhere via GitHub

**1. Create a private GitHub repo containing only what's safe to publish**: `cms_app.py`, this guide, and a `.gitignore` that excludes `tickets.db` (it has real ticket subjects/descriptions). `tickets.db` is uploaded separately, never through git.

```
# .gitignore
tickets.db
tickets.db-journal
```

**2. Push it.**
```bash
cd /path/to/Tickets
git init   # if not already a repo
git add cms_app.py CMS_SETUP_GUIDE.md .gitignore
git commit -m "Ticket tagging CMS"
git remote add origin https://github.com/<your-username>/ticket-cms.git
git branch -M main
git push -u origin main
```
(Use a GitHub personal access token as the password if prompted — GitHub retired plain password pushes.)

**3. Sign up at PythonAnywhere** — the free "Beginner" account gives you `<yourusername>.pythonanywhere.com` with HTTPS out of the box.

**4. Clone the repo** in a Bash console (Consoles tab → Bash):
```bash
git clone https://github.com/<your-username>/ticket-cms.git
cd ticket-cms
pip3.10 install --user flask google-auth
```

**5. Upload `tickets.db` separately** — Files tab → upload it into that same `ticket-cms` folder (not via git).

**6. Create the web app** — Web tab → **Add a new web app** → **Manual configuration** (not the Flask wizard) → the same Python version as step 4.

**7. Point the WSGI file at your code and pin the secret key.** Open the generated WSGI configuration file (linked on the Web tab) and set it up like this:

- If your account's Web tab has an **Environment variables** section, use that to set `CMS_SECRET_KEY`, then the WSGI file only needs:
  ```python
  import sys
  path = '/home/<yourusername>/ticket-cms'
  if path not in sys.path:
      sys.path.insert(0, path)

  from cms_app import app as application
  ```
- If that section isn't available on your account, set the variable directly in the WSGI file, **before** the import line — and make sure `os` is actually imported, since dropping it here causes a `NameError: name 'os' is not defined` on every request:
  ```python
  import sys, os
  path = '/home/<yourusername>/ticket-cms'
  if path not in sys.path:
      sys.path.insert(0, path)

  os.environ['CMS_SECRET_KEY'] = '<paste a value from `python3 -c "import secrets; print(secrets.token_hex(32))"`>'

  from cms_app import app as application
  ```

**8. Add the live domain to Google.** Google Cloud Console → APIs & Services → Credentials → your OAuth client → **Authorized JavaScript origins** → add:
```
https://<yourusername>.pythonanywhere.com
```
Save — can take a few minutes to propagate.

**9. Reload the app** (green button, top of the Web tab).

**10.** Send everyone `https://<yourusername>.pythonanywhere.com` to sign in with their Meritto Google account.

Note: PythonAnywhere's free tier restricts outbound requests to an allowlist, but `accounts.google.com` / `oauth2.googleapis.com` (used to verify the sign-in token) and `github.com` (for cloning) are on that allowlist by default, so this works without extra config.

**Updating the code later:** edit locally → `git commit` → `git push` → on PythonAnywhere, `git pull` inside the `ticket-cms` folder → Reload on the Web tab. `tickets.db` is untouched since it's never part of the repo.

## If you move this to a different shared server instead

1. Add that server's URL to Authorized JavaScript origins (see step 8 above).
2. Copy `cms_app.py` and `tickets.db` there together.
3. Run behind a real WSGI server (not `python3 cms_app.py`'s dev server) — e.g. `gunicorn cms_app:app`.
4. Set a fixed `CMS_SECRET_KEY` environment variable.

## Approval & accuracy tracking

The admin Dashboard tab's "Tagging progress" section shows, per SPOC and overall: total tickets, how many are approved, and an accuracy split:

- **Correct on submit** — admin approved the ticket exactly as the SPOC submitted it, no edits.
- **Corrected by admin** — admin changed at least one of the 5 fields before approving (which fields is tracked internally as `corrected_fields`).
- **Admin-tagged** — admin approved a ticket that never went through a SPOC submission at all.
- **System** — the 66 originally pre-tagged legacy tickets, excluded from the accuracy rate.
- **Accuracy %** = Correct ÷ (Correct + Corrected) — of tickets a SPOC actually submitted and the admin later approved, the fraction that needed no fixes.

Under the hood: the moment a SPOC clicks Submit, their 5 values are frozen into `submitted_*` columns and never touched again. When the admin approves, the app diffs those frozen values against whatever is being approved and permanently writes `accuracy_flag` / `corrected_fields` to that ticket row — a queryable historical record in `tickets.db`, not something recomputed on the fly.

## What still needs judgment

- Only 66 of the 1,291 tickets have a taxonomy someone was fully confident in. The other 1,225 show best-guess suggestions as greyed placeholder text in each field, with an explicit hint in the UI that these are a starting point to check, not confirmed — especially for taxonomies that were never fully verified.
- There's no "reject with a note" step by design — the admin fixes things directly instead of bouncing back to the SPOC.
