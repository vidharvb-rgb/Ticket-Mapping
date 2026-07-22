# Ticket Tagging CMS — Setup Guide

## What this is

`cms_app.py` is a small Flask web app that turns the manual "tag tickets in Excel" process into a real shared workflow, on top of the same `tickets.db` the dashboard already uses:

- **Login** is real Google Sign-In — each teammate signs in with their own Google account. The backend verifies the signed token with Google (not just trusting the browser), then checks the verified email against a hardcoded allow-list.
- **Perugu Govardhan, Ajitesh Das, Mansi Gupta** each see *only their own* tickets, fill in Module / Feature / Ticket Type / Case / Status, and either save a draft or submit for approval.
- **You (admin, vidharv.b@meritto.com)** see every submitted ticket across all three, can edit any field, and click **Approve** — that's the only thing that writes into the final `tag_module` / `tag_feature` / etc. columns (the "Confirmed" columns the main dashboard already reads). Nothing is final until you approve it.
- Every ticket also carries `workflow_status` (`Untagged` → `Draft` → `Submitted` → `Approved`) plus `submitted_by`/`approved_by`/timestamps, so nothing gets lost the way it did in Excel.
- Scope: the same 1,291 tickets already covered by the tagging dashboard. The 66 tickets I'd already confidently tagged earlier are seeded in as pre-approved; the other 1,225 start `Untagged` with your existing "suggested" values shown as placeholder hints in each field.

## One important limitation to know about

A Cowork artifact can't run this — it needs an actual server process and a domain that Google recognizes for the sign-in widget. Two ways to run it:

**Option A — quick, local only.** Run it on your own machine; only you can open it (`localhost` isn't reachable by your teammates). Fine for testing the flow yourself first.

**Option B — actually shared with the team.** Deploy `cms_app.py` to a small server everyone can reach (a company VM, Render, Railway, Fly.io, an internal EC2 box, whatever your team already uses). Whatever domain it ends up on, that exact origin (e.g. `https://tickets.meritto.com`) must be added to the OAuth client's **Authorized JavaScript origins** in Google Cloud Console, or Google will refuse to render the sign-in button there. `tickets.db` should live on that same server so everyone's writes land in one file — SQLite doesn't handle multiple machines writing to the same file over a network share well.

I'd recommend testing locally first (Option A), confirming the workflow feels right, then telling me where it'll actually be hosted so I can help adjust anything host-specific.

## Running it locally

```bash
cd Tickets
pip install flask google-auth --break-system-packages   # if not already installed
python3 cms_app.py
```

Open **http://localhost:5051**. Sign in with one of the 4 allow-listed Google accounts.

## Already configured

- **OAuth Client ID**: `1055140297757-skpbblht6jhqk45je1k17ae068c83j9p.apps.googleusercontent.com` (yours — already wired into `cms_app.py`)
- **Allow-list** (top of `cms_app.py`, `ALLOWLIST` dict):

  | Email | Role | Maps to SPOC |
  |---|---|---|
  | vidharv.b@meritto.com | admin | — |
  | perugu@meritto.com | spoc | Perugu Govardhan |
  | ajitesh.d@meritto.com | spoc | Ajitesh Das |
  | mansi.g@meritto.com | spoc | Mansi Gupta |

To add/remove people later, just edit that dict — no redeploy of anything else needed.

## Check that `http://localhost:5051` is an authorized origin

Since you already have a Client ID, double check in Google Cloud Console → APIs & Services → Credentials → your OAuth client → **Authorized JavaScript origins** includes `http://localhost:5051`. If it only lists a different port/origin, the sign-in button will fail with a console error (`origin_mismatch`) — just add `http://localhost:5051` there and save.

## Deploying to PythonAnywhere (free tier)

I can't create the account or click through their signup for you — that step needs to be done by you directly. Everything after that (uploading files, config) you can do yourself in ~15 minutes:

1. **Sign up** at pythonanywhere.com — choose the free "Beginner" account. This gives you `<yourusername>.pythonanywhere.com` with HTTPS out of the box.

2. **Upload the two files.** In the PythonAnywhere dashboard, go to the **Files** tab and upload `cms_app.py` and `tickets.db` into your home directory (e.g. `/home/<yourusername>/tickets/`).

3. **Install dependencies.** Open a **Bash console** (Consoles tab → Bash) and run:
   ```bash
   pip3.10 install --user flask google-auth
   ```
   (use whichever Python version the console shows; free tier defaults to 3.10).

4. **Create the web app.** Go to the **Web** tab → **Add a new web app** → pick "Manual configuration" (not the Flask wizard) → pick the same Python version.

5. **Point it at your code.** Open the generated **WSGI configuration file** (linked on the Web tab) and replace its contents with:
   ```python
   import sys
   path = '/home/<yourusername>/tickets'
   if path not in sys.path:
       sys.path.insert(0, path)

   from cms_app import app as application
   ```

6. **Set a fixed secret key.** On the Web tab, under "Environment variables," add `CMS_SECRET_KEY` with any long random string (otherwise everyone gets logged out whenever the app restarts). `cms_app.py` already reads this via `os.environ.get("CMS_SECRET_KEY", ...)` — no code change needed.

7. **Reload the app** (green button, top of the Web tab).

8. **Add the origin to Google.** In Google Cloud Console → APIs & Services → Credentials → your OAuth client → Authorized JavaScript origins, add:
   ```
   https://<yourusername>.pythonanywhere.com
   ```
   Save — Google can take a few minutes to propagate this.

9. Send everyone `https://<yourusername>.pythonanywhere.com` to sign in with their Meritto Google account.

Note: PythonAnywhere's free tier restricts outbound requests to an allowlist, but `accounts.google.com` / `oauth2.googleapis.com` (used to verify the sign-in token) are on that allowlist by default, so login will work without extra config.

## If you later move this to a shared server

1. Add that server's URL to Authorized JavaScript origins (see above).
2. Copy `cms_app.py` and `tickets.db` there together.
3. Run behind a real WSGI server (not `python3 cms_app.py`'s dev server) — e.g. `gunicorn cms_app:app`.
4. Set a fixed `CMS_SECRET_KEY` environment variable (right now it generates a random one on each restart, which logs everyone out whenever the server restarts).

## Approval & accuracy tracking

The admin view now has a panel above the ticket table showing, per SPOC and overall: total tickets, how many are approved, and an accuracy split:

- **Correct on submit** — admin approved the ticket exactly as the SPOC submitted it, no edits.
- **Corrected by admin** — admin changed at least one of the 5 fields before approving (which fields is tracked internally as `corrected_fields`).
- **Admin-tagged** — you approved a ticket that never went through a SPOC submission at all (you tagged it yourself).
- **Accuracy %** = Correct ÷ (Correct + Corrected), i.e. of tickets a SPOC actually submitted and you later approved, what fraction needed no fixes.

Under the hood: the moment a SPOC clicks Submit, their 5 values are frozen into `submitted_*` columns and never touched again. When you approve, the app diffs those frozen values against whatever you're approving and writes the result to `accuracy_flag`/`corrected_fields` on that ticket — so this is a permanent, queryable record in `tickets.db`, not something recomputed on the fly. The 66 originally pre-tagged tickets are labeled `System` and excluded from the accuracy rate.

## What still needs your judgment

- Only 66 of the 1,291 tickets have a taxonomy I'm confident in (Lead Manager). The other 1,225 show my best-guess suggestions as greyed placeholder text in each field — the SPOCs should treat those as a starting point to check, not gospel, especially outside Lead Manager (Opportunity Manager / Zing / Audit Trail taxonomies were never fully confirmed with you).
- There's currently no "reject with a note" step, per your call — you fix things directly instead. If that ever feels like too much manual correction, I can add a lightweight comment field for you to leave a note without unlocking full editing.
