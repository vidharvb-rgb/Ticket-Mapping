"""
Ticket Tagging CMS — Google-login gated workflow on top of tickets.db.

Roles:
  - spoc  : sees only their own tickets, fills in the 5 tag fields, saves
            drafts, and submits for approval.
  - admin : sees everything submitted across all SPOCs, can edit any field,
            and approves to finalize into tag_* (the columns the read-only
            tagging dashboard reads as "Confirmed").

Auth: Google Identity Services on the frontend hands us a signed ID token;
the backend verifies that token against Google's public keys (google-auth),
extracts the *verified* email, and checks it against ALLOWLIST below.
Nothing about role/identity is ever trusted from the client — only the
verified token content.

Run:
    pip install flask google-auth --break-system-packages
    python3 cms_app.py
Then open http://localhost:5051
"""
import gzip
import json
import os
import re
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, g, jsonify, request, session

from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token

DB_PATH = Path(__file__).parent / "tickets.db"

# ---------------------------------------------------------------------------
# Configuration — the only two things you should ever need to edit.
# ---------------------------------------------------------------------------
GOOGLE_CLIENT_ID = "1055140297757-skpbblht6jhqk45je1k17ae068c83j9p.apps.googleusercontent.com"

# email -> {role, spoc_name}. spoc_name must exactly match cf_task_spoc_name
# values in tickets.db so a SPOC's login maps to the right ticket set.
ALLOWLIST = {
    "vidharv.b@meritto.com": {"role": "admin", "spoc_name": None, "display_name": "Vidharv"},
    "perugu@meritto.com":    {"role": "spoc",  "spoc_name": "Perugu Govardhan", "display_name": "Perugu Govardhan"},
    "ajitesh.d@meritto.com": {"role": "spoc",  "spoc_name": "Ajitesh Das",      "display_name": "Ajitesh Das"},
    "mansi.g@meritto.com":   {"role": "spoc",  "spoc_name": "Mansi Gupta",      "display_name": "Mansi Gupta"},
}

SPOC_NAMES = [v["spoc_name"] for v in ALLOWLIST.values() if v["spoc_name"]]

TAXONOMY = {
    "module": ["API & Integration", "Amplify", "Applicant Dashboard", "Applicant Data & Upload",
        "Application Form", "Applications", "CRM Configuration", "Campaign & Tracking",
        "Communication & Reminders", "Communication Templates", "Data & Security",
        "Document Verification", "Drip Marketing", "ERP Integration", "Echo", "Lead Manager",
        "Marketing Page", "Master Data", "Mio AI Guide", "Mobile App", "NIAA (Chatbot)",
        "Opportunity Manager", "Permission", "Publisher Integration", "Registration Page",
        "Reports & Dashboard", "SMS Integration", "Score Card", "Social Channel Connector",
        "Team & User Management", "Telephony", "WABA", "Webhook / ERP", "Webhook / Other",
        "Widget", "Workflow Automation", "Zapier", "Zing"],
    "feature": ["API Documentation/Access", "API Errors", "API URL/Details", "Access/Permission",
        "Add Quick Lead", "Allocation", "Application Slowness", "Assignment", "Bulk Data Update",
        "Bulk Data Upload Report", "Bulk Download", "Bulk Upload", "Calendar Pro",
        "Call Routing/Dialing", "Campaign Data Update", "Conversation Capture",
        "Conversion Funnel Report", "Dashboard Access", "Data Sync", "Download Report",
        "Download/Export", "Dynamic Activity API", "Facebook Lead Ads", "Facebook Lead Sync",
        "Feature Request/Check", "Field Configuration", "Field/Data Mapping", "Filters",
        "Follow-up Report", "General / Uncategorized", "Google Remarketing", "IVR/Voice",
        "Listing Columns", "Notifications", "Opportunity Creation", "Opportunity Stages",
        "Performance/Console Errors", "Performance/Slowness", "Pop-up/Redirection",
        "Profile Page", "Purge", "Reassignment", "Report Download", "Reports", "Session Purge",
        "Softphone/Connector Setup", "Sync Delay", "Team Hierarchy", "Telephony Filters",
        "Timeline", "UTM/Source Tracking", "WABA Template Status",
        "WhatsApp/Facebook Integration", "White Screen/Loading"],
    "ticket_type": ["Bug", "Feature Request", "How To", "Query"],
    "case": ["Added in Runtime", "Added to Roadmap", "Addressed by Product", "Adhoc",
        "Alternate Solution Provided", "Cache Issue", "Config Issue", "Confusing/Hidden Config",
        "Default Functionality", "Feature Enhancement", "Gap at Client End", "Gap at Ops End",
        "Gap at Vendor", "Infra issue", "JS Issue", "Knowledge Gap", "Known Case", "Legacy Code",
        "Manual Query Execution Impact", "Marked Completed via Closed Ticket",
        "New Feature Request", "New Imp/Config", "Not a Bug", "Query Addressed",
        "Query Executed", "Regular Query", "Release Impact", "System Limitation",
        "Task Marked Completed Due to No Revert", "Third-Party Error", "Unable to Replicate",
        "Unspecified"],
    "status": ["Added in Runtime", "Added to Backlog", "Added to Roadmap", "Addressed by Product",
        "Alternate Solution Provided", "Clarity Required", "Completed", "Default Functionality",
        "Executed", "Fixed", "Gap at Ops End", "Gap at Vendor", "In Dev", "In Progress",
        "Infra/Server Error", "Knowledge Gap", "Known Case", "Legacy Code",
        "Marked Completed via Closed Ticket", "New Imp/Config", "Not a Bug", "Open",
        "Query Addressed", "Query Executed", "Query Not Executed", "Re-open", "Release Impact",
        "System Limitation", "Task Marked Completed Due to No Revert", "Third-Party Error",
        "Unable to Replicate"],
}

TAG_FIELDS = ["module", "feature", "ticket_type", "case", "status"]

app = Flask(__name__)
app.secret_key = os.environ.get("CMS_SECRET_KEY", secrets.token_hex(32))


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=MEMORY;")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def current_user():
    email = session.get("email")
    if not email or email not in ALLOWLIST:
        return None
    info = ALLOWLIST[email]
    return {"email": email, "role": info["role"], "name": info["display_name"],
             "spoc_name": info["spoc_name"]}


def require_role(role):
    user = current_user()
    if not user:
        return None, (jsonify(error="not signed in"), 401)
    if role and user["role"] != role:
        return None, (jsonify(error="forbidden"), 403)
    return user, None


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
@app.post("/auth/google")
def auth_google():
    body = request.get_json(force=True, silent=True) or {}
    token = body.get("credential")
    if not token:
        return jsonify(ok=False, error="missing credential"), 400
    try:
        claims = google_id_token.verify_oauth2_token(
            token, google_requests.Request(), GOOGLE_CLIENT_ID
        )
    except Exception as e:  # noqa: BLE001 — surfaced to the user as a login error
        return jsonify(ok=False, error=f"invalid token: {e}"), 401

    if not claims.get("email_verified"):
        return jsonify(ok=False, error="email not verified by Google"), 401

    email = claims["email"].lower()
    if email not in ALLOWLIST:
        return jsonify(ok=False, error=f"{email} is not on the access list"), 403

    session["email"] = email
    info = ALLOWLIST[email]
    return jsonify(ok=True, role=info["role"], name=info["display_name"])


@app.post("/auth/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/api/me")
def api_me():
    user = current_user()
    return jsonify(user=user, client_id=GOOGLE_CLIENT_ID, taxonomy=TAXONOMY)


# ---------------------------------------------------------------------------
# Tickets + comments
# ---------------------------------------------------------------------------
TICKET_COLS = """
    id, subject, status, priority, created_time, web_url,
    cf_task_spoc_name, cf_type_of_task,
    tag_module, tag_feature, tag_ticket_type, tag_case, tag_status,
    sugg_module, sugg_feature, sugg_ticket_type, sugg_case, sugg_status,
    spoc_tag_module, spoc_tag_feature, spoc_tag_ticket_type, spoc_tag_case, spoc_tag_status,
    submitted_module, submitted_feature, submitted_ticket_type, submitted_case, submitted_status,
    workflow_status, submitted_by, submitted_at, approved_by, approved_at,
    accuracy_flag, corrected_fields
"""

# SPOCs should never learn that an admin reviewed/approved/corrected a ticket
# — for them the journey ends the moment they submit. We collapse
# Submitted/Approved into a single "Tagged" bucket and drop the
# approval-only columns entirely, so this isn't just a UI hide: it's not in
# the payload their browser receives at all.
def _scrub_for_spoc(t):
    if t.get("workflow_status") in ("Submitted", "Approved"):
        t["workflow_status"] = "Tagged"
    for key in ("approved_by", "approved_at", "accuracy_flag", "corrected_fields",
                "submitted_module", "submitted_feature", "submitted_ticket_type",
                "submitted_case", "submitted_status"):
        t.pop(key, None)
    return t


@app.get("/api/tickets")
def api_tickets():
    user = current_user()
    if not user:
        return jsonify(error="not signed in"), 401

    db = get_db()
    if user["role"] == "spoc":
        rows = db.execute(
            f"SELECT {TICKET_COLS} FROM tickets WHERE cf_task_spoc_name = ?",
            (user["spoc_name"],),
        ).fetchall()
        tickets = [_scrub_for_spoc(dict(r)) for r in rows]
    else:
        placeholders = ",".join("?" for _ in SPOC_NAMES)
        rows = db.execute(
            f"SELECT {TICKET_COLS} FROM tickets WHERE cf_task_spoc_name IN ({placeholders})",
            SPOC_NAMES,
        ).fetchall()
        tickets = [dict(r) for r in rows]
    return jsonify(tickets=tickets)


@app.get("/api/comments/<ticket_id>")
def api_comments(ticket_id):
    user = current_user()
    if not user:
        return jsonify(error="not signed in"), 401

    db = get_db()
    ticket = db.execute(
        "SELECT cf_task_spoc_name FROM tickets WHERE id = ?", (ticket_id,)
    ).fetchone()
    if not ticket:
        return jsonify(error="not found"), 404
    if user["role"] == "spoc" and ticket["cf_task_spoc_name"] != user["spoc_name"]:
        return jsonify(error="forbidden"), 403

    rows = db.execute(
        """SELECT commented_time, commenter_name, commenter_type, commenter_role, content_text
           FROM comments WHERE ticket_id = ? ORDER BY commented_time""",
        (ticket_id,),
    ).fetchall()
    return jsonify(comments=[dict(r) for r in rows])


def _clean_fields(payload):
    values = {}
    for f in TAG_FIELDS:
        v = (payload.get(f) or "").strip()
        values[f] = v or None
    return values


# ---------------------------------------------------------------------------
# SPOC workflow
# ---------------------------------------------------------------------------
@app.post("/api/spoc/save")
def spoc_save():
    user, err = require_role("spoc")
    if err:
        return err
    payload = request.get_json(force=True, silent=True) or {}
    ticket_id = payload.get("id")
    action = payload.get("action")  # 'draft' | 'submit'
    if not ticket_id or action not in ("draft", "submit"):
        return jsonify(error="bad request"), 400

    db = get_db()
    ticket = db.execute(
        "SELECT cf_task_spoc_name, workflow_status FROM tickets WHERE id = ?", (ticket_id,)
    ).fetchone()
    if not ticket or ticket["cf_task_spoc_name"] != user["spoc_name"]:
        return jsonify(error="forbidden"), 403
    if ticket["workflow_status"] == "Approved":
        return jsonify(error="already approved, locked"), 409

    values = _clean_fields(payload)
    new_status = "Submitted" if action == "submit" else "Draft"

    # On an actual submit, freeze a snapshot of exactly what the SPOC entered.
    # That snapshot is never touched again, so later we can tell whether the
    # admin approved it unchanged ("Correct") or had to fix something.
    db.execute(
        """UPDATE tickets SET
             spoc_tag_module = ?, spoc_tag_feature = ?, spoc_tag_ticket_type = ?,
             spoc_tag_case = ?, spoc_tag_status = ?,
             workflow_status = ?,
             submitted_by = CASE WHEN ? = 'Submitted' THEN ? ELSE submitted_by END,
             submitted_at = CASE WHEN ? = 'Submitted' THEN ? ELSE submitted_at END,
             submitted_module = CASE WHEN ? = 'Submitted' THEN ? ELSE submitted_module END,
             submitted_feature = CASE WHEN ? = 'Submitted' THEN ? ELSE submitted_feature END,
             submitted_ticket_type = CASE WHEN ? = 'Submitted' THEN ? ELSE submitted_ticket_type END,
             submitted_case = CASE WHEN ? = 'Submitted' THEN ? ELSE submitted_case END,
             submitted_status = CASE WHEN ? = 'Submitted' THEN ? ELSE submitted_status END
           WHERE id = ?""",
        (values["module"], values["feature"], values["ticket_type"], values["case"],
         values["status"], new_status,
         new_status, user["email"],
         new_status, now_iso(),
         new_status, values["module"],
         new_status, values["feature"],
         new_status, values["ticket_type"],
         new_status, values["case"],
         new_status, values["status"],
         ticket_id),
    )
    db.commit()
    return jsonify(ok=True, workflow_status=new_status)


# ---------------------------------------------------------------------------
# Admin workflow
# ---------------------------------------------------------------------------
@app.post("/api/admin/save")
def admin_save():
    user, err = require_role("admin")
    if err:
        return err
    payload = request.get_json(force=True, silent=True) or {}
    ticket_id = payload.get("id")
    action = payload.get("action")  # 'save' | 'approve'
    if not ticket_id or action not in ("save", "approve"):
        return jsonify(error="bad request"), 400

    db = get_db()
    ticket = db.execute("SELECT id FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    if not ticket:
        return jsonify(error="not found"), 404

    values = _clean_fields(payload)
    db.execute(
        """UPDATE tickets SET
             spoc_tag_module = ?, spoc_tag_feature = ?, spoc_tag_ticket_type = ?,
             spoc_tag_case = ?, spoc_tag_status = ?
           WHERE id = ?""",
        (values["module"], values["feature"], values["ticket_type"], values["case"],
         values["status"], ticket_id),
    )

    accuracy_flag = None
    corrected_fields = None
    if action == "approve":
        # Diff the frozen SPOC submission against what's about to become
        # final, and permanently record the result — no "reject with a
        # note" step by design, the admin just fixes it directly.
        row = db.execute(
            """SELECT submitted_by, submitted_module, submitted_feature, submitted_ticket_type,
                      submitted_case, submitted_status
               FROM tickets WHERE id = ?""",
            (ticket_id,),
        ).fetchone()
        if not row["submitted_by"]:
            accuracy_flag = "Admin-tagged"  # never went through a SPOC submission
        else:
            diffs = [
                f for f in TAG_FIELDS
                if (row[f"submitted_{f}"] or None) != values[f]
            ]
            if diffs:
                accuracy_flag = "Corrected"
                corrected_fields = ",".join(diffs)
            else:
                accuracy_flag = "Correct"

        db.execute(
            """UPDATE tickets SET
                 tag_module = spoc_tag_module, tag_feature = spoc_tag_feature,
                 tag_ticket_type = spoc_tag_ticket_type, tag_case = spoc_tag_case,
                 tag_status = spoc_tag_status,
                 workflow_status = 'Approved', approved_by = ?, approved_at = ?,
                 accuracy_flag = ?, corrected_fields = ?
               WHERE id = ?""",
            (user["email"], now_iso(), accuracy_flag, corrected_fields, ticket_id),
        )
    db.commit()
    return jsonify(ok=True, approved=(action == "approve"),
                    accuracy_flag=accuracy_flag, corrected_fields=corrected_fields)


@app.post("/api/admin/reopen")
def admin_reopen():
    """Unlock an Approved ticket back to Draft so the admin can edit it again."""
    user, err = require_role("admin")
    if err:
        return err
    payload = request.get_json(force=True, silent=True) or {}
    ticket_id = payload.get("id")
    if not ticket_id:
        return jsonify(error="bad request"), 400
    db = get_db()
    db.execute("UPDATE tickets SET workflow_status = 'Draft' WHERE id = ?", (ticket_id,))
    db.commit()
    return jsonify(ok=True)


@app.get("/api/admin/stats")
def admin_stats():
    user, err = require_role("admin")
    if err:
        return err
    db = get_db()
    placeholders = ",".join("?" for _ in SPOC_NAMES)
    rows = db.execute(
        f"""SELECT cf_task_spoc_name, workflow_status, accuracy_flag
            FROM tickets WHERE cf_task_spoc_name IN ({placeholders})""",
        SPOC_NAMES,
    ).fetchall()

    per_spoc = {}
    overall = {"total": 0, "approved": 0, "correct": 0, "corrected": 0, "admin_tagged": 0, "system": 0}
    for r in rows:
        name = r["cf_task_spoc_name"]
        s = per_spoc.setdefault(name, {"total": 0, "approved": 0, "correct": 0,
                                        "corrected": 0, "admin_tagged": 0, "system": 0})
        s["total"] += 1
        overall["total"] += 1
        if r["workflow_status"] == "Approved":
            s["approved"] += 1
            overall["approved"] += 1
            key = {"Correct": "correct", "Corrected": "corrected",
                   "Admin-tagged": "admin_tagged", "System": "system"}.get(r["accuracy_flag"])
            if key:
                s[key] += 1
                overall[key] += 1

    def with_rate(s):
        graded = s["correct"] + s["corrected"]  # System/Admin-tagged weren't a SPOC call to grade
        s["accuracy_pct"] = round(100 * s["correct"] / graded, 1) if graded else None
        return s

    per_spoc = {k: with_rate(v) for k, v in per_spoc.items()}
    overall = with_rate(overall)
    return jsonify(overall=overall, per_spoc=per_spoc)


# ---------------------------------------------------------------------------
# Admin: import a fresh Zoho export without touching tagging/approval state
# ---------------------------------------------------------------------------
# Same shape build_db.py reads from a zoho_tasks_consolidated_*.json file.
# Deliberately excludes every tag_*/sugg_*/spoc_tag_*/submitted_*/approved_*/
# workflow_status/accuracy_* column — an import must never overwrite tagging
# or approval work already in progress, only refresh ticket metadata and pull
# in tickets/comments that didn't exist yet.
IMPORT_META_COLS = [
    "subject", "status", "priority", "due_date", "created_time", "modified_time",
    "completed_time", "department_id", "department_name", "cf_module",
    "cf_task_spoc_id", "cf_task_spoc_name", "cf_type_of_task", "cf_organization_name",
    "cf_task_requested_for", "cf_resolution_category", "description",
    "assignee_name", "assignee_email", "web_url", "comment_count",
]


def _strip_html(html):
    if not html:
        return html
    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"&nbsp;", " ", text)
    text = re.sub(r"&amp;", "&", text)
    text = re.sub(r"&lt;", "<", text)
    text = re.sub(r"&gt;", ">", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _parse_import_record(rec):
    spoc = rec.get("cf_task_spoc") or {}
    assignee = rec.get("assignee") or {}
    comments = rec.get("comments") or []
    meta = (
        rec.get("subject"), rec.get("status"), rec.get("priority"), rec.get("dueDate"),
        rec.get("createdTime"), rec.get("modifiedTime"), rec.get("completedTime"),
        rec.get("departmentId"), rec.get("department_name"), rec.get("cf_module"),
        spoc.get("id"), spoc.get("name"), rec.get("cf_type_of_task"),
        rec.get("cf_organization_name"), rec.get("cf_task_requested_for"),
        rec.get("cf_resolution_category"), rec.get("description"),
        assignee.get("name"), assignee.get("email"), rec.get("webUrl"), len(comments),
    )
    return meta, comments


@app.post("/api/admin/import")
def admin_import():
    user, err = require_role("admin")
    if err:
        return err

    f = request.files.get("file")
    if not f:
        return jsonify(ok=False, error="no file uploaded"), 400

    try:
        stream = gzip.GzipFile(fileobj=f.stream) if (f.filename or "").endswith(".gz") else f.stream
        records = json.load(stream)
    except Exception as e:  # noqa: BLE001 — surfaced to the admin as an import error
        return jsonify(ok=False, error=f"could not parse JSON: {e}"), 400

    if not isinstance(records, list):
        return jsonify(ok=False, error="expected a JSON array of ticket records"), 400

    db = get_db()
    existing_ids = {r["id"] for r in db.execute("SELECT id FROM tickets").fetchall()}

    update_rows = []
    insert_rows = []
    comment_rows = []
    for rec in records:
        ticket_id = rec.get("id")
        if not ticket_id:
            continue
        meta, comments = _parse_import_record(rec)
        if ticket_id in existing_ids:
            update_rows.append(meta + (ticket_id,))
        else:
            insert_rows.append((ticket_id,) + meta)
            existing_ids.add(ticket_id)
        for c in comments:
            comment_rows.append((
                c.get("id"), ticket_id, c.get("commentedTime"), c.get("modifiedTime"),
                c.get("commenterId"), c.get("commenter_name"), c.get("commenter_email"),
                c.get("commenter_type"), c.get("commenter_role"),
                c.get("content"), _strip_html(c.get("content") or ""),
            ))

    if update_rows:
        db.executemany(
            f"UPDATE tickets SET {', '.join(f'{c} = ?' for c in IMPORT_META_COLS)} WHERE id = ?",
            update_rows,
        )
    if insert_rows:
        cols = ["id"] + IMPORT_META_COLS
        db.executemany(
            f"INSERT INTO tickets ({', '.join(cols)}) VALUES ({', '.join('?' for _ in cols)})",
            insert_rows,
        )
    if comment_rows:
        db.executemany(
            "INSERT OR REPLACE INTO comments VALUES (?,?,?,?,?,?,?,?,?,?,?)", comment_rows
        )
    db.commit()

    return jsonify(ok=True, total_in_file=len(records), new_tickets=len(insert_rows),
                    updated_tickets=len(update_rows), comments_written=len(comment_rows))


# ---------------------------------------------------------------------------
# Frontend (single-page, role-aware)
# ---------------------------------------------------------------------------
@app.get("/")
def index():
    return INDEX_HTML


INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Ticket Tagging CMS</title>
<script src="https://accounts.google.com/gsi/client" async defer></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.4/chart.umd.min.js"></script>
<style>
  :root {
    --bg:#0b0d14; --card:#161a26; --card2:#1b2032; --border:#2a2f42;
    --text:#eef0f7; --muted:#9aa1b8;
    --accent:#7c8cff; --accent2:#b06dfc; --confirmed:#3ecf8e; --suggested:#f2b84b;
    --draft:#8a6df0; --danger:#f2604b;
    --grad: linear-gradient(90deg, var(--accent), var(--accent2));
  }
  * { box-sizing: border-box; }
  body { margin:0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         background: radial-gradient(1200px 500px at 15% -10%, rgba(124,140,255,.14), transparent 60%),
                     radial-gradient(1000px 500px at 100% 0%, rgba(176,109,252,.12), transparent 55%),
                     var(--bg);
         color: var(--text); min-height:100vh; }
  .topbar { display:flex; justify-content:space-between; align-items:center; padding:16px 26px;
            border-bottom:1px solid var(--border); position:relative;
            background: linear-gradient(180deg, rgba(124,140,255,.06), transparent); }
  .topbar::after { content:''; position:absolute; left:0; right:0; bottom:-1px; height:2px; background: var(--grad); opacity:.8; }
  .topbar h1 { font-size:17px; margin:0; letter-spacing:.2px; }
  .who { font-size:12.5px; color:var(--muted); display:flex; gap:12px; align-items:center; }
  #app { padding:26px; display:none; max-width:1400px; margin:0 auto; }
  #loginScreen { display:flex; flex-direction:column; align-items:center; justify-content:center; height:80vh; gap:16px; }
  #loginScreen p { color:var(--muted); font-size:13px; }
  .err { color:var(--danger); font-size:13px; }
  .card { background: linear-gradient(180deg, var(--card2), var(--card));
          border:1px solid var(--border); border-radius:14px; padding:18px; margin-bottom:20px;
          box-shadow: 0 10px 30px -12px rgba(0,0,0,.5); }
  .kpis { display:flex; gap:14px; flex-wrap:wrap; margin-bottom:20px; }
  .kpi { background: linear-gradient(160deg, var(--card2), var(--card)); border:1px solid var(--border);
         border-radius:12px; padding:14px 20px; min-width:130px; position:relative; overflow:hidden;
         box-shadow: 0 8px 22px -14px rgba(0,0,0,.6); }
  .kpi::before { content:''; position:absolute; left:0; top:0; bottom:0; width:3px; background: var(--grad); }
  .kpi .num { font-size:24px; font-weight:800; background: var(--grad); -webkit-background-clip:text;
              background-clip:text; color:transparent; }
  .kpi .label { color:var(--muted); font-size:11.5px; margin-top:3px; text-transform:uppercase; letter-spacing:.4px; }
  table { width:100%; border-collapse: collapse; font-size:12.5px; }
  th, td { text-align:left; padding:9px 10px; border-bottom:1px solid var(--border); vertical-align:top; }
  th { color: var(--muted); font-weight:700; position:sticky; top:0; background:var(--card2);
       text-transform:uppercase; font-size:10.5px; letter-spacing:.4px; }
  tbody tr:hover { background: rgba(124,140,255,.06); }
  .subj { max-width:280px; }
  input[type=text], select { background:#0e111b; color:var(--text); border:1px solid var(--border);
         border-radius:7px; padding:6px 9px; font-size:12px; width:150px; }
  input[type=text]:focus, select:focus { outline:none; border-color: var(--accent); }
  input[type=text]::placeholder { color: var(--suggested); opacity:.75; font-style:italic; }
  .badge { padding:3px 10px; border-radius:20px; font-size:10.5px; font-weight:700; white-space:nowrap; }
  .badge.Untagged { background: rgba(154,160,174,.15); color: var(--muted); }
  .badge.Draft { background: rgba(138,109,240,.18); color: var(--draft); }
  .badge.Submitted { background: rgba(242,184,75,.18); color: var(--suggested); }
  .badge.Approved, .badge.Tagged { background: rgba(62,207,142,.18); color: var(--confirmed); }
  .btn { background: var(--grad); color:#fff; border:none; border-radius:8px; padding:7px 14px;
         font-size:12px; cursor:pointer; font-weight:600; }
  .btn:hover { transform: translateY(-1px); box-shadow: 0 6px 16px -6px rgba(124,140,255,.6); }
  .btn.secondary { background:#232838; }
  .btn.approve { background: linear-gradient(90deg, var(--confirmed), #2fb87b); color:#04231a; }
  .btn:disabled { opacity:.4; cursor:not-allowed; }
  .rowActions { display:flex; gap:6px; flex-wrap:wrap; }
  .filters { display:flex; gap:10px; margin-bottom:14px; flex-wrap:wrap; }
  .hint { color:var(--muted); font-size:11.5px; margin-top:2px; }
  a.tlink { color: var(--accent); text-decoration:none; font-size:11.5px; }
  .tabs { display:flex; gap:6px; margin-bottom:20px; border-bottom:1px solid var(--border); }
  .tab { padding:10px 16px; font-size:13px; font-weight:600; color:var(--muted); cursor:pointer;
         border-bottom:2px solid transparent; margin-bottom:-1px; }
  .tab:hover { color: var(--text); }
  .tab.active { color: var(--text); border-bottom-color: var(--accent); }
  .charts-row { display:flex; gap:18px; flex-wrap:wrap; margin-bottom:20px; }
  .chart-card { background: linear-gradient(180deg, var(--card2), var(--card)); border:1px solid var(--border);
                border-radius:14px; padding:18px; flex:1 1 380px; box-shadow: 0 10px 30px -12px rgba(0,0,0,.5); }
  .chart-card h3 { margin:0 0 12px; font-size:13px; color:var(--muted); text-transform:uppercase; letter-spacing:.4px; }
  .chart-card canvas { max-height:280px; }
  .stitle { font-size:11.5px; font-weight:700; color:var(--muted); text-transform:uppercase;
            letter-spacing:.6px; margin:4px 0 12px; padding-top:16px; border-top:1px solid var(--border); }
  .stitle:first-child { padding-top:0; border-top:none; }
  .convLink { background:none; border:none; color:var(--accent); font-size:11.5px; cursor:pointer;
              padding:0; font-weight:600; }
  .convLink:hover { text-decoration:underline; }
  .modalOverlay { display:none; position:fixed; inset:0; background:rgba(6,7,12,.72);
                  z-index:50; align-items:center; justify-content:center; padding:24px; }
  .modalOverlay.open { display:flex; }
  .modalBox { background: linear-gradient(180deg, var(--card2), var(--card)); border:1px solid var(--border);
              border-radius:14px; width:100%; max-width:680px; max-height:82vh; display:flex;
              flex-direction:column; box-shadow: 0 20px 60px -16px rgba(0,0,0,.7); }
  .modalHead { padding:16px 20px; border-bottom:1px solid var(--border); display:flex;
               justify-content:space-between; align-items:flex-start; gap:12px; }
  .modalHead h2 { margin:0 0 4px; font-size:14.5px; }
  .modalHead .sub { color:var(--muted); font-size:11.5px; }
  .modalClose { background:#232838; border:none; color:var(--text); width:28px; height:28px;
                border-radius:8px; cursor:pointer; font-size:14px; flex-shrink:0; }
  .modalBody { padding:16px 20px; overflow:auto; }
  .comment { border:1px solid var(--border); border-radius:10px; padding:10px 12px; margin-bottom:10px;
             background: rgba(255,255,255,.02); }
  .comment .who { display:flex; justify-content:space-between; gap:10px; font-size:11.5px;
                  color:var(--muted); margin-bottom:6px; }
  .comment .who .name { color:var(--text); font-weight:700; }
  .comment .body { font-size:12.5px; white-space:pre-wrap; line-height:1.5; }
  .modalEmpty { color:var(--muted); font-size:12.5px; text-align:center; padding:30px 0; }
</style>
</head>
<body>

<div class="topbar">
  <h1>Ticket Tagging CMS</h1>
  <div class="who" id="who"></div>
</div>

<div id="loginScreen">
  <div id="g_id_signin"></div>
  <p>Sign in with your Meritto Google account. Access is limited to the tagging team.</p>
  <div class="err" id="loginErr"></div>
</div>

<div id="app"></div>

<div class="modalOverlay" id="convOverlay" onclick="if(event.target===this) closeConversation()">
  <div class="modalBox">
    <div class="modalHead">
      <div>
        <h2 id="convTitle">Conversation</h2>
        <div class="sub" id="convSub"></div>
      </div>
      <button class="modalClose" onclick="closeConversation()">&#10005;</button>
    </div>
    <div class="modalBody" id="convBody"></div>
  </div>
</div>

<script>
let ME = null;
let TICKETS = [];
let STATS = null;

function esc(s){ return (s===null||s===undefined) ? '' : String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

function initGoogle(clientId){
  google.accounts.id.initialize({ client_id: clientId, callback: onCredential });
  google.accounts.id.renderButton(document.getElementById('g_id_signin'),
    { theme: 'filled_black', size: 'large', text: 'signin_with' });
}

async function onCredential(resp){
  const r = await fetch('/auth/google', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ credential: resp.credential })
  });
  const data = await r.json();
  if(!data.ok){
    document.getElementById('loginErr').textContent = data.error || 'Sign-in failed.';
    return;
  }
  boot();
}

async function boot(){
  const meResp = await fetch('/api/me');
  const me = await meResp.json();
  if (!meResp.ok || !me.user) {
    if (me.client_id) initGoogle(me.client_id);
    return;
  }
  ME = me.user;
  window.TAXONOMY = me.taxonomy;
  document.getElementById('loginScreen').style.display = 'none';
  document.getElementById('app').style.display = 'block';
  document.getElementById('who').innerHTML =
    `${esc(ME.name)} &middot; ${ME.role === 'admin' ? 'Admin' : 'SPOC'} &middot; ${esc(ME.email)}
     <button class="btn secondary" onclick="logout()">Sign out</button>`;

  const tr = await fetch('/api/tickets');
  const td = await tr.json();
  if (!tr.ok || td.error) {
    sessionExpired();
    return;
  }
  TICKETS = td.tickets || [];

  if (ME.role === 'admin') {
    const sr = await fetch('/api/admin/stats');
    const sd = await sr.json();
    if (!sr.ok || sd.error) {
      sessionExpired();
      return;
    }
    STATS = sd;
    renderAdmin();
  } else {
    renderSpoc();
  }
}

// A dead/expired session must never let a downstream render function throw
// on missing data — that reads as "the dashboard is blank" even though the
// topbar rendered fine. Instead we tear the app view down and force a clean
// re-login.
function sessionExpired(){
  document.getElementById('app').style.display = 'none';
  document.getElementById('app').innerHTML = '';
  document.getElementById('who').innerHTML = '';
  document.getElementById('loginScreen').style.display = 'flex';
  document.getElementById('loginErr').textContent = 'Your session expired — please sign in again.';
}

async function logout(){
  await fetch('/auth/logout', { method:'POST' });
  location.reload();
}

function fieldInput(id, field, current, suggested){
  const val = current || '';
  const ph = suggested ? `suggested: ${suggested}` : '';
  return `<input type="text" list="dl_${field}" data-ticket="${id}" data-field="${field}" value="${esc(val)}" placeholder="${esc(ph)}">`;
}

function datalists(){
  return Object.entries(window.TAXONOMY || {}).map(([k, vals]) =>
    `<datalist id="dl_${k}">${vals.map(v => `<option value="${esc(v)}">`).join('')}</datalist>`
  ).join('');
}

function suggestionHint(){
  return `<div class="hint">Greyed placeholder text is a best-guess suggestion carried over from earlier notes — treat it as a starting point to check, not a confirmed answer, especially outside taxonomies you've already fully verified.</div>`;
}

// ---------------- SPOC VIEW ----------------
// SPOCs only ever see Untagged / Draft / Tagged. The backend already
// collapses Submitted/Approved into "Tagged" (and strips approval-only
// fields) before this ever reaches the browser — the approval process on
// the admin side is never visible to them.
function renderSpoc(){
  const counts = { Untagged:0, Draft:0, Tagged:0 };
  TICKETS.forEach(t => counts[t.workflow_status] = (counts[t.workflow_status]||0)+1);

  document.getElementById('app').innerHTML = `
    ${datalists()}
    <div class="kpis">
      ${Object.entries(counts).map(([k,v]) => `<div class="kpi"><div class="num">${v}</div><div class="label">${k}</div></div>`).join('')}
    </div>
    <div class="card">
      <div class="filters">
        <select id="fStatus">
          <option value="">All statuses</option>
          <option>Untagged</option><option>Draft</option><option>Tagged</option>
        </select>
      </div>
      ${suggestionHint()}
      <div style="max-height:70vh; overflow:auto; margin-top:10px;">
      <table><thead><tr>
        <th>Subject</th><th>Module</th><th>Feature</th><th>Ticket Type</th><th>Case</th><th>Status</th><th>Progress</th><th>Save</th>
      </tr></thead><tbody id="tbody"></tbody></table>
      </div>
    </div>
  `;
  document.getElementById('fStatus').addEventListener('change', drawSpocRows);
  drawSpocRows();
}

function drawSpocRows(){
  const f = document.getElementById('fStatus').value;
  const rows = TICKETS.filter(t => !f || t.workflow_status === f);
  document.getElementById('tbody').innerHTML = rows.map(t => {
    const locked = t.workflow_status === 'Tagged';
    return `<tr data-id="${t.id}">
      <td class="subj">${esc(t.subject)}<br>
        <a class="tlink" href="${esc(t.web_url||'#')}" target="_blank">Open in Zoho &rarr;</a>
        &nbsp;|&nbsp;
        <button class="convLink" onclick="openConversation('${t.id}')">View conversation</button>
      </td>
      <td>${locked ? esc(t.tag_module||t.spoc_tag_module||'') : fieldInput(t.id,'module', t.spoc_tag_module, t.sugg_module)}</td>
      <td>${locked ? esc(t.tag_feature||t.spoc_tag_feature||'') : fieldInput(t.id,'feature', t.spoc_tag_feature, t.sugg_feature)}</td>
      <td>${locked ? esc(t.tag_ticket_type||t.spoc_tag_ticket_type||'') : fieldInput(t.id,'ticket_type', t.spoc_tag_ticket_type, t.sugg_ticket_type)}</td>
      <td>${locked ? esc(t.tag_case||t.spoc_tag_case||'') : fieldInput(t.id,'case', t.spoc_tag_case, t.sugg_case)}</td>
      <td>${locked ? esc(t.tag_status||t.spoc_tag_status||'') : fieldInput(t.id,'status', t.spoc_tag_status, t.sugg_status)}</td>
      <td><span class="badge ${t.workflow_status}">${t.workflow_status}</span></td>
      <td class="rowActions">
        ${locked ? '' : `<button class="btn secondary" onclick="spocSave('${t.id}','draft')">Draft</button>
        <button class="btn" onclick="spocSave('${t.id}','submit')">Submit</button>`}
      </td>
    </tr>`;
  }).join('');
}

async function spocSave(id, action){
  const row = document.querySelector(`tr[data-id="${id}"]`);
  const payload = { id, action };
  row.querySelectorAll('input[data-field]').forEach(inp => payload[inp.dataset.field] = inp.value);
  const r = await fetch('/api/spoc/save', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
  const data = await r.json();
  if(!data.ok){ alert(data.error || 'Save failed'); return; }
  const t = TICKETS.find(x => x.id === id);
  Object.assign(t, { spoc_tag_module: payload.module, spoc_tag_feature: payload.feature,
    spoc_tag_ticket_type: payload.ticket_type, spoc_tag_case: payload.case, spoc_tag_status: payload.status,
    workflow_status: data.workflow_status });
  renderSpoc();
}

// ---------------- ADMIN VIEW ----------------
let ADMIN_TAB = 'queue';
let chartSpocInstance = null, chartAccuracyInstance = null, chartStatusInstance = null,
    chartPriorityInstance = null, chartTypeInstance = null, chartTrendInstance = null;

function renderAdmin(){
  document.getElementById('app').innerHTML = `
    ${datalists()}
    <div class="tabs">
      <div class="tab ${ADMIN_TAB==='queue' ? 'active' : ''}" onclick="switchAdminTab('queue')">Approval Queue</div>
      <div class="tab ${ADMIN_TAB==='dashboard' ? 'active' : ''}" onclick="switchAdminTab('dashboard')">Dashboard</div>
      <div class="tab ${ADMIN_TAB==='database' ? 'active' : ''}" onclick="switchAdminTab('database')">Database</div>
    </div>
    <div id="adminTabContent"></div>
  `;
  if (ADMIN_TAB === 'dashboard') renderAdminDashboard();
  else if (ADMIN_TAB === 'database') renderAdminDatabase();
  else renderAdminQueue();
}

function switchAdminTab(tab){
  ADMIN_TAB = tab;
  renderAdmin();
}

function sectionTitle(text){
  return `<div class="stitle">${text}</div>`;
}

function renderAdminQueue(){
  const counts = { Untagged:0, Draft:0, Submitted:0, Approved:0 };
  TICKETS.forEach(t => counts[t.workflow_status] = (counts[t.workflow_status]||0)+1);
  const spocs = [...new Set(TICKETS.map(t=>t.cf_task_spoc_name))].sort();

  document.getElementById('adminTabContent').innerHTML = `
    <div class="kpis">
      ${Object.entries(counts).map(([k,v]) => `<div class="kpi"><div class="num">${v}</div><div class="label">${k}</div></div>`).join('')}
    </div>
    <div class="card">
      <div class="filters">
        <select id="fSpoc"><option value="">All SPOCs</option>${spocs.map(s=>`<option>${esc(s)}</option>`).join('')}</select>
        <select id="fStatus">
          <option value="Submitted">Submitted (needs approval)</option>
          <option value="">All statuses</option>
          <option>Untagged</option><option>Draft</option><option>Approved</option>
        </select>
      </div>
      ${suggestionHint()}
      <div style="max-height:70vh; overflow:auto; margin-top:10px;">
      <table><thead><tr>
        <th>SPOC</th><th>Subject</th><th>Module</th><th>Feature</th><th>Ticket Type</th><th>Case</th><th>Status</th><th>Workflow</th><th>Actions</th>
      </tr></thead><tbody id="tbody"></tbody></table>
      </div>
      <div class="hint">Approving copies these five fields into the final tag_* columns the tagging dashboard reads as "Confirmed".</div>
    </div>
  `;
  document.getElementById('fSpoc').addEventListener('change', drawAdminRows);
  document.getElementById('fStatus').addEventListener('change', drawAdminRows);
  drawAdminRows();
}

function drawAdminRows(){
  const fs = document.getElementById('fSpoc').value;
  const fst = document.getElementById('fStatus').value;
  const rows = TICKETS.filter(t => (!fs || t.cf_task_spoc_name===fs) && (!fst || t.workflow_status===fst));
  document.getElementById('tbody').innerHTML = rows.map(t => {
    const locked = t.workflow_status === 'Approved';
    return `<tr data-id="${t.id}">
      <td>${esc(t.cf_task_spoc_name)}</td>
      <td class="subj">${esc(t.subject)}<br>
        <a class="tlink" href="${esc(t.web_url||'#')}" target="_blank">Open in Zoho &rarr;</a>
        &nbsp;|&nbsp;
        <button class="convLink" onclick="openConversation('${t.id}')">View conversation</button>
      </td>
      <td>${fieldInput(t.id,'module', t.spoc_tag_module, t.sugg_module)}</td>
      <td>${fieldInput(t.id,'feature', t.spoc_tag_feature, t.sugg_feature)}</td>
      <td>${fieldInput(t.id,'ticket_type', t.spoc_tag_ticket_type, t.sugg_ticket_type)}</td>
      <td>${fieldInput(t.id,'case', t.spoc_tag_case, t.sugg_case)}</td>
      <td>${fieldInput(t.id,'status', t.spoc_tag_status, t.sugg_status)}</td>
      <td><span class="badge ${t.workflow_status}">${t.workflow_status}</span></td>
      <td class="rowActions">
        <button class="btn secondary" onclick="adminSave('${t.id}','save')">Save</button>
        <button class="btn approve" onclick="adminSave('${t.id}','approve')">Approve</button>
        ${locked ? `<button class="btn secondary" onclick="adminReopen('${t.id}')">Reopen</button>` : ''}
      </td>
    </tr>`;
  }).join('');
}

async function adminSave(id, action){
  const row = document.querySelector(`tr[data-id="${id}"]`);
  const payload = { id, action };
  row.querySelectorAll('input[data-field]').forEach(inp => payload[inp.dataset.field] = inp.value);
  const r = await fetch('/api/admin/save', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
  const data = await r.json();
  if(!data.ok){ alert(data.error || 'Save failed'); return; }
  const t = TICKETS.find(x => x.id === id);
  Object.assign(t, { spoc_tag_module: payload.module, spoc_tag_feature: payload.feature,
    spoc_tag_ticket_type: payload.ticket_type, spoc_tag_case: payload.case, spoc_tag_status: payload.status });
  if (data.approved) {
    Object.assign(t, { tag_module: payload.module, tag_feature: payload.feature,
      tag_ticket_type: payload.ticket_type, tag_case: payload.case, tag_status: payload.status,
      workflow_status: 'Approved', accuracy_flag: data.accuracy_flag, corrected_fields: data.corrected_fields });
    await refreshStats();
  }
  renderAdmin();
}

async function adminReopen(id){
  const r = await fetch('/api/admin/reopen', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ id }) });
  const data = await r.json();
  if(!data.ok){ alert(data.error || 'Failed'); return; }
  const t = TICKETS.find(x => x.id === id);
  t.workflow_status = 'Draft';
  await refreshStats();
  renderAdmin();
}

async function refreshStats(){
  const sr = await fetch('/api/admin/stats');
  const sd = await sr.json();
  STATS = (sr.ok && !sd.error) ? sd : null;
}

function renderAdminDashboard(){
  const total = TICKETS.length;
  const open = TICKETS.filter(t => t.status === 'Open').length;
  const inProgress = TICKETS.filter(t => t.status === 'In Progress').length;
  const clarityOrReopen = TICKETS.filter(t => t.status === 'Clarity Required' || t.status === 'Re-open').length;
  const completed = TICKETS.filter(t => t.status === 'Completed').length;
  const highRiskOpen = TICKETS.filter(t => t.status !== 'Completed' &&
    ['Blocker','Highest','High'].includes(t.priority)).length;

  const tagged = TICKETS.filter(t => t.workflow_status === 'Submitted' || t.workflow_status === 'Approved').length;
  const approved = TICKETS.filter(t => t.workflow_status === 'Approved').length;
  const pendingReview = TICKETS.filter(t => t.workflow_status === 'Submitted').length;
  const rateStr = v => (v === null || v === undefined) ? '&mdash;' : `${v}%`;
  // STATS may be null/error-shaped if a stats refresh ever failed after boot
  // — never dereference STATS.overall.* without checking both levels first.
  const overallRate = (STATS && STATS.overall) ? rateStr(STATS.overall.accuracy_pct) : '&mdash;';

  document.getElementById('adminTabContent').innerHTML = `
    ${sectionTitle('Ticket overview')}
    <div class="kpis">
      <div class="kpi"><div class="num">${total}</div><div class="label">Total tickets</div></div>
      <div class="kpi"><div class="num">${open}</div><div class="label">Open</div></div>
      <div class="kpi"><div class="num">${inProgress}</div><div class="label">In progress</div></div>
      <div class="kpi"><div class="num">${clarityOrReopen}</div><div class="label">Clarity / re-open</div></div>
      <div class="kpi"><div class="num">${completed}</div><div class="label">Completed</div></div>
      <div class="kpi"><div class="num">${highRiskOpen}</div><div class="label">High/Blocker &amp; open</div></div>
    </div>
    <div class="charts-row">
      <div class="chart-card"><h3>Status breakdown</h3><canvas id="chartStatus"></canvas></div>
      <div class="chart-card"><h3>Priority breakdown</h3><canvas id="chartPriority"></canvas></div>
    </div>
    <div class="charts-row">
      <div class="chart-card"><h3>Ticket type breakdown</h3><canvas id="chartType"></canvas></div>
      <div class="chart-card"><h3>Tickets created by month</h3><canvas id="chartTrend"></canvas></div>
    </div>

    ${sectionTitle('Tagging progress')}
    <div class="kpis">
      <div class="kpi"><div class="num">${tagged}</div><div class="label">Tagged by SPOCs</div></div>
      <div class="kpi"><div class="num">${approved}</div><div class="label">Approved</div></div>
      <div class="kpi"><div class="num">${pendingReview}</div><div class="label">Awaiting your review</div></div>
      <div class="kpi"><div class="num">${overallRate}</div><div class="label">Overall accuracy</div></div>
    </div>
    <div class="charts-row">
      <div class="chart-card"><h3>Tagged tickets by SPOC</h3><canvas id="chartSpoc"></canvas></div>
      <div class="chart-card"><h3>Accuracy breakdown</h3><canvas id="chartAccuracy"></canvas></div>
    </div>
    ${accuracyPanel()}
  `;
  drawAdminCharts();
}

function renderAdminDatabase(){
  document.getElementById('adminTabContent').innerHTML = `
    <div class="card">
      <h3 style="margin-top:0;">Import fresh ticket data</h3>
      <div class="hint" style="margin-bottom:14px;">
        Upload a Zoho ticket export (the same JSON array <code>build_db.py</code> reads) to refresh ticket
        status, priority, assignee, and comments, and to add tickets that don't exist yet. This never
        touches tagging, workflow status, or approval history for tickets already in progress &mdash;
        only ticket metadata and comments are written. Tickets missing from the file are left alone,
        never deleted. New tickets start <strong>Untagged</strong> with no suggested values.
      </div>
      <div class="hint" style="margin-bottom:14px;">
        Large exports can be slow to upload over the browser &mdash; gzip the file first
        (<code>gzip -k export.json</code>) and upload the resulting <code>.json.gz</code> directly,
        it's decompressed automatically.
      </div>
      <input type="file" id="importFile" accept=".json,.gz">
      <button class="btn" onclick="runImport()">Upload &amp; merge</button>
      <div class="hint" id="importStatus" style="margin-top:12px;"></div>
    </div>
  `;
}

async function runImport(){
  const input = document.getElementById('importFile');
  const status = document.getElementById('importStatus');
  if (!input.files.length) { status.textContent = 'Choose a file first.'; return; }
  const file = input.files[0];
  const button = document.querySelector('#adminTabContent .btn');
  button.disabled = true;
  status.textContent = `Uploading ${esc(file.name)} (${(file.size/1e6).toFixed(1)} MB)...`;

  const form = new FormData();
  form.append('file', file);
  try {
    const r = await fetch('/api/admin/import', { method: 'POST', body: form });
    const data = await r.json();
    if (!r.ok || !data.ok) {
      if (r.status === 401) { sessionExpired(); return; }
      status.textContent = data.error || 'Import failed.';
      return;
    }
    status.textContent = `Done — ${data.total_in_file} tickets in file: ${data.new_tickets} new, ${data.updated_tickets} updated, ${data.comments_written} comments written.`;

    const tr = await fetch('/api/tickets');
    const td = await tr.json();
    if (!tr.ok || td.error) { sessionExpired(); return; }
    TICKETS = td.tickets || [];
    await refreshStats();
  } catch (e) {
    status.textContent = 'Import failed: ' + e.message;
  } finally {
    button.disabled = false;
  }
}

function accuracyPanel(){
  if (!STATS || !STATS.overall || !STATS.per_spoc) {
    return `<div class="card"><div class="hint">Accuracy data isn't available right now.</div></div>`;
  }
  const o = STATS.overall;
  const rateStr = v => (v === null || v === undefined) ? '&mdash;' : `${v}%`;
  const spocRows = Object.entries(STATS.per_spoc).sort((a,b)=>a[0].localeCompare(b[0])).map(([name, s]) => `
    <tr>
      <td>${esc(name)}</td><td>${s.total}</td><td>${s.approved}</td>
      <td>${s.correct}</td><td>${s.corrected}</td><td>${s.admin_tagged}</td>
      <td><strong>${rateStr(s.accuracy_pct)}</strong></td>
    </tr>`).join('');
  return `
    <div class="card">
      <div class="hint" style="margin-bottom:8px;"><strong>Approval &amp; accuracy tracker</strong> &mdash;
        ${o.approved}/${o.total} tickets approved. Accuracy = Correct &divide; (Correct + Corrected), among tickets a SPOC actually submitted.
      </div>
      <table>
        <thead><tr><th>SPOC</th><th>Total</th><th>Approved</th><th>Correct on submit</th><th>Corrected by admin</th><th>Admin-tagged</th><th>Accuracy</th></tr></thead>
        <tbody>
          ${spocRows}
          <tr style="font-weight:600;">
            <td>Overall</td><td>${o.total}</td><td>${o.approved}</td><td>${o.correct}</td>
            <td>${o.corrected}</td><td>${o.admin_tagged}</td><td>${rateStr(o.accuracy_pct)}</td>
          </tr>
        </tbody>
      </table>
    </div>
  `;
}

function drawAdminCharts(){
  if (typeof Chart === 'undefined') return;
  const chartTextColor = '#9aa1b8';
  const gridColor = 'rgba(154,161,184,.12)';
  const palette = ['#7c8cff', '#b06dfc', '#3ecf8e', '#f2b84b', '#f2604b', '#4bd0f2', '#f24b9e'];

  const statusCounts = {};
  TICKETS.forEach(t => { const k = t.status || 'Unknown'; statusCounts[k] = (statusCounts[k]||0)+1; });
  if (chartStatusInstance) chartStatusInstance.destroy();
  const ctxStatus = document.getElementById('chartStatus');
  if (ctxStatus) {
    chartStatusInstance = new Chart(ctxStatus, {
      type: 'doughnut',
      data: { labels: Object.keys(statusCounts), datasets: [{ data: Object.values(statusCounts), backgroundColor: palette, borderColor: '#161a26', borderWidth: 2 }] },
      options: { responsive: true, plugins: { legend: { position: 'bottom', labels: { color: chartTextColor, boxWidth: 12, padding: 10 } } } }
    });
  }

  const priorityOrder = ['Highest', 'Blocker', 'High', 'Moderate', 'Normal', '-None-'];
  const priorityCounts = {};
  TICKETS.forEach(t => { const k = t.priority || 'Unknown'; priorityCounts[k] = (priorityCounts[k]||0)+1; });
  const priorityLabels = priorityOrder.filter(p => priorityCounts[p]).concat(Object.keys(priorityCounts).filter(p => !priorityOrder.includes(p)));
  if (chartPriorityInstance) chartPriorityInstance.destroy();
  const ctxPriority = document.getElementById('chartPriority');
  if (ctxPriority) {
    chartPriorityInstance = new Chart(ctxPriority, {
      type: 'bar',
      data: { labels: priorityLabels, datasets: [{ label: 'Tickets', data: priorityLabels.map(p => priorityCounts[p]||0), backgroundColor: '#f2604b', borderRadius: 6 }] },
      options: { responsive: true, plugins: { legend: { display: false } },
        scales: { x: { ticks: { color: chartTextColor }, grid: { display: false } },
                  y: { ticks: { color: chartTextColor }, grid: { color: gridColor }, beginAtZero: true } } }
    });
  }

  const typeCounts = {};
  TICKETS.forEach(t => { const k = t.cf_type_of_task || 'Unspecified'; typeCounts[k] = (typeCounts[k]||0)+1; });
  const typeLabels = Object.keys(typeCounts).sort((a,b) => typeCounts[b]-typeCounts[a]);
  if (chartTypeInstance) chartTypeInstance.destroy();
  const ctxType = document.getElementById('chartType');
  if (ctxType) {
    chartTypeInstance = new Chart(ctxType, {
      type: 'bar',
      data: { labels: typeLabels, datasets: [{ label: 'Tickets', data: typeLabels.map(l => typeCounts[l]), backgroundColor: '#7c8cff', borderRadius: 6 }] },
      options: { indexAxis: 'y', responsive: true, plugins: { legend: { display: false } },
        scales: { x: { ticks: { color: chartTextColor }, grid: { color: gridColor }, beginAtZero: true },
                  y: { ticks: { color: chartTextColor }, grid: { display: false } } } }
    });
  }

  const monthCounts = {};
  TICKETS.forEach(t => { if (t.created_time) { const m = t.created_time.slice(0, 7); monthCounts[m] = (monthCounts[m]||0)+1; } });
  const months = Object.keys(monthCounts).sort();
  if (chartTrendInstance) chartTrendInstance.destroy();
  const ctxTrend = document.getElementById('chartTrend');
  if (ctxTrend) {
    chartTrendInstance = new Chart(ctxTrend, {
      type: 'line',
      data: { labels: months, datasets: [{ label: 'Created', data: months.map(m => monthCounts[m]), borderColor: '#b06dfc',
        backgroundColor: 'rgba(176,109,252,.18)', fill: true, tension: .3, pointRadius: 3 }] },
      options: { responsive: true, plugins: { legend: { display: false } },
        scales: { x: { ticks: { color: chartTextColor }, grid: { display: false } },
                  y: { ticks: { color: chartTextColor }, grid: { color: gridColor }, beginAtZero: true } } }
    });
  }

  const spocs = [...new Set(TICKETS.map(t => t.cf_task_spoc_name))].sort();
  const totals = spocs.map(s => TICKETS.filter(t => t.cf_task_spoc_name === s).length);
  const taggedCounts = spocs.map(s => TICKETS.filter(t => t.cf_task_spoc_name === s &&
    (t.workflow_status === 'Submitted' || t.workflow_status === 'Approved')).length);
  if (chartSpocInstance) chartSpocInstance.destroy();
  const ctxSpoc = document.getElementById('chartSpoc');
  if (ctxSpoc) {
    chartSpocInstance = new Chart(ctxSpoc, {
      type: 'bar',
      data: { labels: spocs, datasets: [
        { label: 'Total tickets', data: totals, backgroundColor: 'rgba(154,161,184,.25)', borderRadius: 6 },
        { label: 'Tagged', data: taggedCounts, backgroundColor: '#7c8cff', borderRadius: 6 },
      ] },
      options: { responsive: true, plugins: { legend: { labels: { color: chartTextColor } } },
        scales: { x: { ticks: { color: chartTextColor }, grid: { display: false } },
                  y: { ticks: { color: chartTextColor }, grid: { color: gridColor }, beginAtZero: true } } }
    });
  }

  if (chartAccuracyInstance) chartAccuracyInstance.destroy();
  const ctxAcc = document.getElementById('chartAccuracy');
  if (ctxAcc && STATS && STATS.overall) {
    const o = STATS.overall;
    chartAccuracyInstance = new Chart(ctxAcc, {
      type: 'doughnut',
      data: { labels: ['Correct on submit', 'Corrected by admin', 'Admin-tagged', 'System (legacy)'],
        datasets: [{ data: [o.correct, o.corrected, o.admin_tagged, o.system], backgroundColor: palette, borderColor: '#161a26', borderWidth: 2 }] },
      options: { responsive: true, plugins: { legend: { position: 'bottom', labels: { color: chartTextColor, boxWidth: 12, padding: 12 } } } }
    });
  }
}

// ---------------- CONVERSATION MODAL ----------------
// Only the ticket id (a safe primitive) is passed through the onclick
// attribute above. Anything richer — like the subject — is looked up here
// from the in-memory TICKETS array instead of being interpolated into a
// double-quoted HTML attribute: a `"` inside a JSON.stringify'd subject would
// silently break the attribute and kill the click handler with no console
// error, so that string never touches the attribute at all.
async function openConversation(ticketId){
  const t = TICKETS.find(x => x.id === ticketId);
  const overlay = document.getElementById('convOverlay');
  document.getElementById('convTitle').textContent = (t && t.subject) || 'Conversation';
  document.getElementById('convSub').textContent = 'Loading...';
  document.getElementById('convBody').innerHTML = '';
  overlay.classList.add('open');

  try {
    const r = await fetch(`/api/comments/${encodeURIComponent(ticketId)}`);
    const data = await r.json();
    if (!r.ok || data.error) {
      document.getElementById('convSub').textContent = '';
      document.getElementById('convBody').innerHTML = `<div class="modalEmpty">${esc(data.error || 'Could not load this conversation.')}</div>`;
      return;
    }
    const comments = data.comments || [];
    document.getElementById('convSub').textContent = `${comments.length} message${comments.length===1?'':'s'}`;
    if (!comments.length) {
      document.getElementById('convBody').innerHTML = '<div class="modalEmpty">No comments on this ticket yet.</div>';
      return;
    }
    document.getElementById('convBody').innerHTML = comments.map(c => `
      <div class="comment">
        <div class="who">
          <span><span class="name">${esc(c.commenter_name || 'Unknown')}</span> &middot; ${esc(c.commenter_type || c.commenter_role || '')}</span>
          <span>${esc(c.commented_time || '')}</span>
        </div>
        <div class="body">${esc(c.content_text || '')}</div>
      </div>
    `).join('');
  } catch (e) {
    document.getElementById('convSub').textContent = '';
    document.getElementById('convBody').innerHTML = '<div class="modalEmpty">Could not load this conversation.</div>';
  }
}

function closeConversation(){
  document.getElementById('convOverlay').classList.remove('open');
}

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeConversation();
});

boot();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5051, debug=False)
