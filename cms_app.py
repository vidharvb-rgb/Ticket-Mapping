"""
Ticket Tagging CMS — Google-login gated workflow on top of tickets.db.

Roles:
  - spoc  : sees only their own tickets, fills in the 5 tag fields, saves
            drafts, and submits for approval.
  - admin : sees everything submitted across all SPOCs, can edit any field,
            and approves to finalize into tag_* (the columns the main
            dashboard reads as "Confirmed").

Auth: Google Identity Services sign-in widget on the frontend hands us a
signed ID token; the backend verifies that token against Google's public
keys (google-auth), extracts the *verified* email, and checks it against
ALLOWLIST below. Nothing about role/identity is ever trusted from the
client — only the verified token content.

Run:
    pip install flask google-auth --break-system-packages
    python3 cms_app.py
Then open http://localhost:5051
"""
import os
import sqlite3
import secrets
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, request, jsonify, session, redirect, g

from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests

DB_PATH = Path(__file__).parent / "tickets.db"

# ---------------------------------------------------------------------------
# Configuration — the only two things you should ever need to edit.
# ---------------------------------------------------------------------------
GOOGLE_CLIENT_ID = "1055140297757-skpbblht6jhqk45je1k17ae068c83j9p.apps.googleusercontent.com"

# email -> {role, spoc_name}. spoc_name must exactly match cf_task_spoc_name
# values in tickets.db so a SPOC's login maps to the right ticket set.
ALLOWLIST = {
    "vidharv.b@meritto.com": {"role": "admin", "name": "Vidharv"},
    "perugu@meritto.com":    {"role": "spoc",  "name": "Perugu Govardhan"},
    "ajitesh.d@meritto.com": {"role": "spoc",  "name": "Ajitesh Das"},
    "mansi.g@meritto.com":   {"role": "spoc",  "name": "Mansi Gupta"},
}

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
        # WAL/DELETE journal modes can throw "disk I/O error" on some
        # restricted/networked filesystem mounts because they rely on
        # filesystem-level locking that isn't fully supported there.
        # MEMORY mode keeps the rollback journal off disk entirely.
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
    return {"email": email, "role": info["role"], "name": info["name"]}


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
    except Exception as e:  # noqa: BLE001
        return jsonify(ok=False, error=f"invalid token: {e}"), 401

    if not claims.get("email_verified"):
        return jsonify(ok=False, error="email not verified by Google"), 401

    email = claims["email"].lower()
    if email not in ALLOWLIST:
        return jsonify(ok=False, error=f"{email} is not on the access list"), 403

    session["email"] = email
    role = ALLOWLIST[email]["role"]
    return jsonify(ok=True, role=role, name=ALLOWLIST[email]["name"])


@app.post("/auth/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/api/me")
def api_me():
    user = current_user()
    return jsonify(user=user, client_id=GOOGLE_CLIENT_ID, taxonomy=TAXONOMY)


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------
TICKET_COLS = """
    id, subject, status, priority, created_time, web_url, description,
    cf_task_spoc_name, cf_type_of_task, cf_resolution_category,
    tag_module, tag_feature, tag_ticket_type, tag_case, tag_status,
    sugg_module, sugg_feature, sugg_ticket_type, sugg_case, sugg_status,
    spoc_tag_module, spoc_tag_feature, spoc_tag_ticket_type, spoc_tag_case, spoc_tag_status,
    submitted_module, submitted_feature, submitted_ticket_type, submitted_case, submitted_status,
    workflow_status, submitted_by, submitted_at, approved_by, approved_at,
    accuracy_flag, corrected_fields
"""


@app.get("/api/tickets")
def api_tickets():
    user = current_user()
    if not user:
        return jsonify(error="not signed in"), 401

    db = get_db()
    if user["role"] == "spoc":
        rows = db.execute(
            f"SELECT {TICKET_COLS} FROM tickets WHERE cf_task_spoc_name = ?",
            (user["name"],),
        ).fetchall()
    else:
        rows = db.execute(
            f"""SELECT {TICKET_COLS} FROM tickets
                WHERE cf_task_spoc_name IN ('Perugu Govardhan','Ajitesh Das','Mansi Gupta')"""
        ).fetchall()
    return jsonify(tickets=[dict(r) for r in rows])


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
    if user["role"] == "spoc" and ticket["cf_task_spoc_name"] != user["name"]:
        return jsonify(error="forbidden"), 403

    rows = db.execute(
        """SELECT commented_time, commenter_name, commenter_type, commenter_role, content_text
           FROM comments WHERE ticket_id = ? ORDER BY commented_time""",
        (ticket_id,),
    ).fetchall()
    return jsonify(comments=[dict(r) for r in rows])


def _validate_fields(payload):
    values = {}
    for f in TAG_FIELDS:
        v = (payload.get(f) or "").strip()
        values[f] = v or None
    return values


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
    if not ticket or ticket["cf_task_spoc_name"] != user["name"]:
        return jsonify(error="forbidden"), 403
    if ticket["workflow_status"] == "Approved":
        return jsonify(error="already approved, locked"), 409

    values = _validate_fields(payload)
    new_status = "Submitted" if action == "submit" else "Draft"

    # On an actual submit, freeze a snapshot of exactly what the SPOC entered.
    # This snapshot is never touched again, so later we can tell whether the
    # admin approved it unchanged ("Correct") or had to fix it ("Corrected").
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

    values = _validate_fields(payload)
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
        # Compare the frozen SPOC submission against what's about to become
        # final, so we can permanently record whether the SPOC nailed it or
        # the admin had to fix something.
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
    """Unlock an Approved ticket back to Draft so it can be edited again."""
    user, err = require_role("admin")
    if err:
        return err
    payload = request.get_json(force=True, silent=True) or {}
    ticket_id = payload.get("id")
    if not ticket_id:
        return jsonify(error="bad request"), 400
    db = get_db()
    db.execute(
        "UPDATE tickets SET workflow_status = 'Draft' WHERE id = ?", (ticket_id,)
    )
    db.commit()
    return jsonify(ok=True)


@app.get("/api/admin/stats")
def admin_stats():
    user, err = require_role("admin")
    if err:
        return err
    db = get_db()
    rows = db.execute(
        """SELECT cf_task_spoc_name, workflow_status, accuracy_flag
           FROM tickets
           WHERE cf_task_spoc_name IN ('Perugu Govardhan','Ajitesh Das','Mansi Gupta')"""
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
            flag = r["accuracy_flag"]
            key = {"Correct": "correct", "Corrected": "corrected",
                   "Admin-tagged": "admin_tagged", "System": "system"}.get(flag)
            if key:
                s[key] += 1
                overall[key] += 1

    def with_rate(s):
        graded = s["correct"] + s["corrected"]  # excludes admin_tagged/system — those weren't a SPOC call to grade
        s["accuracy_pct"] = round(100 * s["correct"] / graded, 1) if graded else None
        return s

    per_spoc = {k: with_rate(v) for k, v in per_spoc.items()}
    overall = with_rate(overall)
    return jsonify(overall=overall, per_spoc=per_spoc)


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
<style>
  :root { --bg:#0f1117; --card:#181b24; --border:#2a2e3a; --text:#e6e8ee; --muted:#9aa0ae;
          --accent:#6d8dfc; --confirmed:#3ecf8e; --suggested:#f2b84b; --draft:#8a6df0; --danger:#f2604b; }
  * { box-sizing: border-box; }
  body { margin:0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         background: var(--bg); color: var(--text); }
  .topbar { display:flex; justify-content:space-between; align-items:center; padding:14px 24px;
            border-bottom:1px solid var(--border); }
  .topbar h1 { font-size:16px; margin:0; }
  .who { font-size:12.5px; color:var(--muted); display:flex; gap:12px; align-items:center; }
  #app { padding:24px; display:none; }
  #loginScreen { display:flex; flex-direction:column; align-items:center; justify-content:center;
                 height:80vh; gap:16px; }
  #loginScreen p { color:var(--muted); font-size:13px; }
  .err { color:var(--danger); font-size:13px; }
  .card { background: var(--card); border:1px solid var(--border); border-radius:10px; padding:16px; margin-bottom:18px;}
  .kpis { display:flex; gap:14px; flex-wrap:wrap; margin-bottom:18px; }
  .kpi { background: var(--card); border:1px solid var(--border); border-radius:10px; padding:12px 18px; min-width:120px; }
  .kpi .num { font-size:22px; font-weight:700; }
  .kpi .label { color:var(--muted); font-size:11.5px; margin-top:2px; }
  table { width:100%; border-collapse: collapse; font-size:12.5px; }
  th, td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--border); vertical-align:top; }
  th { color: var(--muted); font-weight:600; position:sticky; top:0; background:var(--card); }
  .subj { max-width:280px; }
  input[type=text], select { background:#11131b; color:var(--text); border:1px solid var(--border);
         border-radius:6px; padding:5px 8px; font-size:12px; width:150px; }
  .badge { padding:2px 8px; border-radius:12px; font-size:10.5px; font-weight:600; white-space:nowrap; }
  .badge.Untagged { background: rgba(154,160,174,.15); color: var(--muted); }
  .badge.Draft { background: rgba(138,109,240,.15); color: var(--draft); }
  .badge.Submitted { background: rgba(242,184,75,.15); color: var(--suggested); }
  .badge.Approved { background: rgba(62,207,142,.15); color: var(--confirmed); }
  .btn { background: var(--accent); color:#fff; border:none; border-radius:6px; padding:6px 12px;
         font-size:12px; cursor:pointer; }
  .btn.secondary { background:#2a2e3a; }
  .btn.approve { background: var(--confirmed); color:#062; }
  .btn:disabled { opacity:.4; cursor:not-allowed; }
  .rowActions { display:flex; gap:6px; flex-wrap:wrap; }
  .filters { display:flex; gap:10px; margin-bottom:12px; flex-wrap:wrap; }
  .hint { color:var(--muted); font-size:11.5px; margin-top:2px; }
  a.tlink { color: var(--accent); text-decoration:none; font-size:11.5px; }
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

<script>
let ME = null;
let TICKETS = [];
let STATS = null;

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
  const r = await fetch('/api/me');
  const data = await r.json();
  if(!data.user){
    if (data.client_id) initGoogle(data.client_id);
    return;
  }
  ME = data.user;
  window.TAXONOMY = data.taxonomy;
  document.getElementById('loginScreen').style.display = 'none';
  document.getElementById('app').style.display = 'block';
  document.getElementById('who').innerHTML =
    `${esc(ME.name)} &middot; ${ME.role === 'admin' ? 'Admin' : 'SPOC'} &middot; ${esc(ME.email)}
     <button class="btn secondary" onclick="logout()">Sign out</button>`;

  const tr = await fetch('/api/tickets');
  const td = await tr.json();
  TICKETS = td.tickets || [];

  if (ME.role === 'admin') {
    const sr = await fetch('/api/admin/stats');
    STATS = await sr.json();
    renderAdmin();
  } else {
    renderSpoc();
  }
}

async function logout(){
  await fetch('/auth/logout', { method:'POST' });
  location.reload();
}

function esc(s){ return (s===null||s===undefined) ? '' : String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

function fieldInput(id, field, current, suggested){
  const listId = `dl_${field}`;
  const val = current || '';
  const ph = suggested ? `suggested: ${suggested}` : '';
  return `<input type="text" list="${listId}" data-ticket="${id}" data-field="${field}" value="${esc(val)}" placeholder="${esc(ph)}">`;
}

function datalists(){
  return Object.entries(window.TAXONOMY || {}).map(([k, vals]) =>
    `<datalist id="dl_${k}">${vals.map(v => `<option value="${esc(v)}">`).join('')}</datalist>`
  ).join('');
}

// ---------------- SPOC VIEW ----------------
function renderSpoc(){
  const counts = { Untagged:0, Draft:0, Submitted:0, Approved:0 };
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
          <option>Untagged</option><option>Draft</option><option>Submitted</option><option>Approved</option>
        </select>
      </div>
      <div style="max-height:70vh; overflow:auto;">
      <table><thead><tr>
        <th>Subject</th><th>Module</th><th>Feature</th><th>Ticket Type</th><th>Case</th><th>Status</th><th>Workflow</th><th>Save</th>
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
    const locked = t.workflow_status === 'Approved';
    return `<tr data-id="${t.id}">
      <td class="subj">${esc(t.subject)}<br><a class="tlink" href="${t.web_url||'#'}" target="_blank">Open in Zoho &rarr;</a></td>
      <td>${locked ? esc(t.tag_module||'') : fieldInput(t.id,'module', t.spoc_tag_module, t.sugg_module)}</td>
      <td>${locked ? esc(t.tag_feature||'') : fieldInput(t.id,'feature', t.spoc_tag_feature, t.sugg_feature)}</td>
      <td>${locked ? esc(t.tag_ticket_type||'') : fieldInput(t.id,'ticket_type', t.spoc_tag_ticket_type, t.sugg_ticket_type)}</td>
      <td>${locked ? esc(t.tag_case||'') : fieldInput(t.id,'case', t.spoc_tag_case, t.sugg_case)}</td>
      <td>${locked ? esc(t.tag_status||'') : fieldInput(t.id,'status', t.spoc_tag_status, t.sugg_status)}</td>
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
function renderAdmin(){
  const counts = { Untagged:0, Draft:0, Submitted:0, Approved:0 };
  TICKETS.forEach(t => counts[t.workflow_status] = (counts[t.workflow_status]||0)+1);
  const spocs = [...new Set(TICKETS.map(t=>t.cf_task_spoc_name))].sort();

  document.getElementById('app').innerHTML = `
    ${datalists()}
    <div class="kpis">
      ${Object.entries(counts).map(([k,v]) => `<div class="kpi"><div class="num">${v}</div><div class="label">${k}</div></div>`).join('')}
    </div>
    ${accuracyPanel()}
    <div class="card">
      <div class="filters">
        <select id="fSpoc"><option value="">All SPOCs</option>${spocs.map(s=>`<option>${esc(s)}</option>`).join('')}</select>
        <select id="fStatus">
          <option value="Submitted">Submitted (needs approval)</option>
          <option value="">All statuses</option>
          <option>Untagged</option><option>Draft</option><option>Approved</option>
        </select>
      </div>
      <div style="max-height:70vh; overflow:auto;">
      <table><thead><tr>
        <th>SPOC</th><th>Subject</th><th>Module</th><th>Feature</th><th>Ticket Type</th><th>Case</th><th>Status</th><th>Workflow</th><th>Actions</th>
      </tr></thead><tbody id="tbody"></tbody></table>
      </div>
      <div class="hint">Approving copies these five fields into the final tag_* columns the main dashboard reads as "Confirmed".</div>
    </div>
  `;
  document.getElementById('fSpoc').addEventListener('change', drawAdminRows);
  document.getElementById('fStatus').addEventListener('change', drawAdminRows);
  drawAdminRows();
}

function accuracyPanel(){
  if (!STATS) return '';
  const o = STATS.overall;
  const rateStr = v => (v === null || v === undefined) ? '&mdash;' : `${v}%`;
  const spocRows = Object.entries(STATS.per_spoc).sort((a,b)=>a[0].localeCompare(b[0])).map(([name, s]) => `
    <tr>
      <td>${esc(name)}</td>
      <td>${s.total}</td>
      <td>${s.approved}</td>
      <td>${s.correct}</td>
      <td>${s.corrected}</td>
      <td>${s.admin_tagged}</td>
      <td><strong>${rateStr(s.accuracy_pct)}</strong></td>
    </tr>`).join('');
  return `
    <div class="card">
      <div class="hint" style="margin-bottom:8px;"><strong>Approval &amp; accuracy tracker</strong> &mdash;
        ${o.approved}/${o.total} tickets approved. Accuracy = Correct &divide; (Correct + Corrected), among tickets a SPOC actually submitted.
      </div>
      <table>
        <thead><tr>
          <th>SPOC</th><th>Total</th><th>Approved</th><th>Correct on submit</th><th>Corrected by admin</th><th>Admin-tagged</th><th>Accuracy</th>
        </tr></thead>
        <tbody>
          ${spocRows}
          <tr style="font-weight:600;">
            <td>Overall</td>
            <td>${o.total}</td>
            <td>${o.approved}</td>
            <td>${o.correct}</td>
            <td>${o.corrected}</td>
            <td>${o.admin_tagged}</td>
            <td>${rateStr(o.accuracy_pct)}</td>
          </tr>
        </tbody>
      </table>
    </div>
  `;
}

function drawAdminRows(){
  const fs = document.getElementById('fSpoc').value;
  const fst = document.getElementById('fStatus').value;
  const rows = TICKETS.filter(t => (!fs || t.cf_task_spoc_name===fs) && (!fst || t.workflow_status===fst));
  document.getElementById('tbody').innerHTML = rows.map(t => {
    const locked = t.workflow_status === 'Approved';
    return `<tr data-id="${t.id}">
      <td>${esc(t.cf_task_spoc_name)}</td>
      <td class="subj">${esc(t.subject)}<br><a class="tlink" href="${t.web_url||'#'}" target="_blank">Open in Zoho &rarr;</a></td>
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
  STATS = await sr.json();
}

boot();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5051, debug=False)
