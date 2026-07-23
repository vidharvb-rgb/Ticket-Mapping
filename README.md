# Tickets Folder — Overview


**Tags:** #area/tickets #type/readme #mentions/lead-manager #mentions/reporting #mentions/root

**Related notes:** [[Lead_Manager_Product_Overview]] · [[Manage_Lead_Fields_Product_Overview]] · [[Reporting_Overview]] · [[All_Dashboards_Product_Overview]] · [[nopaperforms-company-profile]]

---

This folder is a self-contained ticket-analysis project built around a Zoho Desk/Sprints export. It takes a raw JSON dump of tasks (tickets) and comments, loads it into a local SQLite database, and serves it through a Flask analytics dashboard. It also contains a set of Excel exports/analyses covering one reporting period ("Q4 — Perugu Govardhan").

## Files in this folder

| File | Size | Purpose |
|---|---|---|
| `zoho_tasks_consolidated_2026-07-17.json` | ~38.2 MB | Raw source export from Zoho (tasks + nested comments). Input to `build_db.py`. Supersedes the earlier `zoho_tasks_consolidated_2026-06-05.json` snapshot (kept alongside for reference). |
| `build_db.py` | 5.3 KB | ETL script: parses the JSON and loads it into `tickets.db`. |
| `tickets.db` (+ `.db-shm`, `.db-wal`) | ~43.5 MB | SQLite database produced by `build_db.py`. Two tables: `tickets`, `comments`. |
| `dashboard.py` | 40 KB | Flask app that serves an interactive analytics dashboard directly from `tickets.db`. |
| `Tickets Q4 - Perugug.xlsx` | 98 KB | Original raw Q4 ticket export (single sheet, unfiltered/unnormalized). |
| `Tickets Q4 - Perugug (Normalized).xlsx` | 102 KB | Cleaned/normalized version of the same export — 1,131 rows, one consistent schema. |
| `Tickets Q4 - Perugug (Analysis).xlsx` | 69 KB | Multi-sheet analysis workbook built from the normalized data — summary metrics, breakdowns, and recommendations. |

Housekeeping files present but not part of the pipeline: `.DS_Store`, a LibreOffice lock file (`.~lock.Tickets Q4 - Perugug (Analysis).xlsx#`), and a stray temp file (`lu8216j3nd.tmp`).

## Data pipeline: JSON → SQLite

`build_db.py` reads `zoho_tasks_consolidated_2026-07-17.json` and rebuilds `tickets.db` from scratch on every run (deletes the old file first). For each ticket record it extracts core fields plus several Zoho custom fields (`cf_*`), and for each nested comment it strips HTML into plain text alongside the original HTML.

**`tickets` table** — one row per ticket (**6,263 rows**):
`id, subject, status, priority, due_date, created_time, modified_time, completed_time, department_id, department_name, cf_module, cf_task_spoc_id, cf_task_spoc_name, cf_type_of_task, cf_organization_name, cf_task_requested_for, cf_resolution_category, description, assignee_name, assignee_email, web_url, comment_count`

**`comments` table** — one row per comment (**29,129 rows**), linked via `ticket_id`:
`id, ticket_id, commented_time, modified_time, commenter_id, commenter_name, commenter_email, commenter_type, commenter_role, content_html, content_text`

Indexes exist on `status`, `priority`, `cf_type_of_task`, `department_name`, `cf_task_requested_for`, `created_time`, `cf_task_spoc_name` (tickets) and `ticket_id`, `commenter_email` (comments), so the dashboard's filters and grouped queries stay fast.

To rebuild the database after a fresh export: `python3 build_db.py` (requires the JSON file to be present in the same folder).

## Dashboard: `dashboard.py`

A single-file Flask app (no separate templates/static files — HTML/CSS/JS is inlined) that reads directly from `tickets.db`. Run it with:

```
python3 dashboard.py
```

then open `http://localhost:5050`.

It exposes a global multi-select filter bar (status, priority, task type, department, SPOC, requested-for, module, resolution category, plus a created-date range) that drives every chart and the ticket table via a shared `build_filter()` query builder. Key views:

- **KPI strip**: total tickets, completed count, open/active count, blocker count, average resolution time (hours).
- **Charts**: tickets created by month, status breakdown (doughnut), task type, priority, department, top 15 modules, average resolution time by task type.
- **Lists**: top 10 task SPOCs, top 10 organizations, ranked by ticket volume.
- **Ticket table**: paginated (20/page), full-text search across subject/organization/SPOC/description, with a link out to each ticket's Zoho web URL.

All `/api/*` endpoints (`/api/kpis`, `/api/by_status`, `/api/by_priority`, `/api/by_type`, `/api/by_department`, `/api/by_month`, `/api/by_module`, `/api/top_spocs`, `/api/top_orgs`, `/api/resolution_by_type`, `/api/filter_options`, `/api/tickets`) accept the same filter query params and return JSON computed live from `tickets.db`.

## Excel exports (Q4 — Perugu Govardhan analysis)

These three workbooks represent a separate, period-specific reporting pass (reporting period **Jan 9 – May 31, 2026**, 191 tickets), distinct from the full 5,340-row database above:

1. **`Tickets Q4 - Perugug.xlsx`** — the raw export as pulled from Zoho, one sheet, columns: `ID, Due Date, Task Hyperlink, Summary, Feature, Analysis, Status, Module, Reason, Type, Status, Task Owner, Category, Priority, Type of Task, Module, Task SPOC - For Analytics, Due Date Bucket, Task Ageing Bucket` (some columns like Status/Module are duplicated in the raw pull).
2. **`Tickets Q4 - Perugug (Normalized).xlsx`** — same column set, cleaned into 1,131 consistent rows (one row per ticket/sub-record) for analysis.
3. **`Tickets Q4 - Perugug (Analysis).xlsx`** — a multi-sheet summary workbook built on top of the normalized data:
   - **Executive Summary** — 191 total tickets, 157 completed (82%), 34 open/in-progress (18%), 2 open blockers, 2 overdue, 2 re-opened, 51% bug rate, 13 modules touched. Headline insight: Lead Manager accounts for 94 of 191 tickets (49%) and the most bugs (48).
   - **Status & Priority** — full status breakdown (Completed 157, Open 27, Clarity Required 4, Re-open 2, In Progress 1), priority breakdown (High 149, Blocker 28, Moderate 13, Normal 1), type distribution (Bug 98, Not a Bug 51, Product Enhancement 27), and a status × priority cross-tab.
   - **Module Analysis** — per-module totals, bug counts, open counts, blockers, bug rate, and open rate for all 13 modules (Lead Manager 94 tickets/48 bugs is the largest; Opportunity Manager and Echo/Zing have the highest bug rates at 62–66%).
   - **Aging Analysis** — open/closed breakdown by ticket age bucket (6-10, 11-15, 16-30, 46-60, 60+ days) and an aging × priority cross-tab for currently open tickets.
   - **Root Cause** — analysis-tag breakdown (One-time Bug Fixed 46, Knowledge Gap 46, Feature Request 27, Request Stuck 20, Not Closed Fully 8, Sync Issue 8, Unable to Replicate 8, Under Dev 7, Config Visibility 6, etc.) and a tagged-reason breakdown (Cache Issue is the top named root cause at 10).
   - **Open Tickets** — action list of all 34 open tickets, sorted by priority then aging, with ID, summary, module, feature, priority, status, aging bucket, due date, and type — includes direct links back to the two open Blocker tickets.
   - **Recommendations** — prioritized action list (🔴 Immediate / 🟠 High / 🟡 Medium / 🟢 Watch) covering: resolving the 2 open blockers, investigating an Echo "white screen" cache-invalidation cluster, triaging the oldest Lead Manager tickets, reducing Knowledge Gap volume via self-serve docs, auditing the high "Not a Bug" closure rate, fixing recurring dashboard sync issues, and monitoring re-opened tickets and Campaign Manager's growing backlog.
   - **Raw Data** — 194-row reference copy of the normalized source data underlying the analysis.

## How the pieces relate

`zoho_tasks_consolidated_2026-07-17.json` (raw Zoho export, full history) → `build_db.py` → `tickets.db` (full 6,263-ticket queryable database) → `dashboard.py` (live interactive dashboard over the full dataset).

The three `.xlsx` files are a separate, narrower artifact: a manually-scoped Q4 export/analysis for one SPOC (Perugu Govardhan) covering 191 tickets, used to produce a written executive summary and action recommendations rather than a live dashboard.
