"""
tools/generate_api_docs.py — GDMR Connect
===========================================
Rebuilds the API documentation from the source code, so it can never drift:

    python tools/generate_api_docs.py

Writes, into docs/:
    GDMR_Connect_API_Documentation.pdf   human-readable reference
    openapi.json                         OpenAPI 3.0 file (import into Swagger UI / Postman / Insomnia)

Every route, method, login/permission check, rate limit, request field, response
code and message is read from the code by tools/api_extract.py (AST based).
The overview sections and module descriptions below are hand-written.
Needs: reportlab (already a dependency).
"""
import json
import os
import re
import sys
from collections import OrderedDict, defaultdict
from datetime import date
from xml.sax.saxutils import escape as X

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from api_extract import extract, ROOT   # noqa: E402

OUT_DIR = os.path.join(ROOT, "docs")
PDF_PATH = os.path.join(OUT_DIR, "GDMR_Connect_API_Documentation.pdf")
OPENAPI_PATH = os.path.join(OUT_DIR, "openapi.json")
PROD = "https://api.gdmrconnect.com"
TODAY = date.today().strftime("%d %B %Y").lstrip("0")

# ── Modules: file -> (title, description), in reading order ───────────────────
MODULES = OrderedDict([
 ("app_new", ("System, Health & Files", "Service health checks and the legacy file-serving route.")),
 ("auth", ("Authentication & Passwords", "Login, password change, emailed password-reset links, log out of all devices and admin force-logout. Everything else in the API needs the token these routes issue.")),
 ("mfa", ("Two-Step Verification (MFA)", "Optional authenticator-app verification: second login step, set-up, backup codes, turn-off, and admin reset.")),
 ("access", ("Special Access (Delegated Permissions)", "Admins/owners grant an employee temporary access to chosen admin modules. These routes create, list and revoke those grants.")),
 ("employees", ("Employees, Managers, Departments", "The employee register: create/edit/remove staff, managers and admins, departments and heads, resignation/offboarding, profile lock, extended leave settings and personal-file documents.")),
 ("attendance", ("Attendance — Check-in / Check-out", "Photo check-in and check-out and the caller's own attendance history, plus the admin attendance listing.")),
 ("attendance_reports", ("Attendance Reports & Exports", "Monthly/yearly attendance reports as PDF, CSV and Excel, including the multi-sheet Master Tracker.")),
 ("biometric", ("Biometric Devices", "Admin management of fingerprint/face devices and the device-facing ADMS endpoints (/iclock/*) that devices call directly.")),
 ("calendar", ("Holidays & Attendance Calendar", "Company holidays, attendance corrections and the calendar views built from them.")),
 ("leaves", ("Leave Management", "Apply for leave (with attachment), approve/reject, revoke, comp-off credits and balances.")),
 ("payroll", ("Payroll", "Salary structures, monthly payslips, loans and advances, and payroll export.")),
 ("pms", ("Performance Management (PMS)", "Review templates, self-assessments, manager reviews, performance notes and warnings, recurring assignments.")),
 ("pms_compliance", ("PMS Compliance & Attendance Blocking", "Tracks whether managers finished their reviews and (when switched on) blocks their team's check-in until they do.")),
 ("ats", ("Recruitment (ATS)", "Candidates through the hiring pipeline: create/edit, resume upload with auto-fill, status changes, documents, recordings, dashboard activity and the AI overview.")),
 ("career", ("Jobs & Employee Referrals", "Job postings (with salary and referral visibility switches) and employee referrals.")),
 ("assessment", ("Assessments", "Create online tests, invite candidates/employees, and the public token-link pages candidates use to take them.")),
 ("lms", ("Learning (LMS)", "Courses, modules and lessons, assignments, progress and completion for admins, managers and employees.")),
 ("work_plans", ("Daily Work Plans", "Employees' daily plans and the team/analytics views built from them.")),
 ("clients", ("Clients & Client Drive", "Client records, shared folders/files and manual updates.")),
 ("chat", ("Team Chat", "Direct messages, channels, unread counts, presence (heartbeat) and typing indicators. The web app polls these every few seconds.")),
 ("assistant", ("AI Assistant", "Text/voice assistant that answers questions using the caller's own permissions.")),
 ("announcements", ("Announcements, My Profile & Uploads", "Company announcements (with attachments) and the caller's own profile and profile picture.")),
 ("notifications", ("Notifications", "Badge counts and today's birthdays.")),
 ("stats", ("Dashboard Statistics", "Admin dashboard numbers and the end-of-day automatic-absent job.")),
 ("assets", ("Assets", "Company assets, assignment and employee asset requests.")),
 ("achievements", ("Achievements", "Employee of the month/quarter/year, awards and hike records.")),
 ("goals", ("My Goals (Sticky Notes)", "Personal daily/weekly goals with start date, deadline, sharing and login reminders.")),
 ("certificates", ("Experience Certificates (QR Verification)", "Generate, reissue and revoke experience certificates and the public QR verification endpoint.")),
])

ACCESS_LABELS = {
    "_is_admin": "Admin / Owner",
    "_ats_allowed": "Recruitment access (admin/owner, HR department, or Special Access “ats”)",
    "_can_view": "Admin / Owner or Special Access “certificates” (view)",
    "_can_write": "Admin / Owner or Special Access “certificates” (edit)",
}
# Plain-English meaning of the permission helpers used inside routes (module-specific first, then generic).
HELPER_LABELS = {
    ("biometric", "_authorized"): "Admin / Owner or Special Access “attendance”",
    ("pms_compliance", "_authorized"): "Admin / Owner or Special Access “pms”",
    "_payroll_allowed": "Admin / Owner, Special Access “payroll”, or anyone in the Accounts department",
    "_require_lms": "Admin / Owner or Special Access “lms”",
    "_reports_allowed": "Admin / Owner or Special Access “attendance” or “summary”",
    "_holiday_allowed": "Admin / Owner or Special Access “attendance”",
    "_can_grant_comp_off": "Admin / Owner, Special Access “leaves” (edit), or the employee's own manager",
    "_can_read_client": "Clients of the caller's departments (admin/owner and any “clients” grant see all)",
    "_can_write_client": "Admin / Owner, Special Access “clients” (edit), or a manager of one of the client's departments",
    "_ip_allowed": "If an IP allow-list is set on the device, only those addresses",
}
IGNORED_HELPERS = {"all_owner_emails", "_register_admin_authed", "_register_admin_core"}
SCOPE_NAMES = {"_mgr_depts", "_dept_scope", "_ats_scope_query", "_scope_query", "_team_ids_incl_dept_head"}

PUBLIC_NOTES = [
    (lambda e: e["path"].startswith("/iclock/"), "Public address, used by biometric devices — the device's registered serial number (?SN=) is the credential"),
    (lambda e: e["path"] == "/api/attendance/auto-absent", "Scheduled job — requires the secret header X-Cron-Secret"),
    (lambda e: e["path"].startswith("/api/assessment/"), "Public — protected by the candidate's private assessment link token"),
    (lambda e: e["path"].startswith("/api/ats/documents/"), "Public — protected by the candidate's private document-upload link token"),
    (lambda e: e["path"].startswith("/api/public/certificates/"), "Public — protected by the unguessable token inside the certificate's QR code"),
    (lambda e: e["path"] == "/api/register-admin", "Open only while no admin/owner exists (first-time setup); otherwise needs an admin/owner login"),
    (lambda e: e["path"] in ("/api/login", "/api/login/mfa", "/api/forgot-password", "/api/reset-password"), "Public (no login) — part of signing in or recovering a password"),
    (lambda e: True, "Public (no login required)"),
]
STATUS_TEXT = {200: "OK", 201: "Created", 204: "No content", 400: "Bad request", 401: "Not logged in / invalid or expired token", 403: "Not allowed", 404: "Not found",
               405: "Method not allowed", 409: "Conflict", 413: "Request too large", 423: "Account temporarily locked", 429: "Too many requests",
               500: "Server error", 502: "Upstream service failed", 503: "Not configured", 504: "Upstream timeout"}


# ── Small helpers ─────────────────────────────────────────────────────────────
def clean(t):
    return (t or "").replace("{…}", "…").strip()


def humanize(fn, module=""):
    t = fn
    for pre in (module + "_", "admin_", "mgr_", "manager_"):
        if pre != "_" and t.startswith(pre) and len(t) > len(pre) + 2:
            t = t[len(pre):]
            break
    t = t.replace("_", " ").strip()
    return t[:1].upper() + t[1:]


def summary_of(e):
    d = (e["doc"] or "").strip()
    if d:
        para = re.split(r"\n\s*\n", d)[0].replace("\n", " ")
        para = re.sub(r"\s+", " ", para)
        masked = para.replace("e.g.", "e§g§").replace("i.e.", "i§e§").replace("etc.", "etc§")
        m = re.match(r"^(.{20,220}?[.!?])(\s|$)", masked)
        out = (m.group(1) if m else masked[:200]).strip()
        return out.replace("§", ".")
    return humanize(e["function"], e["module"])


def access_of(e):
    if not e["login_required"]:
        for test, text in PUBLIC_NOTES:
            if test(e):
                return text
    parts = []
    tags = e["access"]
    admin = any(t.split("(")[0] == "_is_admin" for t in tags)
    grants = []
    for t in tags:
        base = t.split("(")[0]
        if base == "_has_module_grant":
            inner = t[t.index("(") + 1:-1] if "(" in t else ""
            mods = [x.strip() for x in inner.split(",") if x.strip() and x.strip() != "write"]
            edit = "write" in inner
            for m in mods or ["…"]:
                grants.append(f"“{m}”" + (" (edit)" if edit else ""))
    if admin:
        parts.append("Admin / Owner")
    if grants:
        parts.append("Special Access: " + ", ".join(sorted(set(grants))))
    for t in tags:
        base = t.split("(")[0]
        if base in ACCESS_LABELS and base != "_is_admin":
            lbl = ACCESS_LABELS[base] + (" — edit" if "write" in t and base == "_ats_allowed" else "")
            if lbl not in parts:
                parts.append(lbl)
    if e["roles"]:
        parts.append("role check: " + " / ".join(e["roles"]))
    if any(t.split("(")[0] in SCOPE_NAMES for t in tags):
        parts.append("managers see only their own departments")
    other = []
    for t in tags:
        base = t.split("(")[0]
        if base in ACCESS_LABELS or base in ("_has_module_grant", "_is_admin") or base in SCOPE_NAMES or base in IGNORED_HELPERS:
            continue
        label = HELPER_LABELS.get((e["module"], base)) or HELPER_LABELS.get(base)
        if label:
            label += " — edit" if "write" in t else ""
            if label not in parts:
                parts.append(label)
        else:
            other.append(base)
    if other:
        parts.append("also checks: " + ", ".join(sorted({o.lstrip("_").replace("_", " ") for o in other})))
    if not parts:
        return "Any logged-in user" + (" (own records only)" if "/my/" in e["path"] else "")
    return "Logged in; " + "; ".join(parts)


def responses_of(e):
    """{status: [text,...]} with the noise removed."""
    out = defaultdict(list)
    for status, msg, keys, kind in e["returns"]:
        msg, keys = clean(msg), [k for k in (keys or "").split(",") if k]
        if kind == "file":
            t = "file download"
        elif kind == "array":
            t = "JSON list"
        elif msg and keys == ["message"]:
            t = msg
        elif keys == ["message"]:
            t = "error message (varies with the cause)"
        elif keys and [k for k in keys if k != "message"]:
            t = "JSON with " + ", ".join(k for k in keys if k != "message") + (f" — “{msg}”" if msg else "")
        elif kind == "text":
            t = "plain text"
        elif keys:
            t = "JSON"
        else:
            t = "JSON"
        if t and t not in out[status]:
            out[status].append(t)
    for s in list(out):                       # drop the vague "JSON" when something specific exists for that code
        if len(out[s]) > 1 and "JSON" in out[s]:
            out[s].remove("JSON")
    return dict(sorted(out.items()))


def endpoint_key(e):
    return (e["module"], e["path"], e["method"])


# ── Build model ───────────────────────────────────────────────────────────────
def load_model():
    eps = extract()
    order = list(MODULES)
    eps.sort(key=lambda e: (order.index(e["module"]) if e["module"] in order else 99, e["path"], ["GET", "POST", "PUT", "PATCH", "DELETE"].index(e["method"]) if e["method"] in ["GET", "POST", "PUT", "PATCH", "DELETE"] else 9))
    return eps


def grantable_modules():
    s = open(os.path.join(ROOT, "helpers.py"), encoding="utf-8").read()
    m = re.search(r"GRANTABLE_MODULES\s*=\s*\{(.*?)\}", s, re.S)
    return re.findall(r'"([a-z\-]+)":\s*"([^"]+)"', m.group(1)) if m else []


# ═════════════════════════════ OpenAPI ═══════════════════════════════════════
def build_openapi(eps):
    tags = [{"name": MODULES[m][0], "description": MODULES[m][1]} for m in MODULES if any(e["module"] == m for e in eps)]
    paths, used_ids = OrderedDict(), set()
    for e in eps:
        p = paths.setdefault(e["openapi_path"], OrderedDict())
        op_id = e["function"] if e["function"] not in used_ids else f"{e['function']}_{e['method'].lower()}"
        used_ids.add(op_id)
        params = [{"name": n, "in": "path", "required": True, "schema": {"type": "string"}} for n in e["path_params"]]
        params += [{"name": q, "in": "query", "required": False, "schema": {"type": "string"}} for q in e["query"]]
        params += [{"name": h, "in": "header", "required": False, "schema": {"type": "string"}} for h in e["headers"]]
        op = OrderedDict(tags=[MODULES[e["module"]][0]], summary=summary_of(e)[:120], description=(e["doc"].strip() or summary_of(e)) + f"\n\n**Access:** {access_of(e)}",
                         operationId=op_id)
        if params:
            op["parameters"] = params
        if e["method"] in ("POST", "PUT", "PATCH", "DELETE") and (e["body"] or e["form"] or e["files"]):
            content = {}
            if e["body"]:
                content["application/json"] = {"schema": {"type": "object", "properties": {k: {} for k in e["body"]}}}
            if e["form"] or e["files"]:
                props = {k: {"type": "string"} for k in e["form"]}
                props.update({k: {"type": "string", "format": "binary"} for k in e["files"]})
                content["multipart/form-data"] = {"schema": {"type": "object", "properties": props}}
            op["requestBody"] = {"required": False, "content": content}
        resp = OrderedDict()
        for status, texts in responses_of(e).items():
            resp[str(status)] = {"description": "; ".join(texts)[:400] or STATUS_TEXT.get(status, "Response")}
        if not any(k.startswith("2") for k in resp):
            resp["200"] = {"description": "Success"}
        op["responses"] = resp
        op["security"] = [{"bearerAuth": []}] if e["login_required"] else []
        if e["rate_limits"]:
            op["x-rate-limit"] = e["rate_limits"]
        op["x-access"] = access_of(e)
        p[e["method"].lower()] = op
    return OrderedDict([
        ("openapi", "3.0.3"),
        ("info", OrderedDict(title="GDMR Connect API", version=TODAY, description="REST API of the GDMR Connect HRIS. Generated from the source code (tools/generate_api_docs.py). All request/response bodies are JSON unless a route is marked multipart/form-data. Log in with POST /api/login and send the returned token as 'Authorization: Bearer <token>'.")),
        ("servers", [{"url": PROD, "description": "Production (the same API is also reachable at https://www.gdmrconnect.com/api/… through the website proxy)"}]),
        ("tags", tags),
        ("paths", paths),
        ("components", {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT", "description": "Token from POST /api/login (or POST /api/login/mfa). Valid 4 hours; revoked by password change, 'log out of all devices' or admin force-logout."}}}),
    ])


# ═════════════════════════════ PDF ═══════════════════════════════════════════
def build_pdf(eps):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import (BaseDocTemplate, PageTemplate, Frame, Paragraph, Spacer, Table, TableStyle, PageBreak,
                                    KeepTogether, CondPageBreak, Preformatted)
    from reportlab.platypus.tableofcontents import TableOfContents

    INK, MUTED, RULE, SOFT = colors.HexColor("#111827"), colors.HexColor("#6b7280"), colors.HexColor("#e5e7eb"), colors.HexColor("#f3f4f6")
    RED = colors.HexColor("#ed2224")
    MCOL = {"GET": ("#065f46", "#d1fae5"), "POST": ("#1e40af", "#dbeafe"), "PUT": ("#92400e", "#fef3c7"), "PATCH": ("#92400e", "#fef3c7"), "DELETE": ("#991b1b", "#fee2e2")}

    st = {
        "h0": ParagraphStyle("h0", fontName="Helvetica-Bold", fontSize=17, leading=21, textColor=INK, spaceBefore=4, spaceAfter=8),
        "h1": ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=12.5, leading=16, textColor=INK, spaceBefore=12, spaceAfter=5),
        "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=10.5, leading=13.5, textColor=INK, spaceBefore=8, spaceAfter=3),
        "b": ParagraphStyle("b", fontName="Helvetica", fontSize=9, leading=12.8, textColor=INK, spaceAfter=4),
        "s": ParagraphStyle("s", fontName="Helvetica", fontSize=8, leading=10.6, textColor=MUTED, spaceAfter=3),
        "c": ParagraphStyle("c", fontName="Helvetica", fontSize=8, leading=10.4, textColor=INK),
        "cb": ParagraphStyle("cb", fontName="Helvetica-Bold", fontSize=8, leading=10.4, textColor=INK),
        "mono": ParagraphStyle("mono", fontName="Courier-Bold", fontSize=8.6, leading=11, textColor=INK),
        "monos": ParagraphStyle("monos", fontName="Courier", fontSize=7.8, leading=10, textColor=INK),
        "sum": ParagraphStyle("sum", fontName="Helvetica", fontSize=8.6, leading=11.4, textColor=colors.HexColor("#374151"), spaceAfter=3),
        "toc1": ParagraphStyle("toc1", fontName="Helvetica", fontSize=9.5, leading=14, leftIndent=0),
        "bul": ParagraphStyle("bul", fontName="Helvetica", fontSize=9, leading=12.6, textColor=INK, leftIndent=12, spaceAfter=2),
    }

    class Heading(Paragraph):
        def __init__(self, text, style, level=0, outline=True, in_toc=None):
            super().__init__(text, style)
            if in_toc is None and level == 0:
                in_toc = 0                                  # top-level parts always appear in the contents page
            self._toc = (level, re.sub(r"<[^>]+>", "", text), in_toc) if outline else None

    class Doc(BaseDocTemplate):
        def afterFlowable(self, f):
            t = getattr(f, "_toc", None)
            if t:
                level, text, toc_level = t
                key = f"h{self.seq.nextf('toc')}"
                self.canv.bookmarkPage(key)
                self.canv.addOutlineEntry(text, key, level=level, closed=level > 0)
                if toc_level is not None:
                    self.notify("TOCEntry", (toc_level, text, self.page))

    def furniture(c, d):
        c.saveState()
        c.setFillColor(MUTED); c.setFont("Helvetica", 7.5)
        c.drawString(40, 22, f"GDMR Connect — API Documentation · generated {TODAY} from source")
        c.drawRightString(A4[0] - 40, 22, f"Page {d.page}")
        c.restoreState()

    def chip(method):
        fg, bg = MCOL.get(method, ("#111", "#eee"))
        t = Table([[Paragraph(f"<font color='{fg}'><b>{method}</b></font>", ParagraphStyle("m", fontName="Helvetica-Bold", fontSize=8, alignment=1))]], colWidths=[44], rowHeights=[15])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(bg)), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0)]))
        return t

    def P(t, s="b"):
        return Paragraph(t, st[s])

    def code(text):
        pre = Preformatted(text, ParagraphStyle("pre", fontName="Courier", fontSize=7.6, leading=9.6, textColor=INK))
        t = Table([[pre]], colWidths=[515])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), SOFT), ("BOX", (0, 0), (-1, -1), 0.4, RULE), ("LEFTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
        return [t, Spacer(1, 6)]

    def table(header, rows, widths, mono_cols=()):
        data = [[Paragraph(X(h), st["cb"]) for h in header]]
        for r in rows:
            data.append([Paragraph(X(str(c)), st["monos"] if i in mono_cols else st["c"]) for i, c in enumerate(r)])
        t = Table(data, colWidths=widths, repeatRows=1)
        t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, RULE), ("BACKGROUND", (0, 0), (-1, 0), SOFT), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                               ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4), ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
        return [t, Spacer(1, 6)]

    story = []
    # ── Cover ────────────────────────────────────────────────────────────────
    story += [Spacer(1, 70),
              Paragraph("GDMR Connect", ParagraphStyle("t", fontName="Helvetica-Bold", fontSize=30, leading=34, textColor=INK)),
              Paragraph("API Documentation", ParagraphStyle("t2", fontName="Helvetica-Bold", fontSize=18, leading=24, textColor=RED)),
              Spacer(1, 10),
              P(f"Complete reference for all <b>{len(eps)}</b> endpoints of the GDMR Connect HRIS backend (Flask · MongoDB). Generated {TODAY} directly from the source code, so every route, permission check, rate limit, request field and response message shown here is what the code actually does.", "b"),
              Spacer(1, 8),
              *table(["", ""], [["Production base URL", PROD], ["Same API via the website", "https://www.gdmrconnect.com/api/…"], ["Authentication", "Bearer token (JWT) from POST /api/login"],
                                ["Machine-readable version", "docs/openapi.json (OpenAPI 3.0)"], ["Regenerate", "python tools/generate_api_docs.py"]], [150, 365]),
              PageBreak()]

    toc = TableOfContents()
    toc.levelStyles = [st["toc1"], ParagraphStyle("toc2", parent=st["toc1"], fontSize=8.8, leading=12, leftIndent=16)]
    story += [Heading("Contents", st["h0"], outline=False), toc, PageBreak()]

    # ── Part 1: overview ─────────────────────────────────────────────────────
    story += [Heading("1. Overview", st["h0"], 0)]
    story += [Heading("1.1 Conventions", st["h1"], 1),
              P("<b>Format.</b> Requests and responses are JSON (<font face='Courier'>Content-Type: application/json</font>). File uploads use <font face='Courier'>multipart/form-data</font>; the reference marks those routes with “form fields” and “files”. Field names are <font face='Courier'>snake_case</font>."),
              P("<b>IDs</b> are MongoDB ObjectIds: 24-character hex strings (for example <font face='Courier'>66f1c2a9e4b0a1b2c3d4e5f6</font>). Path parts like <font face='Courier'>&lt;job_id&gt;</font> are such IDs unless the name says <i>token</i>."),
              P("<b>Dates</b> are <font face='Courier'>YYYY-MM-DD</font>; timestamps are ISO-8601 in UTC (the app displays them in IST). Booleans are real JSON booleans; money is a plain number in INR."),
              P("<b>Lists</b> are returned as JSON arrays (no pagination); a few endpoints accept <font face='Courier'>limit</font>/<font face='Courier'>days</font> style query parameters, shown per endpoint."),
              P("<b>Compression and caching.</b> JSON responses larger than 500 bytes are gzip-compressed when the client sends <font face='Courier'>Accept-Encoding: gzip</font>. Every <font face='Courier'>/api/…</font> response carries <font face='Courier'>Cache-Control: no-store</font>.")]

    story += [Heading("1.2 Authentication", st["h1"], 1),
              P("1. <b>Log in:</b> <font face='Courier'>POST /api/login</font> with email and password. On success you get a token. Send it on every later request as <font face='Courier'>Authorization: Bearer &lt;token&gt;</font>."),
              P("2. <b>Token lifetime:</b> 4 hours, then the API answers <font face='Courier'>401 Session expired</font> and the user must log in again. There is no refresh token."),
              P("3. <b>Revocation:</b> each token carries a version number. Changing or resetting the password, “log out of all devices” (<font face='Courier'>POST /api/my/logout-all</font>), turning two-step verification off, or an admin force-logout invalidates every older token immediately."),
              P("4. <b>Two-step verification (optional):</b> if the account has it on, <font face='Courier'>POST /api/login</font> returns <font face='Courier'>{\"mfa_required\": true, \"mfa_token\": …}</font> instead of a session. Post that token and the 6-digit authenticator code (or a one-time backup code) to <font face='Courier'>POST /api/login/mfa</font> to receive the real session. The <i>mfa_token</i> lasts 5 minutes and cannot be used as a session."),
              P("5. <b>Lock-out:</b> 5 wrong passwords lock that email for 15 minutes (HTTP 423, identical for real and unknown emails). Wrong two-step codes are throttled the same way."),
              P("6. <b>Forgot password:</b> <font face='Courier'>POST /api/forgot-password</font> emails a single-use link (valid 30 minutes) to the web page <font face='Courier'>/reset-password/&lt;token&gt;</font>, which calls <font face='Courier'>POST /api/reset-password</font>. The password never changes until the link is used."),
              ] + code('POST ' + PROD + '/api/login\nContent-Type: application/json\n\n{"email": "name@company.com", "password": "••••••••"}\n\n200 OK\n{"token": "eyJhbGciOi…", "role": "employee", "password_changed": true,\n "user": {"_id": "66f1…", "name": "Asha K", "email": "name@company.com",\n          "role": "employee", "department": "Brand", "photo_url": null}}\n\nGET ' + PROD + '/api/my/profile\nAuthorization: Bearer eyJhbGciOi…') + [
              P("Public routes (no login) are listed in Appendix A. Everything else answers <font face='Courier'>401</font> without a valid token.")]

    story += [Heading("1.3 Roles and permissions", st["h1"], 1),
              P("Every user has one role. Rules are enforced inside each route, so the reference shows the exact check for each endpoint under <b>Access</b>.")]
    story += table(["Role", "What it can do"], [
        ["owner", "Everything an admin can do, plus owner-only notifications and approvals (for example a manager's own leave goes to the owner)."],
        ["admin", "All admin modules: employees, attendance, leave, payroll, PMS, recruitment, LMS, assessments, clients, assets, announcements and Special Access."],
        ["manager", "Own data plus the department(s) they manage or head: team attendance and leave approvals, PMS reviews, team LMS, work by team, recruitment for their departments."],
        ["employee", "Own data only: attendance, leave, payslips, PMS self-assessment, work plans, courses, referrals, chat, goals."],
    ], [60, 455])
    story += [P("<b>Special Access (delegated permissions).</b> An admin or owner can give any employee temporary access to specific admin modules (<font face='Courier'>POST /api/admin/grant-access</font>). A grant has an access level — <i>view_only</i> or <i>view_edit</i> — a scope and an expiry. Routes marked “Special Access: “module”” accept anyone holding an active grant for that module; “(edit)” needs a <i>view_edit</i> grant. Grantable modules:")]
    story += table(["Module key", "Feature"], [[k, v] for k, v in grantable_modules()], [120, 395], mono_cols=(0,))

    story += [Heading("1.4 Errors", st["h1"], 1),
              P("Errors are JSON with a human-readable message, for example <font face='Courier'>{\"message\": \"Invalid ID\"}</font>, and a meaningful HTTP status. Unexpected failures return a generic <font face='Courier'>500 {\"message\": \"Something went wrong. Please try again.\"}</font> with no technical detail.")]
    story += table(["Status", "Meaning"], [[str(k), v] for k, v in STATUS_TEXT.items()], [60, 455])

    story += [Heading("1.5 Limits and protections", st["h1"], 1)]
    story += table(["Item", "Behaviour"], [
        ["Rate limits", "Applied per route (Appendix B). Exceeding one returns 429. Counters are shared across workers only when REDIS_URL is configured."],
        ["Request size", "JSON bodies over 2 MB are refused (413); no request may exceed 50 MB. Individual upload routes have tighter limits (typically 5–15 MB)."],
        ["Uploads", "Files are checked by their real contents: web pages, scripts and programs are refused and a file must match its extension (a .pdf must be a PDF). Stored on Cloudinary."],
        ["CORS", "Browsers may call the API only from https://www.gdmrconnect.com, https://gdmrconnect.com and local development. Extra origins via the CORS_ORIGINS setting."],
        ["Security headers", "Every response: X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy; HSTS over HTTPS; JSON responses also carry a restrictive Content-Security-Policy."],
        ["Links", "Any URL a user can save (resume, recording, lesson links) must start with http:// or https://."],
    ], [100, 415])

    story += [Heading("1.6 How the web app calls the API", st["h1"], 1),
              P("The React app sends requests to <font face='Courier'>/api/…</font> on its own domain; Vercel forwards them to <font face='Courier'>https://api.gdmrconnect.com/api/…</font>. Each call has a 20-second timeout and up to 3 attempts (1 s and 2 s back-off) on network failures, then one XHR fallback (30 s) for networks that break HTTP/2. 401/403/423/429 are never retried. Team chat polls: conversations every 8 s, messages every 4 s, typing every 3 s, presence every 15–25 s, unread count every 20 s; admin badge counts every 60 s."),
              P("Scheduled jobs (IST) run inside the server, not through the API, except the end-of-day absence job which can be triggered with <font face='Courier'>POST /api/attendance/auto-absent</font> and the secret header <font face='Courier'>X-Cron-Secret</font>.")]

    # ── Module index ─────────────────────────────────────────────────────────
    by_mod = OrderedDict((m, [e for e in eps if e["module"] == m]) for m in MODULES)
    story += [PageBreak(), Heading("2. Endpoint index", st["h0"], 0)]
    story += table(["Module", "Endpoints", "Public"], [[MODULES[m][0], len(v), sum(1 for e in v if not e["login_required"])] for m, v in by_mod.items() if v], [330, 90, 95])
    story += [P(f"Total: {len(eps)} endpoint/method combinations — {sum(1 for e in eps if e['login_required'])} require a login, {sum(1 for e in eps if not e['login_required'])} are public.", "s")]

    # ── Reference ────────────────────────────────────────────────────────────
    story += [PageBreak(), Heading("3. Reference", st["h0"], 0)]
    first = True
    for m, items in by_mod.items():
        if not items:
            continue
        title, desc = MODULES[m]
        story += [CondPageBreak(160), Heading(f"3.{list(MODULES).index(m) + 1} {X(title)}", st["h1"], 1, in_toc=1), P(X(desc))]
        rows = [[e["method"], e["path"].replace("<", "{").replace(">", "}"), summary_of(e)[:90]] for e in items]
        story += table(["Method", "Path", "Summary"], rows, [48, 260, 207], mono_cols=(0, 1))
        for e in items:
            path = e["path"].replace("<", "{").replace(">", "}")
            head = Table([[chip(e["method"]), Paragraph(X(path), st["mono"])]], colWidths=[50, 465])
            head.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
            rows = [("Access", access_of(e))]
            if e["rate_limits"]:
                rows.append(("Rate limit", " · ".join(e["rate_limits"])))
            if e["path_params"]:
                rows.append(("Path", ", ".join(f"{p} ({'secret link token' if 'token' in p else 'file path' if p in ('filename', 'path') else 'ID'})" for p in e["path_params"])))
            if e["query"]:
                rows.append(("Query", ", ".join(e["query"])))
            if e["headers"]:
                rows.append(("Headers", ", ".join(e["headers"])))
            if e["body"]:
                rows.append(("JSON body", ", ".join(e["body"])))
            if e["form"]:
                rows.append(("Form fields", ", ".join(e["form"])))
            if e["files"]:
                rows.append(("Files", ", ".join(e["files"]) + " (multipart/form-data)"))
            resp = responses_of(e)
            ok = [(s, t) for s, t in resp.items() if 200 <= s < 300]
            bad = [(s, t) for s, t in resp.items() if s >= 300]
            if ok:
                rows.append(("Success", "<br/>".join(f"<b>{s}</b> {X('; '.join(t))}" for s, t in ok)))
            if bad:
                rows.append(("Errors", "<br/>".join(f"<b>{s}</b> {X(' · '.join(t))}" for s, t in bad)))
            data = []
            for k, v in rows:
                cell = v if (k in ("Success", "Errors")) else X(v)
                data.append([Paragraph(f"<b>{k}</b>", st["c"]), Paragraph(cell, st["c"])])
            t = Table(data, colWidths=[62, 453])
            t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), 0.25, RULE), ("LEFTPADDING", (0, 0), (-1, -1), 3), ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
            story.append(KeepTogether([Spacer(1, 6), head, P(X(summary_of(e)), "sum"), t]))

    # ── Appendices ───────────────────────────────────────────────────────────
    story += [PageBreak(), Heading("Appendix A — Public endpoints (no login)", st["h0"], 0)]
    story += table(["Method", "Path", "How it is protected"], [[e["method"], e["path"].replace("<", "{").replace(">", "}"), access_of(e)] for e in eps if not e["login_required"]], [48, 190, 277], mono_cols=(0, 1))
    story += [Heading("Appendix B — Rate limits", st["h0"], 0)]
    limited = [e for e in eps if e["rate_limits"]]
    story += table(["Method", "Path", "Limit"], [[e["method"], e["path"].replace("<", "{").replace(">", "}"), " · ".join(e["rate_limits"])] for e in limited], [48, 300, 167], mono_cols=(0, 1))
    story += [P("All other routes have no per-route limit.", "s")]
    story += [Heading("Appendix C — Statistics", st["h0"], 0)]
    cnt = defaultdict(int)
    for e in eps:
        cnt[e["method"]] += 1
    story += table(["Method", "Count"], [[k, v] for k, v in sorted(cnt.items())], [100, 415])

    os.makedirs(OUT_DIR, exist_ok=True)
    doc = Doc(PDF_PATH, pagesize=A4, leftMargin=40, rightMargin=40, topMargin=40, bottomMargin=40,
              title="GDMR Connect — API Documentation", author="GDMR Foundation")
    doc.addPageTemplates([PageTemplate("p", [Frame(40, 40, A4[0] - 80, A4[1] - 80, id="f")], onPage=furniture)])
    doc.multiBuild(story)


def main():
    eps = load_model()
    os.makedirs(OUT_DIR, exist_ok=True)
    spec = build_openapi(eps)
    json.dump(spec, open(OPENAPI_PATH, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    build_pdf(eps)
    print(f"{len(eps)} endpoints documented")
    print("wrote", PDF_PATH)
    print("wrote", OPENAPI_PATH)


if __name__ == "__main__":
    main()
