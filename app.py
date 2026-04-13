from __future__ import annotations

import base64
import json
import os
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from flask import (
    Flask,
    Response,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

UNIVERSITY_NAME = "Kaveri University"
MOTTO = "Knowledge • Discipline • Integrity"

app = Flask(__name__)
app.secret_key = "dev-secret-key-change-me"


@dataclass
class User:
    id: int
    full_name: str
    login_id: str
    email: str
    phone: str
    role: str  # student | day_scholar | faculty | admin | parent
    password_hash: str
    parent_user_id: Optional[int] = None


@dataclass
class PermissionRequest:
    id: int
    student_id: int
    permission_type: str
    destination: str
    requested_from: datetime
    requested_to: datetime
    reason: str
    status: str = "pending"  # pending | approved | rejected
    decision_note: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class IssueReport:
    id: int
    student_id: int
    category: str
    severity: str
    location: str
    issue_text: str
    status: str = "open"  # open | in_progress | resolved
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class AuditLog:
    id: int
    actor_id: int
    action: str
    target_type: str
    target_id: int
    details: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class Notification:
    id: int
    recipient_id: int
    title: str
    message: str
    is_read: bool = False
    created_at: datetime = field(default_factory=datetime.utcnow)


USERS: Dict[int, User] = {}
USERS_BY_LOGIN: Dict[str, int] = {}
PERMISSIONS: List[PermissionRequest] = []
ISSUES: List[IssueReport] = []
AUDIT_LOGS: List[AuditLog] = []
NOTIFICATIONS: List[Notification] = []

_next_ids = {"user": 1, "permission": 1, "issue": 1, "audit": 1, "notification": 1}


def _next_id(kind: str) -> int:
    _next_ids[kind] += 1
    return _next_ids[kind] - 1


def _add_user(
    *,
    full_name: str,
    login_id: str,
    email: str,
    phone: str,
    role: str,
    password: str,
    parent_user_id: Optional[int] = None,
) -> User:
    uid = _next_id("user")
    user = User(
        id=uid,
        full_name=full_name,
        login_id=login_id,
        email=email,
        phone=phone,
        role=role,
        password_hash=generate_password_hash(password),
        parent_user_id=parent_user_id,
    )
    USERS[uid] = user
    USERS_BY_LOGIN[login_id] = uid
    return user


def _seed_demo_data() -> None:
    if USERS:
        return

    admin = _add_user(
        full_name="Admin Office",
        login_id="ADMIN1",
        email="admin@kaveri.edu",
        phone="0000000000",
        role="admin",
        password="admin12345",
    )
    _add_user(
        full_name="Faculty Warden",
        login_id="FAC1",
        email="warden@kaveri.edu",
        phone="0000000001",
        role="faculty",
        password="faculty12345",
    )
    parent = _add_user(
        full_name="Parent Account",
        login_id="PARENT1001",
        email="parent@kaveri.edu",
        phone="9390911031",
        role="parent",
        password="parent12345",
    )
    student = _add_user(
        full_name="Demo Student",
        login_id="STU1001",
        email="stu1001@kaveri.edu",
        phone="9999999999",
        role="student",
        password="student12345",
        parent_user_id=parent.id,
    )

    now = datetime.utcnow()
    PERMISSIONS.append(
        PermissionRequest(
            id=_next_id("permission"),
            student_id=student.id,
            permission_type="leave_pass",
            destination="Home",
            requested_from=now + timedelta(days=1),
            requested_to=now + timedelta(days=3),
            reason="Family function",
            status="pending",
        )
    )
    ISSUES.append(
        IssueReport(
            id=_next_id("issue"),
            student_id=student.id,
            category="hostel",
            severity="medium",
            location="Block A - Room 203",
            issue_text="Ceiling fan not working.",
            status="open",
        )
    )
    AUDIT_LOGS.append(
        AuditLog(
            id=_next_id("audit"),
            actor_id=admin.id,
            action="seed",
            target_type="system",
            target_id=0,
            details="Demo data initialized",
        )
    )


def current_user() -> Optional[User]:
    uid = session.get("user_id")
    if not uid:
        return None
    return USERS.get(int(uid))


def _normalize_phone_e164(phone: str, *, default_country_code: str = "+91") -> Optional[str]:
    raw = (phone or "").strip()
    if not raw:
        return None
    digits = "".join(ch for ch in raw if ch.isdigit())
    if raw.startswith("+") and digits:
        return f"+{digits}"
    # India-style 10-digit number
    if len(digits) == 10:
        return f"{default_country_code}{digits}"
    # Already includes country code digits (e.g., 91XXXXXXXXXX)
    if len(digits) >= 11:
        return f"+{digits}"
    return None


def _whatsapp_click_to_chat_link(phone_e164: str, text: str) -> str:
    number = phone_e164.replace("+", "")
    return f"https://wa.me/{number}?text={urllib.parse.quote(text)}"


def _send_whatsapp_message(phone_e164: str, text: str) -> bool:
    """
    Sends WhatsApp message via WhatsApp Cloud API if configured.
    Required env vars:
      - WHATSAPP_TOKEN
      - WHATSAPP_PHONE_NUMBER_ID
    Returns True when sent successfully; otherwise False.
    """
    token = os.getenv("WHATSAPP_TOKEN")
    phone_number_id = os.getenv("WHATSAPP_PHONE_NUMBER_ID")
    if not token or not phone_number_id:
        return False

    url = f"https://graph.facebook.com/v19.0/{phone_number_id}/messages"
    payload = {
        "messaging_product": "whatsapp",
        "to": phone_e164.replace("+", ""),
        "type": "text",
        "text": {"body": text},
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False


def _notify_parent(student: User, title: str, message: str) -> None:
    if not student.parent_user_id:
        return
    parent = USERS.get(student.parent_user_id)
    parent_phone = _normalize_phone_e164(parent.phone if parent else "")

    sent = False
    wa_link = None
    if parent_phone:
        sent = _send_whatsapp_message(parent_phone, message)
        wa_link = _whatsapp_click_to_chat_link(parent_phone, message)

    NOTIFICATIONS.append(
        Notification(
            id=_next_id("notification"),
            recipient_id=student.parent_user_id,
            title=title,
            message=message + (f" WhatsApp: {wa_link}" if (wa_link and not sent) else ""),
        )
    )


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not current_user():
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapper


@app.before_request
def _inject_globals():
    _seed_demo_data()
    g.current_user = current_user()
    g.university_name = UNIVERSITY_NAME
    g.motto = MOTTO


@app.context_processor
def _template_ctx():
    return {"university_name": UNIVERSITY_NAME, "motto": MOTTO}


@app.route("/branding_logo")
def branding_logo():
    # If you add `static/branding-logo.png`, it will be used automatically.
    logo_path = Path(app.root_path) / "static" / "branding-logo.png"
    if logo_path.exists():
        return send_file(logo_path)

    # Use the logo you uploaded via Cursor (if present).
    uploaded_logo_path = Path(
        r"C:\Users\kadap\.cursor\projects\c-Users-kadap-Desktop-collegeproject\assets"
        r"\c__Users_kadap_AppData_Roaming_Cursor_User_workspaceStorage_84046a03820687d85434f62036861536_images_kaverriiiiiiiiiiiiiiiiii-ddf12044-612c-4153-9ee2-39d291bfa2a7.png"
    )
    if uploaded_logo_path.exists():
        return send_file(uploaded_logo_path)

    # 1x1 transparent PNG fallback (keeps template working without extra assets)
    png_b64 = (
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8"
        "/w8AAuMB9o8l0yAAAAAASUVORK5CYII="
    )
    return Response(base64.b64decode(png_b64), mimetype="image/png")


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register_student():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        login_id = request.form.get("login_id", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        role = request.form.get("role", "").strip()
        parent_login_id = request.form.get("parent_login_id", "").strip()
        parent_phone = request.form.get("parent_phone", "").strip()
        password = request.form.get("password", "")

        if not all([full_name, login_id, email, phone, role, password]):
            flash("Please fill all required fields.", "danger")
            return render_template("register.html")
        if login_id in USERS_BY_LOGIN:
            flash("That Roll Number is already registered.", "danger")
            return render_template("register.html")
        if role not in {"student", "day_scholar"}:
            flash("Invalid user type selected.", "danger")
            return render_template("register.html")

        parent_user_id = None
        if parent_login_id:
            if not parent_phone:
                flash("Parent WhatsApp Number is required when Parent Login ID is provided.", "danger")
                return render_template("register.html")
            parent_id = USERS_BY_LOGIN.get(parent_login_id)
            if parent_id is None:
                parent = _add_user(
                    full_name="Parent Account",
                    login_id=parent_login_id,
                    email=f"{parent_login_id.lower()}@kaveri.edu",
                    phone=parent_phone,
                    role="parent",
                    password="parent12345",
                )
                parent_user_id = parent.id
                flash(
                    f"Parent account created with password: parent12345 (Login ID: {parent_login_id})",
                    "info",
                )
            else:
                parent_user_id = parent_id
                existing_parent = USERS.get(parent_user_id)
                if existing_parent and not (existing_parent.phone or "").strip():
                    existing_parent.phone = parent_phone

        user = _add_user(
            full_name=full_name,
            login_id=login_id,
            email=email,
            phone=phone,
            role=role,
            password=password,
            parent_user_id=parent_user_id,
        )
        session["user_id"] = user.id
        flash("Account created successfully.", "success")
        return redirect(url_for("dashboard"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        login_id = request.form.get("login_id", "").strip()
        password = request.form.get("password", "")
        uid = USERS_BY_LOGIN.get(login_id)
        user = USERS.get(uid) if uid else None
        if not user or not check_password_hash(user.password_hash, password):
            flash("Invalid Login ID or password.", "danger")
            return render_template("login.html")
        session["user_id"] = user.id
        flash("Signed in successfully.", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("Signed out.", "info")
    return redirect(url_for("home"))


@app.route("/faculty-admin")
@login_required
def faculty_admin():
    return redirect(url_for("dashboard"))


@app.route("/request-permission", methods=["GET", "POST"])
@login_required
def request_permission():
    user = current_user()
    if not user or user.role not in {"student", "day_scholar"}:
        flash("Only students/day scholars can submit permission requests.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        permission_type = request.form.get("permission_type", "").strip()
        destination = request.form.get("destination", "").strip()
        requested_from_raw = request.form.get("requested_from", "").strip()
        requested_to_raw = request.form.get("requested_to", "").strip()
        reason = request.form.get("reason", "").strip()

        try:
            requested_from = datetime.fromisoformat(requested_from_raw)
            requested_to = datetime.fromisoformat(requested_to_raw)
        except ValueError:
            flash("Please provide valid date/time values.", "danger")
            return render_template("request_permission.html")

        if requested_to <= requested_from:
            flash("End time must be after start time.", "danger")
            return render_template("request_permission.html")

        pr = PermissionRequest(
            id=_next_id("permission"),
            student_id=user.id,
            permission_type=permission_type,
            destination=destination,
            requested_from=requested_from,
            requested_to=requested_to,
            reason=reason,
            status="pending",
        )
        PERMISSIONS.append(pr)
        AUDIT_LOGS.append(
            AuditLog(
                id=_next_id("audit"),
                actor_id=user.id,
                action="create_permission_request",
                target_type="permission",
                target_id=pr.id,
                details=f"{permission_type} to {destination}",
            )
        )
        if user.parent_user_id:
            msg = (
                f"Kaveri University: New permission request submitted by {user.full_name} "
                f"({permission_type.replace('_', ' ')}) for {destination} "
                f"({requested_from.strftime('%d %b %Y %I:%M %p')} - {requested_to.strftime('%d %b %Y %I:%M %p')})."
            )
            if reason:
                msg += f" Reason: {reason}."
            _notify_parent(user, "New permission request", msg)
        flash("Permission request submitted for approval.", "success")
        return redirect(url_for("dashboard"))

    return render_template("request_permission.html")


@app.route("/report-issue", methods=["GET", "POST"])
@login_required
def report_issue():
    user = current_user()
    if not user or user.role not in {"student", "day_scholar"}:
        flash("Only students/day scholars can report issues.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        category = request.form.get("category", "").strip()
        severity = request.form.get("severity", "").strip()
        location = request.form.get("location", "").strip()
        issue_text = request.form.get("issue_text", "").strip()

        issue = IssueReport(
            id=_next_id("issue"),
            student_id=user.id,
            category=category,
            severity=severity,
            location=location,
            issue_text=issue_text,
            status="open",
        )
        ISSUES.append(issue)
        AUDIT_LOGS.append(
            AuditLog(
                id=_next_id("audit"),
                actor_id=user.id,
                action="create_issue",
                target_type="issue",
                target_id=issue.id,
                details=f"{category} @ {location}",
            )
        )
        if user.parent_user_id:
            msg = (
                f"Kaveri University: {user.full_name} reported a campus issue "
                f"({category}, severity: {severity}) at {location}."
            )
            if issue_text:
                msg += f" Details: {issue_text}"
            _notify_parent(user, "New issue reported", msg)
        flash("Issue submitted successfully.", "success")
        return redirect(url_for("dashboard"))

    return render_template("report_issue.html")


@app.route("/permissions/<int:request_id>/decision", methods=["POST"])
@login_required
def decide_permission(request_id: int):
    user = current_user()
    if not user or user.role not in {"faculty", "admin"}:
        flash("Unauthorized action.", "danger")
        return redirect(url_for("dashboard"))

    decision = request.form.get("decision", "").strip()
    decision_note = request.form.get("decision_note", "").strip() or None

    pr = next((p for p in PERMISSIONS if p.id == request_id), None)
    if not pr:
        flash("Permission request not found.", "danger")
        return redirect(url_for("dashboard"))
    if pr.status != "pending":
        flash("This request has already been decided.", "warning")
        return redirect(url_for("dashboard"))
    if decision not in {"approved", "rejected"}:
        flash("Invalid decision.", "danger")
        return redirect(url_for("dashboard"))

    pr.status = decision
    pr.decision_note = decision_note
    AUDIT_LOGS.append(
        AuditLog(
            id=_next_id("audit"),
            actor_id=user.id,
            action=f"permission_{decision}",
            target_type="permission",
            target_id=pr.id,
            details=decision_note,
        )
    )

    student = USERS.get(pr.student_id)
    if student and student.parent_user_id:
        msg = (
            f"Kaveri University: {student.full_name}'s {pr.permission_type.replace('_', ' ')} request "
            f"({pr.requested_from.strftime('%d %b %Y %I:%M %p')} - {pr.requested_to.strftime('%d %b %Y %I:%M %p')}) "
            f"to {pr.destination} was {decision.upper()}."
        )
        if pr.reason:
            msg += f" Reason: {pr.reason}."
        if decision_note:
            msg += f" Note: {decision_note}."
        _notify_parent(student, "Permission decision update", msg)

    flash(f"Request {decision}.", "success")
    return redirect(url_for("dashboard"))


@app.route("/issues/<int:issue_id>/status", methods=["POST"])
@login_required
def update_issue(issue_id: int):
    user = current_user()
    if not user or user.role not in {"faculty", "admin"}:
        flash("Unauthorized action.", "danger")
        return redirect(url_for("dashboard"))

    status = request.form.get("status", "").strip()
    if status not in {"open", "in_progress", "resolved"}:
        flash("Invalid status.", "danger")
        return redirect(url_for("dashboard"))

    issue = next((i for i in ISSUES if i.id == issue_id), None)
    if not issue:
        flash("Issue not found.", "danger")
        return redirect(url_for("dashboard"))

    issue.status = status
    AUDIT_LOGS.append(
        AuditLog(
            id=_next_id("audit"),
            actor_id=user.id,
            action="update_issue_status",
            target_type="issue",
            target_id=issue.id,
            details=status,
        )
    )
    flash("Issue status updated.", "success")
    return redirect(url_for("dashboard"))


@app.route("/notifications/<int:notification_id>/read")
@login_required
def read_notification(notification_id: int):
    user = current_user()
    n = next((x for x in NOTIFICATIONS if x.id == notification_id), None)
    if not user or not n or n.recipient_id != user.id:
        flash("Notification not found.", "danger")
        return redirect(url_for("dashboard"))
    n.is_read = True
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    if user.role in ("student", "day_scholar"):
        perm_status = request.args.get("perm_status", "all")
        perm_type = request.args.get("perm_type", "all")
        permission_search = request.args.get("permission_search", "").strip()
        issue_status = request.args.get("issue_status", "all")
        issue_severity = request.args.get("issue_severity", "all")
        issue_search = request.args.get("issue_search", "").strip()

        permissions = [p for p in PERMISSIONS if p.student_id == user.id]
        if perm_status != "all":
            permissions = [p for p in permissions if p.status == perm_status]
        if perm_type != "all":
            permissions = [p for p in permissions if p.permission_type == perm_type]
        if permission_search:
            s = permission_search.lower()
            permissions = [
                p
                for p in permissions
                if s in (p.destination or "").lower() or s in (p.reason or "").lower()
            ]
        permissions.sort(key=lambda p: p.created_at, reverse=True)

        issues = [i for i in ISSUES if i.student_id == user.id]
        if issue_status != "all":
            issues = [i for i in issues if i.status == issue_status]
        if issue_severity != "all":
            issues = [i for i in issues if i.severity == issue_severity]
        if issue_search:
            s = issue_search.lower()
            issues = [
                i
                for i in issues
                if s in (i.location or "").lower() or s in (i.issue_text or "").lower()
            ]
        issues.sort(key=lambda i: i.created_at, reverse=True)

        return render_template(
            "dashboard_student.html",
            permissions=permissions,
            issues=issues,
            filters={
                "perm_status": perm_status,
                "perm_type": perm_type,
                "permission_search": permission_search,
                "issue_status": issue_status,
                "issue_severity": issue_severity,
                "issue_search": issue_search,
            },
        )

    if user.role in ("faculty", "admin"):
        perm_status = request.args.get("perm_status", "all")
        perm_type = request.args.get("perm_type", "all")
        perm_student_id = request.args.get("perm_student_id", "").strip()
        permission_search = request.args.get("permission_search", "").strip()
        issue_status = request.args.get("issue_status", "all")
        issue_severity = request.args.get("issue_severity", "all")
        issue_student_id = request.args.get("issue_student_id", "").strip()
        issue_search = request.args.get("issue_search", "").strip()

        perms: List[PermissionRequest] = list(PERMISSIONS)
        if perm_status != "all":
            perms = [p for p in perms if p.status == perm_status]
        if perm_type != "all":
            perms = [p for p in perms if p.permission_type == perm_type]
        if perm_student_id.isdigit():
            sid = int(perm_student_id)
            perms = [p for p in perms if p.student_id == sid]
        if permission_search:
            s = permission_search.lower()
            perms = [
                p
                for p in perms
                if s in (p.destination or "").lower()
                or s in (p.reason or "").lower()
                or s in (USERS.get(p.student_id).full_name.lower() if USERS.get(p.student_id) else "")
            ]
        perms.sort(key=lambda p: p.created_at, reverse=True)
        permissions: List[Tuple[PermissionRequest, str]] = [
            (p, USERS.get(p.student_id).full_name if USERS.get(p.student_id) else "Unknown")
            for p in perms
        ]

        issues_raw: List[IssueReport] = list(ISSUES)
        if issue_status != "all":
            issues_raw = [i for i in issues_raw if i.status == issue_status]
        if issue_severity != "all":
            issues_raw = [i for i in issues_raw if i.severity == issue_severity]
        if issue_student_id.isdigit():
            sid = int(issue_student_id)
            issues_raw = [i for i in issues_raw if i.student_id == sid]
        if issue_search:
            s = issue_search.lower()
            issues_raw = [
                i
                for i in issues_raw
                if s in (i.location or "").lower()
                or s in (i.issue_text or "").lower()
                or s in (USERS.get(i.student_id).full_name.lower() if USERS.get(i.student_id) else "")
            ]
        issues_raw.sort(key=lambda i: i.created_at, reverse=True)
        issues: List[Tuple[IssueReport, str]] = [
            (i, USERS.get(i.student_id).full_name if USERS.get(i.student_id) else "Unknown")
            for i in issues_raw
        ]

        logs = sorted(AUDIT_LOGS, key=lambda x: x.timestamp, reverse=True)[:30]

        return render_template(
            "dashboard_admin.html",
            permissions=permissions,
            issues=issues,
            logs=logs,
            filters={
                "perm_status": perm_status,
                "perm_type": perm_type,
                "perm_student_id": perm_student_id,
                "permission_search": permission_search,
                "issue_status": issue_status,
                "issue_severity": issue_severity,
                "issue_student_id": issue_student_id,
                "issue_search": issue_search,
            },
        )

    if user.role == "parent":
        linked_students = [u for u in USERS.values() if u.parent_user_id == user.id]
        student_ids = {s.id for s in linked_students}
        selected_student_id = request.args.get("student_id", "all")
        perm_status = request.args.get("perm_status", "all")
        permission_search = request.args.get("permission_search", "").strip()

        permissions = [p for p in PERMISSIONS if p.student_id in student_ids]
        if selected_student_id.isdigit() and int(selected_student_id) in student_ids:
            sid = int(selected_student_id)
            permissions = [p for p in permissions if p.student_id == sid]
        if perm_status != "all":
            permissions = [p for p in permissions if p.status == perm_status]
        if permission_search:
            s = permission_search.lower()
            permissions = [
                p
                for p in permissions
                if s in (p.destination or "").lower() or s in (p.reason or "").lower()
            ]
        permissions.sort(key=lambda p: p.created_at, reverse=True)

        notifications = [n for n in NOTIFICATIONS if n.recipient_id == user.id]
        notifications.sort(key=lambda n: n.created_at, reverse=True)

        return render_template(
            "dashboard_parent.html",
            linked_students=linked_students,
            permissions=permissions,
            notifications=notifications,
            filters={
                "student_id": selected_student_id,
                "perm_status": perm_status,
                "permission_search": permission_search,
            },
        )

    flash("Invalid role configuration. Contact administrator.", "danger")
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(debug=True)