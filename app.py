import os
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
import base64
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, Optional

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


APP_DIR = Path(__file__).resolve().parent
DB_PATH = APP_DIR / "app.db"
ASSETS_DIR = APP_DIR / "assets"


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

    app.config.update(
        UNIVERSITY_NAME=os.environ.get("UNIVERSITY_NAME", "Kaveri University"),
        MOTTO=os.environ.get("UNIVERSITY_MOTTO", "Shaping the new"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )

    def db() -> sqlite3.Connection:
        if "db" not in g:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON;")
            g.db = conn
        return g.db

    @app.teardown_appcontext
    def close_db(_: Optional[BaseException]) -> None:
        conn = g.pop("db", None)
        if conn is not None:
            conn.close()

    def _tables_referencing_users_old(conn: sqlite3.Connection) -> list[str]:
        rows = conn.execute(
            """
            SELECT name FROM sqlite_master
            WHERE type = 'table' AND sql IS NOT NULL AND instr(sql, 'users_old') > 0
            """
        ).fetchall()
        return [str(r["name"]) for r in rows]

    def _repair_users_old_foreign_keys(conn: sqlite3.Connection) -> None:
        """Fix tables left pointing at users_old after a partial users-table migration."""
        broken = _tables_referencing_users_old(conn)
        if not broken:
            return

        table_ddl = {
            "permission_requests": """
                CREATE TABLE permission_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    permission_type TEXT NOT NULL,
                    destination TEXT NOT NULL,
                    requested_from TEXT NOT NULL,
                    requested_to TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('pending_parent','pending_faculty','approved','rejected')),
                    decision_note TEXT,
                    decided_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                    parent_decision_note TEXT,
                    parent_decided_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                    parent_decided_at TEXT,
                    created_at TEXT NOT NULL,
                    security_validated_at TEXT,
                    security_validated_by INTEGER REFERENCES users(id) ON DELETE SET NULL
                );
            """,
            "issues": """
                CREATE TABLE issues (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL CHECK(severity IN ('low','medium','high')),
                    location TEXT NOT NULL,
                    issue_text TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('open','in_progress','resolved')),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            """,
            "notifications": """
                CREATE TABLE notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    title TEXT NOT NULL,
                    message TEXT NOT NULL,
                    is_read INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                );
            """,
            "qr_scan_logs": """
                CREATE TABLE qr_scan_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id INTEGER REFERENCES permission_requests(id) ON DELETE SET NULL,
                    actor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                    result TEXT NOT NULL,
                    details TEXT,
                    raw_token TEXT,
                    scanned_at TEXT NOT NULL
                );
            """,
        }

        conn.execute("PRAGMA foreign_keys = OFF")
        try:
            for table in broken:
                ddl = table_ddl.get(table)
                if not ddl:
                    continue
                cols = [str(r["name"]) for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
                if not cols:
                    continue
                col_csv = ", ".join(cols)
                tmp = f"{table}__ku_fix"
                conn.execute(f"CREATE TABLE {tmp} AS SELECT {col_csv} FROM {table}")
                conn.execute(f"DROP TABLE {table}")
                conn.executescript(ddl)
                conn.execute(f"INSERT INTO {table} ({col_csv}) SELECT {col_csv} FROM {tmp}")
                conn.execute(f"DROP TABLE {tmp}")
            conn.commit()
        finally:
            conn.execute("PRAGMA foreign_keys = ON")

    def init_db() -> None:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                login_id TEXT UNIQUE NOT NULL,
                full_name TEXT NOT NULL,
                email TEXT,
                phone TEXT,
                role TEXT NOT NULL CHECK(role IN ('student','day_scholar','parent','faculty','admin','security')),
                password_hash TEXT NOT NULL,
                parent_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS permission_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                permission_type TEXT NOT NULL,
                destination TEXT NOT NULL,
                requested_from TEXT NOT NULL,
                requested_to TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('pending_parent','pending_faculty','approved','rejected')),
                decision_note TEXT,
                decided_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                parent_decision_note TEXT,
                parent_decided_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                parent_decided_at TEXT,
                created_at TEXT NOT NULL,
                security_validated_at TEXT,
                security_validated_by INTEGER REFERENCES users(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS issues (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                category TEXT NOT NULL,
                severity TEXT NOT NULL CHECK(severity IN ('low','medium','high')),
                location TEXT NOT NULL,
                issue_text TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('open','in_progress','resolved')),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                is_read INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_id INTEGER,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id INTEGER NOT NULL,
                details TEXT,
                timestamp TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS qr_scan_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id INTEGER REFERENCES permission_requests(id) ON DELETE SET NULL,
                actor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                result TEXT NOT NULL,
                details TEXT,
                raw_token TEXT,
                scanned_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS indoor_games (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                location TEXT NOT NULL DEFAULT 'Recreation Room',
                max_players INTEGER NOT NULL DEFAULT 2,
                is_active INTEGER NOT NULL DEFAULT 1,
                sort_order INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS game_slots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                game_id INTEGER NOT NULL REFERENCES indoor_games(id) ON DELETE CASCADE,
                slot_date TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT NOT NULL,
                max_bookings INTEGER NOT NULL DEFAULT 1,
                is_active INTEGER NOT NULL DEFAULT 1,
                notes TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS game_bookings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                slot_id INTEGER NOT NULL REFERENCES game_slots(id) ON DELETE CASCADE,
                student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                status TEXT NOT NULL CHECK(status IN ('confirmed','cancelled')),
                created_at TEXT NOT NULL,
                UNIQUE(slot_id, student_id)
            );
            """
        )

        # Seed default indoor games if empty.
        gcount = conn.execute("SELECT COUNT(*) AS c FROM indoor_games").fetchone()
        if gcount and int(gcount["c"]) == 0:
            defaults = [
                ("Chess", "Classic strategy board game", "Recreation Room — Block A", 2, 1),
                ("Carrom", "Finger-flick board game", "Recreation Room — Block A", 4, 2),
                ("Table Tennis", "Indoor paddle sport", "Games Hall", 2, 3),
                ("Badminton (Indoor)", "Shuttle sport in indoor court", "Indoor Sports Court", 4, 4),
                ("Snooker", "Cue sport table", "Recreation Lounge", 2, 5),
            ]
            for name, desc, loc, max_p, order in defaults:
                conn.execute(
                    """
                    INSERT INTO indoor_games (name, description, location, max_players, is_active, sort_order, created_at)
                    VALUES (?, ?, ?, ?, 1, ?, ?)
                    """,
                    (name, desc, loc, max_p, order, datetime.utcnow().isoformat()),
                )
            conn.commit()

        # Migrate permission_requests for security validation columns if DB existed before.
        try:
            cols = {r["name"] for r in conn.execute("PRAGMA table_info(permission_requests)").fetchall()}
            if "security_validated_at" not in cols:
                conn.execute("ALTER TABLE permission_requests ADD COLUMN security_validated_at TEXT")
            if "security_validated_by" not in cols:
                conn.execute("ALTER TABLE permission_requests ADD COLUMN security_validated_by INTEGER")
            conn.commit()
        except sqlite3.OperationalError:
            pass

        def _migrate_permission_workflow(c: sqlite3.Connection) -> None:
            try:
                c.execute("SELECT 1 FROM permission_requests LIMIT 1")
            except sqlite3.OperationalError:
                return
            cols = {r["name"] for r in c.execute("PRAGMA table_info(permission_requests)").fetchall()}
            if "parent_decided_at" not in cols:
                for stmt in (
                    "ALTER TABLE permission_requests ADD COLUMN parent_decision_note TEXT",
                    "ALTER TABLE permission_requests ADD COLUMN parent_decided_by INTEGER",
                    "ALTER TABLE permission_requests ADD COLUMN parent_decided_at TEXT",
                ):
                    try:
                        c.execute(stmt)
                    except sqlite3.OperationalError:
                        pass
                c.commit()
            try:
                c.execute("UPDATE permission_requests SET status = 'pending_parent' WHERE status = 'pending'")
                c.commit()
            except sqlite3.IntegrityError:
                c.execute("PRAGMA foreign_keys = OFF")
                c.executescript(
                    """
                    ALTER TABLE permission_requests RENAME TO permission_requests_old;
                    CREATE TABLE permission_requests (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        permission_type TEXT NOT NULL,
                        destination TEXT NOT NULL,
                        requested_from TEXT NOT NULL,
                        requested_to TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        status TEXT NOT NULL CHECK(status IN ('pending_parent','pending_faculty','approved','rejected')),
                        decision_note TEXT,
                        decided_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                        parent_decision_note TEXT,
                        parent_decided_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                        parent_decided_at TEXT,
                        created_at TEXT NOT NULL,
                        security_validated_at TEXT,
                        security_validated_by INTEGER REFERENCES users(id) ON DELETE SET NULL
                    );
                    INSERT INTO permission_requests (
                        id, student_id, permission_type, destination, requested_from, requested_to,
                        reason, status, decision_note, decided_by, parent_decision_note,
                        parent_decided_by, parent_decided_at, created_at, security_validated_at, security_validated_by
                    )
                    SELECT
                        id, student_id, permission_type, destination, requested_from, requested_to,
                        reason,
                        CASE status WHEN 'pending' THEN 'pending_parent' ELSE status END,
                        decision_note, decided_by,
                        NULL, NULL, NULL,
                        created_at, security_validated_at, security_validated_by
                    FROM permission_requests_old;
                    DROP TABLE permission_requests_old;
                    PRAGMA foreign_keys = ON;
                    """
                )
                c.commit()

        _migrate_permission_workflow(conn)

        # Migrate qr_scan_logs schema to allow NULL request_id.
        try:
            qcols = conn.execute("PRAGMA table_info(qr_scan_logs)").fetchall()
            req_col = next((r for r in qcols if r["name"] == "request_id"), None)
            if req_col and int(req_col["notnull"] or 0) == 1:
                conn.executescript(
                    """
                    PRAGMA foreign_keys = OFF;
                    ALTER TABLE qr_scan_logs RENAME TO qr_scan_logs_old;
                    CREATE TABLE qr_scan_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        request_id INTEGER REFERENCES permission_requests(id) ON DELETE SET NULL,
                        actor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                        result TEXT NOT NULL,
                        details TEXT,
                        raw_token TEXT,
                        scanned_at TEXT NOT NULL
                    );
                    INSERT INTO qr_scan_logs (id, request_id, actor_id, result, details, raw_token, scanned_at)
                    SELECT id, request_id, actor_id, result, details, raw_token, scanned_at FROM qr_scan_logs_old;
                    DROP TABLE qr_scan_logs_old;
                    PRAGMA foreign_keys = ON;
                    """
                )
                conn.commit()
        except sqlite3.OperationalError:
            pass

        # Lightweight migration: add security role support if DB existed before.
        try:
            conn.execute("SELECT 1 FROM users LIMIT 1")
            # If CHECK constraint doesn't include 'security' this will raise on insert attempt.
            conn.execute(
                "INSERT INTO users (login_id, full_name, email, phone, role, password_hash, parent_user_id, created_at) VALUES (?, ?, ?, ?, ?, ?, NULL, ?)",
                ("__role_check_probe__", "probe", "", "", "security", generate_password_hash("x"), datetime.utcnow().isoformat()) )
            conn.execute("DELETE FROM users WHERE login_id = ?", ("__role_check_probe__",))
            conn.commit()
        except sqlite3.IntegrityError:
            # Recreate users table with updated role constraint (SQLite can't alter CHECK directly).
            conn.executescript(
                """
                PRAGMA foreign_keys = OFF;
                ALTER TABLE users RENAME TO users_old;
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    login_id TEXT UNIQUE NOT NULL,
                    full_name TEXT NOT NULL,
                    email TEXT,
                    phone TEXT,
                    role TEXT NOT NULL CHECK(role IN ('student','day_scholar','parent','faculty','admin','security')),
                    password_hash TEXT NOT NULL,
                    parent_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                    created_at TEXT NOT NULL
                );
                INSERT INTO users (id, login_id, full_name, email, phone, role, password_hash, parent_user_id, created_at)
                SELECT id, login_id, full_name, email, phone, role, password_hash, parent_user_id, created_at FROM users_old;
                DROP TABLE users_old;
                PRAGMA foreign_keys = ON;
                """
            )
            conn.commit()
            _repair_users_old_foreign_keys(conn)
        except sqlite3.OperationalError:
            # Fresh DB; nothing to migrate.
            pass

        # Repair any DB that still references users_old (e.g. partial migration).
        _repair_users_old_foreign_keys(conn)

        # Seed a default admin so the app is usable immediately.
        admin_login = os.environ.get("DEFAULT_ADMIN_LOGIN", "ADMIN001")
        admin_password = os.environ.get("DEFAULT_ADMIN_PASSWORD", "admin12345")
        exists = conn.execute("SELECT 1 FROM users WHERE login_id = ?", (admin_login,)).fetchone()
        if not exists:
            conn.execute(
                """
                INSERT INTO users (login_id, full_name, email, phone, role, password_hash, parent_user_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, NULL, ?)
                """,
                (
                    admin_login,
                    "System Administrator",
                    "admin@university.local",
                    "",
                    "admin",
                    generate_password_hash(admin_password),
                    datetime.utcnow().isoformat(),
                ),
            )

        # Seed a default security desk user for QR validation.
        security_login = os.environ.get("DEFAULT_SECURITY_LOGIN", "SECURITY001")
        security_password = os.environ.get("DEFAULT_SECURITY_PASSWORD", "security12345")
        sexists = conn.execute("SELECT 1 FROM users WHERE login_id = ?", (security_login,)).fetchone()
        if not sexists:
            conn.execute(
                """
                INSERT INTO users (login_id, full_name, email, phone, role, password_hash, parent_user_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, NULL, ?)
                """,
                (
                    security_login,
                    "Security Desk",
                    "security@university.local",
                    "",
                    "security",
                    generate_password_hash(security_password),
                    datetime.utcnow().isoformat(),
                ),
            )
        conn.commit()
        conn.close()

    init_db()

    @dataclass(frozen=True)
    class CurrentUser:
        id: int
        login_id: str
        full_name: str
        role: str

    def now_iso() -> str:
        return datetime.utcnow().isoformat()

    def _b64u_encode(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    def _b64u_decode(text: str) -> bytes:
        pad = "=" * (-len(text) % 4)
        return base64.urlsafe_b64decode((text + pad).encode("ascii"))

    def make_qr_token(payload: dict[str, Any]) -> str:
        body = _b64u_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        sig = hmac.new(app.secret_key.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).hexdigest()[:24]
        return f"{body}.{sig}"

    def make_permission_qr_token(request_id: int, expires_iso: str) -> str:
        return make_qr_token({"t": "perm", "rid": request_id, "exp": expires_iso})

    def make_receipt_qr_token(request_id: int, student_id: int, status: str) -> str:
        return make_qr_token({"t": "receipt", "rid": request_id, "sid": student_id, "st": status})

    def make_game_booking_qr_token(booking_id: int, slot_end_iso: str) -> str:
        return make_qr_token({"t": "game", "bid": booking_id, "exp": slot_end_iso})

    def render_qr_svg(token: str) -> Response:
        try:
            import io

            import segno  # type: ignore
        except Exception:
            return Response("QR generator not installed.", status=503)
        qr = segno.make(token, error="m")
        buf = io.StringIO()
        qr.svg(buf, scale=6, dark="#0b0b0b", light="#ffffff", omitsize=False)
        return Response(buf.getvalue(), mimetype="image/svg+xml")

    def render_qr_png(token: str) -> Response:
        try:
            import io

            import segno  # type: ignore
        except Exception:
            return Response("QR generator not installed.", status=503)
        qr = segno.make(token, error="m")
        buf = io.BytesIO()
        qr.save(buf, kind="png", scale=8, dark="#0b0b0b", light="#ffffff")
        buf.seek(0)
        return Response(buf.getvalue(), mimetype="image/png")

    def slot_end_iso(slot_date: str, end_time: str) -> str:
        return f"{slot_date}T{end_time}"

    def slot_starts_in_future(slot_date: str, start_time: str) -> bool:
        try:
            start = datetime.strptime(f"{slot_date} {start_time}", "%Y-%m-%d %H:%M")
        except ValueError:
            return False
        return start > datetime.utcnow()

    def count_slot_bookings(slot_id: int) -> int:
        row = db().execute(
            "SELECT COUNT(*) AS c FROM game_bookings WHERE slot_id = ? AND status = 'confirmed'",
            (slot_id,),
        ).fetchone()
        return int(row["c"]) if row else 0

    def verify_qr_token(token: str) -> Optional[dict[str, Any]]:
        try:
            body, sig = token.split(".", 1)
        except ValueError:
            return None
        expected = hmac.new(app.secret_key.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).hexdigest()[:24]
        if not hmac.compare_digest(expected, sig):
            return None
        try:
            payload = json.loads(_b64u_decode(body).decode("utf-8"))
        except Exception:
            return None
        return payload if isinstance(payload, dict) else None

    def parse_dt_local(value: str) -> datetime:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M")

    def row_to_dt(row_value: Any) -> datetime:
        # Stored as ISO string.
        return datetime.fromisoformat(str(row_value))

    def get_user_by_login(login_id: str) -> Optional[sqlite3.Row]:
        return db().execute("SELECT * FROM users WHERE login_id = ?", (login_id.strip(),)).fetchone()

    def get_user_by_id(user_id: int) -> Optional[sqlite3.Row]:
        return db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    def require_login() -> Optional[Response]:
        if not g.current_user:
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("login"))
        return None

    def require_roles(allowed: set[str]) -> Optional[Response]:
        if not g.current_user or g.current_user.role not in allowed:
            flash("Access denied.", "danger")
            return redirect(url_for("home"))
        return None

    def create_audit(actor_id: Optional[int], action: str, target_type: str, target_id: int, details: str = "") -> None:
        db().execute(
            """
            INSERT INTO audit_logs (actor_id, action, target_type, target_id, details, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (actor_id, action, target_type, target_id, details or None, now_iso()),
        )
        db().commit()

    def create_notification(user_id: int, title: str, message: str) -> None:
        db().execute(
            """
            INSERT INTO notifications (user_id, title, message, is_read, created_at)
            VALUES (?, ?, ?, 0, ?)
            """,
            (user_id, title, message, now_iso()),
        )
        db().commit()

    def status_label(status: str) -> str:
        labels = {
            "pending_parent": "Awaiting Parent Approval",
            "pending_faculty": "Awaiting Faculty Approval",
            "approved": "Approved",
            "rejected": "Rejected",
            "pending": "Pending",
        }
        return labels.get(status, status.replace("_", " ").title())

    def notify_faculty_pending_permission(
        request_id: int, student_name: str, permission_type: str, destination: str
    ) -> None:
        msg = (
            f"{student_name} — {permission_type.replace('_', ' ')} to {destination} "
            f"(#{request_id}). Parent approved; faculty action required."
        )
        staff = db().execute("SELECT id FROM users WHERE role IN ('admin', 'faculty')").fetchall()
        for row in staff:
            create_notification(int(row["id"]), "Permission awaiting faculty approval", msg)

    def student_profile_ready_for_permission(student: sqlite3.Row) -> Optional[str]:
        if not (student["email"] or "").strip():
            return "College email is required. Update your Profile before submitting a request."
        if not (student["phone"] or "").strip():
            return "Your phone number is required. Update your Profile before submitting a request."
        if not student["parent_user_id"]:
            return "Parent/guardian is not linked to your account. Contact administration."
        parent = get_user_by_id(int(student["parent_user_id"]))
        if not parent:
            return "Linked parent account not found. Contact administration."
        if not (parent["full_name"] or "").strip():
            return "Parent name is missing on the linked account. Contact administration."
        if not (parent["phone"] or "").strip():
            return "Parent phone number is missing. Contact administration."
        return None

    @app.before_request
    def load_current_user() -> None:
        g.current_user = None
        user_id = session.get("user_id")
        if user_id:
            user = get_user_by_id(int(user_id))
            if user:
                g.current_user = CurrentUser(
                    id=int(user["id"]),
                    login_id=str(user["login_id"]),
                    full_name=str(user["full_name"]),
                    role=str(user["role"]),
                )

    @app.context_processor
    def inject_brand() -> dict[str, Any]:
        return {
            "university_name": app.config["UNIVERSITY_NAME"],
            "motto": app.config["MOTTO"],
            "status_label": status_label,
        }

    @app.get("/branding-logo")
    def branding_logo() -> Response:
        env_path = os.environ.get("BRANDING_LOGO_PATH", "").strip()
        candidates = [
            Path(env_path) if env_path else None,
            ASSETS_DIR / "logo.png",
            ASSETS_DIR / "logo.jpg",
            ASSETS_DIR / "logo.jpeg",
        ]
        for c in candidates:
            if c and c.exists():
                return send_file(c)

        # Fallback: inline SVG (keeps app working even without a logo file).
        svg = """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128" viewBox="0 0 128 128">
  <rect width="128" height="128" rx="12" fill="#ffffff"/>
  <path d="M26 30h16v46c0 10 6 16 16 16s16-6 16-16V30h16v48c0 22-14 36-32 36S26 100 26 78V30z" fill="#f97316"/>
  <text x="64" y="120" font-family="Segoe UI, Arial" font-size="14" font-weight="800" text-anchor="middle" fill="#111">KU</text>
</svg>
"""
        return Response(svg, mimetype="image/svg+xml")

    @app.get("/homepage-image")
    def homepage_image() -> Response:
        candidates = [
            ASSETS_DIR / "campus.png",
            ASSETS_DIR / "campus.jpg",
            ASSETS_DIR / "homepage.png",
            ASSETS_DIR / "homepage.jpg",
            ASSETS_DIR / "homepage.jpeg",
        ]
        for c in candidates:
            if c.exists():
                return send_file(c)
        return redirect(
            "https://images.unsplash.com/photo-1562774053-701939374585?auto=format&fit=crop&w=1500&q=80"
        )

    @app.get("/back")
    def go_back() -> Response:
        ref = request.referrer
        return redirect(ref) if ref else redirect(url_for("home"))

    @app.get("/")
    def home() -> str:
        return render_template("home.html")

    @app.route("/login", methods=["GET", "POST"])
    def login() -> Response | str:
        if request.method == "POST":
            login_id = request.form.get("login_id", "").strip()
            password = request.form.get("password", "")
            user = get_user_by_login(login_id)
            if not user or not check_password_hash(user["password_hash"], password):
                flash("Invalid credentials.", "danger")
                return render_template("login.html")

            session.clear()
            session["user_id"] = int(user["id"])
            flash(f"Welcome, {user['full_name']}!", "success")
            return redirect(url_for("dashboard"))

        return render_template("login.html")

    def _session_fp_key(login_id: str, phone: str) -> str:
        return f"fp:{login_id}:{phone}"

    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password() -> Response | str:
        if request.method == "GET":
            session.pop("fp_verified", None)
            session.pop("fp_login_id", None)
            session.pop("fp_phone", None)
            return render_template("forgot_password.html", fp_stage="otp_send", prefills=None)

        stage = request.form.get("stage", "otp_send")
        login_id = request.form.get("login_id", "").strip()
        phone = request.form.get("phone", "").strip()
        prefills = {"login_id": login_id, "phone": phone}

        if stage == "otp_send":
            if not login_id or not phone:
                flash("Please provide Login ID and Phone/WhatsApp Number.", "warning")
                return render_template("forgot_password.html", fp_stage="otp_send", prefills=prefills)

            user = get_user_by_login(login_id)
            if not user:
                flash("Account not found.", "danger")
                return render_template("forgot_password.html", fp_stage="otp_send", prefills=prefills)

            stored_phone = (user["phone"] or "").strip()
            if not stored_phone or stored_phone != phone:
                flash("Phone number does not match this Login ID.", "danger")
                return render_template("forgot_password.html", fp_stage="otp_send", prefills=prefills)

            otp = f"{secrets.randbelow(1_000_000):06d}"
            session[_session_fp_key(login_id, phone)] = {
                "otp": otp,
                "expires": (datetime.utcnow() + timedelta(minutes=5)).isoformat(),
            }
            session["fp_login_id"] = login_id
            session["fp_phone"] = phone
            flash(f"OTP sent successfully. Demo OTP: {otp}", "info")
            return render_template("forgot_password.html", fp_stage="otp_verify", prefills=prefills)

        if stage == "otp_verify":
            action = request.form.get("action")
            if action == "resend":
                user = get_user_by_login(login_id)
                stored_phone = (user["phone"] or "").strip() if user else ""
                if not user or not stored_phone or stored_phone != phone:
                    flash("Please re-check Login ID and Phone Number.", "warning")
                    return render_template("forgot_password.html", fp_stage="otp_send", prefills=prefills)

                otp = f"{secrets.randbelow(1_000_000):06d}"
                session[_session_fp_key(login_id, phone)] = {
                    "otp": otp,
                    "expires": (datetime.utcnow() + timedelta(minutes=5)).isoformat(),
                }
                session["fp_login_id"] = login_id
                session["fp_phone"] = phone
                flash(f"OTP resent successfully. Demo OTP: {otp}", "info")
                return render_template("forgot_password.html", fp_stage="otp_verify", prefills=prefills)

            otp_input = request.form.get("otp", "").strip()
            payload = session.get(_session_fp_key(login_id, phone))
            if not payload:
                flash("OTP session expired. Please send OTP again.", "warning")
                return render_template("forgot_password.html", fp_stage="otp_send", prefills=prefills)

            if datetime.utcnow() > datetime.fromisoformat(payload["expires"]):
                session.pop(_session_fp_key(login_id, phone), None)
                flash("OTP expired. Please resend OTP.", "warning")
                return render_template("forgot_password.html", fp_stage="otp_send", prefills=prefills)

            if otp_input != payload["otp"]:
                flash("Invalid OTP.", "danger")
                return render_template("forgot_password.html", fp_stage="otp_verify", prefills=prefills)

            session["fp_verified"] = True
            return render_template("forgot_password.html", fp_stage="reset", prefills=prefills)

        if stage == "reset":
            if not session.get("fp_verified"):
                flash("Please verify OTP first.", "warning")
                return render_template("forgot_password.html", fp_stage="otp_send", prefills=prefills)

            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")
            if len(new_password) < 8:
                flash("Password must be at least 8 characters.", "warning")
                return render_template("forgot_password.html", fp_stage="reset", prefills=prefills)
            if new_password != confirm_password:
                flash("Passwords do not match.", "danger")
                return render_template("forgot_password.html", fp_stage="reset", prefills=prefills)

            user = get_user_by_login(login_id)
            if not user:
                flash("Account not found.", "danger")
                return render_template("forgot_password.html", fp_stage="otp_send", prefills=prefills)

            stored_phone = (user["phone"] or "").strip()
            if not stored_phone or stored_phone != phone:
                flash("Phone number does not match this Login ID.", "danger")
                return render_template("forgot_password.html", fp_stage="otp_send", prefills=prefills)

            db().execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (generate_password_hash(new_password), int(user["id"])),
            )
            db().commit()
            create_audit(int(user["id"]), "password_reset", "user", int(user["id"]), "via_otp")

            session.pop(_session_fp_key(login_id, phone), None)
            session.pop("fp_verified", None)
            session.pop("fp_login_id", None)
            session.pop("fp_phone", None)

            flash("Password updated successfully. Please sign in.", "success")
            return redirect(url_for("login"))

        flash("Invalid forgot-password flow.", "danger")
        return render_template("forgot_password.html", fp_stage="otp_send", prefills=prefills)

    @app.get("/logout")
    def logout() -> Response:
        session.clear()
        flash("You have been logged out.", "info")
        return redirect(url_for("home"))

    @app.route("/profile", methods=["GET", "POST"])
    def profile() -> Response | str:
        gate = require_login()
        if gate:
            return gate

        user = get_user_by_id(g.current_user.id)
        if not user:
            flash("Account not found.", "danger")
            return redirect(url_for("logout"))

        if request.method == "POST":
            full_name = request.form.get("full_name", "").strip()
            email = request.form.get("email", "").strip()
            phone = request.form.get("phone", "").strip()

            if not full_name:
                flash("Full name is required.", "warning")
                return render_template("profile.html", user=dict(user))

            db().execute(
                "UPDATE users SET full_name = ?, email = ?, phone = ? WHERE id = ?",
                (full_name, email, phone, g.current_user.id),
            )
            db().commit()
            create_audit(g.current_user.id, "profile_updated", "user", g.current_user.id, "contact_details")
            flash("Profile updated.", "success")
            return redirect(url_for("profile"))

        return render_template("profile.html", user=dict(user))

    @app.post("/profile/change-password")
    def profile_change_password() -> Response:
        gate = require_login()
        if gate:
            return gate

        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        user = get_user_by_id(g.current_user.id)
        if not user or not check_password_hash(user["password_hash"], current_password):
            flash("Current password is incorrect.", "danger")
            return redirect(url_for("profile"))
        if len(new_password) < 8:
            flash("New password must be at least 8 characters.", "warning")
            return redirect(url_for("profile"))
        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("profile"))

        db().execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password), g.current_user.id),
        )
        db().commit()
        create_audit(g.current_user.id, "password_changed", "user", g.current_user.id, "self_service")
        flash("Password updated.", "success")
        return redirect(url_for("profile"))

    def _session_otp_key(login_id: str, phone: str) -> str:
        return f"otp:{login_id}:{phone}"

    @app.route("/register", methods=["GET", "POST"])
    def register_student() -> Response | str:
        if request.method == "GET":
            session.pop("reg_verified", None)
            session.pop("reg_login_id", None)
            session.pop("reg_phone", None)
            return render_template("register.html", reg_stage="otp_send", prefills=None)

        stage = request.form.get("stage", "otp_send")
        login_id = request.form.get("login_id", "").strip()
        phone = request.form.get("phone", "").strip()
        prefills = {"login_id": login_id, "phone": phone}

        if stage == "otp_send":
            if not login_id or not phone:
                flash("Please provide Roll Number and Phone Number.", "warning")
                return render_template("register.html", reg_stage="otp_send", prefills=prefills)

            if get_user_by_login(login_id):
                flash("An account with this Roll Number already exists. Please log in.", "warning")
                return redirect(url_for("login"))

            otp = f"{secrets.randbelow(1_000_000):06d}"
            session[_session_otp_key(login_id, phone)] = {
                "otp": otp,
                "expires": (datetime.utcnow() + timedelta(minutes=5)).isoformat(),
            }
            session["reg_login_id"] = login_id
            session["reg_phone"] = phone

            # For a real system, integrate SMS/WhatsApp. For now, show via flash.
            flash(f"OTP sent successfully. Demo OTP: {otp}", "info")
            return render_template("register.html", reg_stage="otp_verify", prefills=prefills)

        if stage == "otp_verify":
            action = request.form.get("action")
            if action == "resend":
                otp = f"{secrets.randbelow(1_000_000):06d}"
                session[_session_otp_key(login_id, phone)] = {
                    "otp": otp,
                    "expires": (datetime.utcnow() + timedelta(minutes=5)).isoformat(),
                }
                session["reg_login_id"] = login_id
                session["reg_phone"] = phone
                flash(f"OTP resent successfully. Demo OTP: {otp}", "info")
                return render_template("register.html", reg_stage="otp_verify", prefills=prefills)

            otp_input = request.form.get("otp", "").strip()
            payload = session.get(_session_otp_key(login_id, phone))
            if not payload:
                flash("OTP session expired. Please send OTP again.", "warning")
                return render_template("register.html", reg_stage="otp_send", prefills=prefills)

            if datetime.utcnow() > datetime.fromisoformat(payload["expires"]):
                session.pop(_session_otp_key(login_id, phone), None)
                flash("OTP expired. Please resend OTP.", "warning")
                return render_template("register.html", reg_stage="otp_send", prefills=prefills)

            if otp_input != payload["otp"]:
                flash("Invalid OTP.", "danger")
                return render_template("register.html", reg_stage="otp_verify", prefills=prefills)

            session["reg_verified"] = True
            return render_template("register.html", reg_stage="create", prefills=prefills)

        if stage == "create":
            if not session.get("reg_verified"):
                flash("Please verify OTP first.", "warning")
                return render_template("register.html", reg_stage="otp_send", prefills=prefills)

            full_name = request.form.get("full_name", "").strip()
            email = request.form.get("email", "").strip()
            role = request.form.get("role", "student").strip()
            password = request.form.get("password", "")
            parent_login_id = request.form.get("parent_login_id", "").strip()
            parent_phone = request.form.get("parent_phone", "").strip()
            parent_name = request.form.get("parent_name", "").strip()

            if role not in {"student", "day_scholar"}:
                flash("Invalid user type.", "danger")
                return render_template("register.html", reg_stage="create", prefills=prefills)

            if not parent_phone:
                flash("Parent WhatsApp Number is required.", "warning")
                return render_template("register.html", reg_stage="create", prefills=prefills)

            if not parent_name:
                flash("Parent/Guardian name is required.", "warning")
                return render_template("register.html", reg_stage="create", prefills=prefills)

            parent_user_id = None
            if not parent_login_id:
                # Auto-create a parent login if not provided, since parent notifications depend on it.
                base = f"PARENT_{login_id}".upper()
                candidate = base
                n = 1
                while get_user_by_login(candidate):
                    n += 1
                    candidate = f"{base}_{n}"
                parent_login_id = candidate

            if parent_login_id:
                existing_parent = get_user_by_login(parent_login_id)
                if existing_parent:
                    parent_user_id = int(existing_parent["id"])
                    db().execute(
                        "UPDATE users SET full_name = ?, phone = ? WHERE id = ?",
                        (parent_name, parent_phone, parent_user_id),
                    )
                    db().commit()
                else:
                    temp_password = secrets.token_urlsafe(8)
                    cur = db().execute(
                        """
                        INSERT INTO users (login_id, full_name, email, phone, role, password_hash, parent_user_id, created_at)
                        VALUES (?, ?, ?, ?, 'parent', ?, NULL, ?)
                        """,
                        (
                            parent_login_id,
                            parent_name,
                            "",
                            parent_phone,
                            generate_password_hash(temp_password),
                            now_iso(),
                        ),
                    )
                    parent_user_id = int(cur.lastrowid)
                    db().commit()
                    flash(
                        f"Parent account created. Parent Login ID: {parent_login_id} (temp password: {temp_password})",
                        "info",
                    )

            try:
                cur = db().execute(
                    """
                    INSERT INTO users (login_id, full_name, email, phone, role, password_hash, parent_user_id, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        login_id,
                        full_name,
                        email,
                        phone,
                        role,
                        generate_password_hash(password),
                        parent_user_id,
                        now_iso(),
                    ),
                )
                db().commit()
                create_audit(None, "user_registered", "user", int(cur.lastrowid), f"role={role}")
            except sqlite3.IntegrityError:
                flash("This Roll Number is already registered.", "danger")
                return render_template("register.html", reg_stage="otp_send", prefills=prefills)

            session.clear()
            flash("Account created successfully. Please sign in.", "success")
            return redirect(url_for("login"))

        flash("Invalid registration flow.", "danger")
        return render_template("register.html", reg_stage="otp_send", prefills=prefills)

    @app.get("/dashboard")
    def dashboard() -> Response | str:
        gate = require_login()
        if gate:
            return gate

        if g.current_user.role in {"student", "day_scholar"}:
            return _dashboard_student()
        if g.current_user.role in {"admin", "faculty"}:
            return _dashboard_admin()
        if g.current_user.role == "parent":
            return _dashboard_parent()
        if g.current_user.role == "security":
            return redirect(url_for("security_scan"))

        flash("Unknown role.", "danger")
        return redirect(url_for("home"))

    @app.get("/faculty-admin")
    def faculty_admin() -> Response:
        gate = require_roles({"admin", "faculty"})
        if gate:
            return gate
        return redirect(url_for("dashboard"))

    @app.route("/security", methods=["GET", "POST"])
    def security_scan() -> Response | str:
        gate = require_roles({"admin", "faculty", "security"})
        if gate:
            return gate

        if request.method == "GET":
            return render_template("security_scan.html")

        token = request.form.get("qr_token", "").strip()
        if not token:
            flash("Please provide a QR token.", "warning")
            return render_template("security_scan.html")

        payload = verify_qr_token(token)
        if not payload or payload.get("t") != "perm":
            db().execute(
                "INSERT INTO qr_scan_logs (request_id, actor_id, result, details, raw_token, scanned_at) VALUES (?, ?, ?, ?, ?, ?)",
                (None, g.current_user.id, "invalid", "bad_token", token[:300], now_iso()),
            )
            db().commit()
            flash("Invalid QR code.", "danger")
            return render_template("security_scan.html")

        try:
            request_id = int(payload.get("rid"))
        except Exception:
            request_id = 0

        exp_raw = str(payload.get("exp") or "")
        try:
            exp_dt = datetime.fromisoformat(exp_raw)
        except Exception:
            exp_dt = None

        pr = db().execute("SELECT * FROM permission_requests WHERE id = ?", (request_id,)).fetchone()
        if not pr:
            db().execute(
                "INSERT INTO qr_scan_logs (request_id, actor_id, result, details, raw_token, scanned_at) VALUES (?, ?, ?, ?, ?, ?)",
                (request_id, g.current_user.id, "invalid", "request_not_found", token[:300], now_iso()),
            )
            db().commit()
            flash("Request not found.", "danger")
            return render_template("security_scan.html")

        if pr["status"] != "approved":
            db().execute(
                "INSERT INTO qr_scan_logs (request_id, actor_id, result, details, raw_token, scanned_at) VALUES (?, ?, ?, ?, ?, ?)",
                (request_id, g.current_user.id, "denied", "not_approved", token[:300], now_iso()),
            )
            db().commit()
            flash("QR scanned, but this request is not approved.", "warning")
            return render_template("security_scan.html", pr=dict(pr), token=token)

        if exp_dt and datetime.utcnow() > exp_dt:
            db().execute(
                "INSERT INTO qr_scan_logs (request_id, actor_id, result, details, raw_token, scanned_at) VALUES (?, ?, ?, ?, ?, ?)",
                (request_id, g.current_user.id, "expired", "expired", token[:300], now_iso()),
            )
            db().commit()
            flash("QR scanned, but this request has expired.", "danger")
            return render_template("security_scan.html", pr=dict(pr), token=token)

        # Mark validated (idempotent)
        if not pr["security_validated_at"]:
            db().execute(
                """
                UPDATE permission_requests
                SET security_validated_at = ?, security_validated_by = ?
                WHERE id = ?
                """,
                (now_iso(), g.current_user.id, request_id),
            )
            db().commit()
            create_audit(g.current_user.id, "qr_validated", "permission", request_id, "security_scan")

        db().execute(
            "INSERT INTO qr_scan_logs (request_id, actor_id, result, details, raw_token, scanned_at) VALUES (?, ?, ?, ?, ?, ?)",
            (request_id, g.current_user.id, "valid", "validated", token[:300], now_iso()),
        )
        db().commit()
        flash("Valid QR. Entry/exit validated and recorded.", "success")
        return render_template("security_scan.html", pr=dict(pr), token=token)

    def _filters_from_args(prefix: str) -> dict[str, str]:
        def _get(name: str, default: str = "all") -> str:
            return request.args.get(name, default).strip()

        if prefix == "student":
            return {
                "perm_status": _get("perm_status", "all"),
                "perm_type": _get("perm_type", "all"),
                "permission_search": _get("permission_search", ""),
                "issue_status": _get("issue_status", "all"),
                "issue_severity": _get("issue_severity", "all"),
                "issue_search": _get("issue_search", ""),
            }
        if prefix == "admin":
            return {
                "perm_status": _get("perm_status", "all"),
                "perm_type": _get("perm_type", "all"),
                "perm_student_id": _get("perm_student_id", ""),
                "permission_search": _get("permission_search", ""),
                "issue_status": _get("issue_status", "all"),
                "issue_severity": _get("issue_severity", "all"),
                "issue_student_id": _get("issue_student_id", ""),
                "issue_search": _get("issue_search", ""),
            }
        if prefix == "parent":
            return {
                "student_id": _get("student_id", "all"),
                "perm_status": _get("perm_status", "all"),
                "permission_search": _get("permission_search", ""),
            }
        return {}

    def _dashboard_student() -> str:
        filters = _filters_from_args("student")
        params: list[Any] = [g.current_user.id]
        where = ["student_id = ?"]
        if filters["perm_status"] != "all":
            if filters["perm_status"] == "pending":
                where.append("status IN ('pending_parent', 'pending_faculty')")
            else:
                where.append("status = ?")
                params.append(filters["perm_status"])
        if filters["perm_type"] != "all":
            where.append("permission_type = ?")
            params.append(filters["perm_type"])
        if filters["permission_search"]:
            where.append("(destination LIKE ? OR reason LIKE ?)")
            q = f"%{filters['permission_search']}%"
            params.extend([q, q])

        perm_rows = db().execute(
            f"""
            SELECT * FROM permission_requests
            WHERE {' AND '.join(where)}
            ORDER BY created_at DESC
            LIMIT 200
            """,
            tuple(params),
        ).fetchall()

        permissions = []
        for r in perm_rows:
            r = dict(r)
            r["requested_from"] = row_to_dt(r["requested_from"])
            r["requested_to"] = row_to_dt(r["requested_to"])
            r["created_at"] = row_to_dt(r["created_at"])
            permissions.append(type("Permission", (), r))

        iparams: list[Any] = [g.current_user.id]
        iwhere = ["student_id = ?"]
        if filters["issue_status"] != "all":
            iwhere.append("status = ?")
            iparams.append(filters["issue_status"])
        if filters["issue_severity"] != "all":
            iwhere.append("severity = ?")
            iparams.append(filters["issue_severity"])
        if filters["issue_search"]:
            iwhere.append("(location LIKE ? OR issue_text LIKE ?)")
            q = f"%{filters['issue_search']}%"
            iparams.extend([q, q])

        issue_rows = db().execute(
            f"""
            SELECT * FROM issues
            WHERE {' AND '.join(iwhere)}
            ORDER BY updated_at DESC
            LIMIT 200
            """,
            tuple(iparams),
        ).fetchall()
        issues = []
        for r in issue_rows:
            r = dict(r)
            r["created_at"] = row_to_dt(r["created_at"])
            r["updated_at"] = row_to_dt(r["updated_at"])
            issues.append(type("Issue", (), r))

        game_bookings: list[Any] = []
        if g.current_user.role == "student":
            brow = db().execute(
                """
                SELECT b.*, g.name AS game_name, s.slot_date, s.start_time, s.end_time, g.location
                FROM game_bookings b
                JOIN game_slots s ON s.id = b.slot_id
                JOIN indoor_games g ON g.id = s.game_id
                WHERE b.student_id = ? AND b.status = 'confirmed'
                  AND (s.slot_date || 'T' || s.end_time) >= ?
                ORDER BY s.slot_date, s.start_time
                LIMIT 20
                """,
                (g.current_user.id, now_iso()[:16]),
            ).fetchall()
            for r in brow:
                d = dict(r)
                d["created_at"] = row_to_dt(d["created_at"])
                game_bookings.append(type("GameBooking", (), d))

        return render_template(
            "dashboard_student.html",
            permissions=permissions,
            issues=issues,
            filters=filters,
            game_bookings=game_bookings,
            is_hosteller=g.current_user.role == "student",
        )

    def _dashboard_admin() -> str:
        filters = _filters_from_args("admin")

        perm_stats_rows = db().execute(
            "SELECT status, COUNT(*) as c FROM permission_requests GROUP BY status"
        ).fetchall()
        perm_stats = {str(r["status"]): int(r["c"]) for r in perm_stats_rows}

        issue_stats_rows = db().execute("SELECT status, COUNT(*) as c FROM issues GROUP BY status").fetchall()
        issue_stats = {str(r["status"]): int(r["c"]) for r in issue_stats_rows}

        scan_24h = db().execute(
            "SELECT COUNT(*) as c FROM qr_scan_logs WHERE scanned_at >= ?",
            ((datetime.utcnow() - timedelta(hours=24)).isoformat(),),
        ).fetchone()
        scans_last_24h = int(scan_24h["c"]) if scan_24h else 0

        where = ["1=1"]
        params: list[Any] = []
        if filters["perm_status"] != "all":
            if filters["perm_status"] == "pending":
                where.append("p.status IN ('pending_parent', 'pending_faculty')")
            else:
                where.append("p.status = ?")
                params.append(filters["perm_status"])
        if filters["perm_type"] != "all":
            where.append("p.permission_type = ?")
            params.append(filters["perm_type"])
        if filters["perm_student_id"]:
            where.append("(u.id = ? OR u.login_id LIKE ?)")
            try:
                params.append(int(filters["perm_student_id"]))
            except ValueError:
                params.append(-1)
            params.append(f"%{filters['perm_student_id']}%")
        if filters["permission_search"]:
            where.append("(p.destination LIKE ? OR p.reason LIKE ?)")
            q = f"%{filters['permission_search']}%"
            params.extend([q, q])

        perm_rows = db().execute(
            f"""
            SELECT p.*, u.full_name as student_name, u.login_id as student_roll
            FROM permission_requests p
            JOIN users u ON u.id = p.student_id
            WHERE {' AND '.join(where)}
            ORDER BY p.created_at DESC
            LIMIT 300
            """,
            tuple(params),
        ).fetchall()

        permissions = []
        for r in perm_rows:
            d = dict(r)
            pr = {
                k: d[k]
                for k in (
                    "id",
                    "student_id",
                    "permission_type",
                    "destination",
                    "requested_from",
                    "requested_to",
                    "reason",
                    "status",
                    "decision_note",
                    "decided_by",
                    "parent_decision_note",
                    "parent_decided_by",
                    "parent_decided_at",
                    "security_validated_at",
                    "security_validated_by",
                    "created_at",
                )
            }
            pr["requested_from"] = row_to_dt(pr["requested_from"])
            pr["requested_to"] = row_to_dt(pr["requested_to"])
            pr["created_at"] = row_to_dt(pr["created_at"])
            permissions.append((type("Permission", (), pr), d["student_name"], d["student_roll"]))

        iwhere = ["1=1"]
        iparams: list[Any] = []
        if filters["issue_status"] != "all":
            iwhere.append("i.status = ?")
            iparams.append(filters["issue_status"])
        if filters["issue_severity"] != "all":
            iwhere.append("i.severity = ?")
            iparams.append(filters["issue_severity"])
        if filters["issue_student_id"]:
            iwhere.append("(u.id = ? OR u.login_id LIKE ?)")
            try:
                iparams.append(int(filters["issue_student_id"]))
            except ValueError:
                iparams.append(-1)
            iparams.append(f"%{filters['issue_student_id']}%")
        if filters["issue_search"]:
            iwhere.append("(i.location LIKE ? OR i.issue_text LIKE ?)")
            q = f"%{filters['issue_search']}%"
            iparams.extend([q, q])

        issue_rows = db().execute(
            f"""
            SELECT i.*, u.full_name as student_name, u.login_id as student_roll
            FROM issues i
            JOIN users u ON u.id = i.student_id
            WHERE {' AND '.join(iwhere)}
            ORDER BY i.updated_at DESC
            LIMIT 300
            """,
            tuple(iparams),
        ).fetchall()
        issues = []
        for r in issue_rows:
            d = dict(r)
            issue = {
                k: d[k]
                for k in (
                    "id",
                    "student_id",
                    "category",
                    "severity",
                    "location",
                    "issue_text",
                    "status",
                    "created_at",
                    "updated_at",
                )
            }
            issue["created_at"] = row_to_dt(issue["created_at"])
            issue["updated_at"] = row_to_dt(issue["updated_at"])
            issues.append((type("Issue", (), issue), d["student_name"], d["student_roll"]))

        log_rows = db().execute(
            "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 30"
        ).fetchall()
        logs = []
        for r in log_rows:
            d = dict(r)
            d["timestamp"] = row_to_dt(d["timestamp"])
            logs.append(type("AuditLog", (), d))

        return render_template(
            "dashboard_admin.html",
            permissions=permissions,
            issues=issues,
            logs=logs,
            filters=filters,
            perm_stats=perm_stats,
            issue_stats=issue_stats,
            scans_last_24h=scans_last_24h,
        )

    def _dashboard_parent() -> str:
        filters = _filters_from_args("parent")
        linked = db().execute(
            """
            SELECT id, login_id, full_name, email, role
            FROM users
            WHERE parent_user_id = ?
            ORDER BY created_at DESC
            """,
            (g.current_user.id,),
        ).fetchall()
        linked_students = [type("Student", (), dict(r)) for r in linked]

        student_filter = filters["student_id"]
        where = ["u.parent_user_id = ?"]
        params: list[Any] = [g.current_user.id]
        if student_filter != "all":
            where.append("p.student_id = ?")
            try:
                params.append(int(student_filter))
            except ValueError:
                params.append(-1)
        if filters["perm_status"] != "all":
            if filters["perm_status"] == "pending":
                where.append("p.status IN ('pending_parent', 'pending_faculty')")
            else:
                where.append("p.status = ?")
                params.append(filters["perm_status"])
        if filters["permission_search"]:
            where.append("(p.destination LIKE ? OR p.reason LIKE ?)")
            q = f"%{filters['permission_search']}%"
            params.extend([q, q])

        perm_rows = db().execute(
            f"""
            SELECT p.*, u.full_name AS student_name, u.login_id AS student_roll
            FROM permission_requests p
            JOIN users u ON u.id = p.student_id
            WHERE {' AND '.join(where)}
            ORDER BY p.created_at DESC
            LIMIT 300
            """,
            tuple(params),
        ).fetchall()
        permissions = []
        pending_parent = []
        for r in perm_rows:
            d = dict(r)
            d["requested_from"] = row_to_dt(d["requested_from"])
            d["requested_to"] = row_to_dt(d["requested_to"])
            d["created_at"] = row_to_dt(d["created_at"])
            perm_obj = type("Permission", (), d)
            permissions.append((perm_obj, d.get("student_name", ""), d.get("student_roll", "")))
            if d["status"] == "pending_parent":
                pending_parent.append((perm_obj, d.get("student_name", ""), d.get("student_roll", "")))

        nrows = db().execute(
            """
            SELECT * FROM notifications
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT 200
            """,
            (g.current_user.id,),
        ).fetchall()
        notifications = []
        for r in nrows:
            d = dict(r)
            d["created_at"] = row_to_dt(d["created_at"])
            d["is_read"] = bool(d["is_read"])
            notifications.append(type("Notification", (), d))

        return render_template(
            "dashboard_parent.html",
            linked_students=linked_students,
            permissions=permissions,
            pending_parent_requests=pending_parent,
            notifications=notifications,
            filters=filters,
        )

    @app.route("/permission", methods=["GET", "POST"])
    def request_permission() -> Response | str:
        gate = require_roles({"student", "day_scholar"})
        if gate:
            return gate

        if request.method == "POST":
            permission_type = request.form.get("permission_type", "").strip()
            destination = request.form.get("destination", "").strip()
            requested_from = request.form.get("requested_from", "").strip()
            requested_to = request.form.get("requested_to", "").strip()
            reason = request.form.get("reason", "").strip()

            if permission_type not in {
                "leave_pass",
                "late_entry",
                "late_outing",
                "early_departure",
                "commute_pass",
                "day_scholar_update",
            }:
                flash("Invalid permission type.", "danger")
                return render_template("request_permission.html")

            try:
                dt_from = parse_dt_local(requested_from)
                dt_to = parse_dt_local(requested_to)
            except ValueError:
                flash("Please provide valid From/To date & time.", "warning")
                return render_template("request_permission.html")

            if dt_to <= dt_from:
                flash("To time must be after From time.", "warning")
                return render_template("request_permission.html")

            student = get_user_by_id(g.current_user.id)
            if not student:
                flash("Account not found.", "danger")
                return redirect(url_for("logout"))
            profile_err = student_profile_ready_for_permission(student)
            if profile_err:
                flash(profile_err, "warning")
                return redirect(url_for("profile"))

            cur = db().execute(
                """
                INSERT INTO permission_requests (
                    student_id, permission_type, destination, requested_from, requested_to,
                    reason, status, decision_note, decided_by, parent_decision_note,
                    parent_decided_by, parent_decided_at, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, 'pending_parent', NULL, NULL, NULL, NULL, NULL, ?)
                """,
                (
                    g.current_user.id,
                    permission_type,
                    destination,
                    dt_from.isoformat(),
                    dt_to.isoformat(),
                    reason,
                    now_iso(),
                ),
            )
            db().commit()
            request_id = int(cur.lastrowid)
            create_audit(g.current_user.id, "permission_submitted", "permission", request_id, f"type={permission_type}")

            create_notification(
                int(student["parent_user_id"]),
                "Approve permission request",
                f"{student['full_name']} requested {permission_type.replace('_', ' ')} to {destination}. "
                f"Please review and approve on your Parent Dashboard (Request #{request_id}).",
            )
            create_notification(
                g.current_user.id,
                "Request sent to parent",
                f"Your permission request #{request_id} was sent to your parent/guardian for approval first.",
            )

            flash("Request submitted. Your parent/guardian must approve before faculty review.", "success")
            return redirect(url_for("permission_receipt", request_id=request_id))

        return render_template("request_permission.html")

    @app.get("/permission/<int:request_id>/receipt")
    def permission_receipt(request_id: int) -> Response | str:
        gate = require_login()
        if gate:
            return gate

        pr = db().execute("SELECT * FROM permission_requests WHERE id = ?", (request_id,)).fetchone()
        if not pr:
            flash("Permission request not found.", "danger")
            return redirect(url_for("dashboard"))

        prd = dict(pr)
        prd["requested_from"] = row_to_dt(prd["requested_from"])
        prd["requested_to"] = row_to_dt(prd["requested_to"])
        prd["created_at"] = row_to_dt(prd["created_at"])
        pr_obj = type("Permission", (), prd)

        student = get_user_by_id(int(pr["student_id"]))
        if g.current_user.role in {"student", "day_scholar"} and int(pr["student_id"]) != g.current_user.id:
            flash("Access denied.", "danger")
            return redirect(url_for("dashboard"))
        if g.current_user.role == "parent":
            if not student or int(student["parent_user_id"] or 0) != g.current_user.id:
                flash("Access denied.", "danger")
                return redirect(url_for("dashboard"))

        student_obj = type("Student", (), dict(student)) if student else None
        parent = get_user_by_id(int(student["parent_user_id"])) if student and student["parent_user_id"] else None
        parent_obj = type("Parent", (), dict(parent)) if parent else None
        receipt_qr_token = make_receipt_qr_token(int(pr["id"]), int(pr["student_id"]), str(pr["status"]))
        security_qr_token = ""
        if pr["status"] == "approved":
            security_qr_token = make_permission_qr_token(int(pr["id"]), str(pr["requested_to"]))
        return render_template(
            "receipt_permission.html",
            pr=pr_obj,
            student=student_obj,
            parent=parent_obj,
            receipt_qr_token=receipt_qr_token,
            security_qr_token=security_qr_token,
        )

    @app.get("/permission/<int:request_id>/qr.svg")
    def permission_qr_svg(request_id: int) -> Response:
        gate = require_login()
        if gate:
            return gate

        pr = db().execute("SELECT * FROM permission_requests WHERE id = ?", (request_id,)).fetchone()
        if not pr:
            return Response("Not found", status=404)
        if pr["status"] != "approved":
            return Response("QR available only for approved requests.", status=400)

        student = get_user_by_id(int(pr["student_id"]))
        if g.current_user.role in {"student", "day_scholar"} and int(pr["student_id"]) != g.current_user.id:
            return Response("Access denied", status=403)
        if g.current_user.role == "parent":
            if not student or int(student["parent_user_id"] or 0) != g.current_user.id:
                return Response("Access denied", status=403)

        token = make_permission_qr_token(int(pr["id"]), str(pr["requested_to"]))
        return render_qr_svg(token)

    @app.get("/permission/<int:request_id>/qr.png")
    def permission_qr_png(request_id: int) -> Response:
        gate = require_login()
        if gate:
            return gate

        pr = db().execute("SELECT * FROM permission_requests WHERE id = ?", (request_id,)).fetchone()
        if not pr or pr["status"] != "approved":
            return Response("Not found", status=404)

        student = get_user_by_id(int(pr["student_id"]))
        if g.current_user.role in {"student", "day_scholar"} and int(pr["student_id"]) != g.current_user.id:
            return Response("Access denied", status=403)
        if g.current_user.role == "parent":
            if not student or int(student["parent_user_id"] or 0) != g.current_user.id:
                return Response("Access denied", status=403)

        token = make_permission_qr_token(int(pr["id"]), str(pr["requested_to"]))
        return render_qr_png(token)

    @app.get("/permission/<int:request_id>/receipt-qr.svg")
    def permission_receipt_qr_svg(request_id: int) -> Response:
        gate = require_login()
        if gate:
            return gate

        pr = db().execute("SELECT * FROM permission_requests WHERE id = ?", (request_id,)).fetchone()
        if not pr:
            return Response("Not found", status=404)

        student = get_user_by_id(int(pr["student_id"]))
        if g.current_user.role in {"student", "day_scholar"} and int(pr["student_id"]) != g.current_user.id:
            return Response("Access denied", status=403)
        if g.current_user.role == "parent":
            if not student or int(student["parent_user_id"] or 0) != g.current_user.id:
                return Response("Access denied", status=403)

        token = make_receipt_qr_token(int(pr["id"]), int(pr["student_id"]), str(pr["status"]))
        return render_qr_svg(token)

    @app.post("/permission/<int:request_id>/parent-decide")
    def decide_permission_parent(request_id: int) -> Response:
        gate = require_roles({"parent"})
        if gate:
            return gate

        decision = request.form.get("decision", "").strip()
        note = request.form.get("decision_note", "").strip()
        if decision not in {"approved", "rejected"}:
            flash("Invalid decision.", "danger")
            return redirect(url_for("dashboard"))

        pr = db().execute("SELECT * FROM permission_requests WHERE id = ?", (request_id,)).fetchone()
        if not pr:
            flash("Request not found.", "danger")
            return redirect(url_for("dashboard"))
        if pr["status"] != "pending_parent":
            flash("This request is not awaiting parent approval.", "info")
            return redirect(url_for("dashboard"))

        student = get_user_by_id(int(pr["student_id"]))
        if not student or int(student["parent_user_id"] or 0) != g.current_user.id:
            flash("Access denied.", "danger")
            return redirect(url_for("dashboard"))

        if decision == "approved":
            new_status = "pending_faculty"
            db().execute(
                """
                UPDATE permission_requests
                SET status = ?, parent_decision_note = ?, parent_decided_by = ?, parent_decided_at = ?
                WHERE id = ?
                """,
                (new_status, note or None, g.current_user.id, now_iso(), request_id),
            )
            db().commit()
            create_audit(g.current_user.id, "permission_parent_approved", "permission", request_id, note)
            create_notification(
                int(student["id"]),
                "Parent approved your request",
                f"Request #{request_id} was approved by your parent. Awaiting faculty approval.",
            )
            notify_faculty_pending_permission(
                request_id,
                str(student["full_name"]),
                str(pr["permission_type"]),
                str(pr["destination"]),
            )
            flash("Approved. Request forwarded to faculty for final approval.", "success")
        else:
            db().execute(
                """
                UPDATE permission_requests
                SET status = 'rejected', parent_decision_note = ?, parent_decided_by = ?, parent_decided_at = ?
                WHERE id = ?
                """,
                (note or None, g.current_user.id, now_iso(), request_id),
            )
            db().commit()
            create_audit(g.current_user.id, "permission_parent_rejected", "permission", request_id, note)
            create_notification(
                int(student["id"]),
                "Parent rejected your request",
                f"Request #{request_id} was rejected by your parent. {('Note: ' + note) if note else ''}".strip(),
            )
            flash("Request rejected.", "info")

        return redirect(url_for("dashboard"))

    @app.post("/permission/<int:request_id>/decide")
    def decide_permission(request_id: int) -> Response:
        gate = require_roles({"admin", "faculty"})
        if gate:
            return gate

        decision = request.form.get("decision", "").strip()
        note = request.form.get("decision_note", "").strip()
        if decision not in {"approved", "rejected"}:
            flash("Invalid decision.", "danger")
            return redirect(url_for("dashboard"))

        pr = db().execute("SELECT * FROM permission_requests WHERE id = ?", (request_id,)).fetchone()
        if not pr:
            flash("Request not found.", "danger")
            return redirect(url_for("dashboard"))
        if pr["status"] != "pending_faculty":
            flash("Faculty can act only after parent approval (status: awaiting faculty).", "warning")
            return redirect(url_for("dashboard"))

        db().execute(
            """
            UPDATE permission_requests
            SET status = ?, decision_note = ?, decided_by = ?
            WHERE id = ?
            """,
            (decision, note or None, g.current_user.id, request_id),
        )
        db().commit()
        create_audit(g.current_user.id, f"permission_{decision}", "permission", request_id, note)

        student = get_user_by_id(int(pr["student_id"]))
        if student:
            create_notification(
                int(student["id"]),
                f"Permission {decision}",
                f"Your permission request #{request_id} was {decision} by faculty. {('Note: ' + note) if note else ''}".strip(),
            )
            if student["parent_user_id"]:
                create_notification(
                    int(student["parent_user_id"]),
                    f"Ward permission {decision}",
                    f"{student['full_name']}'s request #{request_id} was {decision} by faculty. {('Note: ' + note) if note else ''}".strip(),
                )

        flash(f"Request marked as {decision}.", "success")
        return redirect(url_for("dashboard"))

    @app.route("/issue", methods=["GET", "POST"])
    def report_issue() -> Response | str:
        gate = require_roles({"student", "day_scholar"})
        if gate:
            return gate

        if request.method == "POST":
            category = request.form.get("category", "").strip()
            severity = request.form.get("severity", "").strip()
            location = request.form.get("location", "").strip()
            issue_text = request.form.get("issue_text", "").strip()

            if severity not in {"low", "medium", "high"}:
                flash("Invalid severity.", "danger")
                return render_template("report_issue.html")

            cur = db().execute(
                """
                INSERT INTO issues (
                    student_id, category, severity, location, issue_text, status, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, 'open', ?, ?)
                """,
                (g.current_user.id, category, severity, location, issue_text, now_iso(), now_iso()),
            )
            db().commit()
            issue_id = int(cur.lastrowid)
            create_audit(g.current_user.id, "issue_reported", "issue", issue_id, f"{category}/{severity}")

            flash("Issue submitted successfully.", "success")
            return redirect(url_for("dashboard"))

        return render_template("report_issue.html")

    @app.post("/issue/<int:issue_id>/update")
    def update_issue(issue_id: int) -> Response:
        gate = require_roles({"admin", "faculty"})
        if gate:
            return gate

        status = request.form.get("status", "").strip()
        if status not in {"open", "in_progress", "resolved"}:
            flash("Invalid status.", "danger")
            return redirect(url_for("dashboard"))

        issue = db().execute("SELECT * FROM issues WHERE id = ?", (issue_id,)).fetchone()
        if not issue:
            flash("Issue not found.", "danger")
            return redirect(url_for("dashboard"))

        db().execute("UPDATE issues SET status = ?, updated_at = ? WHERE id = ?", (status, now_iso(), issue_id))
        db().commit()
        create_audit(g.current_user.id, "issue_status_updated", "issue", issue_id, f"status={status}")

        student = get_user_by_id(int(issue["student_id"]))
        if student:
            create_notification(
                int(student["id"]),
                "Issue status updated",
                f"Your issue #{issue_id} is now '{status.replace('_',' ')}'.",
            )

        flash("Issue updated.", "success")
        return redirect(url_for("dashboard"))

    @app.get("/notification/<int:notification_id>/read")
    def read_notification(notification_id: int) -> Response:
        gate = require_roles({"parent"})
        if gate:
            return gate

        n = db().execute(
            "SELECT * FROM notifications WHERE id = ? AND user_id = ?",
            (notification_id, g.current_user.id),
        ).fetchone()
        if not n:
            flash("Notification not found.", "warning")
            return redirect(url_for("dashboard"))

        db().execute("UPDATE notifications SET is_read = 1 WHERE id = ?", (notification_id,))
        db().commit()
        flash("Marked as read.", "success")
        return redirect(url_for("dashboard"))

    @app.route("/games", methods=["GET", "POST"])
    def games_book() -> Response | str:
        gate = require_roles({"student"})
        if gate:
            return gate

        filter_date = request.args.get("date", "").strip() or datetime.utcnow().strftime("%Y-%m-%d")

        if request.method == "POST":
            action = request.form.get("action", "book")
            if action == "cancel":
                booking_id = int(request.form.get("booking_id", "0") or 0)
                booking = db().execute(
                    "SELECT * FROM game_bookings WHERE id = ? AND student_id = ? AND status = 'confirmed'",
                    (booking_id, g.current_user.id),
                ).fetchone()
                if not booking:
                    flash("Booking not found.", "danger")
                    return redirect(url_for("games_book", date=filter_date))
                db().execute("UPDATE game_bookings SET status = 'cancelled' WHERE id = ?", (booking_id,))
                db().commit()
                create_audit(g.current_user.id, "game_booking_cancelled", "game_booking", booking_id, "")
                flash("Booking cancelled.", "info")
                return redirect(url_for("games_book", date=filter_date))

            slot_id = int(request.form.get("slot_id", "0") or 0)
            slot = db().execute(
                """
                SELECT s.*, g.name AS game_name, g.is_active AS game_active, g.max_players
                FROM game_slots s
                JOIN indoor_games g ON g.id = s.game_id
                WHERE s.id = ?
                """,
                (slot_id,),
            ).fetchone()
            if not slot or not slot["is_active"] or not slot["game_active"]:
                flash("This slot is not available.", "danger")
                return redirect(url_for("games_book", date=filter_date))
            if not slot_starts_in_future(str(slot["slot_date"]), str(slot["start_time"])):
                flash("This slot has already started.", "warning")
                return redirect(url_for("games_book", date=filter_date))
            if count_slot_bookings(slot_id) >= int(slot["max_bookings"]):
                flash("This slot is fully booked.", "warning")
                return redirect(url_for("games_book", date=filter_date))

            try:
                cur = db().execute(
                    """
                    INSERT INTO game_bookings (slot_id, student_id, status, created_at)
                    VALUES (?, ?, 'confirmed', ?)
                    """,
                    (slot_id, g.current_user.id, now_iso()),
                )
                db().commit()
                booking_id = int(cur.lastrowid)
                create_audit(g.current_user.id, "game_booking_created", "game_booking", booking_id, slot["game_name"])
                flash(f"Booked {slot['game_name']} successfully.", "success")
                return redirect(url_for("game_booking_receipt", booking_id=booking_id))
            except sqlite3.IntegrityError:
                flash("You already have a booking for this slot.", "warning")
                return redirect(url_for("games_book", date=filter_date))

        games = db().execute(
            "SELECT * FROM indoor_games WHERE is_active = 1 ORDER BY sort_order, name"
        ).fetchall()
        slots_by_game: dict[int, list[Any]] = {}
        for g_row in games:
            gid = int(g_row["id"])
            slots = db().execute(
                """
                SELECT s.*,
                    (SELECT COUNT(*) FROM game_bookings b
                     WHERE b.slot_id = s.id AND b.status = 'confirmed') AS booked_count
                FROM game_slots s
                WHERE s.game_id = ? AND s.is_active = 1 AND s.slot_date = ?
                ORDER BY s.start_time
                """,
                (gid, filter_date),
            ).fetchall()
            slot_objs = []
            for s in slots:
                d = dict(s)
                d["spots_left"] = max(0, int(d["max_bookings"]) - int(d["booked_count"]))
                d["is_full"] = d["spots_left"] <= 0
                d["can_book"] = (
                    d["spots_left"] > 0
                    and slot_starts_in_future(str(d["slot_date"]), str(d["start_time"]))
                )
                slot_objs.append(type("Slot", (), d))
            slots_by_game[gid] = slot_objs

        my_bookings_rows = db().execute(
            """
            SELECT b.*, g.name AS game_name, s.slot_date, s.start_time, s.end_time, g.location
            FROM game_bookings b
            JOIN game_slots s ON s.id = b.slot_id
            JOIN indoor_games g ON g.id = s.game_id
            WHERE b.student_id = ? AND b.status = 'confirmed'
            ORDER BY s.slot_date DESC, s.start_time DESC
            LIMIT 50
            """,
            (g.current_user.id,),
        ).fetchall()
        my_bookings = [type("Booking", (), dict(r)) for r in my_bookings_rows]

        return render_template(
            "games_book.html",
            games=[type("Game", (), dict(r)) for r in games],
            slots_by_game=slots_by_game,
            my_bookings=my_bookings,
            filter_date=filter_date,
        )

    @app.get("/games/booking/<int:booking_id>/receipt")
    def game_booking_receipt(booking_id: int) -> Response | str:
        gate = require_roles({"student", "admin", "faculty"})
        if gate:
            return gate

        row = db().execute(
            """
            SELECT b.*, u.full_name, u.login_id, g.name AS game_name, g.location,
                   s.slot_date, s.start_time, s.end_time
            FROM game_bookings b
            JOIN users u ON u.id = b.student_id
            JOIN game_slots s ON s.id = b.slot_id
            JOIN indoor_games g ON g.id = s.game_id
            WHERE b.id = ?
            """,
            (booking_id,),
        ).fetchone()
        if not row:
            flash("Booking not found.", "danger")
            return redirect(url_for("dashboard"))

        if g.current_user.role == "student" and int(row["student_id"]) != g.current_user.id:
            flash("Access denied.", "danger")
            return redirect(url_for("dashboard"))

        booking = type("Booking", (), dict(row))
        qr_token = ""
        if row["status"] == "confirmed":
            qr_token = make_game_booking_qr_token(
                booking_id, slot_end_iso(str(row["slot_date"]), str(row["end_time"]))
            )
        return render_template("games_receipt.html", booking=booking, qr_token=qr_token)

    @app.get("/games/booking/<int:booking_id>/qr.svg")
    def game_booking_qr_svg(booking_id: int) -> Response:
        gate = require_login()
        if gate:
            return gate

        row = db().execute(
            """
            SELECT b.*, s.slot_date, s.end_time
            FROM game_bookings b
            JOIN game_slots s ON s.id = b.slot_id
            WHERE b.id = ? AND b.status = 'confirmed'
            """,
            (booking_id,),
        ).fetchone()
        if not row:
            return Response("Not found", status=404)
        if g.current_user.role == "student" and int(row["student_id"]) != g.current_user.id:
            return Response("Access denied", status=403)

        token = make_game_booking_qr_token(
            booking_id, slot_end_iso(str(row["slot_date"]), str(row["end_time"]))
        )
        return render_qr_svg(token)

    @app.route("/admin/games", methods=["GET", "POST"])
    def admin_games() -> Response | str:
        gate = require_roles({"admin"})
        if gate:
            return gate

        if request.method == "POST":
            action = request.form.get("action", "")

            if action == "add_game":
                name = request.form.get("name", "").strip()
                description = request.form.get("description", "").strip()
                location = request.form.get("location", "Recreation Room").strip()
                max_players = max(1, int(request.form.get("max_players", "2") or 2))
                if not name:
                    flash("Game name is required.", "warning")
                    return redirect(url_for("admin_games"))
                cur = db().execute(
                    """
                    INSERT INTO indoor_games (name, description, location, max_players, is_active, sort_order, created_at)
                    VALUES (?, ?, ?, ?, 1, 99, ?)
                    """,
                    (name, description, location, max_players, now_iso()),
                )
                db().commit()
                create_audit(g.current_user.id, "game_added", "indoor_game", int(cur.lastrowid), name)
                flash(f"Game '{name}' added.", "success")
                return redirect(url_for("admin_games"))

            if action == "edit_game":
                game_id = int(request.form.get("game_id", "0") or 0)
                name = request.form.get("name", "").strip()
                description = request.form.get("description", "").strip()
                location = request.form.get("location", "").strip()
                max_players = max(1, int(request.form.get("max_players", "2") or 2))
                is_active = 1 if request.form.get("is_active") == "1" else 0
                if not name:
                    flash("Game name is required.", "warning")
                    return redirect(url_for("admin_games"))
                db().execute(
                    """
                    UPDATE indoor_games
                    SET name = ?, description = ?, location = ?, max_players = ?, is_active = ?
                    WHERE id = ?
                    """,
                    (name, description, location, max_players, is_active, game_id),
                )
                db().commit()
                create_audit(g.current_user.id, "game_updated", "indoor_game", game_id, name)
                flash("Game updated.", "success")
                return redirect(url_for("admin_games"))

            if action == "add_slot":
                game_id = int(request.form.get("game_id", "0") or 0)
                slot_date = request.form.get("slot_date", "").strip()
                start_time = request.form.get("start_time", "").strip()
                end_time = request.form.get("end_time", "").strip()
                max_bookings = max(1, int(request.form.get("max_bookings", "1") or 1))
                notes = request.form.get("notes", "").strip()
                if not game_id or not slot_date or not start_time or not end_time:
                    flash("Please fill all slot fields.", "warning")
                    return redirect(url_for("admin_games"))
                if start_time >= end_time:
                    flash("End time must be after start time.", "warning")
                    return redirect(url_for("admin_games"))
                cur = db().execute(
                    """
                    INSERT INTO game_slots (game_id, slot_date, start_time, end_time, max_bookings, is_active, notes, created_at)
                    VALUES (?, ?, ?, ?, ?, 1, ?, ?)
                    """,
                    (game_id, slot_date, start_time, end_time, max_bookings, notes or None, now_iso()),
                )
                db().commit()
                create_audit(g.current_user.id, "game_slot_added", "game_slot", int(cur.lastrowid), slot_date)
                flash("Time slot added.", "success")
                return redirect(url_for("admin_games"))

            if action == "edit_slot":
                slot_id = int(request.form.get("slot_id", "0") or 0)
                slot_date = request.form.get("slot_date", "").strip()
                start_time = request.form.get("start_time", "").strip()
                end_time = request.form.get("end_time", "").strip()
                max_bookings = max(1, int(request.form.get("max_bookings", "1") or 1))
                is_active = 1 if request.form.get("is_active") == "1" else 0
                notes = request.form.get("notes", "").strip()
                if start_time >= end_time:
                    flash("End time must be after start time.", "warning")
                    return redirect(url_for("admin_games"))
                db().execute(
                    """
                    UPDATE game_slots
                    SET slot_date = ?, start_time = ?, end_time = ?, max_bookings = ?, is_active = ?, notes = ?
                    WHERE id = ?
                    """,
                    (slot_date, start_time, end_time, max_bookings, is_active, notes or None, slot_id),
                )
                db().commit()
                create_audit(g.current_user.id, "game_slot_updated", "game_slot", slot_id, "")
                flash("Slot updated.", "success")
                return redirect(url_for("admin_games"))

            if action == "cancel_booking":
                booking_id = int(request.form.get("booking_id", "0") or 0)
                db().execute("UPDATE game_bookings SET status = 'cancelled' WHERE id = ?", (booking_id,))
                db().commit()
                create_audit(g.current_user.id, "game_booking_admin_cancel", "game_booking", booking_id, "")
                flash("Booking cancelled by admin.", "info")
                return redirect(url_for("admin_games"))

        all_games = db().execute("SELECT * FROM indoor_games ORDER BY sort_order, name").fetchall()
        games = [type("Game", (), dict(r)) for r in all_games]

        upcoming_slots = db().execute(
            """
            SELECT s.*, g.name AS game_name,
                (SELECT COUNT(*) FROM game_bookings b
                 WHERE b.slot_id = s.id AND b.status = 'confirmed') AS booked_count
            FROM game_slots s
            JOIN indoor_games g ON g.id = s.game_id
            WHERE s.slot_date >= date('now')
            ORDER BY s.slot_date, s.start_time
            LIMIT 100
            """
        ).fetchall()
        slots = []
        for r in upcoming_slots:
            d = dict(r)
            d["booked_count"] = int(d["booked_count"])
            slots.append(type("Slot", (), d))

        bookings_rows = db().execute(
            """
            SELECT b.*, u.full_name, u.login_id, g.name AS game_name,
                   s.slot_date, s.start_time, s.end_time
            FROM game_bookings b
            JOIN users u ON u.id = b.student_id
            JOIN game_slots s ON s.id = b.slot_id
            JOIN indoor_games g ON g.id = s.game_id
            WHERE b.status = 'confirmed' AND s.slot_date >= date('now')
            ORDER BY s.slot_date, s.start_time
            LIMIT 80
            """
        ).fetchall()
        bookings = [type("Booking", (), dict(r)) for r in bookings_rows]

        return render_template("admin_games.html", games=games, slots=slots, bookings=bookings)

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=int(os.environ.get("PORT", "5000")))

