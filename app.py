import csv
import datetime as dt
import hashlib
import hmac
import io
import json
import os
import secrets
import sqlite3
from html import escape
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlparse


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = Path(os.environ.get("DATABASE_PATH", str(DATA_DIR / "dbkk_organic.db")))
STATIC_DIR = BASE_DIR / "static"
SESSION_STORE = {}
PASSWORD_ITERATIONS = 140_000

ROLES = {"admin": "DBKK Admin", "vendor": "Vendor", "collector": "Collector / Compost Operator"}
SOURCE_TYPES = [
    "wholesale_market",
    "wet_market_stall",
    "restaurant",
    "food_court_vendor",
    "hotel_kitchen",
    "school_canteen",
    "bazaar",
    "community_site",
]
COMPLIANCE_STATUSES = ["compliant", "partially_compliant", "non_compliant", "pending"]
PICKUP_STATUSES = ["pending", "approved", "assigned", "collected", "cancelled", "failed"]
ACCEPTANCE_STATUSES = ["accepted", "partial", "rejected"]
USAGE_TYPES = ["dbkk_landscape", "community_garden", "sold", "stored", "school_garden", "urban_farming", "other"]


def now_iso():
    return dt.datetime.now().replace(microsecond=0).isoformat(sep=" ")


def today_iso():
    return dt.date.today().isoformat()


def h(value):
    if value is None:
        return ""
    return escape(str(value), quote=True)


def labelize(value):
    if value is None:
        return ""
    return str(value).replace("_", " ").title()


def kg(value):
    try:
        number = float(value or 0)
    except (TypeError, ValueError):
        number = 0
    if number == int(number):
        return f"{int(number):,} kg"
    return f"{number:,.1f} kg"


def moneyless_number(value):
    try:
        number = float(value or 0)
    except (TypeError, ValueError):
        number = 0
    if number == int(number):
        return f"{int(number):,}"
    return f"{number:,.1f}"


def parse_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def parse_int(value, default=None):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def bool_from_form(value):
    return 1 if str(value).lower() in {"1", "true", "yes", "on"} else 0


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PASSWORD_ITERATIONS,
    )
    return f"{PASSWORD_ITERATIONS}${salt}${derived.hex()}"


def verify_password(password, stored):
    try:
        iterations, salt, expected_hash = stored.split("$", 2)
        derived = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            int(iterations),
        ).hex()
        return hmac.compare_digest(derived, expected_hash)
    except Exception:
        return False


def db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin','vendor','collector')),
                phone TEXT,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS destinations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                destination_name TEXT NOT NULL,
                destination_type TEXT NOT NULL,
                address TEXT,
                latitude REAL,
                longitude REAL,
                contact_person TEXT,
                contact_phone TEXT,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS waste_sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_name TEXT NOT NULL,
                source_type TEXT NOT NULL,
                address TEXT,
                latitude REAL,
                longitude REAL,
                zone TEXT,
                contact_person TEXT,
                contact_phone TEXT,
                estimated_organic_kg_per_day REAL NOT NULL DEFAULT 0,
                estimated_recyclable_kg_per_day REAL NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'active',
                assigned_vendor_user_id INTEGER,
                default_destination_id INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (assigned_vendor_user_id) REFERENCES users(id) ON DELETE SET NULL,
                FOREIGN KEY (default_destination_id) REFERENCES destinations(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS segregation_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                waste_source_id INTEGER NOT NULL,
                inspection_date TEXT NOT NULL,
                has_compostable_bin INTEGER NOT NULL DEFAULT 0,
                has_recyclable_bin INTEGER NOT NULL DEFAULT 0,
                segregation_status TEXT NOT NULL,
                contamination_notes TEXT,
                inspected_by_user_id INTEGER,
                remarks TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (waste_source_id) REFERENCES waste_sources(id) ON DELETE CASCADE,
                FOREIGN KEY (inspected_by_user_id) REFERENCES users(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS pickup_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                waste_source_id INTEGER NOT NULL,
                request_type TEXT NOT NULL CHECK(request_type IN ('scheduled','on_demand')),
                requested_pickup_date TEXT NOT NULL,
                estimated_organic_kg REAL NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'pending',
                notes TEXT,
                created_by_user_id INTEGER,
                assigned_collector_user_id INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (waste_source_id) REFERENCES waste_sources(id) ON DELETE CASCADE,
                FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
                FOREIGN KEY (assigned_collector_user_id) REFERENCES users(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS collections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pickup_request_id INTEGER NOT NULL UNIQUE,
                collected_at TEXT NOT NULL,
                actual_organic_kg REAL NOT NULL DEFAULT 0,
                contamination_flag INTEGER NOT NULL DEFAULT 0,
                contamination_notes TEXT,
                collected_by_user_id INTEGER,
                destination_id INTEGER,
                delivery_status TEXT NOT NULL DEFAULT 'pending_delivery',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (pickup_request_id) REFERENCES pickup_requests(id) ON DELETE CASCADE,
                FOREIGN KEY (collected_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
                FOREIGN KEY (destination_id) REFERENCES destinations(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS compost_intakes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                collection_id INTEGER NOT NULL UNIQUE,
                destination_id INTEGER NOT NULL,
                received_date TEXT NOT NULL,
                received_weight_kg REAL NOT NULL DEFAULT 0,
                acceptance_status TEXT NOT NULL,
                batch_code TEXT,
                notes TEXT,
                recorded_by_user_id INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (collection_id) REFERENCES collections(id) ON DELETE CASCADE,
                FOREIGN KEY (destination_id) REFERENCES destinations(id) ON DELETE CASCADE,
                FOREIGN KEY (recorded_by_user_id) REFERENCES users(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS compost_outputs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                compost_intake_id INTEGER NOT NULL,
                output_date TEXT NOT NULL,
                compost_output_kg REAL NOT NULL DEFAULT 0,
                usage_type TEXT NOT NULL,
                usage_destination TEXT,
                notes TEXT,
                recorded_by_user_id INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (compost_intake_id) REFERENCES compost_intakes(id) ON DELETE CASCADE,
                FOREIGN KEY (recorded_by_user_id) REFERENCES users(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS recyclable_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                waste_source_id INTEGER NOT NULL,
                record_date TEXT NOT NULL,
                estimated_recyclable_kg REAL NOT NULL DEFAULT 0,
                handoff_destination TEXT,
                notes TEXT,
                recorded_by_user_id INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (waste_source_id) REFERENCES waste_sources(id) ON DELETE CASCADE,
                FOREIGN KEY (recorded_by_user_id) REFERENCES users(id) ON DELETE SET NULL
            );
            """
        )
        ensure_location_columns(conn)
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count == 0:
            seed_db(conn)
        seed_location_coordinates(conn)


def ensure_location_columns(conn):
    required = {
        "waste_sources": {"latitude": "REAL", "longitude": "REAL"},
        "destinations": {"latitude": "REAL", "longitude": "REAL"},
    }
    for table, columns in required.items():
        existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
        for column, column_type in columns.items():
            if column not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {column_type}")


def seed_location_coordinates(conn):
    source_coordinates = {
        "Jesselton Food Court": (5.9827, 116.0735),
        "Kota Kinabalu Central Market": (5.9818, 116.0731),
        "Likas Hotel Kitchen": (6.0067, 116.1009),
        "Sembulan School Canteen": (5.9539, 116.0715),
        "Ramadan Bazaar Lintasan Deasoka": (5.9812, 116.0754),
    }
    destination_coordinates = {
        "KTE Compost Site": (5.9348, 116.0496),
        "Kapayan Composting Area": (5.9336, 116.0878),
        "DBKK Future Compost Hub": (5.9804, 116.0735),
    }
    for name, (latitude, longitude) in source_coordinates.items():
        conn.execute(
            """
            UPDATE waste_sources
            SET latitude=COALESCE(latitude, ?), longitude=COALESCE(longitude, ?)
            WHERE source_name=?
            """,
            (latitude, longitude, name),
        )
    for name, (latitude, longitude) in destination_coordinates.items():
        conn.execute(
            """
            UPDATE destinations
            SET latitude=COALESCE(latitude, ?), longitude=COALESCE(longitude, ?)
            WHERE destination_name=?
            """,
            (latitude, longitude, name),
        )


def seed_db(conn):
    users = [
        ("Aina Rahman", "admin@dbkk.local", "admin", "088-555 100"),
        ("Jesselton Food Court", "vendor@dbkk.local", "vendor", "012-430 2211"),
        ("KTE Organic Collection", "collector@dbkk.local", "collector", "014-800 7744"),
    ]
    for name, email, role, phone in users:
        conn.execute(
            "INSERT INTO users (name, email, password_hash, role, phone) VALUES (?, ?, ?, ?, ?)",
            (name, email, hash_password("password123"), role, phone),
        )

    admin_id = conn.execute("SELECT id FROM users WHERE role='admin'").fetchone()["id"]
    vendor_id = conn.execute("SELECT id FROM users WHERE role='vendor'").fetchone()["id"]
    collector_id = conn.execute("SELECT id FROM users WHERE role='collector'").fetchone()["id"]

    destinations = [
        ("KTE Compost Site", "kte_site", "Kota Kinabalu industrial composting area", 5.9348, 116.0496, "KTE Site Supervisor", "088-555 210"),
        ("Kapayan Composting Area", "kapayan_site", "Kapayan community composting area", 5.9336, 116.0878, "Kapayan Operator", "088-555 211"),
        ("DBKK Future Compost Hub", "compost_hub", "Proposed DBKK organic diversion hub", 5.9804, 116.0735, "DBKK Solid Waste Unit", "088-555 212"),
    ]
    for row in destinations:
        conn.execute(
            """
            INSERT INTO destinations
                (destination_name, destination_type, address, latitude, longitude, contact_person, contact_phone)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            row,
        )

    kte_id = conn.execute("SELECT id FROM destinations WHERE destination_type='kte_site'").fetchone()["id"]
    kapayan_id = conn.execute("SELECT id FROM destinations WHERE destination_type='kapayan_site'").fetchone()["id"]

    sources = [
        (
            "Jesselton Food Court",
            "food_court_vendor",
            "Jalan Tun Fuad Stephens",
            5.9827,
            116.0735,
            "Central",
            "Farah Lim",
            "012-430 2211",
            180,
            35,
            "active",
            vendor_id,
            kte_id,
        ),
        (
            "Kota Kinabalu Central Market",
            "wholesale_market",
            "Jalan Tun Razak",
            5.9818,
            116.0731,
            "Central",
            "Market Office",
            "088-230 900",
            540,
            95,
            "active",
            None,
            kte_id,
        ),
        (
            "Likas Hotel Kitchen",
            "hotel_kitchen",
            "Likas Bay",
            6.0067,
            116.1009,
            "North",
            "Kitchen Manager",
            "088-420 880",
            220,
            45,
            "active",
            None,
            kapayan_id,
        ),
        (
            "Sembulan School Canteen",
            "school_canteen",
            "Sembulan",
            5.9539,
            116.0715,
            "South",
            "Canteen Lead",
            "088-300 778",
            65,
            12,
            "active",
            None,
            kapayan_id,
        ),
        (
            "Ramadan Bazaar Lintasan Deasoka",
            "bazaar",
            "Lintasan Deasoka",
            5.9812,
            116.0754,
            "Central",
            "Event Coordinator",
            "013-770 9191",
            310,
            50,
            "inactive",
            None,
            kte_id,
        ),
    ]
    for source in sources:
        conn.execute(
            """
            INSERT INTO waste_sources (
                source_name, source_type, address, latitude, longitude, zone, contact_person, contact_phone,
                estimated_organic_kg_per_day, estimated_recyclable_kg_per_day, status,
                assigned_vendor_user_id, default_destination_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            source,
        )

    source_rows = conn.execute("SELECT id, source_name FROM waste_sources").fetchall()
    source_ids = {row["source_name"]: row["id"] for row in source_rows}
    compliance = [
        ("Jesselton Food Court", 1, 1, "compliant", "Bins labelled and separated.", "Ready for regular organic pickup."),
        ("Kota Kinabalu Central Market", 1, 0, "partially_compliant", "Some recyclable bins missing.", "Needs follow-up with stall operators."),
        ("Likas Hotel Kitchen", 1, 1, "compliant", "Low contamination.", "Good segregation area."),
        ("Sembulan School Canteen", 0, 1, "non_compliant", "Compostable waste mixed with general waste.", "Training required."),
        ("Ramadan Bazaar Lintasan Deasoka", 0, 0, "pending", "", "Inspection pending before seasonal activation."),
    ]
    for name, compost_bin, recycle_bin, status, contamination, remarks in compliance:
        conn.execute(
            """
            INSERT INTO segregation_records (
                waste_source_id, inspection_date, has_compostable_bin, has_recyclable_bin,
                segregation_status, contamination_notes, inspected_by_user_id, remarks
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (source_ids[name], today_iso(), compost_bin, recycle_bin, status, contamination, admin_id, remarks),
        )

    pickups = [
        ("Jesselton Food Court", "scheduled", today_iso(), 160, "assigned", "Daily food court organic pickup.", vendor_id, collector_id),
        ("Kota Kinabalu Central Market", "scheduled", today_iso(), 480, "approved", "Morning market organics.", admin_id, collector_id),
        ("Likas Hotel Kitchen", "scheduled", (dt.date.today() + dt.timedelta(days=1)).isoformat(), 210, "pending", "Kitchen separation ready.", admin_id, None),
        ("Sembulan School Canteen", "on_demand", (dt.date.today() + dt.timedelta(days=2)).isoformat(), 55, "pending", "Awaiting bin setup confirmation.", admin_id, None),
        ("Jesselton Food Court", "scheduled", (dt.date.today() - dt.timedelta(days=5)).isoformat(), 165, "collected", "Last completed demo pickup.", vendor_id, collector_id),
    ]
    for name, request_type, pickup_date, estimate, status, notes, created_by, assigned_to in pickups:
        conn.execute(
            """
            INSERT INTO pickup_requests (
                waste_source_id, request_type, requested_pickup_date, estimated_organic_kg,
                status, notes, created_by_user_id, assigned_collector_user_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (source_ids[name], request_type, pickup_date, estimate, status, notes, created_by, assigned_to),
        )

    completed_pickup = conn.execute(
        """
        SELECT id FROM pickup_requests
        WHERE waste_source_id=? AND status='collected'
        ORDER BY id DESC LIMIT 1
        """,
        (source_ids["Jesselton Food Court"],),
    ).fetchone()["id"]
    conn.execute(
        """
        INSERT INTO collections (
            pickup_request_id, collected_at, actual_organic_kg, contamination_flag,
            contamination_notes, collected_by_user_id, destination_id, delivery_status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            completed_pickup,
            (dt.datetime.now() - dt.timedelta(days=5)).replace(microsecond=0).isoformat(sep=" "),
            162,
            0,
            "No major contamination.",
            collector_id,
            kte_id,
            "delivered",
        ),
    )
    collection_id = conn.execute("SELECT id FROM collections WHERE pickup_request_id=?", (completed_pickup,)).fetchone()["id"]
    conn.execute(
        """
        INSERT INTO compost_intakes (
            collection_id, destination_id, received_date, received_weight_kg,
            acceptance_status, batch_code, notes, recorded_by_user_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            collection_id,
            kte_id,
            (dt.date.today() - dt.timedelta(days=5)).isoformat(),
            160,
            "accepted",
            "KTE-ORG-001",
            "Accepted into windrow batch.",
            collector_id,
        ),
    )
    intake_id = conn.execute("SELECT id FROM compost_intakes WHERE batch_code='KTE-ORG-001'").fetchone()["id"]
    conn.execute(
        """
        INSERT INTO compost_outputs (
            compost_intake_id, output_date, compost_output_kg, usage_type,
            usage_destination, notes, recorded_by_user_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            intake_id,
            today_iso(),
            54,
            "dbkk_landscape",
            "DBKK roadside landscaping",
            "First demo output from accepted organic intake.",
            collector_id,
        ),
    )
    conn.execute(
        """
        INSERT INTO recyclable_records (
            waste_source_id, record_date, estimated_recyclable_kg,
            handoff_destination, notes, recorded_by_user_id
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            source_ids["Jesselton Food Court"],
            today_iso(),
            32,
            "Local recycler handoff note only",
            "Basic recyclable tracking, not a full logistics workflow.",
            vendor_id,
        ),
    )


def query_one(sql, params=()):
    with db() as conn:
        return conn.execute(sql, params).fetchone()


def query_all(sql, params=()):
    with db() as conn:
        return conn.execute(sql, params).fetchall()


def execute(sql, params=()):
    with db() as conn:
        cur = conn.execute(sql, params)
        return cur.lastrowid


def execute_many(statements):
    with db() as conn:
        for sql, params in statements:
            conn.execute(sql, params)


def options(items, selected=None, label_func=None, value_func=None):
    rendered = []
    for item in items:
        value = value_func(item) if value_func else item
        label = label_func(item) if label_func else labelize(item)
        selected_attr = " selected" if str(value) == str(selected) else ""
        rendered.append(f'<option value="{h(value)}"{selected_attr}>{h(label)}</option>')
    return "\n".join(rendered)


def yes_no(value):
    return "Yes" if int(value or 0) else "No"


def status_badge(status):
    status = status or "pending"
    return f'<span class="badge badge-{h(status)}">{h(labelize(status))}</span>'


def role_badge(role):
    return f'<span class="role role-{h(role)}">{h(ROLES.get(role, role))}</span>'


def coordinate_pair(row):
    try:
        latitude = row["latitude"]
        longitude = row["longitude"]
    except (KeyError, IndexError):
        return None
    if latitude is None or longitude is None:
        return None
    return f"{float(latitude):.6f},{float(longitude):.6f}"


def map_query(name, address="", latitude=None, longitude=None):
    if latitude not in (None, "") and longitude not in (None, ""):
        return f"{float(latitude):.6f},{float(longitude):.6f}"
    parts = [name, address, "Kota Kinabalu Sabah Malaysia"]
    return " ".join(part for part in parts if part)


def google_embed_url(query, zoom=15):
    return f"https://www.google.com/maps?q={quote(str(query), safe=',')}&z={int(zoom)}&output=embed"


def google_open_url(query):
    return f"https://www.google.com/maps/search/?api=1&query={quote(str(query), safe=',')}"


def google_directions_url(origin, destination):
    return (
        "https://www.google.com/maps/dir/?api=1"
        f"&origin={quote(str(origin), safe=',')}"
        f"&destination={quote(str(destination), safe=',')}"
    )


def latest_compliance_by_source(conn=None):
    close = False
    if conn is None:
        conn = db()
        close = True
    rows = conn.execute(
        """
        SELECT sr.*
        FROM segregation_records sr
        JOIN (
            SELECT waste_source_id, MAX(id) AS latest_id
            FROM segregation_records
            GROUP BY waste_source_id
        ) latest ON latest.latest_id = sr.id
        """
    ).fetchall()
    result = {row["waste_source_id"]: row for row in rows}
    if close:
        conn.close()
    return result


def render_login(error=""):
    error_html = f'<div class="alert alert-error">{h(error)}</div>' if error else ""
    return f"""<!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>DBKK Organic Waste System</title>
        <link rel="stylesheet" href="/static/css/styles.css">
    </head>
    <body class="login-body">
        <main class="login-shell">
            <section class="login-panel">
                <div class="brand-mark">DBKK</div>
                <h1>Organic Waste Segregation & Diversion System</h1>
                <p class="muted">Source segregation, organic pickup, compost intake, compost output, and landfill diversion reporting.</p>
                {error_html}
                <form method="post" action="/login" class="form-stack">
                    <label>Email
                        <input type="email" name="email" value="admin@dbkk.local" required>
                    </label>
                    <label>Password
                        <input type="password" name="password" value="password123" required>
                    </label>
                    <button type="submit" class="btn btn-primary full-width">Sign in</button>
                </form>
                <div class="demo-logins">
                    <strong>Demo accounts</strong>
                    <span>Admin: admin@dbkk.local</span>
                    <span>Vendor: vendor@dbkk.local</span>
                    <span>Collector: collector@dbkk.local</span>
                    <span>Password: password123</span>
                </div>
            </section>
        </main>
    </body>
    </html>"""


def nav_for(user):
    role = user["role"]
    if role == "vendor":
        return [
            ("dashboard", "/dashboard", "Home"),
            ("pickups", "/pickups", "Request Pickup"),
            ("recyclables", "/recyclables", "My Waste"),
            ("history", "/history", "History"),
        ]
    if role == "collector":
        return [
            ("dashboard", "/dashboard", "Today's Jobs"),
            ("pickups", "/pickups", "Pickup Board"),
            ("collections", "/collections", "Collections"),
            ("intakes", "/intakes", "Delivery"),
            ("outputs", "/outputs", "Compost Output"),
        ]
    return [
        ("dashboard", "/dashboard", "Dashboard"),
        ("sources", "/sources", "Waste Sources"),
        ("compliance", "/compliance", "Segregation"),
        ("pickups", "/pickups", "Pickup Board"),
        ("destinations", "/destinations", "Compost Sites"),
        ("reports", "/reports", "Reports"),
    ]


def layout(user, active, title, body, actions=""):
    nav_links = []
    for key, url, label in nav_for(user):
        selected = " active" if key == active else ""
        nav_links.append(f'<a class="nav-link{selected}" href="{url}">{h(label)}</a>')
    return f"""<!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{h(title)} - DBKK Organic Waste System</title>
        <link rel="stylesheet" href="/static/css/styles.css">
    </head>
    <body>
        <aside class="sidebar">
            <a href="/dashboard" class="app-brand">
                <span class="brand-icon">D</span>
                <span>
                    <strong>DBKK Organic</strong>
                    <small>Segregation & Diversion</small>
                </span>
            </a>
            <nav>{''.join(nav_links)}</nav>
        </aside>
        <main class="main">
            <header class="topbar">
                <div>
                    <h1>{h(title)}</h1>
                    <p class="muted">{h(ROLES.get(user['role'], user['role']))}</p>
                </div>
                <div class="topbar-actions">
                    {actions}
                    {role_badge(user['role'])}
                    <span class="user-name">{h(user['name'])}</span>
                    <a class="btn btn-quiet" href="/logout">Logout</a>
                </div>
            </header>
            {body}
        </main>
        <script src="/static/js/app.js"></script>
    </body>
    </html>"""


def metric_card(label, value, note="", tone="neutral"):
    note_html = f'<small>{h(note)}</small>' if note else ""
    return f"""
    <article class="metric metric-{tone}">
        <span>{h(label)}</span>
        <strong>{h(value)}</strong>
        {note_html}
    </article>"""


def empty_state(text):
    return f'<div class="empty-state">{h(text)}</div>'


def bar_chart(rows, label_key, value_key, color="green"):
    if not rows:
        return empty_state("No chart data yet.")
    max_value = max(float(row[value_key] or 0) for row in rows) or 1
    bars = []
    for row in rows:
        value = float(row[value_key] or 0)
        width = max(3, (value / max_value) * 100)
        bars.append(
            f"""
            <div class="bar-row">
                <span>{h(row[label_key])}</span>
                <div class="bar-track"><div class="bar bar-{h(color)}" style="width:{width:.1f}%"></div></div>
                <strong>{h(moneyless_number(value))}</strong>
            </div>"""
        )
    return '<div class="chart-bars">' + "".join(bars) + "</div>"


def progress_bar(percent, label=""):
    safe_percent = max(0, min(100, int(percent or 0)))
    label_html = f"<span>{h(label)}</span>" if label else ""
    return f"""
    <div class="progress-block">
        <div class="progress-meta">{label_html}<strong>{safe_percent}%</strong></div>
        <div class="progress-track"><div class="progress-fill" style="width:{safe_percent}%"></div></div>
    </div>"""


def pickup_action_forms(row, user):
    if user["role"] not in {"collector", "admin"}:
        return ""
    pickup_id = h(row["id"])
    can_work = row["status"] in {"approved", "assigned"}
    if not can_work:
        return ""
    return f"""
    <div class="quick-actions">
        <form method="post" action="/pickups/start">
            <input type="hidden" name="id" value="{pickup_id}">
            <button class="btn btn-small" type="submit">Start</button>
        </form>
        <form method="post" action="/pickups/quick-collect">
            <input type="hidden" name="id" value="{pickup_id}">
            <button class="btn btn-small btn-primary" type="submit">Collected</button>
        </form>
        <form method="post" action="/pickups/report-issue">
            <input type="hidden" name="id" value="{pickup_id}">
            <button class="btn btn-small btn-danger" type="submit">Issue</button>
        </form>
    </div>"""


def pickup_cards(rows, user, collectors=None, allow_admin_update=False):
    if not rows:
        return empty_state("No pickup jobs here.")
    collectors = collectors or []
    cards = []
    for row in rows:
        destination = row["destination_name"] if "destination_name" in row.keys() else ""
        collector = row["collector_name"] if "collector_name" in row.keys() else ""
        admin_update = ""
        if allow_admin_update and user["role"] == "admin":
            admin_update = f"""
            <form method="post" action="/pickups/update" class="pickup-card-update">
                <input type="hidden" name="id" value="{h(row['id'])}">
                <select name="status">{options(PICKUP_STATUSES, row['status'])}</select>
                <select name="assigned_collector_user_id">
                    <option value="">Unassigned</option>
                    {options(collectors, row['assigned_collector_user_id'], lambda item: item['name'], lambda item: item['id'])}
                </select>
                <button class="btn btn-small" type="submit">Save</button>
            </form>"""
        cards.append(
            f"""
            <article class="pickup-card">
                <div class="pickup-card-top">
                    <span class="pickup-id">#{h(row['id'])}</span>
                    {status_badge(row['status'])}
                </div>
                <h3>{h(row['source_name'])}</h3>
                <div class="pickup-facts">
                    <span><strong>{kg(row['estimated_organic_kg'])}</strong> estimated</span>
                    <span>{h(row['requested_pickup_date'])}</span>
                    <span>{h(labelize(row['request_type']))}</span>
                </div>
                <dl class="compact-dl">
                    <div><dt>Destination</dt><dd>{h(destination or 'Not set')}</dd></div>
                    <div><dt>Collector</dt><dd>{h(collector or 'Unassigned')}</dd></div>
                    <div><dt>Notes</dt><dd>{h(row['notes'] or '-')}</dd></div>
                </dl>
                {pickup_action_forms(row, user)}
                {admin_update}
            </article>"""
        )
    return '<div class="pickup-card-grid">' + "".join(cards) + "</div>"


def pickup_board(rows, user, collectors=None):
    groups = [
        ("pending", "Pending"),
        ("approved", "Assigned"),
        ("collected", "Collected"),
        ("failed", "Issues"),
    ]
    columns = []
    for key, label in groups:
        if key == "approved":
            filtered = [row for row in rows if row["status"] in {"approved", "assigned"}]
        elif key == "failed":
            filtered = [row for row in rows if row["status"] in {"failed", "cancelled"}]
        else:
            filtered = [row for row in rows if row["status"] == key]
        columns.append(
            f"""
            <section class="board-column">
                <div class="board-column-head">
                    <h3>{h(label)}</h3>
                    <span>{len(filtered)}</span>
                </div>
                {pickup_cards(filtered, user, collectors, allow_admin_update=(user['role'] == 'admin'))}
            </section>"""
        )
    return '<div class="pickup-board">' + "".join(columns) + "</div>"


def source_scope_clause(user, alias="ws"):
    if user["role"] == "vendor":
        return f" AND {alias}.assigned_vendor_user_id = ?", [user["id"]]
    return "", []


def sabah_project(latitude, longitude):
    min_lon, max_lon = 115.0, 119.4
    min_lat, max_lat = 4.0, 7.4
    x = ((float(longitude) - min_lon) / (max_lon - min_lon)) * 100
    y = ((max_lat - float(latitude)) / (max_lat - min_lat)) * 100
    return max(4, min(96, x)), max(6, min(94, y))


def dashboard_marker_bounds(coordinates):
    if not coordinates:
        return 4.0, 7.4, 115.0, 119.4
    latitudes = [item[0] for item in coordinates]
    longitudes = [item[1] for item in coordinates]
    min_lat, max_lat = min(latitudes), max(latitudes)
    min_lng, max_lng = min(longitudes), max(longitudes)
    lat_pad = max((max_lat - min_lat) * 0.28, 0.018)
    lng_pad = max((max_lng - min_lng) * 0.28, 0.018)
    return min_lat - lat_pad, max_lat + lat_pad, min_lng - lng_pad, max_lng + lng_pad


def dashboard_marker_project(latitude, longitude, bounds):
    min_lat, max_lat, min_lng, max_lng = bounds
    lat_span = max(max_lat - min_lat, 0.001)
    lng_span = max(max_lng - min_lng, 0.001)
    x = ((float(longitude) - min_lng) / lng_span) * 100
    y = ((max_lat - float(latitude)) / lat_span) * 100
    return max(7, min(93, x)), max(8, min(82, y))


def dashboard_marker_position(latitude, longitude, bounds, slots):
    x, y = dashboard_marker_project(latitude, longitude, bounds)
    key = (round(x / 4), round(y / 4))
    slot = slots.get(key, 0)
    slots[key] = slot + 1
    offsets = [
        (0, 0),
        (3.2, -3.0),
        (-3.2, 3.0),
        (3.2, 3.0),
        (-3.2, -3.0),
        (0, 4.0),
        (4.0, 0),
        (-4.0, 0),
    ]
    offset_x, offset_y = offsets[slot % len(offsets)]
    return max(7, min(93, x + offset_x)), max(8, min(82, y + offset_y))


def sabah_dashboard_map(user):
    with db() as conn:
        if user["role"] == "vendor":
            sources = conn.execute(
                """
                SELECT ws.*, d.destination_name, d.address AS destination_address,
                       d.latitude AS destination_latitude, d.longitude AS destination_longitude
                FROM waste_sources ws
                LEFT JOIN destinations d ON d.id=ws.default_destination_id
                WHERE ws.assigned_vendor_user_id=?
                ORDER BY ws.source_name
                """,
                (user["id"],),
            ).fetchall()
        elif user["role"] == "collector":
            sources = conn.execute(
                """
                SELECT DISTINCT ws.*, d.destination_name, d.address AS destination_address,
                       d.latitude AS destination_latitude, d.longitude AS destination_longitude
                FROM waste_sources ws
                JOIN pickup_requests pr ON pr.waste_source_id=ws.id
                LEFT JOIN destinations d ON d.id=ws.default_destination_id
                WHERE pr.assigned_collector_user_id=?
                ORDER BY ws.source_name
                """,
                (user["id"],),
            ).fetchall()
        else:
            sources = conn.execute(
                """
                SELECT ws.*, d.destination_name, d.address AS destination_address,
                       d.latitude AS destination_latitude, d.longitude AS destination_longitude
                FROM waste_sources ws
                LEFT JOIN destinations d ON d.id=ws.default_destination_id
                ORDER BY ws.status DESC, ws.source_name
                """
            ).fetchall()
        destination_ids = sorted(
            {row["default_destination_id"] for row in sources if row["default_destination_id"]}
        )
        destination_where = "WHERE d.is_active=1"
        destination_params = []
        if user["role"] != "admin":
            if destination_ids:
                placeholders = ",".join("?" for _ in destination_ids)
                destination_where = f"WHERE d.is_active=1 AND d.id IN ({placeholders})"
                destination_params = destination_ids
            else:
                destination_where = "WHERE 1=0"
        destinations = conn.execute(
            f"""
            SELECT d.*,
                   (
                       SELECT ROUND(COALESCE(SUM(ci.received_weight_kg), 0), 1)
                       FROM compost_intakes ci
                       WHERE ci.destination_id=d.id
                   ) AS received_kg,
                   (
                       SELECT ROUND(COALESCE(SUM(co.compost_output_kg), 0), 1)
                       FROM compost_outputs co
                       JOIN compost_intakes ci ON ci.id=co.compost_intake_id
                       WHERE ci.destination_id=d.id
                   ) AS output_kg
            FROM destinations d
            {destination_where}
            ORDER BY d.destination_name
            """,
            destination_params,
        ).fetchall()
        latest = latest_compliance_by_source(conn)
        active_pickups = {
            row["waste_source_id"]: row["total"]
            for row in conn.execute(
                """
                SELECT waste_source_id, COUNT(*) AS total
                FROM pickup_requests
                WHERE status IN ('pending','approved','assigned')
                GROUP BY waste_source_id
                """
            ).fetchall()
        }
        collected_totals = {
            row["waste_source_id"]: row["kg"]
            for row in conn.execute(
                """
                SELECT pr.waste_source_id, ROUND(SUM(c.actual_organic_kg), 1) AS kg
                FROM collections c
                JOIN pickup_requests pr ON pr.id=c.pickup_request_id
                GROUP BY pr.waste_source_id
                """
            ).fetchall()
        }
        attention_rows = conn.execute(
            """
            SELECT pr.*, ws.source_name, d.destination_name, u.name AS collector_name
            FROM pickup_requests pr
            JOIN waste_sources ws ON ws.id=pr.waste_source_id
            LEFT JOIN destinations d ON d.id=ws.default_destination_id
            LEFT JOIN users u ON u.id=pr.assigned_collector_user_id
            WHERE pr.status IN ('pending','approved','assigned','failed')
            ORDER BY
                CASE pr.status
                    WHEN 'failed' THEN 1
                    WHEN 'pending' THEN 2
                    WHEN 'approved' THEN 3
                    WHEN 'assigned' THEN 4
                    ELSE 5
                END,
                pr.requested_pickup_date ASC
            """
        ).fetchall()

    attention_by_source = {}
    for item in attention_rows:
        attention_by_source.setdefault(item["waste_source_id"], []).append(item)
    source_cards = []
    destination_cards = []
    marker_buttons = []
    popup_templates = []
    mapped_count = 0
    mapped_destination_count = 0
    pickup_need_count = 0
    total_estimated = 0
    mapped_coordinates = []
    stage_coordinates = []
    for source in sources:
        if source["latitude"] is not None and source["longitude"] is not None:
            stage_coordinates.append((float(source["latitude"]), float(source["longitude"])))
    for destination in destinations:
        if destination["latitude"] is not None and destination["longitude"] is not None:
            stage_coordinates.append((float(destination["latitude"]), float(destination["longitude"])))
    marker_bounds = dashboard_marker_bounds(stage_coordinates)
    marker_slots = {}
    for source in sources:
        total_estimated += float(source["estimated_organic_kg_per_day"] or 0)
        compliance = latest.get(source["id"])
        compliance_status = compliance["segregation_status"] if compliance else "pending"
        pickup_count = active_pickups.get(source["id"], 0)
        attention_items = attention_by_source.get(source["id"], [])
        if pickup_count:
            pickup_need_count += 1
        query = map_query(source["source_name"], source["address"], source["latitude"], source["longitude"])
        if source["latitude"] is not None and source["longitude"] is not None:
            mapped_count += 1
            mapped_coordinates.append((float(source["latitude"]), float(source["longitude"])))
        destination_query = None
        if source["destination_name"]:
            destination_query = map_query(
                source["destination_name"],
                source["destination_address"],
                source["destination_latitude"],
                source["destination_longitude"],
            )
        route_link = (
            f'<a class="btn btn-small" target="_blank" rel="noopener" href="{h(google_directions_url(query, destination_query))}">Route to Site</a>'
            if destination_query
            else ""
        )
        if attention_items:
            marker_kind = "pickup"
            marker_icon = "!"
            marker_label = "Active pickup need"
        elif compliance_status == "compliant":
            marker_kind = "compliant"
            marker_icon = "C"
            marker_label = "Compliant"
        else:
            marker_kind = "partial"
            marker_icon = "P"
            marker_label = "Partial / pending"
        pickup_attention_html = "".join(
            f"""
            <article class="ops-attention-item">
                <div>{status_badge(item['status'])}</div>
                <strong>#{h(item['id'])} - {h(item['requested_pickup_date'])}</strong>
                <span>{kg(item['estimated_organic_kg'])} estimated</span>
                <small>Collector: {h(item['collector_name'] or 'Unassigned')}</small>
                <small>Notes: {h(item['notes'] or '-')}</small>
            </article>
            """
            for item in attention_items
        )
        if not pickup_attention_html:
            pickup_attention_html = '<p class="ops-popup-muted">No active pickup attention for this source.</p>'
        compliance_detail = (
            f"{h(labelize(compliance_status))} on {h(compliance['inspection_date'])}"
            if compliance
            else "No inspection record yet"
        )
        source_popup_id = f"ops-popup-source-{source['id']}"
        popup_templates.append(
            f"""
            <template id="{h(source_popup_id)}">
                <div class="ops-popup-head">
                    <span class="ops-popup-icon ops-marker-{h(marker_kind)}">{h(marker_icon)}</span>
                    <div>
                        <strong>{h(marker_label)}</strong>
                        <h3>{h(source['source_name'])}</h3>
                        <p>{h(labelize(source['source_type']))} - {h(source['zone'])}</p>
                    </div>
                </div>
                <dl class="compact-dl ops-popup-facts">
                    <div><dt>Segregation</dt><dd>{status_badge(compliance_status)}</dd></div>
                    <div><dt>Inspection</dt><dd>{compliance_detail}</dd></div>
                    <div><dt>Pickup attention</dt><dd>{h(len(attention_items))} item(s)</dd></div>
                    <div><dt>Organic estimate</dt><dd>{kg(source['estimated_organic_kg_per_day'])}/day</dd></div>
                    <div><dt>Collected</dt><dd>{kg(collected_totals.get(source['id'], 0))}</dd></div>
                    <div><dt>Compost site</dt><dd>{h(source['destination_name'] or 'Unassigned')}</dd></div>
                </dl>
                <div class="ops-attention-list">
                    <h4>Attention Information</h4>
                    {pickup_attention_html}
                </div>
                <div class="map-actions">
                    <a class="btn btn-small" href="/sources?edit={h(source['id'])}">Source Details</a>
                    <a class="btn btn-small" href="/pickups">Pickup Board</a>
                    <a class="btn btn-small" href="/compliance">Segregation</a>
                    <a class="btn btn-small" target="_blank" rel="noopener" href="{h(google_open_url(query))}">Open Google Map</a>
                    {route_link}
                </div>
            </template>
            """
        )
        if source["latitude"] is not None and source["longitude"] is not None:
            marker_x, marker_y = dashboard_marker_position(source["latitude"], source["longitude"], marker_bounds, marker_slots)
            marker_count = f'<span class="ops-marker-count">{h(len(attention_items))}</span>' if attention_items else ""
            marker_buttons.append(
                f"""
                <button class="ops-map-marker ops-marker-{h(marker_kind)} map-select" type="button"
                    style="--x: {marker_x:.2f}%; --y: {marker_y:.2f}%;"
                    data-map-url="{h(google_embed_url(query))}"
                    data-popup-target="{h(source_popup_id)}"
                    data-popup-kind="{h(marker_kind)}"
                    aria-label="{h(source['source_name'])}: {h(marker_label)}">
                    <span class="ops-marker-symbol">{h(marker_icon)}</span>
                    {marker_count}
                </button>
                """
            )
        source_cards.append(
            f"""
            <article class="sabah-location-card" data-location-type="source">
                <div class="map-card-head">
                    <span class="map-pin map-pin-source">Waste Source</span>
                    {status_badge(compliance_status)}
                </div>
                <div>
                    <h3>{h(source['source_name'])}</h3>
                    <p>{h(labelize(source['source_type']))} - {h(source['zone'])}</p>
                </div>
                <dl>
                    <div><dt>Status</dt><dd>{status_badge(compliance_status)}</dd></div>
                    <div><dt>Pickup need</dt><dd>{h(pickup_count)} active</dd></div>
                    <div><dt>Organic estimate</dt><dd>{kg(source['estimated_organic_kg_per_day'])}/day</dd></div>
                    <div><dt>Collected</dt><dd>{kg(collected_totals.get(source['id'], 0))}</dd></div>
                    <div><dt>Destination</dt><dd>{h(source['destination_name'] or 'Unassigned')}</dd></div>
                </dl>
                <div class="map-actions">
                    <button class="btn btn-small map-select" type="button" data-map-url="{h(google_embed_url(query))}" data-popup-target="{h(source_popup_id)}" data-popup-kind="{h(marker_kind)}">Show on map</button>
                    <a class="btn btn-small" target="_blank" rel="noopener" href="{h(google_open_url(query))}">Open Google Map</a>
                    {route_link}
                    <a class="btn btn-small" href="/sources?edit={h(source['id'])}">Source Details</a>
                    <a class="btn btn-small" href="/pickups">Pickup Board</a>
                </div>
            </article>
            """
        )

    for destination in destinations:
        query = map_query(
            destination["destination_name"],
            destination["address"],
            destination["latitude"],
            destination["longitude"],
        )
        if destination["latitude"] is not None and destination["longitude"] is not None:
            mapped_destination_count += 1
            mapped_coordinates.append((float(destination["latitude"]), float(destination["longitude"])))
        destination_popup_id = f"ops-popup-destination-{destination['id']}"
        popup_templates.append(
            f"""
            <template id="{h(destination_popup_id)}">
                <div class="ops-popup-head">
                    <span class="ops-popup-icon ops-marker-destination">S</span>
                    <div>
                        <strong>Compost site</strong>
                        <h3>{h(destination['destination_name'])}</h3>
                        <p>{h(labelize(destination['destination_type']))}</p>
                    </div>
                </div>
                <dl class="compact-dl ops-popup-facts">
                    <div><dt>Address</dt><dd>{h(destination['address'] or '-')}</dd></div>
                    <div><dt>Received intake</dt><dd>{kg(destination['received_kg'])}</dd></div>
                    <div><dt>Compost output</dt><dd>{kg(destination['output_kg'])}</dd></div>
                    <div><dt>Contact</dt><dd>{h(destination['contact_person'] or '-')}</dd></div>
                    <div><dt>Phone</dt><dd>{h(destination['contact_phone'] or '-')}</dd></div>
                </dl>
                <div class="ops-attention-list">
                    <h4>Site Information</h4>
                    <article class="ops-attention-item">
                        <div><span class="badge badge-active">Active</span></div>
                        <strong>{kg(destination['received_kg'])} received for composting</strong>
                        <span>{kg(destination['output_kg'])} compost output recorded</span>
                        <small>Coordinates: {h(coordinate_pair(destination) or 'Not set')}</small>
                    </article>
                </div>
                <div class="map-actions">
                    <a class="btn btn-small" href="/destinations?edit={h(destination['id'])}">Site Details</a>
                    <a class="btn btn-small" href="/reports">Reports</a>
                    <a class="btn btn-small" target="_blank" rel="noopener" href="{h(google_open_url(query))}">Open Google Map</a>
                </div>
            </template>
            """
        )
        if destination["latitude"] is not None and destination["longitude"] is not None:
            marker_x, marker_y = dashboard_marker_position(destination["latitude"], destination["longitude"], marker_bounds, marker_slots)
            marker_buttons.append(
                f"""
                <button class="ops-map-marker ops-marker-destination map-select" type="button"
                    style="--x: {marker_x:.2f}%; --y: {marker_y:.2f}%;"
                    data-map-url="{h(google_embed_url(query))}"
                    data-popup-target="{h(destination_popup_id)}"
                    data-popup-kind="destination"
                    aria-label="{h(destination['destination_name'])}: Compost site">
                    <span class="ops-marker-symbol">S</span>
                </button>
                """
            )
        destination_cards.append(
            f"""
            <article class="sabah-location-card destination-card" data-location-type="destination">
                <div class="map-card-head">
                    <span class="map-pin map-pin-destination">Compost Site</span>
                    <span class="badge badge-active">Active</span>
                </div>
                <div>
                    <h3>{h(destination['destination_name'])}</h3>
                    <p>{h(labelize(destination['destination_type']))}</p>
                </div>
                <dl>
                    <div><dt>Address</dt><dd>{h(destination['address'] or '-')}</dd></div>
                    <div><dt>Received</dt><dd>{kg(destination['received_kg'])}</dd></div>
                    <div><dt>Compost output</dt><dd>{kg(destination['output_kg'])}</dd></div>
                    <div><dt>Contact</dt><dd>{h(destination['contact_person'] or '-')}</dd></div>
                    <div><dt>Coordinates</dt><dd>{h(coordinate_pair(destination) or 'Not set')}</dd></div>
                </dl>
                <div class="map-actions">
                    <button class="btn btn-small map-select" type="button" data-map-url="{h(google_embed_url(query))}" data-popup-target="{h(destination_popup_id)}" data-popup-kind="destination">Show on map</button>
                    <a class="btn btn-small" target="_blank" rel="noopener" href="{h(google_open_url(query))}">Open Google Map</a>
                    <a class="btn btn-small" href="/destinations?edit={h(destination['id'])}">Site Details</a>
                    <a class="btn btn-small" href="/reports">Reports</a>
                </div>
            </article>
            """
        )

    if mapped_coordinates:
        avg_lat = sum(item[0] for item in mapped_coordinates) / len(mapped_coordinates)
        avg_lng = sum(item[1] for item in mapped_coordinates) / len(mapped_coordinates)
        overview_query = f"{avg_lat:.6f},{avg_lng:.6f}"
        overview_map_url = google_embed_url(overview_query, 12)
    else:
        overview_query = "Sabah Malaysia"
        overview_map_url = google_embed_url(overview_query, 8)
    source_html = "".join(source_cards) if source_cards else empty_state("No organic waste collection sources available.")
    destination_html = "".join(destination_cards) if destination_cards else empty_state("No compost destinations available.")
    marker_html = "".join(marker_buttons) if marker_buttons else '<div class="ops-map-empty">No mapped operation icons yet.</div>'
    popup_template_html = "".join(popup_templates)
    return f"""
    <section class="sabah-dashboard">
        <div class="sabah-map-panel">
            <div class="panel-heading">
                <h2>Dashboard Operations Map</h2>
                <p>Live Google Maps view connected to sources, pickups, segregation, collections, and compost destinations.</p>
            </div>
            <div class="sabah-map-stage google-dashboard-stage" aria-label="Google map of Sabah organic waste source locations">
                <iframe id="googleMapFrame" class="dashboard-google-map-frame" title="Google map of organic collection locations" loading="lazy" referrerpolicy="no-referrer-when-downgrade" src="{h(overview_map_url)}"></iframe>
                <div class="ops-map-marker-layer" aria-label="Clickable operation status markers">
                    {marker_html}
                </div>
                <div id="opsMapPopup" class="ops-map-popup" hidden>
                    <button class="ops-popup-close" type="button" aria-label="Close map details">x</button>
                    <div class="ops-map-popup-body"></div>
                </div>
                <div class="ops-map-popup-templates" hidden>{popup_template_html}</div>
                <div class="google-map-toolbar">
                    <button class="btn btn-small map-select" type="button" data-map-url="{h(overview_map_url)}">Show Sabah Overview</button>
                    <a class="btn btn-small" target="_blank" rel="noopener" href="{h(google_open_url(overview_query))}">Open in Google Maps</a>
                </div>
            </div>
            <div class="sabah-legend">
                <span><i class="legend-dot legend-pickup"></i> Active pickup need</span>
                <span><i class="legend-dot legend-compliant"></i> Compliant</span>
                <span><i class="legend-dot legend-partial"></i> Partial / pending</span>
                <span><i class="legend-dot legend-destination"></i> Compost site</span>
            </div>
        </div>
        <aside class="sabah-overview-panel">
            <div class="sabah-stat-grid four">
                <article><span>Mapped Sources</span><strong>{h(mapped_count)}</strong></article>
                <article><span>Need Collection</span><strong>{h(pickup_need_count)}</strong></article>
                <article><span>Compost Sites</span><strong>{h(mapped_destination_count)}</strong></article>
                <article><span>Daily Organic Estimate</span><strong>{kg(total_estimated)}</strong></article>
            </div>
            <div class="sabah-location-list">
                <section class="sabah-location-group">
                    <h3>Waste Sources</h3>
                    <div class="sabah-location-stack">{source_html}</div>
                </section>
                <section class="sabah-location-group">
                    <h3>Compost Destinations</h3>
                    <div class="sabah-location-stack">{destination_html}</div>
                </section>
            </div>
        </aside>
    </section>
    """


def page_dashboard(user):
    if user["role"] == "admin":
        with db() as conn:
            totals = conn.execute(
                """
                SELECT
                    COUNT(*) AS sources,
                    SUM(CASE WHEN status='active' THEN 1 ELSE 0 END) AS active_sources,
                    COALESCE(SUM(estimated_organic_kg_per_day), 0) AS estimated_daily_organic,
                    COALESCE(SUM(estimated_recyclable_kg_per_day), 0) AS estimated_daily_recyclable
                FROM waste_sources
                """
            ).fetchone()
            pickup_counts = conn.execute(
                """
                SELECT status, COUNT(*) AS count
                FROM pickup_requests
                GROUP BY status
                """
            ).fetchall()
            collected = conn.execute("SELECT COALESCE(SUM(actual_organic_kg),0) AS total FROM collections").fetchone()["total"]
            delivered = conn.execute(
                """
                SELECT COALESCE(SUM(received_weight_kg),0) AS total
                FROM compost_intakes
                WHERE acceptance_status IN ('accepted','partial')
                """
            ).fetchone()["total"]
            compost = conn.execute("SELECT COALESCE(SUM(compost_output_kg),0) AS total FROM compost_outputs").fetchone()["total"]
            contamination = conn.execute("SELECT COUNT(*) AS total FROM collections WHERE contamination_flag=1").fetchone()["total"]
            missed = conn.execute("SELECT COUNT(*) AS total FROM pickup_requests WHERE status='failed'").fetchone()["total"]
            latest = latest_compliance_by_source(conn)
            compliance_counts = {status: 0 for status in COMPLIANCE_STATUSES}
            for row in latest.values():
                compliance_counts[row["segregation_status"]] = compliance_counts.get(row["segregation_status"], 0) + 1
            monthly = conn.execute(
                """
                SELECT substr(collected_at, 1, 7) AS month, ROUND(SUM(actual_organic_kg), 1) AS kg
                FROM collections
                GROUP BY substr(collected_at, 1, 7)
                ORDER BY month DESC
                LIMIT 6
                """
            ).fetchall()
            pending_jobs = conn.execute(
                """
                SELECT pr.*, ws.source_name, d.destination_name, u.name AS collector_name
                FROM pickup_requests pr
                JOIN waste_sources ws ON ws.id=pr.waste_source_id
                LEFT JOIN destinations d ON d.id=ws.default_destination_id
                LEFT JOIN users u ON u.id=pr.assigned_collector_user_id
                WHERE pr.status IN ('pending','approved','assigned','failed')
                ORDER BY
                    CASE pr.status
                        WHEN 'failed' THEN 1
                        WHEN 'pending' THEN 2
                        WHEN 'approved' THEN 3
                        WHEN 'assigned' THEN 4
                        ELSE 5
                    END,
                    pr.requested_pickup_date ASC
                LIMIT 8
                """
            ).fetchall()
            top_sources = conn.execute(
                """
                SELECT id, source_name, source_type, zone, estimated_organic_kg_per_day
                FROM waste_sources
                ORDER BY estimated_organic_kg_per_day DESC
                LIMIT 5
                """
            ).fetchall()
            compost_sites = conn.execute(
                """
                SELECT d.destination_name AS site, ROUND(COALESCE(SUM(ci.received_weight_kg), 0), 1) AS kg
                FROM destinations d
                LEFT JOIN compost_intakes ci ON ci.destination_id=d.id
                GROUP BY d.id
                ORDER BY kg DESC, d.destination_name
                LIMIT 5
                """
            ).fetchall()
            pickup_map = {row["status"]: row["count"] for row in pickup_counts}
        metrics = "".join(
            [
                metric_card("Organic Collected", kg(collected), "Organic waste picked up", "green"),
                metric_card("Diverted From Landfill", kg(delivered), "Accepted compost-site intake", "teal"),
                metric_card("Compliant Vendors", compliance_counts.get("compliant", 0), "Latest inspection status", "blue"),
                metric_card("Pending Pickups", pickup_map.get("pending", 0) + pickup_map.get("approved", 0) + pickup_map.get("assigned", 0), "Needs action", "rose"),
            ]
        )
        compliance_rows = [
            {"label": labelize(key), "value": value}
            for key, value in compliance_counts.items()
        ]
        risk_cards = []
        for source in top_sources:
            comp = latest.get(source["id"])
            status = comp["segregation_status"] if comp else "pending"
            risk_cards.append(
                f"""
                <article class="ops-card">
                    <div>{status_badge(status)}</div>
                    <h3>{h(source['source_name'])}</h3>
                    <p>{h(labelize(source['source_type']))} - {h(source['zone'])}</p>
                    <strong>{kg(source['estimated_organic_kg_per_day'])}/day</strong>
                </article>"""
            )
        body = f"""
        <section class="metrics-grid four">{metrics}</section>
        {sabah_dashboard_map(user)}
        <section class="content-grid two">
            <div class="panel">
                <div class="panel-heading compact-heading">
                    <h2>Top Waste Sources</h2>
                    <p>Highest estimated organic waste generators.</p>
                </div>
                <div class="ops-card-list">{''.join(risk_cards)}</div>
            </div>
            <div class="panel">
                <div class="panel-heading compact-heading">
                    <h2>Segregation</h2>
                    <p>Latest vendor inspection status.</p>
                </div>
                {bar_chart(compliance_rows, "label", "value", "amber")}
            </div>
        </section>
        <section class="content-grid two">
            <div class="panel">
                <div class="panel-heading compact-heading">
                    <h2>Compost Site Intake</h2>
                    <p>Where organic waste has been received.</p>
                </div>
                {bar_chart(compost_sites, "site", "kg", "green")}
            </div>
        </section>
        """
        return layout(user, "dashboard", "Dashboard", body)

    if user["role"] == "vendor":
        with db() as conn:
            sources = conn.execute(
                "SELECT * FROM waste_sources WHERE assigned_vendor_user_id=? ORDER BY source_name",
                (user["id"],),
            ).fetchall()
            source_ids = [row["id"] for row in sources] or [-1]
            placeholders = ",".join("?" for _ in source_ids)
            pickups = conn.execute(
                f"""
                SELECT pr.*, ws.source_name
                FROM pickup_requests pr
                JOIN waste_sources ws ON ws.id=pr.waste_source_id
                WHERE pr.waste_source_id IN ({placeholders})
                ORDER BY pr.requested_pickup_date DESC, pr.id DESC
                LIMIT 8
                """,
                source_ids,
            ).fetchall()
            next_pickup = conn.execute(
                f"""
                SELECT pr.*, ws.source_name
                FROM pickup_requests pr
                JOIN waste_sources ws ON ws.id=pr.waste_source_id
                WHERE pr.waste_source_id IN ({placeholders})
                  AND pr.status IN ('pending','approved','assigned')
                ORDER BY pr.requested_pickup_date ASC
                LIMIT 1
                """,
                source_ids,
            ).fetchone()
            latest = latest_compliance_by_source(conn)
        source_cards = []
        for source in sources:
            comp = latest.get(source["id"])
            source_cards.append(
                f"""
                <article class="source-summary">
                    <h3>{h(source['source_name'])}</h3>
                    <p>{h(labelize(source['source_type']))} - {h(source['zone'])}</p>
                    <div>{status_badge(comp['segregation_status'] if comp else 'pending')}</div>
                    <small>Organic estimate: {kg(source['estimated_organic_kg_per_day'])}/day</small>
                </article>
                """
            )
        rows = pickup_table(pickups, show_source=True, show_collector=False, editable=False, user=user)
        next_html = (
            f"{h(next_pickup['requested_pickup_date'])} for {h(next_pickup['source_name'])} ({h(labelize(next_pickup['status']))})"
            if next_pickup
            else "No upcoming pickup scheduled yet."
        )
        total_vendor_organic = sum(float(source["estimated_organic_kg_per_day"] or 0) for source in sources)
        primary_compliance = latest.get(sources[0]["id"]) if sources else None
        primary_status = primary_compliance["segregation_status"] if primary_compliance else "pending"
        compliance_percent = {
            "compliant": 100,
            "partially_compliant": 70,
            "pending": 35,
            "non_compliant": 20,
        }.get(primary_status, 0)
        body = f"""
        <section class="role-action-grid vendor-home">
            <article class="action-card action-green">
                <span class="action-kicker">Organic Waste Ready</span>
                <h2>{kg(total_vendor_organic)}</h2>
                <p>Estimated daily organic waste from your registered source.</p>
                <a class="btn btn-primary" href="/pickups">Request Pickup</a>
            </article>
            <article class="action-card action-amber">
                <span class="action-kicker">Segregation Check</span>
                <h2>{h(labelize(primary_status))}</h2>
                {progress_bar(compliance_percent, "Readiness")}
                <a class="btn" href="/recyclables">Update My Waste</a>
            </article>
            <article class="action-card action-blue">
                <span class="action-kicker">Next Collection</span>
                <h2>{next_html}</h2>
                <p>Keep compostable waste separated before pickup.</p>
                <a class="btn" href="/history">View History</a>
            </article>
        </section>
        <section class="content-grid two">
            <div class="panel">
                <div class="panel-heading compact-heading">
                    <h2>My Waste Sources</h2>
                    <p>Only your assigned vendor source is shown here.</p>
                </div>
                <div class="source-list">{''.join(source_cards) if source_cards else empty_state('No source assigned.')}</div>
            </div>
            <div class="panel">
                <div class="panel-heading compact-heading">
                    <h2>Recent Pickups</h2>
                    <p>Simple status view for your requests.</p>
                </div>
                {pickup_cards(pickups, user)}
            </div>
        </section>
        """
        return layout(user, "dashboard", "Vendor Dashboard", body)

    with db() as conn:
        assigned = conn.execute(
            """
            SELECT pr.*, ws.source_name, ws.zone
            FROM pickup_requests pr
            JOIN waste_sources ws ON ws.id=pr.waste_source_id
            WHERE pr.assigned_collector_user_id=?
              AND pr.status IN ('approved','assigned')
            ORDER BY pr.requested_pickup_date ASC
            """,
            (user["id"],),
        ).fetchall()
        pending_intakes = conn.execute(
            """
            SELECT c.*, ws.source_name, d.destination_name
            FROM collections c
            JOIN pickup_requests pr ON pr.id=c.pickup_request_id
            JOIN waste_sources ws ON ws.id=pr.waste_source_id
            LEFT JOIN destinations d ON d.id=c.destination_id
            LEFT JOIN compost_intakes ci ON ci.collection_id=c.id
            WHERE c.collected_by_user_id=? AND ci.id IS NULL
            ORDER BY c.collected_at DESC
            """,
            (user["id"],),
        ).fetchall()
    body = f"""
    <section class="role-action-grid collector-home">
        <article class="action-card action-green">
            <span class="action-kicker">Today's Pickups</span>
            <h2>{len(assigned)} jobs</h2>
            <p>Start, collect, or report an issue directly from each card.</p>
        </article>
        <article class="action-card action-amber">
            <span class="action-kicker">Delivery To Log</span>
            <h2>{len(pending_intakes)} loads</h2>
            <p>Collected organic waste still needs compost-site intake confirmation.</p>
            <a class="btn" href="/intakes">Log Delivery</a>
        </article>
    </section>
    <section class="content-grid two">
        <div class="panel">
            <div class="panel-heading compact-heading">
                <h2>Today's Jobs</h2>
                <p>Task board for assigned organic waste pickups.</p>
            </div>
            {pickup_cards(assigned, user)}
        </div>
        <div class="panel">
            <div class="panel-heading compact-heading">
                <h2>Delivery Queue</h2>
                <p>Collected loads that still need intake logging.</p>
            </div>
            {collection_table(pending_intakes, show_destination=True)}
        </div>
    </section>
    """
    return layout(user, "dashboard", "Collector Dashboard", body)


def pickup_table(rows, show_source=True, show_collector=True, editable=False, user=None, collectors=None):
    if not rows:
        return empty_state("No pickup requests found.")
    collectors = collectors or []
    body = []
    for row in rows:
        collector_cell = ""
        if show_collector:
            collector_name = row["collector_name"] if "collector_name" in row.keys() else ""
            collector_cell = f"<td>{h(collector_name or 'Unassigned')}</td>"
        action_cell = ""
        if editable and user and user["role"] == "admin":
            action_cell = f"""
            <td>
                <form method="post" action="/pickups/update" class="inline-form">
                    <input type="hidden" name="id" value="{h(row['id'])}">
                    <select name="status">{options(PICKUP_STATUSES, row['status'])}</select>
                    <select name="assigned_collector_user_id">
                        <option value="">Unassigned</option>
                        {options(collectors, row['assigned_collector_user_id'], lambda item: item['name'], lambda item: item['id'])}
                    </select>
                    <button class="btn btn-small" type="submit">Update</button>
                </form>
            </td>"""
        source_cell = f"<td>{h(row['source_name'])}</td>" if show_source else ""
        body.append(
            f"""
            <tr>
                <td>#{h(row['id'])}</td>
                {source_cell}
                <td>{h(labelize(row['request_type']))}</td>
                <td>{h(row['requested_pickup_date'])}</td>
                <td>{kg(row['estimated_organic_kg'])}</td>
                <td>{status_badge(row['status'])}</td>
                {collector_cell}
                <td>{h(row['notes'])}</td>
                {action_cell}
            </tr>"""
        )
    headers = ["ID"]
    if show_source:
        headers.append("Source")
    headers.extend(["Type", "Pickup Date", "Estimated Organic", "Status"])
    if show_collector:
        headers.append("Collector")
    headers.append("Notes")
    if editable:
        headers.append("Action")
    thead = "".join(f"<th>{h(item)}</th>" for item in headers)
    return f'<div class="table-wrap"><table><thead><tr>{thead}</tr></thead><tbody>{"".join(body)}</tbody></table></div>'


def collection_table(rows, show_destination=True):
    if not rows:
        return empty_state("No collection records found.")
    body = []
    for row in rows:
        destination = ""
        if show_destination:
            destination = f"<td>{h(row['destination_name'] if 'destination_name' in row.keys() else '')}</td>"
        body.append(
            f"""
            <tr>
                <td>#{h(row['id'])}</td>
                <td>{h(row['source_name'] if 'source_name' in row.keys() else '')}</td>
                <td>{h(row['collected_at'])}</td>
                <td>{kg(row['actual_organic_kg'])}</td>
                <td>{yes_no(row['contamination_flag'])}</td>
                {destination}
                <td>{status_badge(row['delivery_status'])}</td>
                <td>{h(row['contamination_notes'])}</td>
            </tr>"""
        )
    destination_header = "<th>Destination</th>" if show_destination else ""
    return f"""
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>ID</th><th>Source</th><th>Collected At</th><th>Actual Organic</th>
                    <th>Contamination</th>{destination_header}<th>Delivery</th><th>Notes</th>
                </tr>
            </thead>
            <tbody>{''.join(body)}</tbody>
        </table>
    </div>"""


def page_map(user):
    with db() as conn:
        if user["role"] == "vendor":
            sources = conn.execute(
                """
                SELECT ws.*, d.destination_name, d.latitude AS destination_latitude,
                       d.longitude AS destination_longitude, d.address AS destination_address
                FROM waste_sources ws
                LEFT JOIN destinations d ON d.id=ws.default_destination_id
                WHERE ws.assigned_vendor_user_id=?
                ORDER BY ws.source_name
                """,
                (user["id"],),
            ).fetchall()
        elif user["role"] == "collector":
            sources = conn.execute(
                """
                SELECT DISTINCT ws.*, d.destination_name, d.latitude AS destination_latitude,
                       d.longitude AS destination_longitude, d.address AS destination_address
                FROM waste_sources ws
                JOIN pickup_requests pr ON pr.waste_source_id=ws.id
                LEFT JOIN destinations d ON d.id=ws.default_destination_id
                WHERE pr.assigned_collector_user_id=?
                ORDER BY ws.source_name
                """,
                (user["id"],),
            ).fetchall()
        else:
            sources = conn.execute(
                """
                SELECT ws.*, d.destination_name, d.latitude AS destination_latitude,
                       d.longitude AS destination_longitude, d.address AS destination_address
                FROM waste_sources ws
                LEFT JOIN destinations d ON d.id=ws.default_destination_id
                ORDER BY ws.status DESC, ws.source_name
                """
            ).fetchall()
        destinations = conn.execute(
            """
            SELECT *
            FROM destinations
            WHERE is_active=1
            ORDER BY destination_name
            """
        ).fetchall()
        latest = latest_compliance_by_source(conn)
        active_pickups = {
            row["waste_source_id"]: row["total"]
            for row in conn.execute(
                """
                SELECT waste_source_id, COUNT(*) AS total
                FROM pickup_requests
                WHERE status IN ('pending','approved','assigned')
                GROUP BY waste_source_id
                """
            ).fetchall()
        }
        collected_totals = {
            row["waste_source_id"]: row["kg"]
            for row in conn.execute(
                """
                SELECT pr.waste_source_id, ROUND(SUM(c.actual_organic_kg), 1) AS kg
                FROM collections c
                JOIN pickup_requests pr ON pr.id=c.pickup_request_id
                GROUP BY pr.waste_source_id
                """
            ).fetchall()
        }

    cards = []
    first_query = None
    source_count = 0
    destination_count = 0
    for row in sources:
        query = map_query(row["source_name"], row["address"], row["latitude"], row["longitude"])
        first_query = first_query or query
        compliance = latest.get(row["id"])
        destination_query = None
        if row["destination_name"]:
            destination_query = map_query(
                row["destination_name"],
                row["destination_address"],
                row["destination_latitude"],
                row["destination_longitude"],
            )
        route_link = (
            f'<a class="btn btn-small" target="_blank" rel="noopener" href="{h(google_directions_url(query, destination_query))}">Route</a>'
            if destination_query
            else ""
        )
        cards.append(
            f"""
            <article class="map-card" data-location-type="source">
                <div class="map-card-head">
                    <span class="map-pin map-pin-source">Source</span>
                    {status_badge(compliance['segregation_status'] if compliance else 'pending')}
                </div>
                <h3>{h(row['source_name'])}</h3>
                <p>{h(labelize(row['source_type']))} - {h(row['zone'])}</p>
                <dl>
                    <div><dt>Organic estimate</dt><dd>{kg(row['estimated_organic_kg_per_day'])}/day</dd></div>
                    <div><dt>Recyclable estimate</dt><dd>{kg(row['estimated_recyclable_kg_per_day'])}/day</dd></div>
                    <div><dt>Active pickups</dt><dd>{h(active_pickups.get(row['id'], 0))}</dd></div>
                    <div><dt>Collected total</dt><dd>{kg(collected_totals.get(row['id'], 0))}</dd></div>
                    <div><dt>Destination</dt><dd>{h(row['destination_name'] or 'Unassigned')}</dd></div>
                </dl>
                <div class="map-actions">
                    <button class="btn btn-small map-select" type="button" data-map-url="{h(google_embed_url(query))}">Show on map</button>
                    <a class="btn btn-small" target="_blank" rel="noopener" href="{h(google_open_url(query))}">Open</a>
                    {route_link}
                </div>
            </article>
            """
        )
        source_count += 1

    for row in destinations:
        query = map_query(row["destination_name"], row["address"], row["latitude"], row["longitude"])
        first_query = first_query or query
        cards.append(
            f"""
            <article class="map-card" data-location-type="destination">
                <div class="map-card-head">
                    <span class="map-pin map-pin-destination">Destination</span>
                    <span class="badge badge-active">Active</span>
                </div>
                <h3>{h(row['destination_name'])}</h3>
                <p>{h(labelize(row['destination_type']))}</p>
                <dl>
                    <div><dt>Address</dt><dd>{h(row['address'])}</dd></div>
                    <div><dt>Contact</dt><dd>{h(row['contact_person'])}</dd></div>
                    <div><dt>Phone</dt><dd>{h(row['contact_phone'])}</dd></div>
                    <div><dt>Coordinates</dt><dd>{h(coordinate_pair(row) or 'Not set')}</dd></div>
                </dl>
                <div class="map-actions">
                    <button class="btn btn-small map-select" type="button" data-map-url="{h(google_embed_url(query))}">Show on map</button>
                    <a class="btn btn-small" target="_blank" rel="noopener" href="{h(google_open_url(query))}">Open</a>
                </div>
            </article>
            """
        )
        destination_count += 1

    initial_query = first_query or "Kota Kinabalu Sabah Malaysia"
    body = f"""
    <section class="metrics-grid compact">
        {metric_card("Mapped Waste Sources", source_count, "Food and organic-waste generators", "green")}
        {metric_card("Mapped Destinations", destination_count, "Compost and diversion sites", "blue")}
    </section>
    <section class="map-layout">
        <div class="panel map-panel">
            <div class="panel-heading">
                <h2>Google Maps Location View</h2>
                <p>Select a source or destination to inspect its location and operating information.</p>
            </div>
            <div class="map-frame-shell">
                <iframe id="googleMapFrame" title="DBKK waste location map" loading="lazy" referrerpolicy="no-referrer-when-downgrade" src="{h(google_embed_url(initial_query))}"></iframe>
            </div>
        </div>
        <aside class="panel map-list-panel">
            <div class="panel-heading">
                <h2>Locations</h2>
                <p>Use filters to focus on generators or compost destinations.</p>
            </div>
            <div class="map-filters" role="group" aria-label="Map location filters">
                <button class="btn btn-small map-filter active" type="button" data-map-filter="all">All</button>
                <button class="btn btn-small map-filter" type="button" data-map-filter="source">Sources</button>
                <button class="btn btn-small map-filter" type="button" data-map-filter="destination">Destinations</button>
            </div>
            <input class="table-search" type="search" placeholder="Search locations..." data-location-search>
            <div class="map-cards">{''.join(cards) if cards else empty_state('No mapped locations yet.')}</div>
        </aside>
    </section>"""
    return layout(user, "map", "Map", body)


def page_sources(user, params):
    require_role(user, {"admin"})
    source_type = params.get("type", [""])[0]
    zone = params.get("zone", [""])[0]
    edit_id = parse_int(params.get("edit", [""])[0])
    where = ["1=1"]
    sql_params = []
    if source_type:
        where.append("ws.source_type=?")
        sql_params.append(source_type)
    if zone:
        where.append("ws.zone=?")
        sql_params.append(zone)
    with db() as conn:
        rows = conn.execute(
            f"""
            SELECT ws.*, d.destination_name, u.name AS vendor_name
            FROM waste_sources ws
            LEFT JOIN destinations d ON d.id=ws.default_destination_id
            LEFT JOIN users u ON u.id=ws.assigned_vendor_user_id
            WHERE {' AND '.join(where)}
            ORDER BY ws.status DESC, ws.source_name
            """,
            sql_params,
        ).fetchall()
        zones = conn.execute("SELECT DISTINCT zone FROM waste_sources WHERE zone IS NOT NULL AND zone<>'' ORDER BY zone").fetchall()
        destinations = conn.execute("SELECT id, destination_name FROM destinations WHERE is_active=1 ORDER BY destination_name").fetchall()
        vendors = conn.execute("SELECT id, name FROM users WHERE role='vendor' AND is_active=1 ORDER BY name").fetchall()
        latest = latest_compliance_by_source(conn)
        editing = None
        if edit_id:
            editing = conn.execute("SELECT * FROM waste_sources WHERE id=?", (edit_id,)).fetchone()
    table_rows = []
    registry_cards = []
    for row in rows:
        comp = latest.get(row["id"])
        query = map_query(row["source_name"], row["address"], row["latitude"], row["longitude"])
        registry_cards.append(
            f"""
            <article class="source-registry-card">
                <div class="source-registry-top">
                    <span>{h(labelize(row['source_type']))}</span>
                    {status_badge(comp['segregation_status'] if comp else 'pending')}
                </div>
                <h3>{h(row['source_name'])}</h3>
                <p>{h(row['zone'])} - {h(row['destination_name'] or 'No compost site')}</p>
                <div class="source-registry-metrics">
                    <strong>{kg(row['estimated_organic_kg_per_day'])}/day</strong>
                    <span>{kg(row['estimated_recyclable_kg_per_day'])}/day recyclable</span>
                </div>
                <div class="quick-actions">
                    <a class="btn btn-small" href="/sources?edit={h(row['id'])}">Edit</a>
                    <a class="btn btn-small" target="_blank" rel="noopener" href="{h(google_open_url(query))}">Map</a>
                </div>
            </article>"""
        )
        table_rows.append(
            f"""
            <tr>
                <td>{h(row['source_name'])}</td>
                <td>{h(labelize(row['source_type']))}</td>
                <td>{h(row['zone'])}</td>
                <td>{kg(row['estimated_organic_kg_per_day'])}/day</td>
                <td>{kg(row['estimated_recyclable_kg_per_day'])}/day</td>
                <td>{status_badge(comp['segregation_status'] if comp else 'pending')}</td>
                <td>{h(row['destination_name'] or 'Unassigned')}</td>
                <td><a class="btn btn-small" target="_blank" rel="noopener" href="{h(google_open_url(query))}">Map</a></td>
                <td>{h(row['vendor_name'] or 'No account')}</td>
                <td>{status_badge(row['status'])}</td>
                <td><a class="btn btn-small" href="/sources?edit={h(row['id'])}">Edit</a></td>
            </tr>"""
        )
    filter_html = f"""
    <form method="get" action="/sources" class="filters">
        <label>Type
            <select name="type">
                <option value="">All types</option>
                {options(SOURCE_TYPES, source_type)}
            </select>
        </label>
        <label>Zone
            <select name="zone">
                <option value="">All zones</option>
                {options([row['zone'] for row in zones], zone)}
            </select>
        </label>
        <button class="btn" type="submit">Filter</button>
        <a class="btn btn-quiet" href="/sources">Clear</a>
    </form>"""
    form = source_form(editing, destinations, vendors)
    table = f"""
    <div class="table-wrap">
        <table data-filterable>
            <thead>
                <tr>
                    <th>Source</th><th>Type</th><th>Zone</th><th>Organic Estimate</th>
                    <th>Recyclable Estimate</th><th>Compliance</th><th>Destination</th>
                    <th>Location</th><th>Vendor Account</th><th>Status</th><th></th>
                </tr>
            </thead>
            <tbody>{''.join(table_rows)}</tbody>
        </table>
    </div>"""
    body = f"""
    <section class="content-grid sidebar-right">
        <div class="panel">
            <div class="panel-heading">
                <h2>Waste Source Registry</h2>
                <p>Master list of food vendors, markets, hotel kitchens, canteens, bazaars, and community compost points.</p>
            </div>
            {filter_html}
            <input class="table-search" type="search" placeholder="Search sources..." data-table-search>
            <div class="source-registry-grid">{''.join(registry_cards) if rows else empty_state('No sources match the selected filters.')}</div>
            <details class="details-block">
                <summary>Detailed records</summary>
                {table if rows else ''}
            </details>
        </div>
        <div class="panel">
            <div class="panel-heading">
                <h2>{'Edit Source' if editing else 'Add Source'}</h2>
                <p>Register high-organic waste generators and assign default compost destinations.</p>
            </div>
            {form}
        </div>
    </section>"""
    return layout(user, "sources", "Waste Sources", body)


def source_form(source, destinations, vendors):
    source = source or {}
    source_id = source["id"] if source else ""
    return f"""
    <form method="post" action="/sources/save" class="form-stack">
        <input type="hidden" name="id" value="{h(source_id)}">
        <label>Source name
            <input name="source_name" required value="{h(source['source_name'] if source else '')}">
        </label>
        <label>Source type
            <select name="source_type" required>{options(SOURCE_TYPES, source['source_type'] if source else '')}</select>
        </label>
        <label>Address
            <textarea name="address" rows="2">{h(source['address'] if source else '')}</textarea>
        </label>
        <div class="split">
            <label>Latitude
                <input type="number" step="0.000001" name="latitude" value="{h(source['latitude'] if source else '')}" placeholder="5.981800">
            </label>
            <label>Longitude
                <input type="number" step="0.000001" name="longitude" value="{h(source['longitude'] if source else '')}" placeholder="116.073100">
            </label>
        </div>
        <div class="split">
            <label>Zone
                <input name="zone" value="{h(source['zone'] if source else '')}" placeholder="Central">
            </label>
            <label>Status
                <select name="status">{options(['active','inactive'], source['status'] if source else 'active')}</select>
            </label>
        </div>
        <div class="split">
            <label>Contact person
                <input name="contact_person" value="{h(source['contact_person'] if source else '')}">
            </label>
            <label>Contact phone
                <input name="contact_phone" value="{h(source['contact_phone'] if source else '')}">
            </label>
        </div>
        <div class="split">
            <label>Organic kg/day
                <input type="number" step="0.1" min="0" name="estimated_organic_kg_per_day" value="{h(source['estimated_organic_kg_per_day'] if source else 0)}">
            </label>
            <label>Recyclable kg/day
                <input type="number" step="0.1" min="0" name="estimated_recyclable_kg_per_day" value="{h(source['estimated_recyclable_kg_per_day'] if source else 0)}">
            </label>
        </div>
        <label>Vendor account
            <select name="assigned_vendor_user_id">
                <option value="">No vendor account</option>
                {options(vendors, source['assigned_vendor_user_id'] if source else '', lambda item: item['name'], lambda item: item['id'])}
            </select>
        </label>
        <label>Default compost destination
            <select name="default_destination_id">
                <option value="">Unassigned</option>
                {options(destinations, source['default_destination_id'] if source else '', lambda item: item['destination_name'], lambda item: item['id'])}
            </select>
        </label>
        <button class="btn btn-primary" type="submit">{'Save Changes' if source else 'Add Source'}</button>
    </form>"""


def page_destinations(user, params):
    require_role(user, {"admin"})
    edit_id = parse_int(params.get("edit", [""])[0])
    with db() as conn:
        destinations = conn.execute("SELECT * FROM destinations ORDER BY is_active DESC, destination_name").fetchall()
        editing = conn.execute("SELECT * FROM destinations WHERE id=?", (edit_id,)).fetchone() if edit_id else None
    rows = []
    destination_cards = []
    for dest in destinations:
        query = map_query(dest["destination_name"], dest["address"], dest["latitude"], dest["longitude"])
        destination_cards.append(
            f"""
            <article class="source-registry-card">
                <div class="source-registry-top">
                    <span>{h(labelize(dest['destination_type']))}</span>
                    <span class="badge badge-active">{'Active' if dest['is_active'] else 'Inactive'}</span>
                </div>
                <h3>{h(dest['destination_name'])}</h3>
                <p>{h(dest['address'])}</p>
                <dl class="compact-dl">
                    <div><dt>Contact</dt><dd>{h(dest['contact_person'] or '-')}</dd></div>
                    <div><dt>Phone</dt><dd>{h(dest['contact_phone'] or '-')}</dd></div>
                </dl>
                <div class="quick-actions">
                    <a class="btn btn-small" href="/destinations?edit={h(dest['id'])}">Edit</a>
                    <a class="btn btn-small" target="_blank" rel="noopener" href="{h(google_open_url(query))}">Map</a>
                </div>
            </article>"""
        )
        rows.append(
            f"""
            <tr>
                <td>{h(dest['destination_name'])}</td>
                <td>{h(labelize(dest['destination_type']))}</td>
                <td>{h(dest['address'])}</td>
                <td><a class="btn btn-small" target="_blank" rel="noopener" href="{h(google_open_url(query))}">Map</a></td>
                <td>{h(dest['contact_person'])}</td>
                <td>{h(dest['contact_phone'])}</td>
                <td>{'Active' if dest['is_active'] else 'Inactive'}</td>
                <td><a class="btn btn-small" href="/destinations?edit={h(dest['id'])}">Edit</a></td>
            </tr>"""
        )
    form = destination_form(editing)
    body = f"""
    <section class="content-grid sidebar-right">
        <div class="panel">
            <div class="panel-heading compact-heading">
                <h2>Compost Sites</h2>
                <p>Receiving sites for diverted organic waste.</p>
            </div>
            <div class="source-registry-grid">{''.join(destination_cards)}</div>
            <details class="details-block">
                <summary>Detailed records</summary>
                <div class="table-wrap">
                    <table>
                        <thead><tr><th>Name</th><th>Type</th><th>Address</th><th>Location</th><th>Contact</th><th>Phone</th><th>Status</th><th></th></tr></thead>
                        <tbody>{''.join(rows)}</tbody>
                    </table>
                </div>
            </details>
        </div>
        <div class="panel">
            <div class="panel-heading compact-heading">
                <h2>{'Edit Destination' if editing else 'Add Destination'}</h2>
                <p>Keep site details current.</p>
            </div>
            {form}
        </div>
    </section>"""
    return layout(user, "destinations", "Destinations", body)


def destination_form(dest):
    dest = dest or {}
    destination_types = ["kte_site", "kapayan_site", "compost_hub", "recycler", "other"]
    return f"""
    <form method="post" action="/destinations/save" class="form-stack">
        <input type="hidden" name="id" value="{h(dest['id'] if dest else '')}">
        <label>Destination name
            <input name="destination_name" required value="{h(dest['destination_name'] if dest else '')}">
        </label>
        <label>Destination type
            <select name="destination_type">{options(destination_types, dest['destination_type'] if dest else 'compost_hub')}</select>
        </label>
        <label>Address
            <textarea name="address" rows="2">{h(dest['address'] if dest else '')}</textarea>
        </label>
        <div class="split">
            <label>Latitude
                <input type="number" step="0.000001" name="latitude" value="{h(dest['latitude'] if dest else '')}" placeholder="5.934800">
            </label>
            <label>Longitude
                <input type="number" step="0.000001" name="longitude" value="{h(dest['longitude'] if dest else '')}" placeholder="116.049600">
            </label>
        </div>
        <div class="split">
            <label>Contact person
                <input name="contact_person" value="{h(dest['contact_person'] if dest else '')}">
            </label>
            <label>Contact phone
                <input name="contact_phone" value="{h(dest['contact_phone'] if dest else '')}">
            </label>
        </div>
        <label class="checkbox-line">
            <input type="checkbox" name="is_active" {'checked' if (not dest or dest['is_active']) else ''}>
            Active destination
        </label>
        <button class="btn btn-primary" type="submit">{'Save Changes' if dest else 'Add Destination'}</button>
    </form>"""


def page_compliance(user):
    require_role(user, {"admin"})
    with db() as conn:
        sources = conn.execute("SELECT id, source_name, zone FROM waste_sources ORDER BY source_name").fetchall()
        records = conn.execute(
            """
            SELECT sr.*, ws.source_name, ws.zone, u.name AS inspector_name
            FROM segregation_records sr
            JOIN waste_sources ws ON ws.id=sr.waste_source_id
            LEFT JOIN users u ON u.id=sr.inspected_by_user_id
            ORDER BY sr.inspection_date DESC, sr.id DESC
            LIMIT 80
            """
        ).fetchall()
        latest = latest_compliance_by_source(conn)
    summary_rows = []
    monitor_cards = []
    compliance_counts = {status: 0 for status in COMPLIANCE_STATUSES}
    missing_compost_bins = 0
    missing_recycle_bins = 0
    for source in sources:
        row = latest.get(source["id"])
        status = row["segregation_status"] if row else "pending"
        compliance_counts[status] = compliance_counts.get(status, 0) + 1
        if not row or not row["has_compostable_bin"]:
            missing_compost_bins += 1
        if not row or not row["has_recyclable_bin"]:
            missing_recycle_bins += 1
        monitor_cards.append(
            f"""
            <article class="compliance-card">
                <div class="source-registry-top">
                    <span>{h(source['zone'])}</span>
                    {status_badge(status)}
                </div>
                <h3>{h(source['source_name'])}</h3>
                <div class="compliance-checks">
                    <span class="{'check-yes' if row and row['has_compostable_bin'] else 'check-no'}">Compost bin: {yes_no(row['has_compostable_bin']) if row else 'No'}</span>
                    <span class="{'check-yes' if row and row['has_recyclable_bin'] else 'check-no'}">Recycle bin: {yes_no(row['has_recyclable_bin']) if row else 'No'}</span>
                </div>
                <p>{h(row['contamination_notes'] if row else 'Needs inspection')}</p>
            </article>"""
        )
        summary_rows.append(
            f"""
            <tr>
                <td>{h(source['source_name'])}</td>
                <td>{h(source['zone'])}</td>
                <td>{status_badge(row['segregation_status'] if row else 'pending')}</td>
                <td>{yes_no(row['has_compostable_bin']) if row else 'No'}</td>
                <td>{yes_no(row['has_recyclable_bin']) if row else 'No'}</td>
                <td>{h(row['inspection_date'] if row else 'Not inspected')}</td>
                <td>{h(row['contamination_notes'] if row else '')}</td>
            </tr>"""
        )
    compliance_rate = int((compliance_counts.get("compliant", 0) / max(1, len(sources))) * 100)
    history_rows = []
    for row in records:
        history_rows.append(
            f"""
            <tr>
                <td>{h(row['inspection_date'])}</td>
                <td>{h(row['source_name'])}</td>
                <td>{status_badge(row['segregation_status'])}</td>
                <td>{yes_no(row['has_compostable_bin'])}</td>
                <td>{yes_no(row['has_recyclable_bin'])}</td>
                <td>{h(row['inspector_name'])}</td>
                <td>{h(row['remarks'])}</td>
            </tr>"""
        )
    form = f"""
    <form method="post" action="/compliance/save" class="form-stack">
        <label>Waste source
            <select name="waste_source_id" required>{options(sources, None, lambda item: f"{item['source_name']} ({item['zone']})", lambda item: item['id'])}</select>
        </label>
        <label>Inspection date
            <input type="date" name="inspection_date" value="{today_iso()}" required>
        </label>
        <div class="split">
            <label class="checkbox-line"><input type="checkbox" name="has_compostable_bin"> Compostable bin present</label>
            <label class="checkbox-line"><input type="checkbox" name="has_recyclable_bin"> Recyclable bin present</label>
        </div>
        <label>Segregation status
            <select name="segregation_status">{options(COMPLIANCE_STATUSES, 'pending')}</select>
        </label>
        <label>Contamination notes
            <textarea name="contamination_notes" rows="3" placeholder="Mixed food packaging, liquids, general waste contamination..."></textarea>
        </label>
        <label>Remarks
            <textarea name="remarks" rows="3" placeholder="Training required, bin labels added, follow-up date..."></textarea>
        </label>
        <button class="btn btn-primary" type="submit">Save Inspection</button>
    </form>"""
    body = f"""
    <section class="metrics-grid four">
        {metric_card("Compliance Rate", f"{compliance_rate}%", "Latest source inspections", "green")}
        {metric_card("Compliant", compliance_counts.get("compliant", 0), "Ready for clean organic collection", "blue")}
        {metric_card("Missing Compost Bins", missing_compost_bins, "Needs DBKK follow-up", "amber")}
        {metric_card("Missing Recycle Bins", missing_recycle_bins, "Basic recyclable awareness", "rose")}
    </section>
    <section class="content-grid sidebar-right">
        <div class="panel">
            <div class="panel-heading compact-heading">
                <h2>Segregation Monitor</h2>
                <p>Vendor readiness at a glance.</p>
            </div>
            <div class="compliance-card-grid">{''.join(monitor_cards)}</div>
            <div class="panel-heading tight"><h2>Inspection History</h2></div>
            <details class="details-block">
                <summary>Detailed records</summary>
                <div class="table-wrap">
                    <table data-filterable>
                        <thead><tr><th>Source</th><th>Zone</th><th>Status</th><th>Compost Bin</th><th>Recycle Bin</th><th>Last Inspection</th><th>Notes</th></tr></thead>
                        <tbody>{''.join(summary_rows)}</tbody>
                    </table>
                </div>
                <div class="table-wrap">
                    <table>
                        <thead><tr><th>Date</th><th>Source</th><th>Status</th><th>Compost Bin</th><th>Recycle Bin</th><th>Inspector</th><th>Remarks</th></tr></thead>
                        <tbody>{''.join(history_rows)}</tbody>
                    </table>
                </div>
            </details>
        </div>
        <div class="panel">
            <div class="panel-heading compact-heading">
                <h2>Add Inspection</h2>
                <p>Update bins, status, and contamination notes.</p>
            </div>
            {form}
        </div>
    </section>"""
    return layout(user, "compliance", "Segregation Compliance", body)


def page_pickups(user):
    with db() as conn:
        if user["role"] == "vendor":
            sources = conn.execute(
                "SELECT id, source_name FROM waste_sources WHERE assigned_vendor_user_id=? AND status='active' ORDER BY source_name",
                (user["id"],),
            ).fetchall()
            rows = conn.execute(
                """
                SELECT pr.*, ws.source_name, d.destination_name, NULL AS collector_name
                FROM pickup_requests pr
                JOIN waste_sources ws ON ws.id=pr.waste_source_id
                LEFT JOIN destinations d ON d.id=ws.default_destination_id
                WHERE ws.assigned_vendor_user_id=?
                ORDER BY pr.requested_pickup_date DESC, pr.id DESC
                """,
                (user["id"],),
            ).fetchall()
            collectors = []
        elif user["role"] == "collector":
            sources = []
            rows = conn.execute(
                """
                SELECT pr.*, ws.source_name, d.destination_name, u.name AS collector_name
                FROM pickup_requests pr
                JOIN waste_sources ws ON ws.id=pr.waste_source_id
                LEFT JOIN destinations d ON d.id=ws.default_destination_id
                LEFT JOIN users u ON u.id=pr.assigned_collector_user_id
                WHERE pr.assigned_collector_user_id=?
                ORDER BY pr.requested_pickup_date DESC, pr.id DESC
                """,
                (user["id"],),
            ).fetchall()
            collectors = []
        else:
            sources = conn.execute("SELECT id, source_name FROM waste_sources WHERE status='active' ORDER BY source_name").fetchall()
            rows = conn.execute(
                """
                SELECT pr.*, ws.source_name, d.destination_name, u.name AS collector_name
                FROM pickup_requests pr
                JOIN waste_sources ws ON ws.id=pr.waste_source_id
                LEFT JOIN destinations d ON d.id=ws.default_destination_id
                LEFT JOIN users u ON u.id=pr.assigned_collector_user_id
                ORDER BY
                    CASE pr.status
                        WHEN 'pending' THEN 1
                        WHEN 'approved' THEN 2
                        WHEN 'assigned' THEN 3
                        WHEN 'collected' THEN 4
                        ELSE 5
                    END,
                    pr.requested_pickup_date DESC
                """
            ).fetchall()
            collectors = conn.execute("SELECT id, name FROM users WHERE role='collector' AND is_active=1 ORDER BY name").fetchall()
    can_create = user["role"] in {"admin", "vendor"}
    form = ""
    if can_create:
        form = f"""
        <div class="panel request-panel">
            <div class="panel-heading compact-heading">
                <h2>{'Request Pickup' if user['role'] == 'vendor' else 'Create Pickup'}</h2>
                <p>Only the essential pickup details are shown first.</p>
            </div>
            <form method="post" action="/pickups/create" class="form-stack">
                <label>Waste source
                    <select name="waste_source_id" required>{options(sources, None, lambda item: item['source_name'], lambda item: item['id'])}</select>
                </label>
                <div class="split">
                    <label>Request type
                        <select name="request_type">{options(['scheduled','on_demand'], 'on_demand')}</select>
                    </label>
                    <label>Pickup date
                        <input type="date" name="requested_pickup_date" value="{today_iso()}" required>
                    </label>
                </div>
                <label>Estimated organic kg
                    <input type="number" step="0.1" min="0" name="estimated_organic_kg" value="0">
                </label>
                <label>Notes
                    <textarea name="notes" rows="3" placeholder="Waste ready time, bin location, source separation note..."></textarea>
                </label>
                <button class="btn btn-primary" type="submit">Submit Request</button>
            </form>
        </div>"""
    if user["role"] == "vendor":
        body = f"""
        <section class="content-grid sidebar-right">
            <div class="panel">
                <div class="panel-heading compact-heading">
                    <h2>My Pickup History</h2>
                    <p>Track pickup requests without the spreadsheet clutter.</p>
                </div>
                {pickup_cards(rows, user)}
            </div>
            {form}
        </section>"""
        return layout(user, "pickups", "Request Pickup", body)
    body = f"""
    <section class="panel board-panel">
        <div class="panel-heading compact-heading">
            <h2>{'Pickup Board' if user['role'] == 'admin' else 'My Pickup Board'}</h2>
            <p>Cards are grouped by what needs to happen next.</p>
        </div>
        {pickup_board(rows, user, collectors)}
    </section>
    {form if user['role'] == 'admin' else ''}"""
    return layout(user, "pickups", "Pickup Board", body)


def page_collections(user):
    require_role(user, {"admin", "collector"})
    with db() as conn:
        if user["role"] == "collector":
            available = conn.execute(
                """
                SELECT pr.id, ws.source_name, pr.requested_pickup_date, pr.estimated_organic_kg
                FROM pickup_requests pr
                JOIN waste_sources ws ON ws.id=pr.waste_source_id
                LEFT JOIN collections c ON c.pickup_request_id=pr.id
                WHERE pr.assigned_collector_user_id=?
                  AND pr.status IN ('approved','assigned')
                  AND c.id IS NULL
                ORDER BY pr.requested_pickup_date ASC
                """,
                (user["id"],),
            ).fetchall()
            rows = conn.execute(
                """
                SELECT c.*, ws.source_name, d.destination_name
                FROM collections c
                JOIN pickup_requests pr ON pr.id=c.pickup_request_id
                JOIN waste_sources ws ON ws.id=pr.waste_source_id
                LEFT JOIN destinations d ON d.id=c.destination_id
                WHERE c.collected_by_user_id=?
                ORDER BY c.collected_at DESC
                """,
                (user["id"],),
            ).fetchall()
        else:
            available = conn.execute(
                """
                SELECT pr.id, ws.source_name, pr.requested_pickup_date, pr.estimated_organic_kg
                FROM pickup_requests pr
                JOIN waste_sources ws ON ws.id=pr.waste_source_id
                LEFT JOIN collections c ON c.pickup_request_id=pr.id
                WHERE pr.status IN ('approved','assigned')
                  AND c.id IS NULL
                ORDER BY pr.requested_pickup_date ASC
                """
            ).fetchall()
            rows = conn.execute(
                """
                SELECT c.*, ws.source_name, d.destination_name
                FROM collections c
                JOIN pickup_requests pr ON pr.id=c.pickup_request_id
                JOIN waste_sources ws ON ws.id=pr.waste_source_id
                LEFT JOIN destinations d ON d.id=c.destination_id
                ORDER BY c.collected_at DESC
                """
            ).fetchall()
        destinations = conn.execute("SELECT id, destination_name FROM destinations WHERE is_active=1 ORDER BY destination_name").fetchall()
    form = f"""
    <form method="post" action="/collections/save" class="form-stack">
        <label>Pickup request
            <select name="pickup_request_id" required>
                {options(available, None, lambda item: f"#{item['id']} - {item['source_name']} ({item['requested_pickup_date']}, est. {moneyless_number(item['estimated_organic_kg'])} kg)", lambda item: item['id'])}
            </select>
        </label>
        <label>Outcome
            <select name="outcome">
                <option value="collected">Collected</option>
                <option value="failed">Failed pickup</option>
            </select>
        </label>
        <label>Collected at
            <input type="datetime-local" name="collected_at" value="{dt.datetime.now().strftime('%Y-%m-%dT%H:%M')}">
        </label>
        <label>Actual organic kg
            <input type="number" step="0.1" min="0" name="actual_organic_kg" value="0">
        </label>
        <label class="checkbox-line">
            <input type="checkbox" name="contamination_flag"> Contamination found
        </label>
        <label>Contamination / rejection notes
            <textarea name="contamination_notes" rows="3" placeholder="Mixed plastics, waste not ready, bin inaccessible..."></textarea>
        </label>
        <label>Destination site
            <select name="destination_id">
                <option value="">No destination selected</option>
                {options(destinations, None, lambda item: item['destination_name'], lambda item: item['id'])}
            </select>
        </label>
        <label>Delivery status
            <select name="delivery_status">{options(['pending_delivery','delivered','rejected'], 'pending_delivery')}</select>
        </label>
        <button class="btn btn-primary" type="submit">Save Collection</button>
    </form>"""
    body = f"""
    <section class="content-grid sidebar-right">
        <div class="panel">
            <div class="panel-heading">
                <h2>Collection Tracking</h2>
                <p>Record actual collected weight, contamination, failed pickup reasons, and delivery status.</p>
            </div>
            {collection_table(rows)}
        </div>
        <div class="panel">
            <div class="panel-heading">
                <h2>Record Collection</h2>
                <p>Approved or assigned pickup requests appear here until collection is recorded.</p>
            </div>
            {form if available else empty_state('No approved or assigned pickups are waiting for collection.')}
        </div>
    </section>"""
    return layout(user, "collections", "Collection Tracking", body)


def page_intakes(user):
    require_role(user, {"admin", "collector"})
    with db() as conn:
        available = conn.execute(
            """
            SELECT c.id, ws.source_name, c.actual_organic_kg, d.destination_name, c.destination_id
            FROM collections c
            JOIN pickup_requests pr ON pr.id=c.pickup_request_id
            JOIN waste_sources ws ON ws.id=pr.waste_source_id
            LEFT JOIN destinations d ON d.id=c.destination_id
            LEFT JOIN compost_intakes ci ON ci.collection_id=c.id
            WHERE ci.id IS NULL AND c.delivery_status IN ('pending_delivery','delivered')
            ORDER BY c.collected_at DESC
            """
        ).fetchall()
        destinations = conn.execute("SELECT id, destination_name FROM destinations WHERE is_active=1 ORDER BY destination_name").fetchall()
        rows = conn.execute(
            """
            SELECT ci.*, ws.source_name, d.destination_name, c.actual_organic_kg
            FROM compost_intakes ci
            JOIN collections c ON c.id=ci.collection_id
            JOIN pickup_requests pr ON pr.id=c.pickup_request_id
            JOIN waste_sources ws ON ws.id=pr.waste_source_id
            JOIN destinations d ON d.id=ci.destination_id
            ORDER BY ci.received_date DESC, ci.id DESC
            """
        ).fetchall()
    intake_rows = []
    for row in rows:
        intake_rows.append(
            f"""
            <tr>
                <td>#{h(row['id'])}</td>
                <td>{h(row['source_name'])}</td>
                <td>{h(row['destination_name'])}</td>
                <td>{h(row['received_date'])}</td>
                <td>{kg(row['received_weight_kg'])}</td>
                <td>{status_badge(row['acceptance_status'])}</td>
                <td>{h(row['batch_code'])}</td>
                <td>{h(row['notes'])}</td>
            </tr>"""
        )
    form = f"""
    <form method="post" action="/intakes/save" class="form-stack">
        <label>Collection
            <select name="collection_id" required>
                {options(available, None, lambda item: f"#{item['id']} - {item['source_name']} ({moneyless_number(item['actual_organic_kg'])} kg)", lambda item: item['id'])}
            </select>
        </label>
        <label>Receiving destination
            <select name="destination_id" required>{options(destinations, None, lambda item: item['destination_name'], lambda item: item['id'])}</select>
        </label>
        <label>Received date
            <input type="date" name="received_date" value="{today_iso()}" required>
        </label>
        <label>Received weight kg
            <input type="number" step="0.1" min="0" name="received_weight_kg" value="0">
        </label>
        <label>Acceptance status
            <select name="acceptance_status">{options(ACCEPTANCE_STATUSES, 'accepted')}</select>
        </label>
        <label>Compost batch reference
            <input name="batch_code" placeholder="KTE-ORG-002">
        </label>
        <label>Intake notes
            <textarea name="notes" rows="3"></textarea>
        </label>
        <button class="btn btn-primary" type="submit">Log Compost Intake</button>
    </form>"""
    body = f"""
    <section class="content-grid sidebar-right">
        <div class="panel">
            <div class="panel-heading">
                <h2>Compost Intake Records</h2>
                <p>Confirms collected organic waste actually entered composting.</p>
            </div>
            <div class="table-wrap">
                <table>
                    <thead><tr><th>ID</th><th>Source</th><th>Destination</th><th>Received</th><th>Weight</th><th>Status</th><th>Batch</th><th>Notes</th></tr></thead>
                    <tbody>{''.join(intake_rows)}</tbody>
                </table>
            </div>
        </div>
        <div class="panel">
            <div class="panel-heading">
                <h2>Log Intake</h2>
                <p>Accept, partially accept, or reject delivered organic material.</p>
            </div>
            {form if available else empty_state('No collection is waiting for compost-site intake.')}
        </div>
    </section>"""
    return layout(user, "intakes", "Compost Intake", body)


def page_outputs(user):
    require_role(user, {"admin", "collector"})
    with db() as conn:
        intakes = conn.execute(
            """
            SELECT ci.id, ci.batch_code, ws.source_name, ci.received_weight_kg
            FROM compost_intakes ci
            JOIN collections c ON c.id=ci.collection_id
            JOIN pickup_requests pr ON pr.id=c.pickup_request_id
            JOIN waste_sources ws ON ws.id=pr.waste_source_id
            WHERE ci.acceptance_status IN ('accepted','partial')
            ORDER BY ci.received_date DESC
            """
        ).fetchall()
        rows = conn.execute(
            """
            SELECT co.*, ci.batch_code, ws.source_name
            FROM compost_outputs co
            JOIN compost_intakes ci ON ci.id=co.compost_intake_id
            JOIN collections c ON c.id=ci.collection_id
            JOIN pickup_requests pr ON pr.id=c.pickup_request_id
            JOIN waste_sources ws ON ws.id=pr.waste_source_id
            ORDER BY co.output_date DESC, co.id DESC
            """
        ).fetchall()
    output_rows = []
    for row in rows:
        output_rows.append(
            f"""
            <tr>
                <td>#{h(row['id'])}</td>
                <td>{h(row['batch_code'])}</td>
                <td>{h(row['source_name'])}</td>
                <td>{h(row['output_date'])}</td>
                <td>{kg(row['compost_output_kg'])}</td>
                <td>{h(labelize(row['usage_type']))}</td>
                <td>{h(row['usage_destination'])}</td>
                <td>{h(row['notes'])}</td>
            </tr>"""
        )
    form = f"""
    <form method="post" action="/outputs/save" class="form-stack">
        <label>Compost intake / batch
            <select name="compost_intake_id" required>
                {options(intakes, None, lambda item: f"#{item['id']} - {item['batch_code'] or 'No batch'} - {item['source_name']} ({moneyless_number(item['received_weight_kg'])} kg input)", lambda item: item['id'])}
            </select>
        </label>
        <label>Output date
            <input type="date" name="output_date" value="{today_iso()}" required>
        </label>
        <label>Compost output kg
            <input type="number" step="0.1" min="0" name="compost_output_kg" value="0">
        </label>
        <label>Usage type
            <select name="usage_type">{options(USAGE_TYPES, 'dbkk_landscape')}</select>
        </label>
        <label>Usage destination
            <input name="usage_destination" placeholder="DBKK landscaping, community garden, school garden...">
        </label>
        <label>Notes
            <textarea name="notes" rows="3"></textarea>
        </label>
        <button class="btn btn-primary" type="submit">Record Output</button>
    </form>"""
    body = f"""
    <section class="content-grid sidebar-right">
        <div class="panel">
            <div class="panel-heading">
                <h2>Compost Output Tracking</h2>
                <p>Closes the loop from separated organic waste to usable compost.</p>
            </div>
            <div class="table-wrap">
                <table>
                    <thead><tr><th>ID</th><th>Batch</th><th>Source</th><th>Output Date</th><th>Output</th><th>Usage</th><th>Destination</th><th>Notes</th></tr></thead>
                    <tbody>{''.join(output_rows)}</tbody>
                </table>
            </div>
        </div>
        <div class="panel">
            <div class="panel-heading">
                <h2>Record Compost Output</h2>
                <p>Track compost produced and where it is used or distributed.</p>
            </div>
            {form if intakes else empty_state('No accepted compost intake is available for output tracking.')}
        </div>
    </section>"""
    return layout(user, "outputs", "Compost Output", body)


def page_recyclables(user):
    require_role(user, {"admin", "vendor"})
    with db() as conn:
        if user["role"] == "vendor":
            sources = conn.execute(
                "SELECT id, source_name FROM waste_sources WHERE assigned_vendor_user_id=? ORDER BY source_name",
                (user["id"],),
            ).fetchall()
            rows = conn.execute(
                """
                SELECT rr.*, ws.source_name, u.name AS recorder_name
                FROM recyclable_records rr
                JOIN waste_sources ws ON ws.id=rr.waste_source_id
                LEFT JOIN users u ON u.id=rr.recorded_by_user_id
                WHERE ws.assigned_vendor_user_id=?
                ORDER BY rr.record_date DESC, rr.id DESC
                """,
                (user["id"],),
            ).fetchall()
        else:
            sources = conn.execute("SELECT id, source_name FROM waste_sources ORDER BY source_name").fetchall()
            rows = conn.execute(
                """
                SELECT rr.*, ws.source_name, u.name AS recorder_name
                FROM recyclable_records rr
                JOIN waste_sources ws ON ws.id=rr.waste_source_id
                LEFT JOIN users u ON u.id=rr.recorded_by_user_id
                ORDER BY rr.record_date DESC, rr.id DESC
                """
            ).fetchall()
    record_rows = []
    for row in rows:
        record_rows.append(
            f"""
            <tr>
                <td>{h(row['record_date'])}</td>
                <td>{h(row['source_name'])}</td>
                <td>{kg(row['estimated_recyclable_kg'])}</td>
                <td>{h(row['handoff_destination'])}</td>
                <td>{h(row['recorder_name'])}</td>
                <td>{h(row['notes'])}</td>
            </tr>"""
        )
    form = f"""
    <form method="post" action="/recyclables/save" class="form-stack">
        <label>Waste source
            <select name="waste_source_id" required>{options(sources, None, lambda item: item['source_name'], lambda item: item['id'])}</select>
        </label>
        <label>Record date
            <input type="date" name="record_date" value="{today_iso()}" required>
        </label>
        <label>Estimated recyclable kg
            <input type="number" step="0.1" min="0" name="estimated_recyclable_kg" value="0">
        </label>
        <label>Recycler handoff note
            <input name="handoff_destination" placeholder="Recycler name, holding area, pending pickup...">
        </label>
        <label>Notes
            <textarea name="notes" rows="3"></textarea>
        </label>
        <button class="btn btn-primary" type="submit">Save Recyclable Record</button>
    </form>"""
    body = f"""
    <section class="content-grid sidebar-right">
        <div class="panel">
            <div class="panel-heading">
                <h2>Recyclable Awareness Records</h2>
                <p>Lightweight tracking only: separated amount and optional handoff note.</p>
            </div>
            <div class="table-wrap">
                <table>
                    <thead><tr><th>Date</th><th>Source</th><th>Estimated Recyclable</th><th>Handoff</th><th>Recorded By</th><th>Notes</th></tr></thead>
                    <tbody>{''.join(record_rows)}</tbody>
                </table>
            </div>
        </div>
        <div class="panel">
            <div class="panel-heading">
                <h2>Add Recyclable Record</h2>
                <p>Keep recyclable tracking visible without building a full recycler marketplace.</p>
            </div>
            {form if sources else empty_state('No assigned waste source available.')}
        </div>
    </section>"""
    return layout(user, "recyclables", "Recyclables", body)


def page_history(user):
    if user["role"] != "vendor":
        return page_pickups(user)
    with db() as conn:
        rows = conn.execute(
            """
            SELECT pr.*, ws.source_name, d.destination_name, NULL AS collector_name
            FROM pickup_requests pr
            JOIN waste_sources ws ON ws.id=pr.waste_source_id
            LEFT JOIN destinations d ON d.id=ws.default_destination_id
            WHERE ws.assigned_vendor_user_id=?
            ORDER BY pr.requested_pickup_date DESC, pr.id DESC
            """,
            (user["id"],),
        ).fetchall()
        collected = conn.execute(
            """
            SELECT COALESCE(SUM(c.actual_organic_kg), 0) AS kg
            FROM collections c
            JOIN pickup_requests pr ON pr.id=c.pickup_request_id
            JOIN waste_sources ws ON ws.id=pr.waste_source_id
            WHERE ws.assigned_vendor_user_id=?
            """,
            (user["id"],),
        ).fetchone()["kg"]
    body = f"""
    <section class="metrics-grid compact">
        {metric_card("Total Collected", kg(collected), "Organic waste collected from your source", "green")}
        {metric_card("Pickup Requests", len(rows), "All request statuses", "blue")}
    </section>
    <section class="panel">
        <div class="panel-heading compact-heading">
            <h2>Pickup History</h2>
            <p>Card view of your previous and upcoming pickup requests.</p>
        </div>
        {pickup_cards(rows, user)}
    </section>"""
    return layout(user, "history", "History", body)


def page_reports(user):
    require_role(user, {"admin"})
    with db() as conn:
        monthly = conn.execute(
            """
            SELECT substr(collected_at, 1, 7) AS month, ROUND(SUM(actual_organic_kg), 1) AS kg
            FROM collections
            GROUP BY substr(collected_at, 1, 7)
            ORDER BY month DESC
            """
        ).fetchall()
        top_sources = conn.execute(
            """
            SELECT source_name, zone, source_type, estimated_organic_kg_per_day
            FROM waste_sources
            ORDER BY estimated_organic_kg_per_day DESC
            LIMIT 10
            """
        ).fetchall()
        compost_by_usage = conn.execute(
            """
            SELECT usage_type, ROUND(SUM(compost_output_kg), 1) AS kg
            FROM compost_outputs
            GROUP BY usage_type
            ORDER BY kg DESC
            """
        ).fetchall()
        latest = latest_compliance_by_source(conn)
        all_sources = conn.execute("SELECT id FROM waste_sources").fetchall()
        compliance_counts = {status: 0 for status in COMPLIANCE_STATUSES}
        for source in all_sources:
            row = latest.get(source["id"])
            compliance_counts[row["segregation_status"] if row else "pending"] += 1
        collected = conn.execute("SELECT COALESCE(SUM(actual_organic_kg),0) AS kg FROM collections").fetchone()["kg"]
        delivered = conn.execute(
            """
            SELECT COALESCE(SUM(received_weight_kg),0) AS kg
            FROM compost_intakes
            WHERE acceptance_status IN ('accepted','partial')
            """
        ).fetchone()["kg"]
        compost = conn.execute("SELECT COALESCE(SUM(compost_output_kg),0) AS kg FROM compost_outputs").fetchone()["kg"]
        contamination = conn.execute("SELECT COUNT(*) AS total FROM collections WHERE contamination_flag=1").fetchone()["total"]
        failed = conn.execute("SELECT COUNT(*) AS total FROM pickup_requests WHERE status='failed'").fetchone()["total"]
    monthly_rows = "".join(f"<tr><td>{h(r['month'])}</td><td>{kg(r['kg'])}</td></tr>" for r in monthly)
    top_rows = "".join(
        f"<tr><td>{h(r['source_name'])}</td><td>{h(labelize(r['source_type']))}</td><td>{h(r['zone'])}</td><td>{kg(r['estimated_organic_kg_per_day'])}/day</td></tr>"
        for r in top_sources
    )
    output_rows = "".join(f"<tr><td>{h(labelize(r['usage_type']))}</td><td>{kg(r['kg'])}</td></tr>" for r in compost_by_usage)
    compliance_rows = "".join(
        f"<tr><td>{h(labelize(status))}</td><td>{count}</td></tr>"
        for status, count in compliance_counts.items()
    )
    body = f"""
    <section class="metrics-grid">
        {metric_card("Landfill Diversion", kg(delivered), "Accepted or partially accepted compost intake", "green")}
        {metric_card("Organic Collected", kg(collected), "Actual collection total", "blue")}
        {metric_card("Compost Output", kg(compost), "Finished compost recorded", "amber")}
        {metric_card("Operational Exceptions", contamination + failed, f"{contamination} contamination, {failed} failed pickups", "rose")}
    </section>
    <section class="report-actions">
        <a class="btn" href="/reports/export?kind=monthly">Export Monthly CSV</a>
        <a class="btn" href="/reports/export?kind=compliance">Export Compliance CSV</a>
        <a class="btn" href="/reports/export?kind=diversion">Export Diversion CSV</a>
    </section>
    <section class="content-grid two">
        <div class="panel">
            <div class="panel-heading"><h2>Monthly Organic Waste Collected</h2></div>
            <div class="table-wrap"><table><thead><tr><th>Month</th><th>Collected</th></tr></thead><tbody>{monthly_rows}</tbody></table></div>
        </div>
        <div class="panel">
            <div class="panel-heading"><h2>Vendor Compliance Report</h2></div>
            <div class="table-wrap"><table><thead><tr><th>Status</th><th>Sources</th></tr></thead><tbody>{compliance_rows}</tbody></table></div>
        </div>
        <div class="panel">
            <div class="panel-heading"><h2>Top Organic Waste Generators</h2></div>
            <div class="table-wrap"><table><thead><tr><th>Source</th><th>Type</th><th>Zone</th><th>Daily Estimate</th></tr></thead><tbody>{top_rows}</tbody></table></div>
        </div>
        <div class="panel">
            <div class="panel-heading"><h2>Compost Output Report</h2></div>
            <div class="table-wrap"><table><thead><tr><th>Usage</th><th>Output</th></tr></thead><tbody>{output_rows}</tbody></table></div>
        </div>
    </section>"""
    return layout(user, "reports", "Reports", body)


def require_role(user, allowed):
    if user["role"] not in allowed:
        raise PermissionError("You do not have access to that page.")


def save_source(form):
    source_id = parse_int(form.get("id", ""))
    params = (
        form.get("source_name", "").strip(),
        form.get("source_type", "restaurant"),
        form.get("address", "").strip(),
        parse_float(form.get("latitude")) if form.get("latitude", "").strip() else None,
        parse_float(form.get("longitude")) if form.get("longitude", "").strip() else None,
        form.get("zone", "").strip(),
        form.get("contact_person", "").strip(),
        form.get("contact_phone", "").strip(),
        parse_float(form.get("estimated_organic_kg_per_day")),
        parse_float(form.get("estimated_recyclable_kg_per_day")),
        form.get("status", "active"),
        parse_int(form.get("assigned_vendor_user_id", "")),
        parse_int(form.get("default_destination_id", "")),
    )
    if source_id:
        execute(
            """
            UPDATE waste_sources SET
                source_name=?, source_type=?, address=?, latitude=?, longitude=?, zone=?, contact_person=?, contact_phone=?,
                estimated_organic_kg_per_day=?, estimated_recyclable_kg_per_day=?, status=?,
                assigned_vendor_user_id=?, default_destination_id=?
            WHERE id=?
            """,
            params + (source_id,),
        )
    else:
        execute(
            """
            INSERT INTO waste_sources (
                source_name, source_type, address, latitude, longitude, zone, contact_person, contact_phone,
                estimated_organic_kg_per_day, estimated_recyclable_kg_per_day, status,
                assigned_vendor_user_id, default_destination_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            params,
        )


def save_destination(form):
    dest_id = parse_int(form.get("id", ""))
    params = (
        form.get("destination_name", "").strip(),
        form.get("destination_type", "compost_hub"),
        form.get("address", "").strip(),
        parse_float(form.get("latitude")) if form.get("latitude", "").strip() else None,
        parse_float(form.get("longitude")) if form.get("longitude", "").strip() else None,
        form.get("contact_person", "").strip(),
        form.get("contact_phone", "").strip(),
        bool_from_form(form.get("is_active", "")),
    )
    if dest_id:
        execute(
            """
            UPDATE destinations SET
                destination_name=?, destination_type=?, address=?, latitude=?, longitude=?, contact_person=?, contact_phone=?, is_active=?
            WHERE id=?
            """,
            params + (dest_id,),
        )
    else:
        execute(
            """
            INSERT INTO destinations
                (destination_name, destination_type, address, latitude, longitude, contact_person, contact_phone, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            params,
        )


def save_compliance(form, user):
    execute(
        """
        INSERT INTO segregation_records (
            waste_source_id, inspection_date, has_compostable_bin, has_recyclable_bin,
            segregation_status, contamination_notes, inspected_by_user_id, remarks
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            parse_int(form.get("waste_source_id")),
            form.get("inspection_date") or today_iso(),
            bool_from_form(form.get("has_compostable_bin", "")),
            bool_from_form(form.get("has_recyclable_bin", "")),
            form.get("segregation_status", "pending"),
            form.get("contamination_notes", "").strip(),
            user["id"],
            form.get("remarks", "").strip(),
        ),
    )


def source_allowed_for_user(source_id, user):
    if user["role"] == "admin":
        return True
    row = query_one("SELECT id FROM waste_sources WHERE id=? AND assigned_vendor_user_id=?", (source_id, user["id"]))
    return row is not None


def save_pickup(form, user):
    source_id = parse_int(form.get("waste_source_id"))
    if not source_allowed_for_user(source_id, user):
        raise PermissionError("You cannot create a pickup for that source.")
    status = "approved" if user["role"] == "admin" else "pending"
    execute(
        """
        INSERT INTO pickup_requests (
            waste_source_id, request_type, requested_pickup_date, estimated_organic_kg,
            status, notes, created_by_user_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            source_id,
            form.get("request_type", "on_demand"),
            form.get("requested_pickup_date") or today_iso(),
            parse_float(form.get("estimated_organic_kg")),
            status,
            form.get("notes", "").strip(),
            user["id"],
        ),
    )


def update_pickup(form):
    execute(
        """
        UPDATE pickup_requests
        SET status=?, assigned_collector_user_id=?
        WHERE id=?
        """,
        (
            form.get("status", "pending"),
            parse_int(form.get("assigned_collector_user_id", "")),
            parse_int(form.get("id")),
        ),
    )


def ensure_pickup_worker_access(pickup, user):
    if user["role"] == "admin":
        return
    if user["role"] == "collector" and pickup["assigned_collector_user_id"] == user["id"]:
        return
    raise PermissionError("This pickup is not assigned to you.")


def start_pickup(form, user):
    pickup_id = parse_int(form.get("id"))
    pickup = query_one("SELECT * FROM pickup_requests WHERE id=?", (pickup_id,))
    if not pickup:
        raise ValueError("Pickup request not found.")
    ensure_pickup_worker_access(pickup, user)
    assigned_to = pickup["assigned_collector_user_id"] or (user["id"] if user["role"] == "collector" else None)
    execute(
        """
        UPDATE pickup_requests
        SET status='assigned', assigned_collector_user_id=?
        WHERE id=?
        """,
        (assigned_to, pickup_id),
    )


def quick_collect_pickup(form, user):
    pickup_id = parse_int(form.get("id"))
    pickup = query_one(
        """
        SELECT pr.*, ws.default_destination_id
        FROM pickup_requests pr
        JOIN waste_sources ws ON ws.id=pr.waste_source_id
        WHERE pr.id=?
        """,
        (pickup_id,),
    )
    if not pickup:
        raise ValueError("Pickup request not found.")
    ensure_pickup_worker_access(pickup, user)
    existing = query_one("SELECT id FROM collections WHERE pickup_request_id=?", (pickup_id,))
    if existing:
        execute("UPDATE pickup_requests SET status='collected' WHERE id=?", (pickup_id,))
        return
    execute_many(
        [
            (
                """
                INSERT INTO collections (
                    pickup_request_id, collected_at, actual_organic_kg, contamination_flag,
                    contamination_notes, collected_by_user_id, destination_id, delivery_status
                )
                VALUES (?, ?, ?, 0, ?, ?, ?, 'pending_delivery')
                """,
                (
                    pickup_id,
                    now_iso(),
                    parse_float(pickup["estimated_organic_kg"]),
                    "Quick collected from pickup board.",
                    user["id"],
                    pickup["default_destination_id"],
                ),
            ),
            ("UPDATE pickup_requests SET status='collected' WHERE id=?", (pickup_id,)),
        ]
    )


def report_pickup_issue(form, user):
    pickup_id = parse_int(form.get("id"))
    pickup = query_one("SELECT * FROM pickup_requests WHERE id=?", (pickup_id,))
    if not pickup:
        raise ValueError("Pickup request not found.")
    ensure_pickup_worker_access(pickup, user)
    execute(
        """
        UPDATE pickup_requests
        SET status='failed', notes=TRIM(COALESCE(notes,'') || ?)
        WHERE id=?
        """,
        ("\nIssue reported from pickup board.", pickup_id),
    )


def save_collection(form, user):
    pickup_id = parse_int(form.get("pickup_request_id"))
    pickup = query_one("SELECT * FROM pickup_requests WHERE id=?", (pickup_id,))
    if not pickup:
        raise ValueError("Pickup request not found.")
    if user["role"] == "collector" and pickup["assigned_collector_user_id"] != user["id"]:
        raise PermissionError("This pickup is not assigned to you.")
    outcome = form.get("outcome", "collected")
    if outcome == "failed":
        execute(
            """
            UPDATE pickup_requests
            SET status='failed', notes=COALESCE(notes,'') || ?
            WHERE id=?
            """,
            (f"\nFailed pickup: {form.get('contamination_notes', '').strip()}", pickup_id),
        )
        return
    collected_at = form.get("collected_at") or dt.datetime.now().strftime("%Y-%m-%dT%H:%M")
    collected_at = collected_at.replace("T", " ")
    execute_many(
        [
            (
                """
                INSERT INTO collections (
                    pickup_request_id, collected_at, actual_organic_kg, contamination_flag,
                    contamination_notes, collected_by_user_id, destination_id, delivery_status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    pickup_id,
                    collected_at,
                    parse_float(form.get("actual_organic_kg")),
                    bool_from_form(form.get("contamination_flag", "")),
                    form.get("contamination_notes", "").strip(),
                    user["id"],
                    parse_int(form.get("destination_id", "")),
                    form.get("delivery_status", "pending_delivery"),
                ),
            ),
            ("UPDATE pickup_requests SET status='collected' WHERE id=?", (pickup_id,)),
        ]
    )


def save_intake(form, user):
    collection_id = parse_int(form.get("collection_id"))
    status = form.get("acceptance_status", "accepted")
    delivery_status = "rejected" if status == "rejected" else "delivered"
    execute_many(
        [
            (
                """
                INSERT INTO compost_intakes (
                    collection_id, destination_id, received_date, received_weight_kg,
                    acceptance_status, batch_code, notes, recorded_by_user_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    collection_id,
                    parse_int(form.get("destination_id")),
                    form.get("received_date") or today_iso(),
                    parse_float(form.get("received_weight_kg")),
                    status,
                    form.get("batch_code", "").strip(),
                    form.get("notes", "").strip(),
                    user["id"],
                ),
            ),
            ("UPDATE collections SET delivery_status=? WHERE id=?", (delivery_status, collection_id)),
        ]
    )


def save_output(form, user):
    execute(
        """
        INSERT INTO compost_outputs (
            compost_intake_id, output_date, compost_output_kg, usage_type,
            usage_destination, notes, recorded_by_user_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            parse_int(form.get("compost_intake_id")),
            form.get("output_date") or today_iso(),
            parse_float(form.get("compost_output_kg")),
            form.get("usage_type", "other"),
            form.get("usage_destination", "").strip(),
            form.get("notes", "").strip(),
            user["id"],
        ),
    )


def save_recyclable(form, user):
    source_id = parse_int(form.get("waste_source_id"))
    if not source_allowed_for_user(source_id, user):
        raise PermissionError("You cannot record recyclables for that source.")
    execute(
        """
        INSERT INTO recyclable_records (
            waste_source_id, record_date, estimated_recyclable_kg,
            handoff_destination, notes, recorded_by_user_id
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            source_id,
            form.get("record_date") or today_iso(),
            parse_float(form.get("estimated_recyclable_kg")),
            form.get("handoff_destination", "").strip(),
            form.get("notes", "").strip(),
            user["id"],
        ),
    )


def export_report(kind):
    output = io.StringIO()
    writer = csv.writer(output)
    with db() as conn:
        if kind == "monthly":
            writer.writerow(["month", "organic_collected_kg"])
            rows = conn.execute(
                """
                SELECT substr(collected_at, 1, 7) AS month, ROUND(SUM(actual_organic_kg), 1) AS kg
                FROM collections
                GROUP BY substr(collected_at, 1, 7)
                ORDER BY month DESC
                """
            ).fetchall()
            for row in rows:
                writer.writerow([row["month"], row["kg"]])
        elif kind == "compliance":
            writer.writerow(["source_name", "zone", "latest_status", "has_compostable_bin", "has_recyclable_bin", "inspection_date"])
            rows = conn.execute(
                """
                SELECT ws.source_name, ws.zone, sr.segregation_status, sr.has_compostable_bin,
                       sr.has_recyclable_bin, sr.inspection_date
                FROM waste_sources ws
                LEFT JOIN (
                    SELECT *
                    FROM segregation_records
                    WHERE id IN (
                        SELECT MAX(id) FROM segregation_records GROUP BY waste_source_id
                    )
                ) sr ON sr.waste_source_id=ws.id
                ORDER BY ws.source_name
                """
            ).fetchall()
            for row in rows:
                writer.writerow(
                    [
                        row["source_name"],
                        row["zone"],
                        row["segregation_status"] or "pending",
                        yes_no(row["has_compostable_bin"] or 0),
                        yes_no(row["has_recyclable_bin"] or 0),
                        row["inspection_date"] or "",
                    ]
                )
        else:
            writer.writerow(["metric", "value"])
            collected = conn.execute("SELECT COALESCE(SUM(actual_organic_kg),0) FROM collections").fetchone()[0]
            delivered = conn.execute(
                "SELECT COALESCE(SUM(received_weight_kg),0) FROM compost_intakes WHERE acceptance_status IN ('accepted','partial')"
            ).fetchone()[0]
            compost = conn.execute("SELECT COALESCE(SUM(compost_output_kg),0) FROM compost_outputs").fetchone()[0]
            writer.writerow(["organic_collected_kg", collected])
            writer.writerow(["accepted_compost_intake_kg", delivered])
            writer.writerow(["compost_output_kg", compost])
            writer.writerow(["estimated_landfill_diversion_kg", delivered])
    return output.getvalue()


class App(BaseHTTPRequestHandler):
    server_version = "DBKKOrganic/1.0"

    def do_GET(self):
        try:
            init_db()
            path, params = self.path_and_query()
            if path.startswith("/static/"):
                return self.serve_static(path)
            if path == "/health":
                return self.send_html("ok")
            if path == "/login":
                return self.send_html(render_login())
            if path == "/logout":
                return self.logout()
            user = self.current_user()
            if path in {"", "/"}:
                return self.redirect("/dashboard" if user else "/login")
            if not user:
                return self.redirect("/login")
            if path == "/dashboard":
                return self.send_html(page_dashboard(user))
            if path == "/map":
                return self.redirect("/dashboard")
            if path == "/sources":
                return self.send_html(page_sources(user, params))
            if path == "/destinations":
                return self.send_html(page_destinations(user, params))
            if path == "/compliance":
                return self.send_html(page_compliance(user))
            if path == "/pickups":
                return self.send_html(page_pickups(user))
            if path == "/collections":
                return self.send_html(page_collections(user))
            if path == "/intakes":
                return self.send_html(page_intakes(user))
            if path == "/outputs":
                return self.send_html(page_outputs(user))
            if path == "/recyclables":
                return self.send_html(page_recyclables(user))
            if path == "/history":
                return self.send_html(page_history(user))
            if path == "/reports":
                return self.send_html(page_reports(user))
            if path == "/reports/export":
                require_role(user, {"admin"})
                kind = params.get("kind", ["diversion"])[0]
                return self.send_csv(export_report(kind), f"dbkk_{kind}_report.csv")
            return self.not_found()
        except PermissionError as exc:
            return self.send_error_page(HTTPStatus.FORBIDDEN, str(exc))
        except Exception as exc:
            return self.send_error_page(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))

    def do_POST(self):
        try:
            init_db()
            path, _ = self.path_and_query()
            if path == "/login":
                return self.login()
            user = self.current_user()
            if not user:
                return self.redirect("/login")
            form = self.read_form()
            if path == "/sources/save":
                require_role(user, {"admin"})
                save_source(form)
                return self.redirect("/sources")
            if path == "/destinations/save":
                require_role(user, {"admin"})
                save_destination(form)
                return self.redirect("/destinations")
            if path == "/compliance/save":
                require_role(user, {"admin"})
                save_compliance(form, user)
                return self.redirect("/compliance")
            if path == "/pickups/create":
                require_role(user, {"admin", "vendor"})
                save_pickup(form, user)
                return self.redirect("/pickups")
            if path == "/pickups/update":
                require_role(user, {"admin"})
                update_pickup(form)
                return self.redirect("/pickups")
            if path == "/pickups/start":
                require_role(user, {"admin", "collector"})
                start_pickup(form, user)
                return self.redirect("/pickups")
            if path == "/pickups/quick-collect":
                require_role(user, {"admin", "collector"})
                quick_collect_pickup(form, user)
                return self.redirect("/pickups")
            if path == "/pickups/report-issue":
                require_role(user, {"admin", "collector"})
                report_pickup_issue(form, user)
                return self.redirect("/pickups")
            if path == "/collections/save":
                require_role(user, {"admin", "collector"})
                save_collection(form, user)
                return self.redirect("/collections")
            if path == "/intakes/save":
                require_role(user, {"admin", "collector"})
                save_intake(form, user)
                return self.redirect("/intakes")
            if path == "/outputs/save":
                require_role(user, {"admin", "collector"})
                save_output(form, user)
                return self.redirect("/outputs")
            if path == "/recyclables/save":
                require_role(user, {"admin", "vendor"})
                save_recyclable(form, user)
                return self.redirect("/recyclables")
            return self.not_found()
        except PermissionError as exc:
            return self.send_error_page(HTTPStatus.FORBIDDEN, str(exc))
        except Exception as exc:
            return self.send_error_page(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))

    def path_and_query(self):
        parsed = urlparse(self.path)
        return parsed.path.rstrip("/") or "/", parse_qs(parsed.query)

    def read_form(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8")
        parsed = parse_qs(raw, keep_blank_values=True)
        return {key: values[-1] for key, values in parsed.items()}

    def current_user(self):
        cookie_header = self.headers.get("Cookie")
        if not cookie_header:
            return None
        cookie = SimpleCookie(cookie_header)
        morsel = cookie.get("session_id")
        if not morsel:
            return None
        user_id = SESSION_STORE.get(morsel.value)
        if not user_id:
            return None
        return query_one("SELECT * FROM users WHERE id=? AND is_active=1", (user_id,))

    def login(self):
        form = self.read_form()
        user = query_one("SELECT * FROM users WHERE email=? AND is_active=1", (form.get("email", "").strip(),))
        if not user or not verify_password(form.get("password", ""), user["password_hash"]):
            return self.send_html(render_login("Invalid email or password."), status=HTTPStatus.UNAUTHORIZED)
        session_id = secrets.token_urlsafe(32)
        SESSION_STORE[session_id] = user["id"]
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", "/dashboard")
        self.send_header("Set-Cookie", f"session_id={session_id}; HttpOnly; Path=/; SameSite=Lax")
        self.end_headers()

    def logout(self):
        cookie_header = self.headers.get("Cookie")
        if cookie_header:
            cookie = SimpleCookie(cookie_header)
            morsel = cookie.get("session_id")
            if morsel:
                SESSION_STORE.pop(morsel.value, None)
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", "/login")
        self.send_header("Set-Cookie", "session_id=; Max-Age=0; Path=/; SameSite=Lax")
        self.end_headers()

    def redirect(self, location):
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        self.end_headers()

    def serve_static(self, path):
        rel = unquote(path.replace("/static/", "", 1))
        target = (STATIC_DIR / rel).resolve()
        if not str(target).startswith(str(STATIC_DIR.resolve())) or not target.exists():
            return self.not_found()
        content_type = "text/plain"
        if target.suffix == ".css":
            content_type = "text/css"
        elif target.suffix == ".js":
            content_type = "application/javascript"
        elif target.suffix in {".png", ".jpg", ".jpeg", ".gif", ".webp"}:
            content_type = f"image/{target.suffix.lstrip('.')}"
        data = target.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_html(self, html, status=HTTPStatus.OK):
        data = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_csv(self, csv_text, filename):
        data = csv_text.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{quote(filename)}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def not_found(self):
        return self.send_error_page(HTTPStatus.NOT_FOUND, "Page not found.")

    def send_error_page(self, status, message):
        user = self.current_user()
        body = f"""
        <section class="panel error-panel">
            <div class="panel-heading">
                <h2>{h(status.phrase)}</h2>
                <p>{h(message)}</p>
            </div>
            <a class="btn" href="/dashboard">Back to dashboard</a>
        </section>"""
        if user:
            return self.send_html(layout(user, "dashboard", status.phrase, body), status=status)
        return self.send_html(render_login(message), status=status)

    def log_message(self, fmt, *args):
        print(f"[{now_iso()}] {self.address_string()} {fmt % args}")


def run():
    init_db()
    port = int(os.environ.get("PORT", "5000"))
    host = os.environ.get("HOST", "127.0.0.1")
    server = ThreadingHTTPServer((host, port), App)
    print(f"DBKK Organic Waste System running at http://{host}:{port}")
    print(f"Database: {DB_PATH}")
    server.serve_forever()


if __name__ == "__main__":
    run()
