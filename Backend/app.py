
import os
import sys
from datetime import timedelta
import time
import secrets
import hmac
import logging
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from flask import Flask, render_template, request, redirect, session, url_for, jsonify, abort
from authlib.integrations.flask_client import OAuth
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
load_dotenv()
import json
import psycopg2
from db import get_db_connection, release_db_connection

def get_db():
    conn = psycopg2.connect(os.getenv("DATABASE_URL"))
    return conn, conn.cursor()


_admin_indexes_ready = False
_callback_schema_ready = False
_callback_schema_failed_once = False
_base_schema_ready = False


def ensure_base_schema():
    global _base_schema_ready
    if _base_schema_ready:
        return

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS callback_requests (
                id SERIAL PRIMARY KEY,
                phone VARCHAR(20),
                email VARCHAR(255),
                name TEXT,
                service TEXT,
                preferred_time TEXT,
                message TEXT,
                source_page TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'pending'
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS business_registrations (
                id SERIAL PRIMARY KEY,
                business_name TEXT NOT NULL,
                business_type TEXT,
                services TEXT,
                owner_name TEXT,
                email TEXT,
                phone TEXT,
                city TEXT,
                status VARCHAR(20) DEFAULT 'NEW',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
        cur.close()
        _base_schema_ready = True
    finally:
        release_db_connection(conn)


def ensure_admin_indexes():
    global _admin_indexes_ready
    if _admin_indexes_ready:
        return

    ensure_base_schema()
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("CREATE INDEX IF NOT EXISTS idx_callback_requests_created_at ON callback_requests (created_at DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_callback_requests_status ON callback_requests (status)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_business_registrations_status ON business_registrations (status)")
        conn.commit()
        cur.close()
        _admin_indexes_ready = True
    finally:
        release_db_connection(conn)


def ensure_callback_schema():
    global _callback_schema_ready
    if _callback_schema_ready:
        return

    ensure_base_schema()
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("ALTER TABLE callback_requests ADD COLUMN IF NOT EXISTS name TEXT")
        cur.execute("ALTER TABLE callback_requests ADD COLUMN IF NOT EXISTS service TEXT")
        cur.execute("ALTER TABLE callback_requests ADD COLUMN IF NOT EXISTS preferred_time TEXT")
        cur.execute("ALTER TABLE callback_requests ADD COLUMN IF NOT EXISTS message TEXT")
        cur.execute("ALTER TABLE callback_requests ADD COLUMN IF NOT EXISTS source_page TEXT")
        conn.commit()
        cur.close()

        # Try strict DB-level de-dup index. If old duplicate rows already exist,
        # skip this and rely on application-level duplicate checks instead.
        try:
            cur = conn.cursor()
            cur.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS uq_callback_daily_lead
                ON callback_requests (
                    COALESCE(phone, ''),
                    COALESCE(email, ''),
                    COALESCE(service, ''),
                    DATE(created_at)
                )
            """)
            conn.commit()
            cur.close()
        except Exception:
            conn.rollback()
            cur = conn.cursor()
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_callback_daily_lookup
                ON callback_requests (
                    COALESCE(phone, ''),
                    COALESCE(email, ''),
                    COALESCE(service, ''),
                    DATE(created_at)
                )
            """)
            conn.commit()
            cur.close()
        _callback_schema_ready = True
    finally:
        release_db_connection(conn)


def ensure_callback_schema_safe():
    global _callback_schema_failed_once
    if _callback_schema_ready or _callback_schema_failed_once:
        return
    try:
        ensure_callback_schema()
    except Exception as exc:
        # Do not crash public pages if DB is temporarily unreachable.
        logging.exception("callback schema init skipped due to DB error: %s", exc)
        _callback_schema_failed_once = True

app = Flask(__name__,
    template_folder="../frontend/templates",
    static_folder="../frontend/static")

from admin import admin_bp

app.register_blueprint(admin_bp)



from Backend.otp import otp_bp
app.register_blueprint(otp_bp)

app.secret_key = os.getenv("FLASK_SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("SECRET_KEY not set in environment")

app.config.update(
    SESSION_PERMANENT=False,                 # Browser-session cookie only
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=20),  # Fallback timeout
    SESSION_REFRESH_EACH_REQUEST=True
)
app.config["SESSION_IDLE_TIMEOUT_SECONDS"] = int(os.getenv("SESSION_IDLE_TIMEOUT_SECONDS", "300"))
app.config["SESSION_BOOT_ID"] = str(time.time_ns())
app.config["LOGIN_RATE_LIMIT_WINDOW_SECONDS"] = int(os.getenv("LOGIN_RATE_LIMIT_WINDOW_SECONDS", "900"))
app.config["LOGIN_RATE_LIMIT_MAX_ATTEMPTS"] = int(os.getenv("LOGIN_RATE_LIMIT_MAX_ATTEMPTS", "8"))

DATABASE_URL = os.getenv("DATABASE_URL")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH")

_failed_login_attempts = {}

oauth = OAuth(app)

google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid email profile"
    }
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KNOWLEDGE_PATH = os.path.join(BASE_DIR, "company_knowledge.json")

with open(KNOWLEDGE_PATH) as f:
    knowledge = json.load(f)


def normalize_session_role():
    # Keep auth/session keys consistent so template checks are reliable.
    if session.get("admin_logged_in") or session.get("is_admin"):
        session["role"] = "admin"
        session.pop("user", None)
        return

    if session.get("user"):
        session["role"] = "user"
        session.pop("admin_logged_in", None)
        session.pop("is_admin", None)
        return

    session.pop("role", None)
    session.pop("admin_logged_in", None)
    session.pop("is_admin", None)


def get_client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def is_login_rate_limited(ip):
    now = int(time.time())
    window = app.config["LOGIN_RATE_LIMIT_WINDOW_SECONDS"]
    max_attempts = app.config["LOGIN_RATE_LIMIT_MAX_ATTEMPTS"]
    history = [ts for ts in _failed_login_attempts.get(ip, []) if now - ts <= window]
    _failed_login_attempts[ip] = history
    return len(history) >= max_attempts


def record_login_failure(ip):
    now = int(time.time())
    _failed_login_attempts.setdefault(ip, []).append(now)


def clear_login_failures(ip):
    _failed_login_attempts.pop(ip, None)


def is_valid_admin_login(email, password):
    if not ADMIN_EMAIL or email != ADMIN_EMAIL:
        return False
    if ADMIN_PASSWORD_HASH:
        return check_password_hash(ADMIN_PASSWORD_HASH, password)
    if ADMIN_PASSWORD:
        return hmac.compare_digest(ADMIN_PASSWORD, password)
    return False


def get_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def validate_csrf():
    token = request.form.get("csrf_token", "")
    if not token or token != session.get("_csrf_token"):
        abort(403)


def status_redirect(default_path, status):
    target = (request.form.get("return_to") or "").strip()
    if not target.startswith("/") or target.startswith("//"):
        target = default_path
    sep = "&" if "?" in target else "?"
    return redirect(f"{target}{sep}status={status}")


def admin_business_next_redirect(op_status=None):
    target = (request.form.get("next_url") or "").strip()
    if not target.startswith("/") or target.startswith("//"):
        target = "/admin/businesses"

    parts = urlsplit(target)
    path = parts.path or "/admin/businesses"
    if not path.startswith("/admin/businesses"):
        path = "/admin/businesses"

    query_items = [(k, v) for (k, v) in parse_qsl(parts.query, keep_blank_values=True) if k != "op_status"]
    if op_status:
        query_items.append(("op_status", op_status))

    sanitized = urlunsplit(("", "", path, urlencode(query_items, doseq=True), ""))
    return redirect(sanitized)

def get_bot_reply(message, lang="en"):
    raw = (message or "").strip()
    raw_lower = raw.lower()
    msg = re.sub(r"\s+", " ", re.sub(r"[^a-z0-9+&/\-\s]", " ", raw_lower)).strip()
    is_te = str(lang or "").lower().startswith("te")

    company = knowledge.get("company", {})
    contact = knowledge.get("contact", {})
    policies = knowledge.get("policies", {})
    plans = knowledge.get("plans", {})
    services = knowledge.get("services_offered", [])

    company_name = company.get("name", "SV Accountax Crew")
    company_about = company.get("about", "")
    phone = contact.get("phone", "9676359019")
    email = contact.get("email", "svatcrew@outlook.com")
    hours = contact.get("hours", "Monday-Saturday, 10:00 AM to 7:00 PM")
    whatsapp = contact.get("whatsapp", "919676359019")

    def text(en_value, te_value):
        return te_value if is_te else en_value

    def has_any(keywords):
        return any((k in msg) or (k in raw_lower) for k in keywords)

    def pack(reply, suggestions):
        unique = []
        for item in suggestions:
            if item not in unique:
                unique.append(item)
        return {"reply": reply, "suggestions": unique[:5]}

    if not msg and not raw_lower:
        return pack(
            text(
                (
                    f"Hi, welcome to {company_name}.\n"
                    "I am your virtual receptionist. I can guide you on ITR, GST, TDS, registrations, plans, and documents."
                ),
                (
                    f"హాయ్, {company_name} కు స్వాగతం.\n"
                    "నేను మీ వర్చువల్ రిసెప్షనిస్ట్‌ను. ITR, GST, TDS, రిజిస్ట్రేషన్స్, ప్లాన్లు, డాక్యుమెంట్స్ పై మీకు సహాయం చేస్తాను."
                ),
            ),
            ["Services", "Plans", "Document Checklist", "Book Consultation", "WhatsApp Chat"],
        )

    if has_any(["hi", "hello", "hey", "good morning", "good evening", "హాయ్", "హలో", "నమస్కారం"]) and len(raw) <= 40:
        return pack(
            text(
                f"Hello! Welcome to {company_name}.\nHow can I help you today with tax or compliance support?",
                f"హలో! {company_name} కు స్వాగతం.\nట్యాక్స్ లేదా కంప్లయన్స్ సహాయం కోసం నేను ఎలా సహాయం చేయగలను?",
            ),
            ["Services", "Plans", "Document Checklist", "Book Consultation", "WhatsApp Chat"],
        )

    if has_any(["thank", "thanks", "thank you", "ధన్యవాదాలు"]):
        return pack(
            text(
                "You are welcome. I am here to help.\nWould you like support with services, plans, or documents?",
                "స్వాగతం. మీకు సహాయం చేయడానికి నేను ఇక్కడ ఉన్నాను.\nసేవలు, ప్లాన్లు లేదా డాక్యుమెంట్స్ లో ఏది కావాలి?",
            ),
            ["Services", "Plans", "Document Checklist", "Contact"],
        )

    if has_any(["bye", "goodbye", "see you", "బై", "వీడ్కోలు"]):
        return pack(
            text(
                f"Thank you for contacting {company_name}. Have a great day.",
                f"{company_name} ను సంప్రదించినందుకు ధన్యవాదాలు. మీ రోజు శుభంగా ఉండాలి.",
            ),
            ["WhatsApp Chat", "Contact"],
        )

    if has_any(["whatsapp", "expert", "human", "agent", "talk to expert", "speak to someone", "వాట్సాప్", "ఎక్స్‌పర్ట్"]):
        return pack(
            text(
                (
                    "You can connect with our team instantly on WhatsApp:\n"
                    f"https://wa.me/{whatsapp}?text=Hi%20I%20need%20help%20with%20tax%20and%20compliance\n\n"
                    "Please share your requirement there and we will guide you."
                ),
                (
                    "మా టీమ్‌తో వెంటనే WhatsApp లో కనెక్ట్ అవ్వండి:\n"
                    f"https://wa.me/{whatsapp}?text=Hi%20I%20need%20help%20with%20tax%20and%20compliance\n\n"
                    "మీ అవసరాన్ని అక్కడ పంపండి, మేము గైడ్ చేస్తాము."
                ),
            ),
            ["Book Consultation", "Contact", "Working Hours"],
        )

    if has_any(["book consultation", "consultation", "callback", "call back", "appointment", "కన్సల్టేషన్", "కాల్ బ్యాక్"]):
        return pack(
            text(
                (
                    "Sure. You can book a consultation using our callback form.\n"
                    "If urgent, please message us on WhatsApp and our team will respond quickly."
                ),
                (
                    "సరే. మా callback form ద్వారా consultation బుక్ చేసుకోవచ్చు.\n"
                    "అత్యవసరమైతే WhatsApp లో మెసేజ్ చేయండి, మా టీమ్ త్వరగా స్పందిస్తుంది."
                ),
            ),
            ["Book Consultation", "WhatsApp Chat", "Contact"],
        )

    if has_any(["document", "documents", "checklist", "proof", "required docs", "డాక్యుమెంట్", "చెక్‌లిస్ట్", "పత్రాలు"]):
        return pack(
            text(
                "You can use our Document Checklist Center to see required documents for ITR, GST, and registrations.",
                "ITR, GST, registrations కోసం అవసరమైన పత్రాలు చూడటానికి మా Document Checklist Center ఉపయోగించండి.",
            ),
            ["Document Checklist", "ITR", "GST", "Registrations"],
        )

    if has_any(["service", "services", "what do you do", "offerings", "సేవలు"]):
        service_lines = "\n".join([f"• {s}" for s in services])
        return pack(
            text(
                f"Our services include:\n{service_lines}\n\nWhich service do you want help with?",
                f"మా సేవలు ఇవి:\n{service_lines}\n\nమీకు ఏ సేవలో సహాయం కావాలి?",
            ),
            ["ITR", "GST", "TDS", "Registrations", "Accounting"],
        )

    if has_any(["plan", "plans", "package", "subscription", "ప్లాన్", "ప్యాకేజ్"]):
        basic = plans.get("basic", {})
        pro = plans.get("professional", {})
        business = plans.get("business", {})
        return pack(
            text(
                (
                    f"{basic.get('name', 'Basic Plan')} ({basic.get('for', 'Individuals')}): "
                    + ", ".join(basic.get("includes", []))
                    + "\n"
                    + f"{pro.get('name', 'Professional Plan')} ({pro.get('for', 'Professionals')}): "
                    + ", ".join(pro.get("includes", []))
                    + "\n"
                    + f"{business.get('name', 'Business Plan')} ({business.get('for', 'Businesses')}): "
                    + ", ".join(business.get("includes", []))
                    + "\n\nPlease tell me your profile: Individual or Business."
                ),
                (
                    f"{basic.get('name', 'Basic Plan')} ({basic.get('for', 'Individuals')}): "
                    + ", ".join(basic.get("includes", []))
                    + "\n"
                    + f"{pro.get('name', 'Professional Plan')} ({pro.get('for', 'Professionals')}): "
                    + ", ".join(pro.get("includes", []))
                    + "\n"
                    + f"{business.get('name', 'Business Plan')} ({business.get('for', 'Businesses')}): "
                    + ", ".join(business.get("includes", []))
                    + "\n\nదయచేసి మీ ప్రొఫైల్ చెప్పండి: వ్యక్తిగతం లేదా బిజినెస్."
                ),
            ),
            ["Basic Plan", "Professional Plan", "Business Plan", "Individual", "Business / Startup"],
        )

    if has_any(["basic plan"]):
        basic = plans.get("basic", {})
        return pack(
            text(
                f"{basic.get('name', 'Basic Plan')} is for {basic.get('for', 'Individuals')}.\nIncludes: " + ", ".join(basic.get("includes", [])),
                f"{basic.get('name', 'Basic Plan')} {basic.get('for', 'Individuals')} కోసం.\nఇందులో: " + ", ".join(basic.get("includes", [])),
            ),
            ["Professional Plan", "Business Plan", "Book Consultation", "WhatsApp Chat"],
        )

    if has_any(["professional plan"]):
        pro = plans.get("professional", {})
        return pack(
            text(
                f"{pro.get('name', 'Professional Plan')} is for {pro.get('for', 'professionals')}.\nIncludes: " + ", ".join(pro.get("includes", [])),
                f"{pro.get('name', 'Professional Plan')} {pro.get('for', 'professionals')} కోసం.\nఇందులో: " + ", ".join(pro.get("includes", [])),
            ),
            ["Business Plan", "Basic Plan", "Book Consultation", "WhatsApp Chat"],
        )

    if has_any(["business plan"]):
        business = plans.get("business", {})
        return pack(
            text(
                f"{business.get('name', 'Business Plan')} is for {business.get('for', 'businesses')}.\nIncludes: " + ", ".join(business.get("includes", [])),
                f"{business.get('name', 'Business Plan')} {business.get('for', 'businesses')} కోసం.\nఇందులో: " + ", ".join(business.get("includes", [])),
            ),
            ["Professional Plan", "Book Consultation", "WhatsApp Chat", "Contact"],
        )

    if has_any(["itr", "income tax", "file tax", "ఐటీఆర్", "ఇన్కమ్ ట్యాక్స్"]):
        return pack(
            text(
                "We handle complete Income Tax Return (ITR) filing with document review and compliance support.\nWould you like us to guide you with required documents next?",
                "మేము పూర్తి Income Tax Return (ITR) ఫైలింగ్‌ను document review మరియు compliance support తో చేస్తాము.\nతర్వాత అవసరమైన పత్రాలపై గైడ్ చేయాలా?",
            ),
            ["Document Checklist", "Basic Plan", "Professional Plan", "Book Consultation"],
        )

    if has_any(["gst registration", "gst return", "gstr", "gst", "జీఎస్టీ"]):
        return pack(
            text(
                "We support GST Registration and GST Returns Filing for individuals and businesses.\nWe can also help with ongoing monthly GST compliance.",
                "వ్యక్తిగతం మరియు బిజినెస్‌ల కోసం GST Registration మరియు GST Returns Filing లో మేము సహాయం చేస్తాము.\nనెలవారీ GST compliance లో కూడా మద్దతు ఇస్తాము.",
            ),
            ["Professional Plan", "Business Plan", "Book Consultation", "WhatsApp Chat"],
        )

    if has_any(["tds", "24q", "26q", "27q"]):
        return pack(
            text(
                "Yes, we handle TDS Returns including 24Q, 26Q, and 27Q.",
                "అవును, 24Q, 26Q, 27Q సహా TDS Returns ను మేము నిర్వహిస్తాము.",
            ),
            ["Professional Plan", "Business Plan", "Book Consultation", "WhatsApp Chat"],
        )

    if has_any(["msme", "udyam"]):
        return pack(
            text(
                "We provide MSME Registration support end-to-end.",
                "MSME Registration కోసం end-to-end support అందిస్తాము.",
            ),
            ["Registrations", "Document Checklist", "Book Consultation", "WhatsApp Chat"],
        )

    if has_any(["iec", "import export"]):
        return pack(
            text(
                "We provide IEC Registration support for import-export businesses.",
                "Import-export బిజినెస్‌లకు IEC Registration support అందిస్తాము.",
            ),
            ["Registrations", "Document Checklist", "Book Consultation", "WhatsApp Chat"],
        )

    if has_any(["registration", "registrations", "partnership", "llp", "private limited", "pvt ltd", "incorporation", "roc", "రిజిస్ట్రేషన్"]):
        return pack(
            text(
                "We support Partnership, LLP, Pvt Ltd incorporation, and ROC compliances.",
                "Partnership, LLP, Pvt Ltd incorporation మరియు ROC compliances లో మేము సహాయం చేస్తాము.",
            ),
            ["Business Plan", "Document Checklist", "Book Consultation", "WhatsApp Chat"],
        )

    if has_any(["accounting", "bookkeeping", "audit", "assurance", "advisory", "project report", "loan report", "అకౌంటింగ్"]):
        return pack(
            text(
                "We provide Accounting and Bookkeeping, Audit and Assurance support, Business Advisory, and Project Reports for Loans.",
                "Accounting మరియు Bookkeeping, Audit మరియు Assurance support, Business Advisory, Project Reports for Loans సేవలు అందిస్తున్నాము.",
            ),
            ["Business Plan", "Book Consultation", "WhatsApp Chat", "Contact"],
        )

    if has_any(["policy", "privacy", "confidential", "confidentiality", "data safety", "data security", "పాలసీ", "గోప్యత"]):
        return pack(
            text(
                (
                    f"Policy summary:\n• {policies.get('confidentiality', 'Client data is kept confidential.')}\n"
                    f"• {policies.get('third_party', 'No data is shared with third parties.')}"
                ),
                (
                    "పాలసీ సారాంశం:\n"
                    f"• {policies.get('confidentiality', 'Client data is kept confidential.')}\n"
                    f"• {policies.get('third_party', 'No data is shared with third parties.')}"
                ),
            ),
            ["Contact", "WhatsApp Chat"],
        )

    if has_any(["about", "who are you", "sv accountax crew", "మీ గురించి"]):
        return pack(
            text(
                f"{company_name}\n\n{company_about}",
                f"{company_name}\n\n{company_about}",
            ),
            ["Services", "Plans", "Contact", "WhatsApp Chat"],
        )

    if has_any(["contact", "phone", "email", "call", "reach", "number", "mobile", "సంప్రదింపు", "ఫోన్", "నంబర్", "ఇమెయిల్"]):
        return pack(
            text(
                f"Contact us:\nPhone: +91 {phone}\nEmail: {email}\nWhatsApp: https://wa.me/{whatsapp}\nHours: {hours}",
                f"సంప్రదించండి:\nఫోన్: +91 {phone}\nఇమెయిల్: {email}\nWhatsApp: https://wa.me/{whatsapp}\nపని గంటలు: {hours}",
            ),
            ["WhatsApp Chat", "Working Hours", "Book Consultation"],
        )

    if has_any(["working hours", "timing", "open", "hours", "పని గంటలు", "సమయం"]):
        return pack(
            text(
                f"Our working hours are {hours}.",
                f"మా పని గంటలు: {hours}.",
            ),
            ["Contact", "WhatsApp Chat"],
        )

    if has_any(["cost", "price", "pricing", "fee", "fees", "charges", "quote", "ఖర్చు", "ఫీజు", "ప్రైస్"]):
        return pack(
            text(
                (
                    "Sure, I will guide you.\n"
                    "Please share your profile so we can assist correctly:\n"
                    "1) Individual (salary / self-employed)\n"
                    "2) Business / Startup\n\n"
                    "Also mention required service (ITR, GST, TDS, registration, accounting, or ROC)."
                ),
                (
                    "సరే, నేను గైడ్ చేస్తాను.\n"
                    "సరైన సహాయం కోసం మీ ప్రొఫైల్ చెప్పండి:\n"
                    "1) వ్యక్తిగతం (salary / self-employed)\n"
                    "2) Business / Startup\n\n"
                    "అలాగే అవసరమైన సేవ చెప్పండి (ITR, GST, TDS, registration, accounting, లేదా ROC)."
                ),
            ),
            ["Individual", "Business / Startup", "Services", "Book Consultation", "WhatsApp Chat"],
        )

    if has_any(["individual", "salary", "salaried", "self employed", "self-employed", "freelancer", "వ్యక్తిగతం", "సాలరీ"]):
        return pack(
            text(
                (
                    "Noted: Individual profile.\n"
                    "Please share the service needed (ITR / GST / TDS / registration), and we will guide step-by-step.\n"
                    f"For faster support: https://wa.me/{whatsapp}"
                ),
                (
                    "గమనించాం: Individual profile.\n"
                    "మీకు కావాల్సిన సేవ చెప్పండి (ITR / GST / TDS / registration), మేము step-by-step గైడ్ చేస్తాము.\n"
                    f"త్వరిత సహాయం కోసం: https://wa.me/{whatsapp}"
                ),
            ),
            ["ITR", "GST", "TDS", "Book Consultation", "WhatsApp Chat"],
        )

    if has_any(["business / startup", "startup", "business", "company", "firm", "బిజినెస్", "స్టార్టప్", "కంపెనీ"]):
        return pack(
            text(
                (
                    "Noted: Business/Startup profile.\n"
                    "Please share required support (GST, ROC, registration, accounting, compliance), and we will guide the next steps.\n"
                    f"For faster support: https://wa.me/{whatsapp}"
                ),
                (
                    "గమనించాం: Business/Startup profile.\n"
                    "మీకు కావాల్సిన support (GST, ROC, registration, accounting, compliance) చెప్పండి, తర్వాతి steps మేము గైడ్ చేస్తాము.\n"
                    f"త్వరిత సహాయం కోసం: https://wa.me/{whatsapp}"
                ),
            ),
            ["GST", "ROC", "Registrations", "Business Plan", "WhatsApp Chat"],
        )

    return pack(
        text(
            (
                f"I am the virtual receptionist for {company_name}.\n"
                "I may not have full details for this query right now.\n"
                "Please contact our team directly for accurate guidance:\n"
                f"WhatsApp: https://wa.me/{whatsapp}\n"
                f"Call: +91 {phone}"
            ),
            (
                f"నేను {company_name} వర్చువల్ రిసెప్షనిస్ట్‌ను.\n"
                "ఈ ప్రశ్నకు సంబంధించిన పూర్తి వివరాలు ఇప్పుడే అందుబాటులో లేవు.\n"
                "సరైన మార్గదర్శకత్వం కోసం మా టీమ్‌ను నేరుగా సంప్రదించండి:\n"
                f"WhatsApp: https://wa.me/{whatsapp}\n"
                f"కాల్: +91 {phone}"
            ),
        ),
        ["WhatsApp Chat", "Contact", "Book Consultation", "Services"],
    )


@app.route("/chat", methods=["POST"])
def chat():
    payload = request.get_json(silent=True) or {}
    user_message = payload.get("message", "")
    lang = payload.get("lang", "en")
    response = get_bot_reply(user_message, lang)
    return jsonify(response)


@app.route("/google-login")
def google_login():
    redirect_uri = url_for("google_callback", _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route("/google/callback")
def google_callback():
    token = google.authorize_access_token(leeway=10)
    user = google.get(
        "https://www.googleapis.com/oauth2/v2/userinfo"
    ).json()
    next_page = session.get("next")
    session.clear()
    session["role"] = "user"
    session["user"] = {
        "email": user["email"],
        "name": user["name"],
        "picture": user["picture"]
    }
    session["_boot_id"] = app.config["SESSION_BOOT_ID"]
    session["_last_seen"] = int(time.time())
    return redirect(next_page or "/")


@app.after_request
def disable_cache(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.before_request
def enforce_short_session():
    # Ensure auth cookies are non-persistent and enforce server-side expiry.
    session.permanent = False
    now = int(time.time())
    role = session.get("role")

    if role:
        # Invalidate authenticated sessions from previous server runs.
        if session.get("_boot_id") != app.config["SESSION_BOOT_ID"]:
            session.clear()
            return

        last_seen = session.get("_last_seen")
        if last_seen and now - int(last_seen) > app.config["SESSION_IDLE_TIMEOUT_SECONDS"]:
            session.clear()
            return

    session["_last_seen"] = now
@app.route("/")
def home():
    normalize_session_role()
    return render_template("home.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        validate_csrf()
        next_page = session.get("next")
        email = request.form.get("email")
        password = request.form.get("password")

        if not email or not password:
            return "Email and password required", 400

        hashed_password = generate_password_hash(password)

        conn, cursor = get_db()

        try:
            cursor.execute(
                "INSERT INTO users (email, password) VALUES (%s, %s)",
                (email, hashed_password)
            )
            conn.commit()
        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            cursor.close()
            conn.close()
            return "Email already registered", 409
        except Exception as e:
            conn.rollback()
            cursor.close()
            conn.close()
            raise e

        cursor.close()
        conn.close()

        session.clear()
        session["role"] = "user"
        session["user"] = {
            "email": email,
            "name": email.split("@")[0]
        }
        session["_boot_id"] = app.config["SESSION_BOOT_ID"]
        session["_last_seen"] = int(time.time())

        return redirect(next_page or "/")

    return render_template("auth.html", mode="signup")
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        validate_csrf()
        ip = get_client_ip()
        if is_login_rate_limited(ip):
            return "Too many failed login attempts. Please try again later.", 429

        next_page = session.get("next")
        email = request.form.get("email")
        password = request.form.get("password")

        # 🔐 ADMIN LOGIN (from environment variables)
        if is_valid_admin_login(email, password):
            session.clear()
            session["role"] = "admin"
            session["admin_logged_in"] = True
            session["email"] = email
            session["_boot_id"] = app.config["SESSION_BOOT_ID"]
            session["_last_seen"] = int(time.time())
            clear_login_failures(ip)
            return redirect(next_page or "/")

        # 👤 CUSTOMER LOGIN
        conn, cursor = get_db()
        cursor.execute(
            "SELECT id, password FROM users WHERE email=%s",
            (email,)
        )
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and check_password_hash(user[1], password):
            session.clear()
            session["role"] = "user"
            session["user"] = {
                "id": user[0],
                "email": email,
                "name": email.split("@")[0]
            }
            session["_boot_id"] = app.config["SESSION_BOOT_ID"]
            session["_last_seen"] = int(time.time())
            clear_login_failures(ip)
            return redirect(next_page or "/")

        record_login_failure(ip)
        return "Invalid login credentials", 401

    return render_template("auth.html", mode="login")


    return render_template("auth.html", mode="login")

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        validate_csrf()
        email = request.form["email"]
        return redirect("/login")
    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    if request.method == "POST":
        validate_csrf()
        new_password = request.form["password"]

        print("Resetting password with token:", token)

        return redirect("/login")

    return render_template("reset_password.html")

@app.route("/dashboard")
def dashboard():
    normalize_session_role()
    if session.get("role") != "user" or not session.get("user"):
        return redirect("/login")
    return render_template("dashboard.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/belated-itr")
def belated_itr():
    return render_template("belated_itrfiling.html")

@app.route("/tax-planning")
def tax_planning_services():
    return render_template("tax_planning_services.html")

@app.route("/chatbot")
def chatbot():
    return render_template("chatbot.html")


@app.route("/consultation")
def consultation():
    return render_template("consultation.html")


@app.route("/document-checklist")
@app.route("/document_checklist")
@app.route("/checklist")
def document_checklist():
    return render_template("document_checklist.html")


@app.route("/privacy-policy")
def privacy_policy():
    return render_template("privacy_policy.html")


@app.route("/terms-and-conditions")
def terms_and_conditions():
    return render_template("terms_and_conditions.html")


@app.route("/data-confidentiality")
def data_confidentiality():
    return render_template("data_confidentiality.html")


def redirect_to_offline_support():
    whatsapp_number = os.getenv("WHATSAPP_NUMBER", "919676359019")
    whatsapp_text = os.getenv(
        "WHATSAPP_TEXT",
        "Hi%20I%20need%20assistance%20with%20tax%20and%20compliance"
    )
    return redirect(f"https://wa.me/{whatsapp_number}?text={whatsapp_text}")


@app.route("/buy-now")
def buy_now():
    return redirect_to_offline_support()

@app.route("/payment")
def payment():
    return redirect_to_offline_support()


@app.route("/pay", methods=["POST"])
def pay():
    return redirect_to_offline_support()

@app.route("/payment-success")
def payment_success():
    return redirect_to_offline_support()

@app.route("/request-callback", methods=["POST"])
def request_callback():
    validate_csrf()
    phone = (request.form.get("phone") or "").strip()
    email = (request.form.get("email") or "").strip()
    name = (request.form.get("name") or "").strip()
    service = (request.form.get("service") or "").strip()
    preferred_time = (request.form.get("preferred_time") or "").strip()
    message = (request.form.get("message") or "").strip()
    source_page = (request.form.get("source_page") or request.path or "").strip()

    if not phone and not email:
        return status_redirect("/consultation", "missing_contact")

    try:
        conn = get_db_connection()
    except psycopg2.OperationalError:
        return status_redirect("/consultation", "db_error")

    cursor = None
    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 1
            FROM callback_requests
            WHERE COALESCE(phone, '') = %s
              AND COALESCE(email, '') = %s
              AND COALESCE(service, '') = %s
              AND DATE(created_at) = CURRENT_DATE
            LIMIT 1
        """, (phone, email, service))
        if cursor.fetchone():
            cursor.close()
            return status_redirect("/consultation", "duplicate")

        cursor.execute("""
            INSERT INTO callback_requests
            (phone, email, name, service, preferred_time, message, source_page)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (phone, email, name, service, preferred_time, message, source_page))
        conn.commit()
        cursor.close()
    except psycopg2.OperationalError:
        conn.rollback()
        return status_redirect("/consultation", "db_error")
    except UniqueViolation:
        conn.rollback()
        return status_redirect("/consultation", "duplicate")
    finally:
        release_db_connection(conn)

    print("📞 NEW CALLBACK REQUEST:", phone, email, service)
    return status_redirect("/consultation", "submitted")


from psycopg2.errors import UniqueViolation

@app.route("/register-business", methods=["GET", "POST"])
def register_business():
    if request.method == "POST":
        validate_csrf()
        conn, cursor = get_db()

        try:
            cursor.execute("""
                INSERT INTO business_registrations
                (business_name, business_type, services, owner_name, email, phone, city)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
            """, (
                request.form["business_name"],
                request.form["business_type"],
                ", ".join(request.form.getlist("services")),
                request.form["owner_name"],
                request.form["email"],
                request.form["phone"],
                request.form["city"]
            ))
            conn.commit()

        except UniqueViolation:
            conn.rollback()
            return "❌ Business already registered", 409

        finally:
            cursor.close()
            conn.close()

        return redirect("/business-success")

    return render_template("register_business.html")

@app.route("/admin/update-status", methods=["POST"])
def update_business_status():
    if not session.get("admin_logged_in"):
        return redirect("/login")
    validate_csrf()

    business_id = request.form["id"]
    status = request.form["status"]

    try:
        conn = get_db_connection()
    except psycopg2.OperationalError:
        return admin_business_next_redirect("db_error")
    try:
        cur = conn.cursor()
        cur.execute("""
            UPDATE business_registrations
            SET status = %s
            WHERE id = %s
        """, (status, business_id))
        conn.commit()
        cur.close()
    except psycopg2.OperationalError:
        conn.rollback()
        return admin_business_next_redirect("db_error")
    finally:
        release_db_connection(conn)

    return admin_business_next_redirect()


@app.route("/admin/delete-business", methods=["POST"])
def delete_business():
    if not session.get("admin_logged_in"):
        return redirect("/login")
    validate_csrf()

    business_id = request.form["id"]

    try:
        conn = get_db_connection()
    except psycopg2.OperationalError:
        return admin_business_next_redirect("db_error")
    try:
        cur = conn.cursor()
        cur.execute("""
            DELETE FROM business_registrations
            WHERE id = %s
        """, (business_id,))
        conn.commit()
        cur.close()
    except psycopg2.OperationalError:
        conn.rollback()
        return admin_business_next_redirect("db_error")
    finally:
        release_db_connection(conn)

    return admin_business_next_redirect()

@app.route("/business-success")
def business_success():
    return render_template("business_success.html")


@app.context_processor
def inject_whatsapp():
    return {
        "WHATSAPP_NUMBER": os.getenv("WHATSAPP_NUMBER"),
        "WHATSAPP_TEXT": os.getenv("WHATSAPP_TEXT"),
        "csrf_token": get_csrf_token
    }

@app.errorhandler(403)
def forbidden(_error):
    return render_template("403.html"), 403


#admin dashboard

@app.route("/admin/dashboard")
def admin_dashboard():
    normalize_session_role()
    if session.get("role") != "admin":
        return redirect("/login")

    try:
        ensure_admin_indexes()
        conn = get_db_connection()
    except psycopg2.OperationalError:
        return render_template(
            "admin_dashboard.html",
            callback_count=0,
            business_count=0,
            new_callbacks=0,
            new_businesses=0,
            db_error=True
        )

    try:
        cursor = conn.cursor()
        # Single round-trip query for dashboard counters.
        cursor.execute("""
            SELECT
                (SELECT COUNT(*) FROM callback_requests) AS callback_count,
                (SELECT COUNT(*) FROM business_registrations) AS business_count,
                (SELECT COUNT(*) FROM callback_requests WHERE status = 'pending') AS new_callbacks,
                (SELECT COUNT(*) FROM business_registrations WHERE status = 'NEW') AS new_businesses
        """)
        callback_count, business_count, new_callbacks, new_businesses = cursor.fetchone()

        return render_template(
            "admin_dashboard.html",
            callback_count=callback_count,
            business_count=business_count,
            new_callbacks=new_callbacks,
            new_businesses=new_businesses
        )
    except psycopg2.OperationalError:
        return render_template(
            "admin_dashboard.html",
            callback_count=0,
            business_count=0,
            new_callbacks=0,
            new_businesses=0,
            db_error=True
        )
    finally:
        if cursor is not None:
            cursor.close()
        release_db_connection(conn)

if __name__ == "__main__":
    app.run(debug=True, port=5003)
