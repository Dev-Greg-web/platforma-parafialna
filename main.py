from flask import Flask, render_template, request, flash, redirect, url_for, session, send_from_directory, send_file, abort, jsonify
from markupsafe import Markup, escape
from models import (
    Users, Attendance, Announcement, Schedule, db,
    PasswordResetRequest, SystemSettings, AuditLog, PushSubscription,
    get_setting, set_setting
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_limiter import Limiter
from apscheduler.schedulers.background import BackgroundScheduler
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload
from sqlalchemy import inspect, text
from datetime import datetime, timedelta, date, timezone
from zoneinfo import ZoneInfo
import calendar
import os
import secrets
from dotenv import load_dotenv
import pandas as pd
import io
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.chart import PieChart, Reference
from openpyxl.utils import get_column_letter
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import urllib.request
import json
from threading import Thread, Lock
import requests
from sqlalchemy.orm import joinedload
from collections import defaultdict
from functools import wraps
import re

load_dotenv()

app = Flask(__name__)

_SVG_ICON_CACHE = {}

def _load_raw_svg_icon(name):
    """Wczytuje zawartość pliku .svg z static/icons/ (z pamięcią podręczną)."""
    if not name or not re.fullmatch(r"[a-z0-9-]+", name):
        return ""
    if name not in _SVG_ICON_CACHE:
        icon_path = os.path.join(app.root_path, "static", "icons", f"{name}.svg")
        if os.path.isfile(icon_path):
            with open(icon_path, "r", encoding="utf-8") as f:
                _SVG_ICON_CACHE[name] = f.read().strip()
        else:
            _SVG_ICON_CACHE[name] = ""
    return _SVG_ICON_CACHE[name]

def render_svg_icon(name, cls="w-4 h-4 shrink-0 inline-block"):
    """Renderuje bezpiecznie ikonę SVG z static/icons/ z podanymi klasami CSS."""
    raw = _load_raw_svg_icon(name)
    if not raw:
        return Markup("")
    safe_cls = escape(cls)
    return Markup(raw.replace("<svg ", f'<svg class="{safe_cls}" aria-hidden="true" ', 1))

def get_svg_icon_map(names=None):
    """Zwraca mapę nazwa -> surowe źródło SVG do użycia w JavaScript."""
    icons_dir = os.path.join(app.root_path, "static", "icons")
    if names is None and os.path.isdir(icons_dir):
        names = [f[:-4] for f in sorted(os.listdir(icons_dir)) if f.endswith(".svg")]
    return {n: _load_raw_svg_icon(n) for n in (names or []) if _load_raw_svg_icon(n)}

app.jinja_env.globals["render_svg_icon"] = render_svg_icon
app.jinja_env.globals["svg_icon"] = render_svg_icon
app.jinja_env.globals["get_svg_icon_map"] = get_svg_icon_map

app.secret_key = os.getenv("TAJNE_HASLO") or secrets.token_hex(32)
db_url = os.getenv("DATABASE_URL", "sqlite:///ministranci.db")

if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql+psycopg://", 1)
elif db_url.startswith("postgresql://") and not db_url.startswith("postgresql+"):
    db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = db_url

app.permanent_session_lifetime = timedelta(minutes=15)

# --- UTWARDZENIE CIASTECZEK I SESJI ---
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Włącz HTTPS cookie, jeśli aplikacja działa na serwerze z SSL (np. Render / Heroku)
if os.getenv("FLASK_ENV") == "production" or os.getenv("RENDER"):
    app.config["SESSION_COOKIE_SECURE"] = True

app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 280,
    "pool_pre_ping": True
}

db.init_app(app)

# --- OCHRONA CSRF ORAZ RATE LIMITING (BRUTE-FORCE PROTECTION) ---
csrf = CSRFProtect(app)

def get_client_ip():
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
    return request.remote_addr or "127.0.0.1"

limiter = Limiter(
    get_client_ip,
    app=app,
    default_limits=["500 per day", "120 per hour"],
    storage_uri="memory://"
)

_AUDIT_EXPORT_LOCK = Lock()
AUDIT_LOG_AUTO_EXPORT_LIMIT = 100

_AUDIT_EVENT_CATEGORY_STYLES = {
    "LOG_AUTH_01": ("Logowanie / Autoryzacja (Sukces)", "ECFDF5"),
    "LOG_AUTH_02": ("Odmowa / Błąd Autoryzacji", "FEF2F2"),
    "LOG_2FA_01": ("Weryfikacja 2FA", "FFFBEB"),
    "LOG_PWD_RESET": ("Reset Hasła", "FFFBEB"),
    "LOG_REG_01": ("Rejestracja Konta", "F5F3FF"),
    "LOG_DRIVE_EXPORT": ("Eksport Google Drive", "F0F9FF"),
    "LOG_ADMIN_ACTION": ("Akcja Administracyjna", "F8FAFC"),
}


def _extract_drive_folder_id(raw_val):
    """Wyciąga czyste ID folderu Google Drive z podanego ID lub pełnego linku."""
    val = (raw_val or "").strip()
    if not val:
        return ""
    m_folder = re.search(r"/folders/([a-zA-Z0-9_-]+)", val)
    if m_folder:
        return m_folder.group(1)
    m_id = re.search(r"[?&]id=([a-zA-Z0-9_-]+)", val)
    if m_id:
        return m_id.group(1)
    return val.split("?")[0].strip()


def get_audit_logs_drive_folder_id():
    """Zwraca docelowe ID folderu Google Drive dla archiwum AuditLog."""
    return (
        _extract_drive_folder_id(get_setting("audit_logs_drive_folder_id", ""))
        or _extract_drive_folder_id(os.getenv("GOOGLE_DRIVE_LOGS_FOLDER_ID", ""))
        or _extract_drive_folder_id(os.getenv("GOOGLE_DRIVE_FOLDER_ID", ""))
    )


def log_audit_event(event_code, username=None, ip_address=None, details=None):
    try:
        if username is None:
            try:
                username = session.get('username')
            except Exception:
                username = None
        if ip_address is None:
            try:
                ip_address = get_client_ip()
            except Exception:
                ip_address = None
        entry = AuditLog(
            event_code=str(event_code)[:50],
            username=str(username)[:50] if username else None,
            ip_address=str(ip_address)[:255] if ip_address else None,
            details=str(details) if details else None,
            created_at=datetime.now()
        )
        db.session.add(entry)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Błąd zapisu AuditLog ({event_code}): {e}")
        return

    # Automatyczny eksport po osiągnięciu pełnego bufora 50 / 50 logów
    try:
        if AuditLog.query.count() >= AUDIT_LOG_AUTO_EXPORT_LIMIT and _AUDIT_EXPORT_LOCK.acquire(blocking=False):
            try:
                if AuditLog.query.count() >= AUDIT_LOG_AUTO_EXPORT_LIMIT:
                    export_audit_logs_batch_to_drive(clear_exported=True, trigger_label="AUTO_50")
            except Exception as export_err:
                try:
                    db.session.rollback()
                    set_setting("last_audit_drive_export_error", str(export_err)[:250])
                except Exception:
                    pass
                print(f"Ostrzeżenie automatycznego eksportu AuditLog (50/50): {export_err}")
            finally:
                _AUDIT_EXPORT_LOCK.release()
    except Exception as lock_err:
        print(f"Błąd sprawdzania limitu AuditLog: {lock_err}")

@app.errorhandler(429)
def ratelimit_handler(e):
    flash("Zbyt wiele prób w krótkim czasie (przekroczono limit zapytań). Odczekaj chwilę i spróbuj ponownie.", "danger")
    return render_template('login.html'), 429

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash("Sesja formularza wygasła lub brak poprawnego tokenu bezpieczeństwa CSRF. Odśwież stronę i spróbuj ponownie.", "danger")
    return render_template('login.html'), 400

# --- NATIVE PROTECTION / DECORATORS ---

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Proszę się zalogować, aby uzyskać dostęp.", "warning")
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('user_role') != 'admin':
            if session.get('has_admin_rank'):
                flash("Aby wejść do Panelu Admina, zaloguj się na Konto Admina (wymaga GPS i kodu z Telegrama).", "warning")
                return redirect(url_for('login_page', mode='admin'))
            flash("Brak wymaganych uprawnień administratora!", "danger")
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

def staff_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('user_role') not in ['admin', 'ksiądz']:
            flash("Brak dostępu do tej sekcji.", "danger")
            return redirect(url_for('dashboard_page'))
        return f(*args, **kwargs)
    return decorated_function

# --- FILTRY JINJA2 ---
@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M'):
    if value is None:
        return ""
    return value.strftime(format)

@app.template_filter('dateformat')
def dateformat(value, format='%Y-%m-%d'):
    if value is None:
        return ""
    if isinstance(value, str):
        try:
            value = datetime.strptime(value, '%Y-%m-%d').date()
        except ValueError:
            return value
    return value.strftime(format)

# --- ROZSZERZONE NAGŁÓWKI BEZPIECZEŃSTWA (SECURITY HEADERS + CSP + HSTS) ---
@app.after_request
def add_security_headers(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(self)"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.tailwindcss.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    if os.getenv("FLASK_ENV") == "production" or os.getenv("RENDER"):
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

def format_datetime_pl(dt):
    if not dt: return ""
    dni = ["pon.", "wt.", "śr.", "czw.", "pt.", "sob.", "nd."]
    godz_min = dt.strftime("%H:%M")
    return f"{dni[dt.weekday()]} {dt.day}.{dt.month} o {godz_min}"

app.jinja_env.filters['datetime_pl'] = format_datetime_pl

def get_env_admin_name():
    return os.getenv("ADMIN_NAME") or os.getenv("admin_name") or "AdminGreg"

def get_env_admin_pass():
    val = os.getenv("ADMIN_PASSWORD") or os.getenv("admin_password")
    return val.strip() if val and val.strip() else None

def get_attendance_days_back():
    try:
        val = int(get_setting('attendance_days_back', 3))
        return max(0, min(365, val))
    except (ValueError, TypeError):
        return 3

def parse_user_agent(ua_string):
    if not ua_string:
        return "Nieznane urządzenie"
    ua = ua_string.lower()
    
    if "android" in ua:
        os_info = "Telefon/Tablet Android"
    elif "iphone" in ua:
        os_info = "Apple iPhone (iOS)"
    elif "ipad" in ua or "ipod" in ua:
        os_info = "Apple iPad (iOS)"
    elif "windows" in ua:
        os_info = "Komputer Windows PC"
    elif "macintosh" in ua or "mac os" in ua:
        os_info = "Komputer Mac (macOS)"
    elif "linux" in ua:
        os_info = "Komputer Linux"
    else:
        os_info = "Nieznany system/urządzenie"
        
    if "edg" in ua:
        browser = "Microsoft Edge"
    elif "chrome" in ua and "safari" in ua:
        browser = "Google Chrome"
    elif "firefox" in ua:
        browser = "Mozilla Firefox"
    elif "safari" in ua:
        browser = "Apple Safari"
    elif "opera" in ua or "opr" in ua:
        browser = "Opera"
    else:
        browser = "Inna przeglądarka"
        
    return f"{os_info} | Przeglądarka: {browser}"

def resolve_ip_and_coords(ip_addr):
    result = {
        "display": ip_addr,
        "lat": None,
        "lng": None
    }
    
    if not ip_addr or ip_addr == "127.0.0.1":
        result["display"] = "127.0.0.1 (Lokalny komputer testowy)"
        result["lat"] = "52.2297"
        result["lng"] = "21.0118"
        return result
        
    try:
        token = os.getenv("IPINFO_TOKEN") or "093ef441db1164"
        url = f"https://ipinfo.io/{ip_addr}/json?token={token}"
        res = requests.get(url, timeout=2)
        if res.status_code == 200:
            data = res.json()
            city = data.get("city", "Nieznane miasto")
            country = data.get("country", "PL")
            loc = data.get("loc", "")
            
            if loc:
                result["display"] = f"{ip_addr} ({city}, {country}) | Szacowany GPS z IP: {loc}"
                parts = loc.split(",")
                if len(parts) == 2:
                    result["lat"] = parts[0].strip()
                    result["lng"] = parts[1].strip()
            else:
                result["display"] = f"{ip_addr} ({city}, {country})"
    except Exception as e:
        print(f"Błąd pobierania IPinfo: {e}")
    return result

def send_telegram_alert(tresc):
    token = os.getenv("TELEGRAM_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        print("--- [Telegram] Brak tokenu lub Chat ID w zmiennych środowiskowych! ---")
        return
        
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id, 
        "text": tresc,
        "disable_web_page_preview": False
    }
    try:
        requests.post(url, json=payload, timeout=5)
    except Exception as e:
        print(f"Błąd powiadomienia Telegram: {e}")

def verify_user_password(user, password, env_admin_name=None, env_admin_pass=None):
    if not user or not password or not user.password:
        return False
    if user.password.startswith(('pbkdf2:', 'scrypt:')):
        try:
            return check_password_hash(user.password, password)
        except Exception:
            return False
    if user.role == 'admin':
        return False
    return user.password == password

@app.route('/telegram-webhook', methods=['POST'])
@app.route('/telegram_webhook', methods=['POST'])
@csrf.exempt
def telegram_webhook():
    webhook_secret = os.getenv("TELEGRAM_WEBHOOK_SECRET")
    if webhook_secret:
        header_secret = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
        if not secrets.compare_digest(header_secret, webhook_secret):
            log_audit_event(
                "LOG_AUTH_02",
                username="TELEGRAM_WEBHOOK",
                ip_address=get_client_ip(),
                details="Odrzucono wywołanie webhooka Telegram - nieprawidłowy X-Telegram-Bot-Api-Secret-Token"
            )
            abort(403)

    update = request.get_json(silent=True)
    if not update or "message" not in update:
        return "OK", 200

    message = update["message"]
    chat_id = str(message.get("chat", {}).get("id"))
    text = message.get("text", "").strip()

    # Weryfikacja, czy wiadomość pochodzi od uprawnionego administratora
    allowed_chat_id = os.getenv("TELEGRAM_CHAT_ID")
    if chat_id != str(allowed_chat_id):
        return "OK", 200

    # Szukamy aktywnej (PENDING) prośby z ostatnich 5 minut (dla dowolnego admina)
    piec_minut_temu = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=5)
    pending_request = PasswordResetRequest.query.filter(
        PasswordResetRequest.status == 'PENDING',
        PasswordResetRequest.created_at >= piec_minut_temu
    ).order_by(PasswordResetRequest.created_at.desc()).first()

    admin = db.session.get(Users, pending_request.user_id) if pending_request else None
    if not admin:
        env_admin_name = get_env_admin_name()
        admin = Users.query.filter_by(username=env_admin_name).first()

    if not admin:
        return "OK", 200

    # Normalizacja tekstu do małych liter dla łatwiejszego porównywania
    text_clean = text.lower().strip()

    # 1. Próba ustawienia nowego hasła z wartością (np. /ustaw_haslo MojeHaslo123)
    if text.startswith("/ustaw_haslo "):
        if not pending_request:
            send_telegram_alert("[BŁĄD] Brak aktywnej prośby o zmianę hasła lub czas na odpowiedź (5 min) wygasł! Wywołaj najpierw reset na stronie.")
            return "OK", 200

        nowe_haslo = text.replace("/ustaw_haslo ", "").strip()
        if len(nowe_haslo) < 4:
            send_telegram_alert("[UWAGA] Hasło jest za krótkie! Wyślij ponownie w formacie:\n`/ustaw_haslo MojeBezpieczneHaslo123`")
            return "OK", 200

        # Zapisujemy nowe shashowane hasło w bazie danych
        admin.password = generate_password_hash(nowe_haslo, method='pbkdf2:sha256')
        admin.failed_login_attempts = 0
        admin.locked_until = None
        pending_request.status = 'APPROVED'
        db.session.commit()

        log_audit_event(
            "LOG_PWD_RESET",
            username=admin.username,
            ip_address=pending_request.ip_address,
            details="Hasło administratora zostało zmienione poprzez autoryzację Telegram."
        )
        send_telegram_alert(f"[OK] *SUKCES!* Hasło dla konta `{admin.username}` zostało pomyślnie zmienione w bazie danych (zaszyfrowane PBKDF2-SHA256)!")

    # 2. Samo "ustaw hasło" / "/ustaw_haslo" (poinstruowanie użytkownika)
    elif text_clean in ["ustaw hasło", "ustaw haslo", "ustaw_haslo", "/ustaw_haslo"]:
        if pending_request:
            send_telegram_alert("[KLUCZ] Aby ustawić nowe hasło, dopisz je po spacji w poleceniu, np.:\n\n`/ustaw_haslo MojeTajneHaslo123`")
        else:
            send_telegram_alert("[INFO] Brak aktywnej prośby o reset. Aby zmienić hasło, kliknij najpierw przycisk 'Wyślij Hasło' na stronie logowania.")

    # 3. Odrzucenie prośby (obsługuje: /odrzuc, /odrzuć, odrzuc, odrzuć, odrzut)
    elif text_clean in ["/odrzuc", "/odrzuć", "odrzuc", "odrzuć", "odrzut"]:
        if pending_request:
            pending_request.status = 'REJECTED'
            db.session.commit()
            log_audit_event(
                "LOG_PWD_RESET",
                username=admin.username,
                ip_address=pending_request.ip_address,
                details="Prośba o reset hasła administratora została odrzucona przez Telegram."
            )
            send_telegram_alert("[ODRZUCONO] *PROŚBA ODRZUCONA!* Próba zmiany hasła została pomyślnie anulowana.")
        else:
            send_telegram_alert("[INFO] Brak aktywnych żądań resetu hasła do odrzucenia.")

    return "OK", 200

@app.route('/health')
@limiter.exempt
def health_check():
    return jsonify({"status": "ok"}), 200

@app.route('/')
def login_page():
    requested_mode = (request.args.get('mode') or '').strip().lower()
    if 'user_id' in session:
        if session.get('user_role') == 'admin':
            return redirect(url_for('admin_page'))
        if requested_mode == 'admin':
            return render_template('login.html')
        elif session.get('user_role') == 'ksiądz':
            return redirect(url_for('ksDash'))
        return redirect(url_for('dashboard_page'))

    rejected_banner = None
    approved_banner = None
    pending_id = session.get('pending_registration_user_id')
    if pending_id:
        pending_user = Users.query.get(pending_id)
        if not pending_user:
            session.pop('pending_registration_user_id', None)
        elif not pending_user.is_approved and (getattr(pending_user, 'verification_status', None) == 'REJECTED' or pending_user.rejection_reason):
            powod = (pending_user.rejection_reason or "Brak podanego powodu.").strip()
            rejected_banner = f"Twoje konto zostało odrzucone przez administratora. Powód odrzucenia: {powod}"
        elif pending_user.is_approved:
            approved_banner = "Twoje konto zostało zatwierdzone przez administratora! Możesz się już zalogować."
            session.pop('pending_registration_user_id', None)

    return render_template('login.html', rejected_banner=rejected_banner, approved_banner=approved_banner)

@app.route("/auth_process", methods=['POST'])
@limiter.limit("5 per minute")
def auth_process():
    action = request.form.get("action")
    username = (request.form.get("username") or "").strip()
    password = request.form.get("haslo") or request.form.get("password")
    login_mode = (request.form.get("login_mode") or "normal").strip().lower()
    redirect_kwargs = {'mode': 'admin'} if login_mode == 'admin' else {}
    
    env_admin_name = get_env_admin_name()
    env_admin_pass = get_env_admin_pass()

    if not password or not username:
        flash("Proszę podać login oraz hasło.", "warning")
        return redirect(url_for('login_page', **redirect_kwargs))

    user_ip = get_client_ip()
    ip_data = resolve_ip_and_coords(user_ip)
    resolved_ip_str = ip_data["display"]
    
    user_agent_raw = request.headers.get('User-Agent', 'Nieznana przeglądarka')
    device_info = parse_user_agent(user_agent_raw)
    
    teraz = datetime.now()
    data_str = teraz.strftime("%d.%m.%Y")
    godzina_str = teraz.strftime("%H:%M:%S")

    browser_lat = request.form.get("geo_lat")
    browser_lng = request.form.get("geo_lng")
    has_gps = bool(browser_lat and browser_lng and browser_lat.strip() != "" and browser_lng.strip() != "")

    if action == "login":
        if not request.form.get('regulamin'):
            flash('Musisz zaakceptować regulamin, aby się zalogować!', 'danger')
            return redirect(url_for('login_page', **redirect_kwargs))

        # Upewniamy się, że główny administrator z .env posiada swoje konto w bazie Users
        if username == env_admin_name:
            admin_in_db = Users.query.filter_by(username=username).first()
            if not admin_in_db:
                if not env_admin_pass:
                    raise RuntimeError("Brak zmiennej środowiskowej ADMIN_PASSWORD / admin_password wymaganej do utworzenia konta administratora!")
                hashed_admin_pass = generate_password_hash(env_admin_pass, method='pbkdf2:sha256')
                admin_in_db = Users(
                    imie="Główny", 
                    nazwisko="Szef", 
                    username=username, 
                    password=hashed_admin_pass, 
                    role='admin', 
                    uproszczony=False,
                    is_approved=True,
                    verification_status='APPROVED'
                )
                db.session.add(admin_in_db)
                db.session.commit()

        user = Users.query.filter_by(username=username).first()

        # Sprawdzenie blokady konta Brute-Force
        if user and user.locked_until:
            if user.locked_until > datetime.now():
                pozostalo_sek = int((user.locked_until - datetime.now()).total_seconds())
                pozostalo_min = max(1, (pozostalo_sek + 59) // 60)
                log_audit_event(
                    "LOG_AUTH_02",
                    username=username,
                    ip_address=resolved_ip_str,
                    details=f"Odrzucono próbę logowania - konto zablokowane (pozostało ok. {pozostalo_min} min)"
                )
                flash(f"Konto jest zablokowane z powodu zbyt wielu nieudanych prób logowania. Spróbuj ponownie za {pozostalo_min} min.", "danger")
                return redirect(url_for('login_page', **redirect_kwargs))
            else:
                # Blokada wygasła - zerujemy licznik sprzed blokady
                user.failed_login_attempts = 0
                user.locked_until = None

        is_pass_valid = verify_user_password(user, password)

        if not user or not is_pass_valid:
            if user:
                user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
                if user.failed_login_attempts >= 5:
                    user.locked_until = datetime.now() + timedelta(minutes=15)
                    db.session.commit()
                    log_audit_event(
                        "LOG_AUTH_02",
                        username=username,
                        ip_address=resolved_ip_str,
                        details=f"Blokada konta na 15 minut po {user.failed_login_attempts} nieudanych próbach logowania"
                    )
                    lock_alert = (
                        f"[ALERT BRUTE-FORCE] *ZABLOKOWANO KONTO!*\n\n"
                        f"Konto `{username}` zostało zablokowane na 15 minut po {user.failed_login_attempts} nieudanych próbach logowania.\n"
                        f"IP: {resolved_ip_str}\n"
                        f"Urządzenie: {device_info}\n"
                        f"Czas: {data_str} {godzina_str}"
                    )
                    Thread(target=send_telegram_alert, args=[lock_alert]).start()
                    flash("Przekroczono limit 5 nieudanych prób logowania. Konto zostało zablokowane na 15 minut.", "danger")
                    return redirect(url_for('login_page', **redirect_kwargs))
                else:
                    db.session.commit()
                    log_audit_event(
                        "LOG_AUTH_02",
                        username=username,
                        ip_address=resolved_ip_str,
                        details=f"Błędne hasło (próba {user.failed_login_attempts}/5, tryb: {login_mode})"
                    )
            else:
                log_audit_event(
                    "LOG_AUTH_02",
                    username=username,
                    ip_address=resolved_ip_str,
                    details=f"Nieudane logowanie - nieistniejący użytkownik (tryb: {login_mode})"
                )

            if login_mode == "admin":
                flash("Podane dane logowania administratora są nieprawidłowe.", "danger")
                return redirect(url_for('login_page', mode='admin'))
            flash("Niepoprawna nazwa użytkownika lub hasło.", "danger")
            return redirect(url_for('login_page'))

        # Hasło poprawne - zerujemy licznik błędnych logowań
        user.failed_login_attempts = 0
        user.locked_until = None
        if user.role != 'admin' and user.password and user.password.startswith(('pbkdf2:', 'scrypt:')):
            user.password = password

        # Wariant 1: Logowanie na KONTO ADMINA (wymaga rangi admin, akceptacji GPS oraz kodu 2FA z Telegrama)
        if login_mode == "admin":
            if user.role != 'admin':
                db.session.commit()
                log_audit_event(
                    "LOG_AUTH_02",
                    username=username,
                    ip_address=resolved_ip_str,
                    details="Próba logowania w trybie Admin przez konto bez uprawnień administratora"
                )
                flash("Twoje konto nie posiada rangi administratora! Wybierz 'Konto normalne', aby się zalogować.", "danger")
                return redirect(url_for('login_page'))

            if not has_gps:
                db.session.commit()
                log_audit_event(
                    "LOG_AUTH_02",
                    username=username,
                    ip_address=resolved_ip_str,
                    details="Odrzucono logowanie administratora - brak udostępnionej lokalizacji GPS"
                )
                alert_text = (
                    f"[BLOKADA] ODRZUCONO PRÓBĘ LOGOWANIA ADMINA (BRAK GPS)!\n\n"
                    f"Wykryto PRAWIDŁOWE hasło do konta Admin ({username}), ale logowanie zostało ZABLOKOWANE ze względu na brak zgody na geolokalizację GPS!\n\n"
                    f"DANE POŁĄCZENIA:\n"
                    f"Data: {data_str}\n"
                    f"Godzina: {godzina_str}\n"
                    f"Adres IP: {user_ip}\n"
                    f"Szacowane IP: {resolved_ip_str}\n"
                    f"Urządzenie: {device_info}\n"
                )
                thr = Thread(target=send_telegram_alert, args=[alert_text])
                thr.start()

                flash("Logowanie na konto Administratora wymaga OBOWIĄZKOWEGO udostępnienia lokalizacji GPS z urządzenia! Włącz geolokalizację i spróbuj ponownie.", "danger")
                return redirect(url_for('login_page', mode='admin'))

            user.registration_ip = resolved_ip_str
            user.latitude = str(browser_lat.strip())
            user.longitude = str(browser_lng.strip())
            user.is_approved = True
            user.verification_status = 'APPROVED'
            
            bloki = ["".join([str(secrets.randbelow(10)) for _ in range(3)]) for _ in range(4)]
            kod_2fa = "-".join(bloki)
            
            user.two_factor_code = kod_2fa
            user.two_factor_expiry = datetime.now() + timedelta(minutes=5)
            db.session.commit()

            log_audit_event(
                "LOG_2FA_01",
                username=username,
                ip_address=resolved_ip_str,
                details="Wygenerowano i wysłano kod 2FA dla logowania administratora"
            )

            maps_url = f"https://www.google.com/maps/search/?api=1&query={browser_lat.strip()},{browser_lng.strip()}"

            telegram_2fa_text = (
                f"======================================\n"
                f"SEKCJA 1: KOD WERYFIKACYJNY 2FA\n"
                f"======================================\n\n"
                f"TWÓJ KOD DOSTĘPU: `{kod_2fa}`\n\n"
                f"Kod wygaśnie za 5 minut.\n\n"
                f"======================================\n"
                f"SEKCJA 2: DANE LOGUJĄCEGO SIĘ (DOWODY)\n"
                f"======================================\n\n"
                f"Konto: Administrator (@{username})\n"
                f"Data: {data_str}\n"
                f"Godzina: {godzina_str}\n"
                f"IP: {user_ip}\n"
                f"Sieć/IP Geolokalizacja: {resolved_ip_str}\n"
                f"Dokładne GPS Urządzenia: {browser_lat.strip()}, {browser_lng.strip()}\n"
                f"Google Maps: {maps_url}\n"
                f"Urządzenie: {device_info}\n"
                f"Full User-Agent: {user_agent_raw}\n\n"
                f"UWAGA: Jeśli to nie Ty, zgłoś to natychmiast!"
            )

            try:
                thr = Thread(target=send_telegram_alert, args=[telegram_2fa_text])
                thr.start()
                
                session.clear()
                session['pending_admin_id'] = user.id
                return redirect(url_for('two_factor_page'))
            except Exception:
                flash("Coś poszło nie tak przy generowaniu kodu 2FA.", "danger")
                return redirect(url_for('login_page', mode='admin'))

        # Wariant 2: Logowanie na KONTO NORMALNE (również dla osób z rangą admina - bez wymogu GPS i bez kodu Telegram)
        else:
            if not user.is_approved and user.role != 'admin':
                db.session.commit()
                if getattr(user, 'verification_status', None) == 'REJECTED' or user.rejection_reason:
                    powod = (user.rejection_reason or "Brak podanego powodu.").strip()
                    log_audit_event(
                        "LOG_AUTH_02",
                        username=username,
                        ip_address=resolved_ip_str,
                        details=f"Próba logowania na odrzucone konto (powód: {powod})"
                    )
                    flash(f"Twoje konto zostało odrzucone przez administratora. Powód odrzucenia: {powod}", "rejected")
                    return redirect(url_for('login_page'))
                log_audit_event(
                    "LOG_AUTH_02",
                    username=username,
                    ip_address=resolved_ip_str,
                    details="Próba logowania na niezatwierdzone konto"
                )
                flash("Twoje konto oczekuje na weryfikację przez administratora.", "warning")
                return redirect(url_for('login_page'))
            
            user.registration_ip = resolved_ip_str
            
            if has_gps:
                user.latitude = str(browser_lat.strip())
                user.longitude = str(browser_lng.strip())
            elif not user.latitude or not user.longitude:
                user.latitude = ip_data["lat"]
                user.longitude = ip_data["lng"]
            
            db.session.commit()
            
            session.clear()
            session['user_id'] = user.id
            session['username'] = user.username
            session['user_role'] = 'ksiądz' if user.role == 'ksiądz' else 'user'
            session['has_admin_rank'] = (user.role == 'admin')
            session['login_mode'] = 'normal'
            session['uproszczony'] = user.uproszczony
            
            log_audit_event(
                "LOG_AUTH_01",
                username=user.username,
                ip_address=resolved_ip_str,
                details="Pomyślne logowanie na konto normalne"
            )
            flash(f"Witaj pomyślnie, {user.imie}!", "success")
            
            if user.role == 'ksiądz':
                return redirect(url_for('ksDash'))
            return redirect(url_for('dashboard_page'))
                
    elif action == "register":
        if not request.form.get('regulamin'):
            flash('Musisz zaakceptować regulamin, aby się zarejestrować!', 'danger')
            return redirect(url_for('login_page'))

        user = Users.query.filter_by(username=username).first()
        if user or username == env_admin_name:
            if user and not user.is_approved and getattr(user, 'verification_status', None) == 'REJECTED':
                flash("Ta nazwa użytkownika jest już zajęta (konto o tym loginie zostało wcześniej odrzucone).", "danger")
            else:
                flash("Ta nazwa użytkownika jest już zajęta.", "danger")
            return redirect(url_for('login_page'))
        else:
            final_lat = str(browser_lat.strip()) if has_gps else None
            final_lng = str(browser_lng.strip()) if has_gps else None

            # Jawne hasło dla zwykłych użytkowników (role='user')
            new_user = Users(
                imie=request.form.get("imie", "").strip(), 
                nazwisko=request.form.get("nazwisko", "").strip(), 
                username=username, 
                password=password,
                role='user',
                uproszczony=False,
                is_approved=False,
                verification_status='PENDING',
                rejection_reason=None,
                admin_message=None,
                registration_ip=resolved_ip_str,
                registration_device=device_info,
                latitude=final_lat,
                longitude=final_lng
            )
            db.session.add(new_user)
            db.session.commit()
            session['pending_registration_user_id'] = new_user.id

            push_sub_raw = (request.form.get("push_subscription_json") or "").strip()
            if push_sub_raw:
                try:
                    push_data = json.loads(push_sub_raw)
                    endpoint = (push_data.get("endpoint") or "").strip()
                    keys = push_data.get("keys") or {}
                    p256dh = (keys.get("p256dh") or "").strip()
                    auth_key = (keys.get("auth") or "").strip()
                    if endpoint and p256dh and auth_key:
                        existing_sub = PushSubscription.query.filter_by(endpoint=endpoint).first()
                        if existing_sub:
                            existing_sub.user_id = new_user.id
                            existing_sub.p256dh = p256dh
                            existing_sub.auth = auth_key
                            existing_sub.user_agent = device_info
                        else:
                            db.session.add(PushSubscription(
                                user_id=new_user.id,
                                endpoint=endpoint,
                                p256dh=p256dh,
                                auth=auth_key,
                                user_agent=device_info
                            ))
                        db.session.commit()
                except Exception:
                    db.session.rollback()
            
            log_audit_event(
                "LOG_REG_01",
                username=username,
                ip_address=resolved_ip_str,
                details=f"Rejestracja nowego konta: {new_user.imie} {new_user.nazwisko} (@{username})"
            )
            send_web_push_to_users(
                user_ids=get_admin_user_ids(),
                title="Nowe konto do weryfikacji",
                body=f"{new_user.imie} {new_user.nazwisko} (@{username}) czeka na weryfikację.",
                url="/admin#weryfikacja"
            )
            flash("Konto stworzone. Poczekaj na weryfikację przez administratora.", "success")
            return redirect(url_for('login_page'))

    return redirect(url_for('login_page'))

def _process_user_update(user_id):
    user = Users.query.get_or_404(user_id)
    user.imie = request.form.get('imie', user.imie).strip()
    user.nazwisko = request.form.get('nazwisko', user.nazwisko).strip()
    user.username = request.form.get('username', user.username).strip()
    new_role = request.form.get('role', user.role).strip()
    user.role = new_role

    if new_role == 'admin':
        user.is_approved = True
        user.verification_status = 'APPROVED'
        user.rejection_reason = None
    elif 'is_approved' in request.form:
        approved_val = str(request.form.get('is_approved')).strip().lower() in ('true', '1', 'on', 'yes')
        user.is_approved = approved_val
        if approved_val:
            user.verification_status = 'APPROVED'
            user.rejection_reason = None
        elif user.verification_status != 'REJECTED':
            user.verification_status = 'PENDING'

    if 'uproszczony' in request.form:
        user.uproszczony = str(request.form.get('uproszczony')).strip().lower() in ('true', '1', 'on', 'yes')

    new_password = (request.form.get('password') or '').strip()
    if new_role == 'admin':
        if new_password:
            if not new_password.startswith(('pbkdf2:', 'scrypt:')):
                user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
            else:
                user.password = new_password
        elif user.password and not user.password.startswith(('pbkdf2:', 'scrypt:')):
            user.password = generate_password_hash(user.password, method='pbkdf2:sha256')
    else:
        if new_password:
            user.password = new_password

    user.failed_login_attempts = 0
    user.locked_until = None

    try:
        db.session.commit()
        log_audit_event(
            "LOG_ADMIN_ACTION",
            details=f"Zaktualizowano profil użytkownika @{user.username} (rola: {user.role})"
        )
        flash(f'Dane użytkownika {user.imie} {user.nazwisko} (@{user.username}) zostały zaktualizowane!', 'success')
    except Exception:
        db.session.rollback()
        flash('Wystąpił błąd podczas zapisu danych (prawdopodobnie login jest zajęty).', 'danger')

    return redirect(url_for('admin_page'))

@app.route('/admin/edit_user/<int:user_id>', methods=['POST'])
@admin_required
def admin_edit_user(user_id):
    return _process_user_update(user_id)

@app.route('/edit_user/<int:user_id>', methods=['POST'])
@admin_required
def edit_user(user_id):
    return _process_user_update(user_id)

@app.route('/verify-2fa', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def two_factor_page():
    if 'pending_admin_id' not in session:
        return redirect(url_for('login_page'))
        
    if request.method == 'POST':
        wpisany_kod = request.form.get("kod_2fa", "").strip()
        admin = db.session.get(Users, session['pending_admin_id'])
        
        if admin and admin.two_factor_code and admin.two_factor_code == wpisany_kod and admin.two_factor_expiry and datetime.now() < admin.two_factor_expiry:
            admin.two_factor_code = None
            admin.two_factor_expiry = None
            admin.failed_login_attempts = 0
            admin.locked_until = None
            db.session.commit()
            
            session.clear()
            session['user_id'] = admin.id
            session['username'] = admin.username
            session['user_role'] = 'admin'
            session['has_admin_rank'] = True
            session['login_mode'] = 'admin'
            session['uproszczony'] = False
            
            log_audit_event(
                "LOG_2FA_01",
                username=admin.username,
                details="Pomyślna weryfikacja kodu 2FA administratora"
            )
            log_audit_event(
                "LOG_AUTH_01",
                username=admin.username,
                details="Zalogowano do Panelu Administratora (po weryfikacji GPS + 2FA)"
            )
            flash("Autoryzacja 2FA pomyślna. Witaj, Szefie!", "success")
            return redirect(url_for('admin_page'))
        else:
            log_audit_event(
                "LOG_AUTH_02",
                username=admin.username if admin else "UNKNOWN",
                details="Nieudana weryfikacja kodu 2FA (błędny lub wygasły kod)"
            )
            flash("Wpisany kod 2FA jest niepoprawny lub wygasł.", "danger")
            
    return render_template('verify_2fa.html')

def _approve_user_account(user):
    uname = user.username
    full_name = f"{user.imie} {user.nazwisko}"
    admin_message = (request.form.get('admin_message') or '').strip()
    role = (request.form.get('role') or '').strip()
    uproszczony_raw = request.form.get('uproszczony')

    user.is_approved = True
    user.verification_status = 'APPROVED'
    user.rejection_reason = None
    if admin_message:
        user.admin_message = admin_message
    if role in ('user', 'ksiądz'):
        user.role = role
    if uproszczony_raw is not None:
        user.uproszczony = str(uproszczony_raw).strip().lower() in ('true', '1', 'on', 'yes')

    db.session.commit()
    log_audit_event("LOG_ADMIN_ACTION", details=f"Zatwierdzono konto użytkownika @{uname}")
    sent_count = send_web_push_to_users(
        user_ids=[user.id],
        title="Konto zatwierdzone",
        body="Twoje konto zostało zatwierdzone przez administratora. Możesz się już zalogować.",
        url="/"
    )
    push_info = " Wysłano powiadomienie Push." if sent_count > 0 else " (Brak aktywnej subskrypcji Push — zobaczy informację na stronie logowania)."
    flash(f"Konto użytkownika {uname} ({full_name}) zostało pomyślnie zatwierdzone!{push_info}", "success")


def _reject_user_account(user):
    uname = user.username
    full_name = f"{user.imie} {user.nazwisko}"
    rejection_reason = (request.form.get('rejection_reason') or request.form.get('powod_odrzucenia') or '').strip()
    if not rejection_reason:
        flash("Musisz podać powód odrzucenia konta!", "danger")
        return False

    user.is_approved = False
    user.verification_status = 'REJECTED'
    user.rejection_reason = rejection_reason
    db.session.commit()
    log_audit_event("LOG_ADMIN_ACTION", details=f"Odrzucono konto @{uname}. Powód: {rejection_reason}")
    sent_count = send_web_push_to_users(
        user_ids=[user.id],
        title="Konto odrzucone",
        body=f"Twoje konto zostało odrzucone przez administratora. Powód: {rejection_reason}",
        url="/"
    )
    push_info = " Wysłano powiadomienie Push." if sent_count > 0 else " (Brak aktywnej subskrypcji Push — zobaczy powód na stronie logowania)."
    flash(f"Konto użytkownika {uname} ({full_name}) zostało odrzucone.{push_info}", "warning")
    return True


@app.route('/admin/weryfikacja')
@admin_required
def panel_weryfikacji():
    return redirect(url_for('admin_page') + '#weryfikacja')

@app.route('/admin/weryfikacja/<int:user_id>/<string:akcja>', methods=['POST'])
@admin_required
def przetworz_weryfikacje(user_id, akcja):
    uzytkownik = Users.query.get_or_404(user_id)
    if akcja in ('zatwierdz', 'akceptuj'):
        _approve_user_account(uzytkownik)
    elif akcja == 'odrzuc':
        _reject_user_account(uzytkownik)
    return redirect(url_for('admin_page') + '#weryfikacja')

@app.route('/reset-admin-password', methods=['POST'])
@limiter.limit("3 per 5 minutes")
def reset_admin_password():
    username = request.form.get("username", "").strip()
    env_admin_name = get_env_admin_name()
    
    admin = Users.query.filter_by(username=username).first()
    if admin and (admin.role == 'admin' or username == env_admin_name):
        teraz_utc = datetime.now(timezone.utc)

        # 1. Sprawdzenie limitu czasowego (Max 1 próba na 5 minut)
        ostatnia_prosoba = PasswordResetRequest.query.filter_by(
            user_id=admin.id, 
            status='PENDING'
        ).order_by(PasswordResetRequest.created_at.desc()).first()

        if ostatnia_prosoba:
            created_at_utc = ostatnia_prosoba.created_at
            if created_at_utc.tzinfo is None:
                created_at_utc = created_at_utc.replace(tzinfo=timezone.utc)

            roznica_czasu = teraz_utc - created_at_utc

            if roznica_czasu < timedelta(minutes=5):
                sekundy_minely = int(roznica_czasu.total_seconds())
                roznica = max(0, 300 - sekundy_minely)
                flash(f"Prośba o zmianę hasła została już wysłana! Odczekaj {roznica} sek. przed kolejną próbą.", "warning")
                return redirect(url_for('login_page'))

        user_ip = get_client_ip()
        ip_data = resolve_ip_and_coords(user_ip)
        resolved_ip_str = ip_data["display"]
        device_info = parse_user_agent(request.headers.get('User-Agent', ''))
        
        teraz_lokalnie = datetime.now()
        data_str = teraz_lokalnie.strftime("%d.%m.%Y")
        godzina_str = teraz_lokalnie.strftime("%H:%M:%S")

        browser_lat = (request.form.get("geo_lat") or "").strip()
        browser_lng = (request.form.get("geo_lng") or "").strip()

        if not browser_lat or not browser_lng:
            log_audit_event(
                "LOG_PWD_RESET",
                username=username,
                ip_address=resolved_ip_str,
                details="Odrzucono prośbę o reset hasła administratora (brak współrzędnych GPS)"
            )
            alert_brak_gps = (
                f"[BLOKADA] ODRZUCONO PROŚBĘ RESETU HASŁA (BRAK GPS)!\n\n"
                f"Ktoś próbował wywołać reset hasła administratora (`{username}`), "
                f"ale zgoda na geolokalizację została zablokowana lub odrzucona!\n\n"
                f"DANE POŁĄCZENIA:\n"
                f"Data: {data_str}\n"
                f"Godzina: {godzina_str}\n"
                f"Adres IP: {user_ip}\n"
                f"Sieć IP: {resolved_ip_str}\n"
                f"Urządzenie: {device_info}\n"
            )
            thr = Thread(target=send_telegram_alert, args=[alert_brak_gps])
            thr.start()

            flash("Procedura resetu hasła wymusza udostępnienie lokalizacji GPS! Zaznacz zgodę w przeglądarce i spróbuj ponownie.", "danger")
            return redirect(url_for('login_page'))

        maps_url = f"https://www.google.com/maps/search/?api=1&query={browser_lat},{browser_lng}"
        user_agent_raw = request.headers.get('User-Agent', 'Nieznana przeglądarka')

        nowa_prosoba = PasswordResetRequest(
            user_id=admin.id,
            ip_address=resolved_ip_str,
            status='PENDING',
            created_at=datetime.now(timezone.utc).replace(tzinfo=None)
        )
        db.session.add(nowa_prosoba)
        db.session.commit()

        log_audit_event(
            "LOG_PWD_RESET",
            username=username,
            ip_address=resolved_ip_str,
            details=f"Wysłano żądanie resetu hasła administratora na Telegram (GPS: {browser_lat}, {browser_lng})"
        )

        tekst_telegram = (
            f"[ALERT] *PROŚBA O ZMIANĘ HASŁA ADMINISTRATORA!*\n\n"
            f"Szefie, ktoś uruchomił procedurę zmiany/resetu hasła do konta Admin (`{username}`).\n\n"
            f"*SZCZEGÓŁY PRÓBY:*\n"
            f"Data: {data_str}\n"
            f"Godzina: {godzina_str}\n"
            f"IP: {user_ip}\n"
            f"Sieć/IP Geolokalizacja: {resolved_ip_str}\n"
            f"Dokładne GPS Urządzenia: {browser_lat}, {browser_lng}\n"
            f"Google Maps: {maps_url}\n"
            f"Urządzenie: {device_info}\n"
            f"Full User-Agent: {user_agent_raw}\n\n"
            f"UWAGA: Jeśli to nie Ty, zgłoś to natychmiast!\n\n"
            f"*CZY TO TY?*\n"
            f"Jeśli chcesz zmienić hasło, odpisz na tę wiadomość podając nowe hasło w formacie:\n"
            f"`/ustaw_haslo TwojeNoweHaslo`\n\n"
            f"LUB jeśli chcesz odrzucić próbę, wpisz: `/odrzuc`\n\n"
            f"*Ważność żądania: 5 minut.*"
        )

        thr = Thread(target=send_telegram_alert, args=[tekst_telegram])
        thr.start()

        flash("Wysłano zapytanie autoryzacyjne na Telegram! Potwierdź zmianę i podaj nowe hasło w komunikatorze.", "info")
    else:
        log_audit_event(
            "LOG_PWD_RESET",
            username=username or "UNKNOWN",
            details="Nieudana próba wywołania resetu hasła dla konta niebędącego administratorem"
        )
        flash("Ta opcja jest dostępna tylko dla kont o randze Administratora.", "danger")
        
    return redirect(url_for('login_page'))

@app.route('/add_attendance', methods=['POST'])
@login_required
def add_attendance():
    data_str = request.form.get("date") or request.form.get("data_sluzby")
    typ_mszy = request.form.get("typ_mszy") or request.form.get("typ")
    nazwa_inna = request.form.get("nazwa_inna") or request.form.get("inna")
    godzina = request.form.get("godzina")
    
    try:
        wybrana_data = date.fromisoformat(data_str)
        dzisiaj = date.today()
        days_back = int(get_setting('attendance_days_back', 3))
        hard_limit = date(2026, 4, 12)
        min_allowed_date = max(dzisiaj - timedelta(days=days_back), hard_limit)

        if wybrana_data > dzisiaj or wybrana_data < min_allowed_date:
            flash(f"Możesz zgłosić służbę maksymalnie do {days_back} dni wstecz.", "danger")
            return redirect(url_for('dashboard_page'))

        istniejaca = Attendance.query.filter_by(
            user_id=session['user_id'], 
            data_sluzby=wybrana_data, 
            godzina=godzina
        ).first()

        if istniejaca:
            flash("Masz już zgłoszoną służbę o tej godzinie.", "danger")
            return redirect(url_for('dashboard_page'))

        nowa = Attendance(
            user_id=session['user_id'],
            data_sluzby=wybrana_data,
            typ_mszy=typ_mszy,
            nazwa_inna=nazwa_inna if typ_mszy == 'inna' else None,
            godzina=godzina
        )
        db.session.add(nowa)
        db.session.commit()
        flash("Obecność na służbie zapisana pomyślnie.", "success")
    except Exception:
        db.session.rollback()
        flash("Coś poszło nie tak przy zapisywaniu służby.", "danger")

    return redirect(url_for('dashboard_page'))

@app.route('/admin/update_attendance_window', methods=['POST'])
@admin_required
def update_attendance_window():
    raw_days = request.form.get('days_back') or request.form.get('attendance_days_back') or '3'
    try:
        days_back = max(0, min(365, int(raw_days)))
        set_setting('attendance_days_back', str(days_back))
        log_audit_event(
            "LOG_ADMIN_ACTION",
            details=f"Zmieniono limit dni wstecz na zgłaszanie służb na: {days_back} dni"
        )
        flash(f"Okno czasowe zgłaszania służb zostało zaktualizowane (do {days_back} dni wstecz).", "success")
    except (ValueError, TypeError):
        flash("Podano nieprawidłową liczbę dni.", "danger")
    return redirect(request.referrer or url_for('admin_page'))

# --- BEZPIECZNE USUWANIE UŻYTKOWNIKA I CZYSZCZCZENIE KLUCZY OBCYCH ---
@app.route('/admin/delete_user/<int:id>', methods=['POST'])
@admin_required
def delete_user(id):
    user_to_del = Users.query.get_or_404(id)
    if user_to_del.role == 'admin':
        flash("Nie można usunąć głównego konta Administratora!", "danger")
        return redirect(request.referrer or url_for('admin_page'))
        
    try:
        uname = user_to_del.username
        PasswordResetRequest.query.filter_by(user_id=id).delete()
        Attendance.query.filter_by(user_id=id).delete()
        Schedule.query.filter_by(user_id=id).delete()
        db.session.delete(user_to_del)
        db.session.commit()
        log_audit_event("LOG_ADMIN_ACTION", details=f"Usunięto konto użytkownika @{uname}")
        flash(f"Użytkownik {uname} został trwale usunięty.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Błąd podczas usuwania użytkownika: {e}", "danger")
    return redirect(request.referrer or url_for('admin_page'))

@app.route('/admin/delete/<int:id>', methods=['POST'])
@admin_required
def delete_attendance(id):
    entry = Attendance.query.get_or_404(id)
    try:
        db.session.delete(entry)
        db.session.commit()
        log_audit_event("LOG_ADMIN_ACTION", details=f"Usunięto wpis służby #{id}")
        flash("Wpis o służbie został usunięty.", "success")
    except Exception:
        db.session.rollback()
        flash("Coś poszło nie tak przy usuwaniu wpisu.", "danger")
    return redirect(request.referrer or url_for('admin_page'))

@app.route('/admin/edit/<int:id>', methods=['POST'])
@app.route('/edit_attendance/<int:id>', methods=['POST'])
@admin_required
def edit_entry(id):
    entry = Attendance.query.get_or_404(id)
    try:
        raw_date = request.form.get('date') or request.form.get('data_sluzby')
        entry.data_sluzby = date.fromisoformat(raw_date)
        entry.godzina = request.form.get('godzina')
        entry.typ_mszy = request.form.get('typ_mszy')
        entry.nazwa_inna = request.form.get('nazwa_inna') if entry.typ_mszy == 'inna' else None
        db.session.commit()
        log_audit_event("LOG_ADMIN_ACTION", details=f"Zmodyfikowano wpis służby #{id}")
        flash("Wpis o służbie został zaktualizowany.", "success")
    except Exception:
        db.session.rollback()
        flash("Coś poszło nie tak przy aktualizacji wpisu.", "danger")
    return redirect(url_for('admin_page'))

def _normalize_hour(godz_raw):
    g = (godz_raw or "").strip()
    if re.match(r'^\d:\d{2}$', g):
        g = '0' + g
    return g[:5]

@app.route('/admin/add_attendance_admin', methods=['POST'])
@admin_required
def add_attendance_admin():
    batches_json = (request.form.get("batches_json") or "").strip()
    added_count = 0
    unique_users = set()
    valid_user_ids = {u.id for u in Users.query.with_entities(Users.id).all()}

    try:
        if batches_json:
            batches = json.loads(batches_json)
            if not isinstance(batches, list) or len(batches) == 0:
                flash("Wypełnij wymagane pola (wybierz co najmniej jednego ministranta i dodaj służbę)!", "warning")
                return redirect(request.referrer or url_for('admin_page'))

            for batch in batches:
                if not isinstance(batch, dict):
                    continue
                raw_uids = batch.get("user_ids", [])
                batch_uids = []
                for uid in raw_uids:
                    for part in str(uid).split(','):
                        part = part.strip()
                        if part.isdigit():
                            val = int(part)
                            if val in valid_user_ids and val not in batch_uids:
                                batch_uids.append(val)

                services = batch.get("services", [])
                if not batch_uids or not isinstance(services, list) or len(services) == 0:
                    continue

                for srv in services:
                    if not isinstance(srv, dict):
                        continue
                    d_str = (srv.get("data_sluzby") or "").strip()
                    godz = _normalize_hour(srv.get("godzina"))
                    typ = (srv.get("typ_mszy") or "").strip()[:20]
                    inna = (srv.get("nazwa_inna") or "").strip()[:100]
                    try:
                        ilosc = max(1, min(50, int(srv.get("ilosc") or 1)))
                    except (ValueError, TypeError):
                        ilosc = 1

                    if not d_str or not godz or not typ:
                        continue

                    wybrana_data = date.fromisoformat(d_str)
                    for uid in batch_uids:
                        for _ in range(ilosc):
                            nowa_sluzba = Attendance(
                                user_id=uid,
                                data_sluzby=wybrana_data,
                                typ_mszy=typ,
                                nazwa_inna=(inna or "Inna") if typ == 'inna' else None,
                                godzina=godz
                            )
                            db.session.add(nowa_sluzba)
                            added_count += 1
                            unique_users.add(uid)
        else:
            raw_user_ids = request.form.getlist("user_ids")
            single_id = request.form.get("user_id")
            if not raw_user_ids and single_id:
                raw_user_ids = [single_id]
                
            all_user_ids = []
            for uid in raw_user_ids:
                for part in str(uid).split(','):
                    part = part.strip()
                    if part.isdigit():
                        val = int(part)
                        if val in valid_user_ids and val not in all_user_ids:
                            all_user_ids.append(val)

            dates_list = [d.strip() for d in request.form.getlist("data_sluzby") if d and d.strip()]
            godziny_list = [_normalize_hour(g) for g in request.form.getlist("godzina") if g and g.strip()]
            typy_list = [t.strip()[:20] for t in request.form.getlist("typ_mszy") if t and t.strip()]
            inne_list = request.form.getlist("nazwa_inna")
            ilosci_list = request.form.getlist("ilosc")

            if not all_user_ids or not dates_list or not godziny_list or not typy_list:
                flash("Wypełnij wymagane pola (wybierz co najmniej jednego ministranta, datę i godzinę)!", "warning")
                return redirect(request.referrer or url_for('admin_page'))

            num_services = min(len(dates_list), len(godziny_list), len(typy_list))
            for idx in range(num_services):
                wybrana_data = date.fromisoformat(dates_list[idx])
                godz = godziny_list[idx]
                typ = typy_list[idx]
                inna = (inne_list[idx].strip()[:100] if idx < len(inne_list) and inne_list[idx] else "")
                try:
                    ilosc = max(1, min(50, int(ilosci_list[idx]) if idx < len(ilosci_list) and ilosci_list[idx] else 1))
                except (ValueError, TypeError):
                    ilosc = 1

                for uid in all_user_ids:
                    for _ in range(ilosc):
                        nowa_sluzba = Attendance(
                            user_id=uid,
                            data_sluzby=wybrana_data,
                            typ_mszy=typ,
                            nazwa_inna=(inna or "Inna") if typ == 'inna' else None,
                            godzina=godz
                        )
                        db.session.add(nowa_sluzba)
                        added_count += 1
                        unique_users.add(uid)

        if added_count == 0:
            flash("Wypełnij wymagane pola (wybierz co najmniej jednego ministranta, datę i godzinę)!", "warning")
            return redirect(request.referrer or url_for('admin_page'))

        db.session.commit()
        log_audit_event(
            "LOG_ADMIN_ACTION",
            details=f"Masowe/ręczne dodanie {added_count} służb dla {len(unique_users)} ministrantów"
        )
        flash(f"Pomyślnie dodano {added_count} wpis(ów) służby dla {len(unique_users)} ministrant(ów).", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Coś poszło nie tak przy dodawaniu służby: {e}", "danger")

    return redirect(request.referrer or url_for('admin_page'))

@app.route('/admin/add_announcement', methods=['POST'])
@staff_required
def add_announcement():
    tytul_val = request.form.get('tytul') or "Ogłoszenie"
    nowe = Announcement(tytul=tytul_val.strip(), tresc=request.form.get('tresc', '').strip())
    db.session.add(nowe)
    db.session.commit()
    log_audit_event("LOG_ADMIN_ACTION", details=f"Dodano ogłoszenie: {nowe.tytul}")
    send_web_push_to_users(
        user_ids=None,
        title=f"Nowe ogłoszenie: {nowe.tytul}",
        body=(nowe.tresc[:140] + ("..." if len(nowe.tresc) > 140 else "")) if nowe.tresc else "Sprawdź tablicę ogłoszeń w panelu.",
        url="/dashboard"
    )
    flash("Nowe ogłoszenie dodane pomyślnie.", "success")
    if session.get('user_role') == 'ksiądz':
        return redirect(url_for('ksDash'))
    return redirect(url_for('admin_page'))

@app.route('/admin/edit_announcement/<int:id>', methods=['POST'])
@admin_required
def edit_announcement(id):
    ogloszenie = Announcement.query.get_or_404(id)
    ogloszenie.tytul = request.form.get('tytul', '').strip() or ogloszenie.tytul
    ogloszenie.tresc = request.form.get('tresc', '').strip()
    db.session.commit()
    log_audit_event("LOG_ADMIN_ACTION", details=f"Zaktualizowano ogłoszenie #{id}")
    flash("Ogłoszenie zaktualizowane.", "success")
    return redirect(url_for('admin_page'))

@app.route('/admin/delete_announcement/<int:id>', methods=['POST'])
@admin_required
def delete_announcement(id):
    ogloszenie = Announcement.query.get_or_404(id)
    db.session.delete(ogloszenie)
    db.session.commit()
    log_audit_event("LOG_ADMIN_ACTION", details=f"Usunięto ogłoszenie #{id}")
    flash("Ogłoszenie usunięte.", "warning")
    return redirect(request.referrer or url_for('admin_page'))

@app.route('/admin/add_schedule', methods=['POST'])
@staff_required
def add_schedule():
    fallback = url_for('ksDash') if session.get('user_role') == 'ksiądz' else url_for('admin_page')
    schedule_batches_json = (request.form.get('schedule_batches_json') or '').strip()
    valid_days = {'Poniedziałek', 'Wtorek', 'Środa', 'Czwartek', 'Piątek', 'Sobota', 'Niedziela'}
    valid_user_ids = {u.id for u in Users.query.with_entities(Users.id).all()}

    if schedule_batches_json:
        try:
            batches = json.loads(schedule_batches_json)
            if not isinstance(batches, list) or len(batches) == 0:
                flash("Nie udało się zapisać. Wybierz co najmniej jednego ministranta oraz termin dyżuru!", "warning")
                return redirect(request.referrer or fallback)

            added_count = 0
            already_assigned = 0
            skipped_removed_hour = 0
            affected_users = set()

            for item in batches:
                if not isinstance(item, dict):
                    continue
                uids = []
                if 'user_id' in item and str(item.get('user_id')).isdigit():
                    uid_val = int(item['user_id'])
                    if uid_val in valid_user_ids:
                        uids.append(uid_val)
                for raw_uid in item.get('user_ids', []):
                    if str(raw_uid).isdigit():
                        uid_val = int(raw_uid)
                        if uid_val in valid_user_ids and uid_val not in uids:
                            uids.append(uid_val)

                slots = item.get('slots', [])
                if not uids or not isinstance(slots, list):
                    continue

                for slot in slots:
                    if not isinstance(slot, dict):
                        continue
                    dzien = (slot.get('dzien') or '').strip()
                    godzina = _normalize_hour(slot.get('godzina'))
                    if dzien not in valid_days or not godzina:
                        continue
                    if godzina == '14:00':
                        skipped_removed_hour += 1
                        continue
                    for uid in uids:
                        existing = Schedule.query.filter_by(user_id=uid, dzien_tygodnia=dzien, godzina=godzina).first()
                        if not existing:
                            db.session.add(Schedule(user_id=uid, dzien_tygodnia=dzien, godzina=godzina))
                            added_count += 1
                            affected_users.add(uid)
                        else:
                            already_assigned += 1

            db.session.commit()
            if added_count > 0:
                log_audit_event("LOG_ADMIN_ACTION", details=f"Masowe przypisanie {added_count} dyżur(ów) w grafiku dla {len(affected_users)} osób")
                send_web_push_to_users(
                    user_ids=list(affected_users),
                    title="Nowe dyżury w grafiku",
                    body="Zostałeś przypisany do nowego dyżuru w grafiku tygodniowym.",
                    url="/dashboard"
                )
                msg = f"Pomyślnie zapisano {added_count} przypisań w grafiku dla {len(affected_users)} ministrant(ów)."
                if already_assigned > 0:
                    msg += f" ({already_assigned} było już przypisanych)."
                flash(msg, "success")
            elif skipped_removed_hour > 0:
                flash("Msza o godzinie 14:00 została usunięta z harmonogramu i nie może zostać dodana.", "warning")
            elif already_assigned > 0:
                flash("Wszyscy wybrani ministranci są już przypisani do wskazanych terminów!", "info")
            else:
                flash("Wybierz co najmniej jednego ministranta oraz prawidłowy dzień i godzinę.", "warning")
        except Exception as e:
            db.session.rollback()
            flash(f"Coś poszło nie tak przy masowym przypisywaniu grafiku: {e}", "danger")

        return redirect(request.referrer or fallback)

    raw_user_ids = request.form.getlist('user_ids')
    single_id = request.form.get('user_id')
    if not raw_user_ids and single_id:
        raw_user_ids = [single_id]
        
    all_user_ids = []
    for uid in raw_user_ids:
        for part in str(uid).split(','):
            part = part.strip()
            if part.isdigit():
                uid_val = int(part)
                if uid_val in valid_user_ids and uid_val not in all_user_ids:
                    all_user_ids.append(uid_val)
                
    dzien = (request.form.get('dzien') or '').strip()
    godzina = _normalize_hour(request.form.get('godzina'))
    
    if not all_user_ids or dzien not in valid_days or not godzina:
        flash("Nie udało się zapisać. Wybierz co najmniej jednego ministranta oraz dzień i godzinę!", "warning")
        return redirect(request.referrer or fallback)

    if godzina == '14:00':
        flash("Msza o godzinie 14:00 została usunięta z harmonogramu i nie może zostać dodana.", "warning")
        return redirect(request.referrer or fallback)
        
    try:
        added_count = 0
        already_assigned = 0
        for uid in all_user_ids:
            existing = Schedule.query.filter_by(user_id=uid, dzien_tygodnia=dzien, godzina=godzina).first()
            if not existing:
                nowy_dyzur = Schedule(
                    user_id=uid,
                    dzien_tygodnia=dzien,
                    godzina=godzina
                )
                db.session.add(nowy_dyzur)
                added_count += 1
            else:
                already_assigned += 1
        db.session.commit()
        if added_count > 0:
            log_audit_event("LOG_ADMIN_ACTION", details=f"Dodano {added_count} dyżur(ów) do grafiku ({dzien}, {godzina})")
            msg = f"Pomyślnie dodano {added_count} ministrant(ów) do grafiku ({dzien}, {godzina})."
            if already_assigned > 0:
                msg += f" ({already_assigned} osób było już przypisanych)."
            flash(msg, "success")
        else:
            flash("Wszyscy wybrani ministranci są już przypisani do tej godziny w grafiku!", "info")
    except Exception as e:
        db.session.rollback()
        flash(f"Coś poszło nie tak przy dodawaniu służby: {e}", "danger")
        
    return redirect(request.referrer or fallback)

@app.route('/admin/delete_schedule/<int:id>', methods=['POST'])
@staff_required
def delete_schedule(id):
    dyzur = db.session.get(Schedule, id)
    if dyzur:
        try:
            db.session.delete(dyzur)
            db.session.commit()
            log_audit_event("LOG_ADMIN_ACTION", details=f"Usunięto dyżur #{id} z grafiku")
            flash("Służba została usunięta z grafiku.", "success")
        except Exception:
            db.session.rollback()
            flash("Błąd podczas usuwania służby.", "danger")
    else:
        flash("Nie znaleziono takiego wpisu w grafiku.", "warning")
            
    fallback = url_for('ksDash') if session.get('user_role') == 'ksiądz' else url_for('admin_page')
    return redirect(request.referrer or fallback)

@app.route('/admin')
@admin_required
def admin_page():
    all_attendance = db.session.query(Attendance, Users).join(Users).order_by(
        Attendance.data_sluzby.desc(), Attendance.godzina.desc()
    ).all()
    
    all_users_approved = Users.query.filter_by(is_approved=True).all()
    pending_users = Users.query.filter(
        Users.is_approved == False,
        (Users.verification_status.is_(None)) | (Users.verification_status != 'REJECTED')
    ).order_by(Users.created_at.desc()).all()
    rejected_users = Users.query.filter(
        Users.is_approved == False,
        Users.verification_status == 'REJECTED'
    ).order_by(Users.created_at.desc()).all()
    all_announcements = Announcement.query.order_by(Announcement.data_dodania.desc()).all()
    schedules = db.session.query(Schedule, Users).join(Users, Schedule.user_id == Users.id).all()

    wszystkie_dyzury = Schedule.query.all()
    aktualny_uzytkownik = db.session.get(Users, session['user_id'])
    
    plan_tygodnia = {'Poniedziałek': {}, 'Wtorek': {}, 'Środa': {}, 'Czwartek': {}, 'Piątek': {}, 'Sobota': {}, 'Niedziela': {}}
    plan_liczniki = {}
    for sch, u in schedules:
        dzien = sch.dzien_tygodnia
        godzina = sch.godzina
        if godzina == '14:00':
            continue
        if godzina not in plan_tygodnia[dzien]: plan_tygodnia[dzien][godzina] = []
        plan_tygodnia[dzien][godzina].append({'id': sch.id, 'user': u})
    for dzien in plan_tygodnia:
        plan_tygodnia[dzien] = dict(sorted(plan_tygodnia[dzien].items()))
        plan_liczniki[dzien] = sum(len(servers) for servers in plan_tygodnia[dzien].values())

    all_atts = Attendance.query.all()
    atts_by_user = defaultdict(list)
    for att in all_atts:
        atts_by_user[att.user_id].append(att)

    user_stats = []
    for u in all_users_approved:
        his_atts = atts_by_user[u.id]
        total = len(his_atts)
        morning = sum(1 for a in his_atts if a.typ_mszy == 'poranna')
        evening = sum(1 for a in his_atts if a.typ_mszy == 'wieczorna')
        user_stats.append({
            'username': u.username, 'imie': u.imie, 'nazwisko': u.nazwisko,
            'full_name': f"{u.imie} {u.nazwisko}", 'uproszczony': u.uproszczony,
            'total': total, 'morning': morning, 'evening': evening, 'other': total - (morning + evening)
        })

    unapproved_users = pending_users
    unapproved_count = len(unapproved_users)
    approved_users = Users.query.filter_by(is_approved=True).order_by(Users.nazwisko, Users.imie).all()
    verified_history_users = Users.query.filter(
        Users.verification_status.in_(['APPROVED', 'REJECTED'])
    ).order_by(Users.created_at.desc(), Users.id.desc()).all()
    all_users = Users.query.order_by(Users.created_at.desc()).all()
    audit_logs_total_count = AuditLog.query.count()
    audit_logs = AuditLog.query.order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).limit(AUDIT_LOG_AUTO_EXPORT_LIMIT).all()
    attendance_days_back = get_attendance_days_back()
    last_drive_export_month = get_setting('last_drive_export_month', 'Brak')
    audit_logs_drive_folder_id = (
        _extract_drive_folder_id(get_setting('audit_logs_drive_folder_id', ''))
        or _extract_drive_folder_id(os.getenv('GOOGLE_DRIVE_LOGS_FOLDER_ID', ''))
    )
    last_audit_drive_export = get_setting('last_audit_drive_export', 'Brak')
    last_audit_drive_export_error = get_setting('last_audit_drive_export_error', '')
    
    return render_template(
        "admin.html", 
        attendances=all_attendance, 
        users=all_users, 
        approved_users=approved_users,
        verified_history_users=verified_history_users,
        pending_users=pending_users,
        rejected_users=rejected_users,
        announcements=all_announcements, 
        stats=user_stats, 
        plan=plan_tygodnia, 
        liczniki=plan_liczniki,
        unapproved_users=unapproved_users,
        unapproved_count=unapproved_count,
        dyzury=wszystkie_dyzury,
        dyzury_count=len(wszystkie_dyzury),
        user=aktualny_uzytkownik.username if aktualny_uzytkownik else session.get('username', 'Admin'),
        audit_logs=audit_logs,
        audit_logs_total_count=audit_logs_total_count,
        audit_logs_limit=AUDIT_LOG_AUTO_EXPORT_LIMIT,
        audit_logs_drive_folder_id=audit_logs_drive_folder_id,
        last_audit_drive_export=last_audit_drive_export,
        last_audit_drive_export_error=last_audit_drive_export_error,
        attendance_days_back=attendance_days_back,
        last_drive_export_month=last_drive_export_month
    )

@app.route('/admin/change_password_inline/<int:user_id>', methods=['POST'])
@app.route('/admin/change_user_password/<int:user_id>', methods=['POST'])
@admin_required
def admin_change_password_inline(user_id):
    user = Users.query.get_or_404(user_id)
    nowe_haslo = request.form.get('new_password')
    
    if nowe_haslo and nowe_haslo.strip() != "":
        clean_pwd = nowe_haslo.strip()
        if user.role == 'admin':
            user.password = generate_password_hash(clean_pwd, method='pbkdf2:sha256')
        else:
            user.password = clean_pwd
        user.failed_login_attempts = 0
        user.locked_until = None
        db.session.commit()
        log_audit_event("LOG_ADMIN_ACTION", details=f"Zmieniono hasło (inline) dla użytkownika @{user.username}")
        flash(f'Hasło użytkownika {user.imie} {user.nazwisko} zostało zaktualizowane!', 'success')
    else:
        flash('Hasło nie może być puste!', 'danger')
        
    return redirect(url_for('admin_page'))

@app.route('/admin/approve_user/<int:user_id>', methods=['POST'])
@admin_required
def approve_user(user_id):
    user = Users.query.get_or_404(user_id)
    _approve_user_account(user)
    return redirect(url_for('admin_page') + '#weryfikacja')

@app.route('/admin/reject_user/<int:user_id>', methods=['POST'])
@admin_required
def reject_user(user_id):
    user = Users.query.get_or_404(user_id)
    _reject_user_account(user)
    return redirect(url_for('admin_page') + '#weryfikacja')

@app.route('/admin/verify_action/<int:user_id>/<string:akcja>', methods=['POST'])
@admin_required
def verify_action(user_id, akcja):
    u = Users.query.get_or_404(user_id)
    if akcja in ('zatwierdz', 'akceptuj'):
        _approve_user_account(u)
    elif akcja == 'odrzuc':
        _reject_user_account(u)
    return redirect(url_for('admin_page') + '#weryfikacja')

@app.route('/admin/delete_bulk_users', methods=['POST'])
@admin_required
def delete_bulk_users():
    user_ids = request.form.getlist('user_ids')
    if user_ids:
        deleted_count = 0
        current_username = session.get('username')
        try:
            for uid in user_ids:
                user_to_del = db.session.get(Users, int(uid)) if str(uid).isdigit() else db.session.get(Users, uid)
                if user_to_del and user_to_del.role != 'admin' and user_to_del.username != current_username:
                    PasswordResetRequest.query.filter_by(user_id=user_to_del.id).delete()
                    Attendance.query.filter_by(user_id=user_to_del.id).delete()
                    Schedule.query.filter_by(user_id=user_to_del.id).delete()
                    db.session.delete(user_to_del)
                    deleted_count += 1
            db.session.commit()
            if deleted_count > 0:
                log_audit_event("LOG_ADMIN_ACTION", details=f"Masowe usunięcie {deleted_count} kont użytkowników")
                flash(f"Pomyślnie usunięto {deleted_count} zaznaczonych kont użytkowników.", "success")
            else:
                flash("Nie usunięto żadnego użytkownika (brak uprawnień do usunięcia kont administratora).", "warning")
        except Exception as e:
            db.session.rollback()
            print(f"Błąd przy masowym usuwaniu użytkowników: {e}")
            flash("Wystąpił błąd podczas usuwania wybranych użytkowników.", "danger")
    else:
        flash("Proszę zaznaczyć użytkowników do usunięcia.", "warning")
    return redirect(request.referrer or url_for('admin_page'))

@app.route('/admin/delete_bulk_attendances', methods=['POST'])
@admin_required
def delete_bulk_attendances():
    att_ids = request.form.getlist('att_ids')
    if att_ids:
        deleted_count = 0
        try:
            for aid in att_ids:
                entry = db.session.get(Attendance, int(aid)) if str(aid).isdigit() else db.session.get(Attendance, aid)
                if entry:
                    db.session.delete(entry)
                    deleted_count += 1
            db.session.commit()
            if deleted_count > 0:
                log_audit_event("LOG_ADMIN_ACTION", details=f"Masowe usunięcie {deleted_count} wpisów służb")
                flash(f"Pomyślnie usunięto {deleted_count} zaznaczonych służb.", "success")
            else:
                flash("Nie znaleziono wskazanych służb do usunięcia.", "warning")
        except Exception as e:
            db.session.rollback()
            print(f"Błąd przy masowym usuwaniu służb: {e}")
            flash("Wystąpił błąd podczas usuwania wybranych służb.", "danger")
    else:
        flash("Proszę zaznaczyć służby do usunięcia.", "warning")
    return redirect(url_for('admin_page'))

@app.route('/ksDash')
@staff_required
def ksDash():
    all_attendance = db.session.query(Attendance, Users).join(Users).order_by(
        Attendance.data_sluzby.desc(), Attendance.godzina.desc()
    ).all()
    all_users = Users.query.all()
    all_announcements = Announcement.query.order_by(Announcement.data_dodania.desc()).all()
    schedules = db.session.query(Schedule, Users).join(Users, Schedule.user_id == Users.id).all()
    
    plan_tygodnia = {'Poniedziałek': {}, 'Wtorek': {}, 'Środa': {}, 'Czwartek': {}, 'Piątek': {}, 'Sobota': {}, 'Niedziela': {}}
    plan_liczniki = {}

    for sch, u in schedules:
        dzien = sch.dzien_tygodnia
        godzina = sch.godzina
        if godzina not in plan_tygodnia[dzien]:
            plan_tygodnia[dzien][godzina] = []
        plan_tygodnia[dzien][godzina].append({'id': sch.id, 'user': u})
        
    for dzien in plan_tygodnia:
        plan_tygodnia[dzien] = dict(sorted(plan_tygodnia[dzien].items()))
        count = sum(len(servers) for servers in plan_tygodnia[dzien].values())
        plan_liczniki[dzien] = count
    
    user_atts_map = {u.id: [] for u in all_users}
    for att, usr in all_attendance:
        if usr.id in user_atts_map:
            user_atts_map[usr.id].append(att)

    user_stats = []
    for u in all_users:
        his_atts = user_atts_map.get(u.id, [])
        total = len(his_atts)
        morning = sum(1 for a in his_atts if a.typ_mszy == 'poranna')
        evening = sum(1 for a in his_atts if a.typ_mszy == 'wieczorna')
        other = total - (morning + evening)
        
        user_stats.append({
            'username': u.username, 
            'imie': u.imie,
            'nazwisko': u.nazwisko,
            'full_name': f"{u.imie} {u.nazwisko}",
            'total': total, 
            'morning': morning, 
            'evening': evening, 
            'other': other
        })

    return render_template(
        'ks.html', 
        attendances=all_attendance, 
        users=all_users, 
        announcements=all_announcements, 
        stats=user_stats, 
        plan=plan_tygodnia, 
        liczniki=plan_liczniki
    )

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard_page():
    user_id = session['user_id']
    aktualny_uzytkownik = db.session.get(Users, user_id)
    if not aktualny_uzytkownik:
        return redirect(url_for('logout'))

    days_back = int(get_setting('attendance_days_back', 3))
    dzisiaj = date.today()
    hard_limit = date(2026, 4, 12)
    min_allowed_date = max(dzisiaj - timedelta(days=days_back), hard_limit)

    if request.method == 'POST':
        data_sluzby_str = request.form.get('data_sluzby') or request.form.get('date')
        godzina = request.form.get('godzina')
        typ_mszy = request.form.get('typ') or request.form.get('typ_mszy')
        raw_inna = request.form.get('inna') or request.form.get('nazwa_inna')
        nazwa_inna = raw_inna if typ_mszy == 'inna' else None
        
        try:
            data_sluzby = datetime.strptime(data_sluzby_str, '%Y-%m-%d').date()

            if data_sluzby > dzisiaj or data_sluzby < min_allowed_date:
                flash(f"Możesz zgłosić służbę maksymalnie do {days_back} dni wstecz.", "danger")
                return redirect(url_for('dashboard_page'))

            istniejaca = Attendance.query.filter_by(
                user_id=user_id, 
                data_sluzby=data_sluzby, 
                godzina=godzina
            ).first()

            if istniejaca:
                flash("Masz już zgłoszoną służbę o tej godzinie.", "danger")
                return redirect(url_for('dashboard_page'))

            new_attendance = Attendance(
                user_id=user_id,
                data_sluzby=data_sluzby,
                typ_mszy=typ_mszy,
                nazwa_inna=nazwa_inna,
                godzina=godzina
            )
            db.session.add(new_attendance)
            db.session.commit()
            flash('Obecność na służbie zapisana pomyślnie.', 'success')
        except Exception:
            db.session.rollback()
            flash("Coś poszło nie tak przy zapisywaniu służby.", "danger")
        return redirect(url_for('dashboard_page'))
        
    announcements = Announcement.query.order_by(Announcement.id.desc()).all()
    attendances = Attendance.query.filter_by(user_id=user_id).order_by(Attendance.data_sluzby.desc()).all()
    
    moje_dyzury = Schedule.query.filter_by(user_id=user_id).order_by(Schedule.dzien_tygodnia, Schedule.godzina).all()
    schedules = Schedule.query.options(joinedload(Schedule.user)).all()
    
    dni_kolejnosc = ['Poniedziałek', 'Wtorek', 'Środa', 'Czwartek', 'Piątek', 'Sobota', 'Niedziela']
    plan_tygodnia = {dzien: {} for dzien in dni_kolejnosc}
    plan_liczniki = {dzien: 0 for dzien in dni_kolejnosc}
    
    for sch in schedules:
        dzien = sch.dzien_tygodnia
        godzina = sch.godzina
        if dzien in plan_tygodnia:
            if godzina not in plan_tygodnia[dzien]:
                plan_tygodnia[dzien][godzina] = []
            plan_tygodnia[dzien][godzina].append(sch.user)
            plan_liczniki[dzien] += 1
            
    for dzien in plan_tygodnia:
        plan_tygodnia[dzien] = dict(sorted(plan_tygodnia[dzien].items()))
    
    min_date_iso = min_allowed_date.isoformat()
    max_date_iso = dzisiaj.isoformat()

    if aktualny_uzytkownik.uproszczony:
        return render_template(
            'dash_uproszczony.html',
            user=aktualny_uzytkownik.username,
            user_obj=aktualny_uzytkownik,
            announcements=announcements,
            attendances=attendances,
            attendance_days_back=days_back,
            min_attendance_date=min_date_iso,
            max_attendance_date=max_date_iso
        )
    return render_template(
        'dashboard.html',
        user=aktualny_uzytkownik.username,
        user_obj=aktualny_uzytkownik,
        announcements=announcements,
        attendances=attendances,
        moje_dyzury=moje_dyzury,
        plan=plan_tygodnia,
        liczniki=plan_liczniki,
        attendance_days_back=days_back,
        min_attendance_date=min_date_iso,
        max_attendance_date=max_date_iso
    )


@app.route('/dismiss_welcome_message', methods=['POST'])
@login_required
def dismiss_welcome_message():
    aktualny_uzytkownik = db.session.get(Users, session['user_id'])
    if aktualny_uzytkownik and getattr(aktualny_uzytkownik, 'admin_message', None):
        aktualny_uzytkownik.admin_message = None
        db.session.commit()
    return redirect(url_for('dashboard_page'))

@app.route('/delete_my_attendance/<int:id>', methods=['POST'])
@login_required
def delete_my_attendance(id):
    entry = Attendance.query.get_or_404(id)
    if entry.user_id != session['user_id']:
        flash("Brak uprawnień. Nie można usunąć cudzego wpisu.", "danger")
        return redirect(request.referrer or url_for('dashboard_page'))
    try:
        db.session.delete(entry)
        db.session.commit()
        flash("Wpis o Twojej służbie został usunięty.", "success")
    except Exception:
        db.session.rollback()
        flash("Coś poszło nie tak przy usuwaniu służby.", "danger")
    return redirect(request.referrer or url_for('dashboard_page'))

@app.route('/edit_my_attendance/<int:id>', methods=['POST'])
@login_required
def edit_my_attendance(id):
    att = Attendance.query.get_or_404(id)
    if att.user_id != session['user_id']:
        flash('Brak uprawnień do edycji tej służby.', 'danger')
        return redirect(url_for('dashboard_page'))
        
    try:
        raw_date = request.form.get('data_sluzby') or request.form.get('date')
        wybrana_data = datetime.strptime(raw_date, '%Y-%m-%d').date()
        dzisiaj = date.today()
        days_back = int(get_setting('attendance_days_back', 3))
        hard_limit = date(2026, 4, 12)
        min_allowed_date = max(dzisiaj - timedelta(days=days_back), hard_limit)

        if wybrana_data > dzisiaj or wybrana_data < min_allowed_date:
            flash(f"Możesz zgłosić służbę maksymalnie do {days_back} dni wstecz.", "danger")
            return redirect(url_for('dashboard_page'))

        nowa_godzina = request.form.get('godzina')
        istniejaca = Attendance.query.filter(
            Attendance.user_id == session['user_id'],
            Attendance.data_sluzby == wybrana_data,
            Attendance.godzina == nowa_godzina,
            Attendance.id != id
        ).first()
        if istniejaca:
            flash("Masz już zgłoszoną służbę o tej godzinie.", "danger")
            return redirect(url_for('dashboard_page'))

        att.data_sluzby = wybrana_data
        att.godzina = nowa_godzina
        att.typ_mszy = request.form.get('typ') or request.form.get('typ_mszy')
        raw_inna = request.form.get('inna') or request.form.get('nazwa_inna')
        att.nazwa_inna = raw_inna if att.typ_mszy == 'inna' else None
        
        db.session.commit()
        flash('Zgłoszenie zostało pomyślnie zaktualizowane.', 'success')
    except Exception:
        db.session.rollback()
        flash('Coś poszło nie tak przy edycji służby.', 'danger')
        
    return redirect(url_for('dashboard_page'))

@app.route('/switch-to-normal')
@login_required
def switch_to_normal():
    user = db.session.get(Users, session['user_id'])
    if not user:
        return redirect(url_for('logout'))
    session['user_role'] = 'ksiądz' if user.role == 'ksiądz' else 'user'
    session['has_admin_rank'] = (user.role == 'admin')
    session['login_mode'] = 'normal'
    session['uproszczony'] = user.uproszczony
    flash(f"Przełączono na konto normalne użytkownika (@{user.username}).", "info")
    return redirect(url_for('dashboard_page'))

@app.route('/logout')
def logout():
    mode = request.args.get('mode')
    session.clear()
    if mode in ('admin', 'normal'):
        return redirect(url_for('login_page', mode=mode))
    return redirect(url_for('login_page'))

@app.route('/forget-password')
def forget_password():
    return render_template('forget-password.html')

@app.route('/robots.txt')
def static_from_root():
    return send_from_directory(app.static_folder, 'robots.txt')

@app.route('/sitemap.xml')
def sitemap_from_root():
    return send_from_directory(app.static_folder, 'sitemap.xml')

# --- GENEROWANIE RAPORTU EXCEL ORAZ INTEGRACJA Z GOOGLE DRIVE ---

def generate_attendances_excel_bytes(year=None, month=None):
    query = db.session.query(Attendance, Users).join(Users)
    if year is not None and month is not None:
        year_int = int(year)
        month_int = int(month)
        last_day = calendar.monthrange(year_int, month_int)[1]
        start_date = date(year_int, month_int, 1)
        end_date = date(year_int, month_int, last_day)
        query = query.filter(Attendance.data_sluzby >= start_date, Attendance.data_sluzby <= end_date)
        filename = f"Sluzby_{year_int}_{month_int:02d}.xlsx"
    else:
        filename = "sluzby_export.xlsx"

    attendances = query.order_by(
        Attendance.data_sluzby.desc(), Attendance.godzina.desc()
    ).all()

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Lista Służb"
    ws.views.sheetView[0].showGridLines = True

    header_font = Font(name="Calibri", size=11, bold=True, color="FFFFFF")
    header_fill = PatternFill(start_color="5E3BEE", end_color="5E3BEE", fill_type="solid")
    align_center = Alignment(horizontal="center", vertical="center")
    align_left = Alignment(horizontal="left", vertical="center")
    thin_border = Border(
        left=Side(style='thin', color='D1D5DB'),
        right=Side(style='thin', color='D1D5DB'),
        top=Side(style='thin', color='D1D5DB'),
        bottom=Side(style='thin', color='D1D5DB')
    )

    headers = ["ID", "Imię i Nazwisko", "Login", "Data Służby", "Godzina", "Typ Liturgii", "Nazwa Inna / Uwagi"]
    ws.append(headers)

    for col_num in range(1, len(headers) + 1):
        cell = ws.cell(row=1, column=col_num)
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = align_center
        cell.border = thin_border

    typ_counts = defaultdict(int)
    user_summary = defaultdict(lambda: {"name": "", "username": "", "total": 0, "morning": 0, "evening": 0, "other": 0})
    for u_item in Users.query.filter_by(is_approved=True).all():
        if u_item.role != 'ksiądz':
            u_stat = user_summary[u_item.id]
            u_stat["name"] = f"{u_item.imie} {u_item.nazwisko}"
            u_stat["username"] = u_item.username

    for idx, (att, u) in enumerate(attendances, start=2):
        typ_label = att.typ_mszy.capitalize() if att.typ_mszy else "Nieokreślony"
        typ_counts[typ_label] += 1

        u_stat = user_summary[u.id]
        u_stat["name"] = f"{u.imie} {u.nazwisko}"
        u_stat["username"] = u.username
        u_stat["total"] += 1
        if att.typ_mszy == 'poranna':
            u_stat["morning"] += 1
        elif att.typ_mszy == 'wieczorna':
            u_stat["evening"] += 1
        else:
            u_stat["other"] += 1

        row = [
            att.id,
            f"{u.imie} {u.nazwisko}",
            u.username,
            att.data_sluzby.strftime("%Y-%m-%d") if att.data_sluzby else "",
            att.godzina,
            typ_label,
            att.nazwa_inna or ""
        ]
        ws.append(row)

        for col_num in range(1, len(headers) + 1):
            c = ws.cell(row=idx, column=col_num)
            c.border = thin_border
            c.alignment = align_center if col_num in [1, 4, 5, 6] else align_left

    for col in ws.columns:
        max_len = max(len(str(cell.value or '')) for cell in col)
        col_letter = get_column_letter(col[0].column)
        ws.column_dimensions[col_letter].width = max(max_len + 4, 12)

    # Arkusz 2: Podsumowanie liczby służb każdego ministranta
    ws_summary = wb.create_sheet(title="Podsumowanie Ministrantów")
    ws_summary.views.sheetView[0].showGridLines = True
    summary_headers = ["Lp.", "Imię i Nazwisko", "Login", "Liczba Służb", "Poranne", "Wieczorne", "Inne"]
    ws_summary.append(summary_headers)
    for col_num in range(1, len(summary_headers) + 1):
        cell = ws_summary.cell(row=1, column=col_num)
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = align_center
        cell.border = thin_border

    sorted_summary = sorted(user_summary.values(), key=lambda x: (-x["total"], x["name"]))
    for s_idx, item in enumerate(sorted_summary, start=2):
        ws_summary.append([
            s_idx - 1,
            item["name"],
            item["username"],
            item["total"],
            item["morning"],
            item["evening"],
            item["other"]
        ])
        for col_num in range(1, len(summary_headers) + 1):
            c = ws_summary.cell(row=s_idx, column=col_num)
            c.border = thin_border
            c.alignment = align_center if col_num in [1, 4, 5, 6, 7] else align_left

    for col in ws_summary.columns:
        max_len = max(len(str(cell.value or '')) for cell in col)
        col_letter = get_column_letter(col[0].column)
        ws_summary.column_dimensions[col_letter].width = max(max_len + 4, 14)

    # Arkusz 3: Statystyki i Wykres
    ws_chart = wb.create_sheet(title="Statystyki i Wykres")
    ws_chart.views.sheetView[0].showGridLines = True

    ws_chart.append(["Typ Liturgii", "Liczba Służb"])
    ws_chart.cell(row=1, column=1).font = header_font
    ws_chart.cell(row=1, column=1).fill = header_fill
    ws_chart.cell(row=1, column=2).font = header_font
    ws_chart.cell(row=1, column=2).fill = header_fill

    r_idx = 2
    for t_name, count in typ_counts.items():
        ws_chart.append([t_name, count])
        ws_chart.cell(row=r_idx, column=1).border = thin_border
        ws_chart.cell(row=r_idx, column=2).border = thin_border
        r_idx += 1

    if r_idx > 2:
        pie = PieChart()
        pie.title = "Podział Służb ze względu na Typ"
        labels = Reference(ws_chart, min_col=1, min_row=2, max_row=r_idx - 1)
        data = Reference(ws_chart, min_col=2, min_row=1, max_row=r_idx - 1)
        pie.add_data(data, titles_from_data=True)
        pie.set_categories(labels)
        ws_chart.add_chart(pie, "D4")

    output = io.BytesIO()
    wb.save(output)
    output.seek(0)
    return output, filename

def _style_excel_header(ws, headers, fill_hex="5E3BEE"):
    """Zapisuje i formatuje nagłówek arkusza Excel."""
    header_font = Font(name="Calibri", size=11, bold=True, color="FFFFFF")
    header_fill = PatternFill(start_color=fill_hex, end_color=fill_hex, fill_type="solid")
    align_center = Alignment(horizontal="center", vertical="center")
    thin_border = Border(
        left=Side(style='thin', color='CBD5E1'),
        right=Side(style='thin', color='CBD5E1'),
        top=Side(style='thin', color='CBD5E1'),
        bottom=Side(style='thin', color='CBD5E1')
    )
    ws.append(headers)
    ws.row_dimensions[1].height = 24
    for col_num in range(1, len(headers) + 1):
        cell = ws.cell(row=1, column=col_num)
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = align_center
        cell.border = thin_border
    return thin_border


def generate_audit_logs_excel_bytes(logs=None):
    """Generuje sformatowany skoroszyt .xlsx dla dziennika AuditLog (wpisy + podsumowanie)."""
    if logs is None:
        logs = AuditLog.query.order_by(AuditLog.created_at.asc(), AuditLog.id.asc()).all()

    now_pl = get_poland_now()
    filename = f"AuditLog_Archiwum_{now_pl.strftime('%Y-%m-%d_%H-%M-%S')}.xlsx"

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Dziennik AuditLog"
    ws.views.sheetView[0].showGridLines = True
    ws.freeze_panes = "A2"

    headers = [
        "Lp.",
        "ID Logu",
        "Data i Czas",
        "Kod Zdarzenia",
        "Kategoria",
        "Użytkownik",
        "Adres IP",
        "Szczegóły Zdarzenia"
    ]
    thin_border = _style_excel_header(ws, headers)

    align_center = Alignment(horizontal="center", vertical="center")
    align_left_wrap = Alignment(horizontal="left", vertical="center", wrap_text=True)
    code_font = Font(name="Consolas", size=10, bold=True, color="1E293B")
    body_font = Font(name="Calibri", size=10, color="0F172A")

    event_counts = defaultdict(int)
    col_max_lens = {idx: len(h) for idx, h in enumerate(headers, start=1)}
    row_texts = []

    for lp_idx, item in enumerate(logs, start=1):
        row_num = lp_idx + 1
        code = item.event_code or "LOG_SYSTEM"
        category_label, fill_hex = _AUDIT_EVENT_CATEGORY_STYLES.get(
            code, ("Zdarzenie Systemowe", "F8FAFC")
        )
        event_counts[code] += 1
        row_fill = PatternFill(start_color=fill_hex, end_color=fill_hex, fill_type="solid")
        ts_str = item.created_at.strftime("%Y-%m-%d %H:%M:%S") if item.created_at else ""
        ip_str = item.ip_address or "-"
        details_str = item.details or ""

        row_vals = [
            lp_idx,
            item.id,
            ts_str,
            code,
            category_label,
            item.username or "-",
            ip_str,
            details_str
        ]
        ws.append(row_vals)
        row_texts.append((row_num, ip_str, details_str))

        for col_num, val in enumerate(row_vals, start=1):
            col_max_lens[col_num] = max(col_max_lens[col_num], len(str(val)))
            c = ws.cell(row=row_num, column=col_num)
            c.border = thin_border
            c.fill = row_fill
            c.font = code_font if col_num in (2, 4, 7) else body_font
            c.alignment = align_center if col_num in (1, 2, 3, 4) else align_left_wrap

    if logs:
        ws.auto_filter.ref = f"A1:H{len(logs) + 1}"

    col_widths = {
        1: max(col_max_lens[1] + 3, 7),
        2: max(col_max_lens[2] + 3, 10),
        3: max(col_max_lens[3] + 3, 21),
        4: max(col_max_lens[4] + 4, 21),
        5: max(col_max_lens[5] + 4, 30),
        6: min(max(col_max_lens[6] + 4, 18), 28),
        7: min(max(col_max_lens[7] + 4, 24), 52),
        8: min(max(col_max_lens[8] + 4, 48), 75),
    }
    for col_idx, width in col_widths.items():
        ws.column_dimensions[get_column_letter(col_idx)].width = width

    # Dynamiczna wysokość wiersza, aby zawinięty tekst w Adres IP / Szczegółach nigdy nie był ucięty
    eff_w7 = max(col_widths[7] - 3, 20)
    eff_w8 = max(col_widths[8] - 3, 40)
    for row_num, ip_str, details_str in row_texts:
        lines_7 = sum(max(1, (len(p) + eff_w7 - 1) // eff_w7) for p in (ip_str.splitlines() or [""]))
        lines_8 = sum(max(1, (len(p) + eff_w8 - 1) // eff_w8) for p in (details_str.splitlines() or [""]))
        ws.row_dimensions[row_num].height = max(22, max(lines_7, lines_8) * 15 + 6)

    # Arkusz 2: Podsumowanie i Statystyki
    ws_summary = wb.create_sheet(title="Podsumowanie")
    ws_summary.views.sheetView[0].showGridLines = True
    ws_summary.freeze_panes = "A2"
    sum_headers = ["Parametr / Kod Zdarzenia", "Wartość / Kategoria", "Liczba Zdarzeń", "Udział %"]
    _style_excel_header(ws_summary, sum_headers)

    first_ts = logs[0].created_at.strftime("%Y-%m-%d %H:%M:%S") if logs and logs[0].created_at else "-"
    last_ts = logs[-1].created_at.strftime("%Y-%m-%d %H:%M:%S") if logs and logs[-1].created_at else "-"
    total_logs = len(logs)

    meta_rows = [
        ("Wygenerowano", now_pl.strftime("%Y-%m-%d %H:%M:%S Europe/Warsaw"), "", ""),
        ("Liczba wpisów w paczce", f"{total_logs} / {AUDIT_LOG_AUTO_EXPORT_LIMIT}", total_logs, "100.0%"),
        ("Zakres czasowy", f"{first_ts}  ->  {last_ts}", "", ""),
    ]
    for m_idx, m_row in enumerate(meta_rows, start=2):
        ws_summary.append(list(m_row))
        for col_num in range(1, 5):
            c = ws_summary.cell(row=m_idx, column=col_num)
            c.border = thin_border
            c.font = Font(name="Calibri", size=10, bold=(col_num == 1), color="0F172A")
            c.fill = PatternFill(start_color="F1F5F9", end_color="F1F5F9", fill_type="solid")
            c.alignment = align_center if col_num in (3, 4) else align_left_wrap

    chart_start_row = len(meta_rows) + 3
    ws_summary.cell(row=chart_start_row - 1, column=1, value="").border = thin_border
    stat_row = chart_start_row
    for code, count in sorted(event_counts.items(), key=lambda kv: (-kv[1], kv[0])):
        cat_label, fill_hex = _AUDIT_EVENT_CATEGORY_STYLES.get(code, ("Zdarzenie Systemowe", "F8FAFC"))
        pct = f"{(count / total_logs * 100):.1f}%" if total_logs > 0 else "0.0%"
        ws_summary.cell(row=stat_row, column=1, value=code)
        ws_summary.cell(row=stat_row, column=2, value=cat_label)
        ws_summary.cell(row=stat_row, column=3, value=count)
        ws_summary.cell(row=stat_row, column=4, value=pct)
        row_fill = PatternFill(start_color=fill_hex, end_color=fill_hex, fill_type="solid")
        for col_num in range(1, 5):
            c = ws_summary.cell(row=stat_row, column=col_num)
            c.border = thin_border
            c.fill = row_fill
            c.font = code_font if col_num == 1 else body_font
            c.alignment = align_center if col_num in (1, 3, 4) else align_left_wrap
        stat_row += 1

    if event_counts:
        pie = PieChart()
        pie.title = "Struktura Zdarzeń AuditLog"
        labels = Reference(ws_summary, min_col=1, min_row=chart_start_row, max_row=stat_row - 1)
        data = Reference(ws_summary, min_col=3, min_row=chart_start_row, max_row=stat_row - 1)
        pie.add_data(data, titles_from_data=False)
        pie.set_categories(labels)
        ws_summary.add_chart(pie, "F2")

    sum_widths = {1: 28, 2: 34, 3: 18, 4: 14}
    for col_idx, width in sum_widths.items():
        ws_summary.column_dimensions[get_column_letter(col_idx)].width = width

    output = io.BytesIO()
    wb.save(output)
    output.seek(0)
    return output, filename


def upload_excel_to_google_drive(file_bytes, filename, folder_id=None):
    oauth_client_id = os.getenv("GOOGLE_OAUTH_CLIENT_ID")
    oauth_client_secret = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET")
    oauth_refresh_token = os.getenv("GOOGLE_OAUTH_REFRESH_TOKEN")
    raw_sa_json = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON")
    target_folder_id = _extract_drive_folder_id(folder_id) or _extract_drive_folder_id(os.getenv("GOOGLE_DRIVE_FOLDER_ID"))

    if oauth_client_id and oauth_client_secret and oauth_refresh_token:
        from google.oauth2.credentials import Credentials as OAuthCredentials
        from google.auth.transport.requests import Request as GoogleAuthRequest

        credentials = OAuthCredentials(
            token=None,
            refresh_token=oauth_refresh_token.strip(),
            token_uri="https://oauth2.googleapis.com/token",
            client_id=oauth_client_id.strip(),
            client_secret=oauth_client_secret.strip(),
            scopes=["https://www.googleapis.com/auth/drive.file"]
        )
        credentials.refresh(GoogleAuthRequest())
    elif raw_sa_json:
        if os.path.isfile(raw_sa_json):
            with open(raw_sa_json, "r", encoding="utf-8") as f:
                service_account_info = json.load(f)
        else:
            service_account_info = json.loads(raw_sa_json)

        scopes = [
            "https://www.googleapis.com/auth/drive.file",
            "https://www.googleapis.com/auth/drive"
        ]
        credentials = service_account.Credentials.from_service_account_info(
            service_account_info,
            scopes=scopes
        )
    else:
        raise RuntimeError(
            "Brak konfiguracji Google Drive: ustaw GOOGLE_OAUTH_CLIENT_ID, "
            "GOOGLE_OAUTH_CLIENT_SECRET i GOOGLE_OAUTH_REFRESH_TOKEN (dla zwykłego Gmaila) "
            "lub GOOGLE_SERVICE_ACCOUNT_JSON (dla Dysku współdzielonego)."
        )

    drive_service = build("drive", "v3", credentials=credentials)

    file_metadata = {
        "name": filename,
        "mimeType": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    }
    if target_folder_id:
        file_metadata["parents"] = [target_folder_id]

    if isinstance(file_bytes, io.BytesIO):
        file_bytes.seek(0)
        stream = file_bytes
    else:
        stream = io.BytesIO(file_bytes)

    media = MediaIoBaseUpload(
        stream,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        resumable=False
    )

    uploaded = drive_service.files().create(
        body=file_metadata,
        media_body=media,
        fields="id, name, webViewLink",
        supportsAllDrives=True
    ).execute()

    return uploaded


def export_audit_logs_batch_to_drive(logs_batch=None, clear_exported=True, trigger_label="AUTO_50"):
    """Eksportuje paczkę logów AuditLog do sformatowanego .xlsx i wysyła do folderu logów na Google Drive."""
    if logs_batch is None:
        query = AuditLog.query.order_by(AuditLog.created_at.asc(), AuditLog.id.asc())
        if trigger_label == "AUTO_50":
            query = query.limit(AUDIT_LOG_AUTO_EXPORT_LIMIT)
        logs_batch = query.all()

    if not logs_batch:
        return None, None, 0

    excel_bytes, filename = generate_audit_logs_excel_bytes(logs_batch)
    target_folder_id = get_audit_logs_drive_folder_id()
    uploaded = upload_excel_to_google_drive(excel_bytes, filename, folder_id=target_folder_id)
    file_id = uploaded.get("id", "N/A") if isinstance(uploaded, dict) else "N/A"
    exported_ids = [item.id for item in logs_batch if item.id is not None]

    if clear_exported and exported_ids:
        AuditLog.query.filter(AuditLog.id.in_(exported_ids)).delete(synchronize_session=False)
        db.session.commit()

    now_label = get_poland_now().strftime("%Y-%m-%d %H:%M:%S")
    set_setting("last_audit_drive_export", f"{now_label} | {filename} (ID: {file_id})"[:250])
    set_setting("last_audit_drive_export_error", "")

    folder_note = target_folder_id if target_folder_id else "Domyślny folder główny Drive"
    Thread(
        target=send_telegram_alert,
        args=[(
            f"[DRIVE] *EKSPORT LOGÓW AUDITLOG ({len(exported_ids)}/{AUDIT_LOG_AUTO_EXPORT_LIMIT})*\n\n"
            f"Tryb: `{trigger_label}`\n"
            f"Plik: `{filename}`\n"
            f"Folder ID: `{folder_note}`\n"
            f"Drive ID: `{file_id}`"
        )]
    ).start()
    send_web_push_to_users(
        user_ids=get_admin_user_ids(),
        title="Eksport AuditLog na Dysk Google",
        body=f"Wysłano paczkę {len(exported_ids)} logów ({filename}).",
        url="/admin#ustawienia"
    )

    return uploaded, filename, len(exported_ids)


@app.route('/admin/update_audit_logs_folder', methods=['POST'])
@admin_required
def update_audit_logs_folder():
    raw_folder = request.form.get('audit_logs_drive_folder_id', '')
    clean_id = _extract_drive_folder_id(raw_folder)
    set_setting('audit_logs_drive_folder_id', clean_id[:250])
    log_audit_event(
        "LOG_ADMIN_ACTION",
        details=f"Zaktualizowano dedykowany folder Google Drive dla AuditLog: {clean_id or 'brak (fallback na domyślny)'}"
    )
    if clean_id:
        flash(f"Zapisano ID folderu Google Drive dla logów: {clean_id}", "success")
    else:
        flash("Wyczyszczono indywidualny folder logów — system użyje GOOGLE_DRIVE_LOGS_FOLDER_ID lub domyślnego folderu.", "info")
    return redirect(url_for('admin_page') + '#ustawienia')


@app.route('/admin/export_audit_logs')
@admin_required
def export_audit_logs():
    output, filename = generate_audit_logs_excel_bytes()
    return send_file(
        output,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        as_attachment=True,
        download_name=filename
    )


@app.route('/admin/export_audit_logs_drive_now', methods=['POST'])
@admin_required
def export_audit_logs_drive_now():
    total_now = AuditLog.query.count()
    if total_now == 0:
        flash("Dziennik AuditLog jest obecnie pusty — brak logów do wysłania.", "warning")
        return redirect(url_for('admin_page') + '#ustawienia')

    clear_after = request.form.get('clear_after_export') == '1'
    try:
        with _AUDIT_EXPORT_LOCK:
            uploaded, filename, exported_count = export_audit_logs_batch_to_drive(
                clear_exported=clear_after,
                trigger_label="MANUAL"
            )
        file_id = uploaded.get("id", "N/A") if isinstance(uploaded, dict) else "N/A"
        status_note = " i wyczyszczono bufor w bazie" if clear_after else ""
        flash(
            f"Pomyślnie wyeksportowano {exported_count} logów ({filename}, ID: {file_id}) na Dysk Google{status_note}!",
            "success"
        )
    except Exception as e:
        db.session.rollback()
        set_setting("last_audit_drive_export_error", str(e)[:250])
        flash(f"Błąd wysyłki logów AuditLog na Dysk Google: {e}", "danger")

    return redirect(url_for('admin_page') + '#ustawienia')

def get_poland_now():
    return datetime.now(ZoneInfo("Europe/Warsaw"))

def scheduled_monthly_drive_export(force=False):
    now = get_poland_now()
    last_day_of_month = calendar.monthrange(now.year, now.month)[1]

    if not force and now.day != last_day_of_month:
        return False

    with app.app_context():
        month_key = f"{now.year}-{now.month:02d}"
        if not force and get_setting("last_drive_export_month", "") == month_key:
            return False

        try:
            excel_bytes, filename = generate_attendances_excel_bytes(year=now.year, month=now.month)
            uploaded = upload_excel_to_google_drive(excel_bytes, filename)
            set_setting("last_drive_export_month", month_key)
            file_id = uploaded.get("id", "N/A") if isinstance(uploaded, dict) else "N/A"
            log_audit_event(
                "LOG_DRIVE_EXPORT",
                username="SYSTEM",
                ip_address="127.0.0.1",
                details=f"Automatyczny miesięczny eksport na Dysk Google: {filename} (ID: {file_id})"
            )
            send_telegram_alert(
                f"[DRIVE] *AUTOMATYCZNY EKSPORT NA DYSK GOOGLE ZAKOŃCZONY!*\n\n"
                f"Plik: `{filename}`\n"
                f"Drive ID: `{file_id}`\n"
                f"Okres: {month_key}"
            )
            return True
        except Exception as e:
            log_audit_event(
                "LOG_DRIVE_EXPORT",
                username="SYSTEM",
                ip_address="127.0.0.1",
                details=f"Błąd automatycznego eksportu na Dysk Google ({month_key}): {e}"
            )
            send_telegram_alert(
                f"[BŁĄD] *BŁĄD AUTOMATYCZNEGO EKSPORTU NA DYSK GOOGLE!*\n\n"
                f"Okres: {month_key}\n"
                f"Szczegóły: `{e}`"
            )
            return False

@app.route('/admin/export_drive_now', methods=['POST'])
@admin_required
def export_drive_now():
    now = datetime.now(ZoneInfo("Europe/Warsaw"))
    year = request.form.get('year', type=int) or now.year
    month = request.form.get('month', type=int) or now.month
    try:
        excel_bytes, filename = generate_attendances_excel_bytes(year=year, month=month)
        uploaded = upload_excel_to_google_drive(excel_bytes, filename)
        file_id = uploaded.get("id", "N/A") if isinstance(uploaded, dict) else "N/A"
        set_setting("last_drive_export_month", f"{year}-{month:02d}")
        log_audit_event(
            "LOG_DRIVE_EXPORT",
            details=f"Ręczny eksport służb na Dysk Google: {filename} (ID: {file_id})"
        )
        Thread(
            target=send_telegram_alert,
            args=[f"[DRIVE] *RĘCZNY EKSPORT NA DYSK GOOGLE:* Wyeksportowano plik `{filename}` (ID: `{file_id}`)."]
        ).start()
        flash(f"Pomyślnie wysłano raport {filename} na Dysk Google (ID: {file_id})!", "success")
    except Exception as e:
        log_audit_event(
            "LOG_DRIVE_EXPORT",
            details=f"Błąd ręcznego eksportu na Dysk Google ({year}-{month:02d}): {e}"
        )
        flash(f"Błąd wysyłki na Dysk Google: {e}", "danger")

    return redirect(request.referrer or url_for('admin_page'))

@app.route('/admin/export_attendances')
@staff_required
def export_attendances():
    year = request.args.get('year', type=int)
    month = request.args.get('month', type=int)
    output, filename = generate_attendances_excel_bytes(year=year, month=month)

    return send_file(
        output,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        as_attachment=True,
        download_name=filename
    )

@app.route("/admin/export_ranking")
@staff_required
def export_ranking():
    users = Users.query.filter(Users.role.in_(['user', 'admin'])).all()
    attendances = Attendance.query.all()
    
    morning_count = defaultdict(int)
    evening_count = defaultdict(int)
    other_count = defaultdict(int)
    total_count = defaultdict(int)
    
    for att in attendances:
        total_count[att.user_id] += 1
        time_str = att.godzina.replace(":", "")
        try:
            hour_val = int(time_str[:2])
            if hour_val < 12:
                morning_count[att.user_id] += 1
            elif hour_val >= 17:
                evening_count[att.user_id] += 1
            else:
                other_count[att.user_id] += 1
        except ValueError:
            other_count[att.user_id] += 1

    data = []
    for u in users:
        tot = total_count[u.id]
        level = "LIDER" if tot >= 20 else ("AKTYWNY" if tot >= 5 else "POCZĄTKUJĄCY")
        data.append({
            "Login": u.username,
            "Imię i Nazwisko": f"{u.imie} {u.nazwisko}",
            "Suma Służb (Punkty)": tot,
            "Służby Poranne": morning_count[u.id],
            "Służby Wieczorne": evening_count[u.id],
            "Inne / Dodatkowe": other_count[u.id],
            "Status Aktywności": level
        })
        
    df = pd.DataFrame(data).sort_values(by="Suma Służb (Punkty)", ascending=False)
    buffer = io.BytesIO()
    df.to_excel(buffer, index=False, sheet_name="Cyfrowy Ranking")
    buffer.seek(0)
    
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"cyfrowy_ranking_{date.today()}.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

@app.route('/export_schedule')
@login_required
def export_schedule():
    schedules = db.session.query(Schedule, Users).join(Users, Schedule.user_id == Users.id).all()
    
    data = []
    dni_kolejnosc = {'Poniedziałek': 1, 'Wtorek': 2, 'Środa': 3, 'Czwartek': 4, 'Piątek': 5, 'Sobota': 6, 'Niedziela': 7}
    
    for sch, u in schedules:
        data.append({
            'Dzień Tygodnia': sch.dzien_tygodnia,
            'Kolejność': dni_kolejnosc.get(sch.dzien_tygodnia, 8),
            'Godzina': sch.godzina,
            'Imię i Nazwisko': f"{u.imie} {u.nazwisko}",
            'Pseudonim (Login)': u.username
        })

    df = pd.DataFrame(data)
    if not df.empty:
        df = df.sort_values(by=['Kolejność', 'Godzina'])
        df = df.drop(columns=['Kolejność'])
    else:
        df = pd.DataFrame(columns=['Dzień Tygodnia', 'Godzina', 'Imię i Nazwisko', 'Pseudonim (Login)'])

    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Plan_Sluzb')
    
    output.seek(0)
    nazwa_pliku = f"Plan_Sluzb_{date.today().strftime('%Y-%m-%d')}.xlsx"
    return send_file(output, download_name=nazwa_pliku, as_attachment=True)

@app.route('/admin/toggle_uproszczony/<int:id>', methods=['POST'])
@admin_required
def toggle_uproszczony(id):
    u = Users.query.get_or_404(id)
    u.uproszczony = not u.uproszczony
    db.session.commit()
    log_audit_event("LOG_ADMIN_ACTION", details=f"Zmieniono tryb interfejsu dla @{u.username} na {'uproszczony' if u.uproszczony else 'pełny'}")
    flash(f"Zmieniono tryb wyświetlania dla użytkownika {u.username}.", "success")
    return redirect(request.referrer or url_for('admin_page'))

# --- ZABEZPIECZENIE SERWOWANIA PLIKU PRZED PATH TRAVERSAL ---
@app.route('/download/regulamin.pdf')
def pobierz_regulamin():
    katalog = os.path.join(app.root_path, 'static', 'docs')
    safe_path = os.path.abspath(os.path.join(katalog, 'regulamin.pdf'))
    if not safe_path.startswith(os.path.abspath(katalog)):
        abort(403)
    return send_from_directory(
        katalog, 
        'regulamin.pdf', 
        as_attachment=True, 
        download_name='regulamin.pdf'
    )

@app.route('/pomoc')
def pomoc_page():
    return render_template('pomoc.html')

def ensure_schema_migrations():
    try:
        inspector = inspect(db.engine)
        if 'users' in inspector.get_table_names():
            existing_cols = {col['name'] for col in inspector.get_columns('users')}
            with db.engine.begin() as conn:
                if 'failed_login_attempts' not in existing_cols:
                    conn.execute(text("ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0"))
                if 'locked_until' not in existing_cols:
                    conn.execute(text("ALTER TABLE users ADD COLUMN locked_until TIMESTAMP NULL"))
                if 'registration_device' not in existing_cols:
                    conn.execute(text("ALTER TABLE users ADD COLUMN registration_device VARCHAR(255) NULL"))
                if 'verification_status' not in existing_cols:
                    conn.execute(text("ALTER TABLE users ADD COLUMN verification_status VARCHAR(20) DEFAULT 'PENDING'"))
                if 'rejection_reason' not in existing_cols:
                    conn.execute(text("ALTER TABLE users ADD COLUMN rejection_reason TEXT NULL"))
                if 'admin_message' not in existing_cols:
                    conn.execute(text("ALTER TABLE users ADD COLUMN admin_message TEXT NULL"))
        # Uzupełnienie verification_status dla istniejących użytkowników (działa spójnie na SQLite i PostgreSQL)
        users_to_sync = Users.query.filter(Users.verification_status.is_(None)).all()
        for u in users_to_sync:
            u.verification_status = 'APPROVED' if u.is_approved else 'PENDING'
        # Usunięcie wycofanej mszy o godzinie 14:00 z grafiku
        removed_14 = Schedule.query.filter_by(godzina='14:00').delete()
        if users_to_sync or removed_14:
            db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Ostrzeżenie migracji schematu: {e}")

def init_admin_account():
    env_admin_name = get_env_admin_name()
    env_admin_pass = get_env_admin_pass()
    
    admin_user = Users.query.filter_by(username=env_admin_name).first()
    if not admin_user:
        if not env_admin_pass:
            raise RuntimeError("Brak zmiennej środowiskowej ADMIN_PASSWORD / admin_password wymaganej do utworzenia nowego konta administratora!")
        hashed_admin_pass = generate_password_hash(env_admin_pass, method='pbkdf2:sha256')
        admin_user = Users(
            imie="Główny", 
            nazwisko="Szef", 
            username=env_admin_name, 
            password=hashed_admin_pass, 
            role='admin', 
            uproszczony=False,
            is_approved=True,
            verification_status='APPROVED'
        )
        db.session.add(admin_user)
        db.session.commit()
    else:
        changed = False
        if not admin_user.password or not admin_user.password.startswith(('pbkdf2:', 'scrypt:')):
            raw_pwd = admin_user.password if admin_user.password else env_admin_pass
            if not raw_pwd:
                raise RuntimeError("Brak hasła dla konta administratora (ADMIN_PASSWORD / admin_password)!")
            admin_user.password = generate_password_hash(raw_pwd, method='pbkdf2:sha256')
            changed = True
        if admin_user.role != 'admin':
            admin_user.role = 'admin'
            changed = True
        if not admin_user.is_approved:
            admin_user.is_approved = True
            changed = True
        if admin_user.verification_status != 'APPROVED':
            admin_user.verification_status = 'APPROVED'
            changed = True
        if changed:
            db.session.commit()

    # Upewniamy się, że wszyscy użytkownicy z rangą admin są zatwierdzeni i mają zaszyfrowane hasło PBKDF2
    all_admins = Users.query.filter_by(role='admin').all()
    if all_admins:
        admin_changed = False
        for adm in all_admins:
            if not adm.is_approved:
                adm.is_approved = True
                admin_changed = True
            if adm.verification_status != 'APPROVED':
                adm.verification_status = 'APPROVED'
                admin_changed = True
            if adm.password and not adm.password.startswith(('pbkdf2:', 'scrypt:')):
                adm.password = generate_password_hash(adm.password, method='pbkdf2:sha256')
                admin_changed = True
        if admin_changed:
            db.session.commit()

    # Domyślne ustawienie limitu dni wstecz na wpisywanie służb (3 dni)
    if db.session.get(SystemSettings, 'attendance_days_back') is None:
        set_setting('attendance_days_back', '3')

# --- WEB PUSH (PWA) ---

def get_admin_user_ids():
    """Zwraca listę ID kont z rolą admin."""
    return [u.id for u in Users.query.filter_by(role='admin').with_entities(Users.id).all()]

def get_vapid_keys():
    """Zwraca parę kluczy VAPID (publiczny base64url, prywatny base64url). Generuje automatycznie, jeśli brak."""
    pub = (os.getenv("VAPID_PUBLIC_KEY") or "").strip()
    priv = (os.getenv("VAPID_PRIVATE_KEY") or "").strip()
    if pub and priv:
        return pub, priv

    pub_db = (get_setting("vapid_public_key", "") or "").strip()
    priv_db = (get_setting("vapid_private_key", "") or "").strip()
    if pub_db and priv_db:
        return pub_db, priv_db

    from py_vapid import Vapid
    from py_vapid.utils import b64urlencode
    from cryptography.hazmat.primitives import serialization

    vapid = Vapid()
    vapid.generate_keys()
    raw_pub = vapid.public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    raw_priv = vapid.private_key.private_numbers().private_value.to_bytes(32, "big")
    pub_b64 = b64urlencode(raw_pub)
    priv_b64 = b64urlencode(raw_priv)
    set_setting("vapid_public_key", pub_b64)
    set_setting("vapid_private_key", priv_b64)
    return pub_b64, priv_b64


def _dispatch_web_push_worker(subs_data, payload_json, priv_key, claims):
    from pywebpush import webpush, WebPushException

    expired_ids = []
    for sub_id, sub_info in subs_data:
        try:
            webpush(
                subscription_info=sub_info,
                data=payload_json,
                vapid_private_key=priv_key,
                vapid_claims=claims
            )
        except WebPushException as ex:
            status = getattr(getattr(ex, "response", None), "status_code", None)
            if status in (404, 410):
                expired_ids.append(sub_id)
            else:
                print(f"Ostrzeżenie Web Push (sub #{sub_id}): {ex}")
        except Exception as ex:
            print(f"Błąd wysyłki Web Push (sub #{sub_id}): {ex}")

    if expired_ids:
        with app.app_context():
            try:
                PushSubscription.query.filter(PushSubscription.id.in_(expired_ids)).delete(synchronize_session=False)
                db.session.commit()
            except Exception:
                db.session.rollback()


def send_web_push_to_users(user_ids=None, title="System Ministranci", body="", url="/dashboard"):
    """Wysyła powiadomienia Web Push w tle do wskazanych użytkowników (lub wszystkich, gdy user_ids=None)."""
    try:
        _, priv_key = get_vapid_keys()
        query = PushSubscription.query
        if user_ids is not None:
            if not user_ids:
                return 0
            query = query.filter(PushSubscription.user_id.in_(user_ids))
        subs = query.all()
        if not subs:
            return 0

        subs_data = [
            (
                s.id,
                {"endpoint": s.endpoint, "keys": {"p256dh": s.p256dh, "auth": s.auth}}
            )
            for s in subs
        ]
        payload_json = json.dumps({"title": title, "body": body, "url": url})
        claims = {"sub": os.getenv("VAPID_SUBJECT", "mailto:admin@ministranci.local")}
        Thread(target=_dispatch_web_push_worker, args=(subs_data, payload_json, priv_key, claims)).start()
        return len(subs_data)
    except Exception as e:
        print(f"Błąd przygotowania Web Push: {e}")
        return 0


@app.route('/sw.js')
def service_worker():
    response = send_from_directory(os.path.join(app.root_path, 'static'), 'sw.js', mimetype='application/javascript')
    response.headers['Service-Worker-Allowed'] = '/'
    response.headers['Cache-Control'] = 'no-cache'
    return response


@app.route('/api/push/public-key')
@login_required
def push_public_key():
    pub_key, _ = get_vapid_keys()
    return jsonify({"publicKey": pub_key})


@app.route('/api/push/subscribe', methods=['POST'])
@login_required
def push_subscribe():
    data = request.get_json(silent=True) or {}
    endpoint = (data.get('endpoint') or '').strip()
    keys = data.get('keys') or {}
    p256dh = (keys.get('p256dh') or '').strip()
    auth = (keys.get('auth') or '').strip()

    if not endpoint or not p256dh or not auth:
        return jsonify({"ok": False, "error": "Brak wymaganych danych subskrypcji Push."}), 400

    existing = PushSubscription.query.filter_by(endpoint=endpoint).first()
    ua = parse_user_agent(request.headers.get('User-Agent', ''))
    if existing:
        existing.user_id = session['user_id']
        existing.p256dh = p256dh
        existing.auth = auth
        existing.user_agent = ua
    else:
        db.session.add(PushSubscription(
            user_id=session['user_id'],
            endpoint=endpoint,
            p256dh=p256dh,
            auth=auth,
            user_agent=ua
        ))
    db.session.commit()
    return jsonify({"ok": True})


@app.route('/api/push/unsubscribe', methods=['POST'])
@login_required
def push_unsubscribe():
    data = request.get_json(silent=True) or {}
    endpoint = (data.get('endpoint') or '').strip()
    if endpoint:
        PushSubscription.query.filter_by(endpoint=endpoint, user_id=session['user_id']).delete()
        db.session.commit()
    return jsonify({"ok": True})


@app.route('/admin/send_push_notification', methods=['POST'])
@admin_required
def admin_send_push_notification():
    title = (request.form.get('push_title') or 'System Ministranci').strip()[:100]
    body = (request.form.get('push_body') or '').strip()[:300]
    if not body:
        flash("Wpisz treść powiadomienia Push!", "warning")
        return redirect(url_for('admin_page') + '#ustawienia')

    sent_count = send_web_push_to_users(user_ids=None, title=title, body=body, url="/dashboard")
    log_audit_event("LOG_ADMIN_ACTION", details=f"Wysłano powiadomienie Web Push ({sent_count} urządzeń): {title}")
    flash(f"Wysłano powiadomienie Web Push do {sent_count} zapisanych urządzeń.", "success")
    return redirect(url_for('admin_page') + '#ustawienia')


# --- HARMONOGRAM APSCHEDULER (AUTOMATYCZNY EKSPORT NA KONIEC MIESIĄCA) ---
scheduler = BackgroundScheduler(timezone=ZoneInfo("Europe/Warsaw"))
scheduler.add_job(
    func=scheduled_monthly_drive_export,
    trigger="cron",
    hour=23,
    minute=50,
    id="monthly_drive_export",
    replace_existing=True
)
if not scheduler.running and os.environ.get("WERKZEUG_RUN_MAIN") != "false":
    try:
        scheduler.start()
    except Exception as e:
        print(f"Ostrzeżenie uruchomienia BackgroundScheduler: {e}")

with app.app_context():
    db.create_all()
    ensure_schema_migrations()
    init_admin_account()

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
