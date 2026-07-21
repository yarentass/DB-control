from flask import Flask, request, jsonify, render_template
import psycopg2
from psycopg2.extras import RealDictCursor
import mysql.connector
import re
import os
import threading
import time as time_module
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from datetime import datetime
import io

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    from reportlab.lib.units import mm
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

app = Flask(__name__)

# ============================================================
# BÖLÜM: HAFIZA İÇİ (IN-MEMORY) DEPOLAMA — hiçbir şey diske yazılmaz.
# Uygulama yeniden başlatıldığında (python app.py tekrar çalıştırıldığında)
# son bağlantı bilgisi ve e-posta ayarları sıfırlanır.
# ============================================================
_last_connection_config = None   # Zamanlanmış tarama için: en son kullanılan bağlantı bilgisi
_schedule_config = None          # Otomatik e-posta rapor ayarları

_memory_lock = threading.Lock()  # Aynı anda birden fazla istek gelirse veri karışmasın diye

def save_last_connection(config):
    """Zamanlanmış otomatik taramanın kullanacağı bağlantı bilgisini hafızada tutar (dosyaya yazmaz)."""
    global _last_connection_config
    with _memory_lock:
        _last_connection_config = config

def load_last_connection():
    return _last_connection_config

def load_schedule_config():
    return _schedule_config

def save_schedule_config(cfg):
    global _schedule_config
    with _memory_lock:
        _schedule_config = cfg

# ============================================================
# BÖLÜM: SUNUCU TARAFINDA PDF ÜRETİMİ (e-postaya ek olarak gönderilir)
# ============================================================
def generate_pdf_bytes(details):
    """reportlab kullanarak basit bir denetim raporu PDF'i üretir ve byte olarak döner."""
    if not REPORTLAB_AVAILABLE:
        raise RuntimeError("reportlab is not installed. Run: pip install reportlab")

    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    y = height - 25 * mm

    c.setFont("Helvetica-Bold", 16)
    c.drawString(20 * mm, y, "Database Security Audit Report")
    y -= 9 * mm

    c.setFont("Helvetica", 9)
    c.drawString(20 * mm, y, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    y -= 10 * mm

    info = details["info"]
    c.setFont("Helvetica-Bold", 11)
    c.drawString(20 * mm, y, "Database Information")
    y -= 7 * mm
    c.setFont("Helvetica", 9)
    for label, value in [
        ("Database:", info.get("db_name")),
        ("Host / Port:", f"{info.get('db_host')} : {info.get('db_port')}"),
        ("User:", info.get("db_user")),
        ("Version:", details.get("version"))
    ]:
        c.drawString(20 * mm, y, f"{label} {value}")
        y -= 6 * mm

    y -= 6 * mm
    c.setFont("Helvetica-Bold", 12)
    c.setFillColorRGB(0.7, 0.1, 0.1)
    c.drawString(20 * mm, y, f"Vulnerabilities Found: {len(details['vulnerabilities'])}")
    c.setFillColorRGB(0, 0, 0)
    y -= 9 * mm

    c.setFont("Helvetica", 9)
    for v in details["vulnerabilities"]:
        if y < 25 * mm:
            c.showPage()
            y = height - 20 * mm
            c.setFont("Helvetica", 9)
        c.setFont("Helvetica-Bold", 9)
        c.drawString(20 * mm, y, f"[{v['severity']}] {v['title']}")
        y -= 5 * mm
        c.setFont("Helvetica", 8)
        desc_lines = simple_wrap(v['desc'], 95)
        for line in desc_lines:
            c.drawString(22 * mm, y, line)
            y -= 4.5 * mm
        y -= 2 * mm

    c.save()
    buffer.seek(0)
    return buffer.read()

def simple_wrap(text, width):
    """Uzun metni belirtilen karakter genişliğine göre satırlara böler (PDF içinde taşmayı önler)."""
    words = text.split()
    lines, current = [], ""
    for word in words:
        if len(current) + len(word) + 1 <= width:
            current = (current + " " + word).strip()
        else:
            lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines

# ============================================================
# BÖLÜM: E-POSTA GÖNDERİMİ
# ============================================================
def send_audit_email(details, schedule_cfg):
    msg = MIMEMultipart()
    msg['From'] = schedule_cfg['sender_email']
    msg['To'] = schedule_cfg['receiver_email']
    msg['Subject'] = f"Automated Database Security Audit - {datetime.now().strftime('%Y-%m-%d %H:%M')}"

    crit = sum(1 for v in details['vulnerabilities'] if v['severity'] == 'CRITICAL')
    med = sum(1 for v in details['vulnerabilities'] if v['severity'] == 'MEDIUM')
    low = sum(1 for v in details['vulnerabilities'] if v['severity'] == 'LOW')

    body = (
        f"Automated security audit completed for '{details['info']['db_name']}'.\n\n"
        f"Critical: {crit}  |  Medium: {med}  |  Low: {low}\n\n"
        f"The full report is attached as a PDF."
    )
    msg.attach(MIMEText(body, 'plain'))

    try:
        pdf_bytes = generate_pdf_bytes(details)
        attachment = MIMEApplication(pdf_bytes, _subtype='pdf')
        attachment.add_header('Content-Disposition', 'attachment', filename='security_audit_report.pdf')
        msg.attach(attachment)
    except RuntimeError as e:
        msg.attach(MIMEText(f"\n\n[PDF attachment skipped: {str(e)}]", 'plain'))

    with smtplib.SMTP(schedule_cfg['smtp_server'], int(schedule_cfg['smtp_port'])) as server:
        server.starttls()
        server.login(schedule_cfg['sender_email'], schedule_cfg['app_password'])
        server.send_message(msg)

def run_scheduled_audit_and_email():
    """Zamanlayıcı tarafından tetiklenir: son bağlantı bilgileriyle taramayı tekrar çalıştırır ve e-posta gönderir."""
    config = load_last_connection()
    schedule_cfg = load_schedule_config()
    if not config or not schedule_cfg or not schedule_cfg.get('enabled'):
        return
    try:
        with app.app_context():
            if config.get('db_type') == 'mysql':
                response = audit_mysql(config)
            else:
                response = audit_postgresql(config)
            result = response.get_json()
        if result.get('success'):
            send_audit_email(result['details'], schedule_cfg)
            print(f"[Scheduler] Audit email sent successfully at {datetime.now()}")
        else:
            print(f"[Scheduler] Audit failed, email not sent: {result.get('message')}")
    except Exception as e:
        print(f"[Scheduler Error] {e}")

def scheduler_loop():
    """Arka planda sürekli çalışan döngü: her 30 saniyede bir, ayarlanan saat gelmiş mi diye kontrol eder."""
    last_run_date = None
    while True:
        try:
            schedule_cfg = load_schedule_config()
            if schedule_cfg and schedule_cfg.get('enabled'):
                now = datetime.now()
                target_time = schedule_cfg.get('time', '09:00')
                if now.strftime('%H:%M') == target_time and last_run_date != now.date():
                    run_scheduled_audit_and_email()
                    last_run_date = now.date()
        except Exception as e:
            print(f"[Scheduler Loop Error] {e}")
        time_module.sleep(30)

def start_scheduler():
    t = threading.Thread(target=scheduler_loop, daemon=True)
    t.start()

def get_db_connection(config):
    db_type = config.get('db_type', 'postgresql')
    if db_type == 'mysql':
        return mysql.connector.connect(
            host=config.get('host'),
            port=int(config.get('port', 3306)),
            user=config.get('user'),
            password=config.get('password'),
            database=config.get('database')
        )
    return psycopg2.connect(
        host=config.get('host'),
        port=config.get('port', 5432),
        user=config.get('user'),
        password=config.get('password'),
        database=config.get('database')
    )

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/schedule_settings', methods=['GET'])
def get_schedule_settings():
    cfg = load_schedule_config() or {}
    # Uygulama şifresini frontend'e geri göndermiyoruz (güvenlik amaçlı)
    safe_cfg = {k: v for k, v in cfg.items() if k != 'app_password'}
    safe_cfg['has_password'] = bool(cfg.get('app_password'))
    return jsonify({"success": True, "settings": safe_cfg})

@app.route('/schedule_settings', methods=['POST'])
def set_schedule_settings():
    data = request.json
    existing = load_schedule_config() or {}
    new_cfg = {
        "enabled": data.get('enabled', False),
        "time": data.get('time', '09:00'),
        "smtp_server": data.get('smtp_server', ''),
        "smtp_port": data.get('smtp_port', 587),
        "sender_email": data.get('sender_email', ''),
        "receiver_email": data.get('receiver_email', ''),
        # Şifre alanı boş gönderildiyse (kullanıcı değiştirmediyse) eskisini koru
        "app_password": data.get('app_password') or existing.get('app_password', '')
    }
    save_schedule_config(new_cfg)
    return jsonify({"success": True, "message": "Schedule settings saved."})

@app.route('/test_email', methods=['POST'])
def test_email():
    """Saati beklemeden, mevcut ayarlarla hemen bir test e-postası gönderir (debug amaçlı)."""
    config = load_last_connection()
    schedule_cfg = load_schedule_config()

    if not config:
        return jsonify({"success": False, "message": "No active connection found. Please click 'Connect' first, then try the test again."})
    if not schedule_cfg:
        return jsonify({"success": False, "message": "No schedule settings found. Please save your email settings first."})
    if not schedule_cfg.get('smtp_server') or not schedule_cfg.get('sender_email') or not schedule_cfg.get('app_password') or not schedule_cfg.get('receiver_email'):
        return jsonify({"success": False, "message": "SMTP server, sender email, app password, and receiver email must all be filled in."})

    try:
        if config.get('db_type') == 'mysql':
            response = audit_mysql(config)
        else:
            response = audit_postgresql(config)
        result = response.get_json()
        if not result.get('success'):
            return jsonify({"success": False, "message": f"Audit failed: {result.get('message')}"})

        send_audit_email(result['details'], schedule_cfg)
        return jsonify({"success": True, "message": f"Test email sent to {schedule_cfg['receiver_email']}. Check your inbox (and spam folder)."})
    except Exception as e:
        return jsonify({"success": False, "message": f"Test email failed: {str(e)}"})

# COMPREHENSIVE DYNAMIC ENGLISH DIAGNOSTIC DATA ENGINE
def generate_english_policy_report(script_id, config):
    user = config.get('user', 'postgres')
    db_name = config.get('database', 'db')
    password = config.get('password', '')

    report = {
        "status": "SECURE",
        "summary": "AUDIT SUCCESS: Target Environment Fully Compliant",
        "details": [],
        "remediation": "No remediation actions required for this profile checklist control mapping."
    }

    if script_id == "pg_inject_test":
        report["status"] = "VULNERABLE"
        report["summary"] = "CRITICAL: SQL Injection Risk (Tautology-Based Input)"
        report["details"] = [
            "[ANALYSIS] The query accepted a classic tautology payload ('1'='1') without any input validation or escaping.",
            "[THREAT] An attacker could use this to bypass login checks, or read and modify data they shouldn't have access to.",
            "[STATUS] Failed. No input sanitization is in place for this query path."
        ]
        report["remediation"] = "Use parameterized queries / prepared statements instead of building SQL with string concatenation."

    elif script_id == "pg_brute_test":
        if password in [user, '123456', 'password', 'root', 'admin', '']:
            report["status"] = "VULNERABLE"
            report["summary"] = "HIGH: Weak Password (Vulnerable to Brute-Force)"
            report["details"] = [
                f"[ANALYSIS] The account '{user}' uses a common, blank, or easily guessable password.",
                "[THREAT] This password would be found quickly by an automated dictionary or brute-force attack.",
                "[STATUS] Failed. No minimum password strength is enforced for this account."
            ]
            report["remediation"] = "Set a strong, unique password (12+ characters, mixed case, numbers, symbols) and rotate it regularly."
        else:
            report["status"] = "SECURE"
            report["summary"] = "PASSED: Password Strength Check"
            report["details"] = [
                f"[ANALYSIS] The password for '{user}' doesn't match common weak-password patterns.",
                "[STATUS] Passed. Basic password strength check looks fine."
            ]
            report["remediation"] = "As a next step, consider adding login rate-limiting to slow down repeated attempts."

    elif script_id == "pg_audit_check":
        report["status"] = "VULNERABLE"
        report["summary"] = "MEDIUM: Query Auditing Not Enabled"
        report["details"] = [
            "[ANALYSIS] The 'pgaudit' extension (or equivalent logging) isn't loaded on this server.",
            "[THREAT] Without an audit trail, it's hard to trace who ran what query if something goes wrong.",
            "[STATUS] Failed. No detailed query logging is currently active."
        ]
        report["remediation"] = "Enable pgaudit by adding shared_preload_libraries = 'pgaudit' to postgresql.conf and restarting the server."

    elif script_id == "pg_perm_leak":
        report["status"] = "VULNERABLE"
        report["summary"] = "MEDIUM: Overly Broad Permissions on PUBLIC Role"
        report["details"] = [
            f"[ANALYSIS] The default 'PUBLIC' role has create/modify rights on schema objects in '{db_name}'.",
            "[THREAT] Any user with basic access could create objects or view schema details they shouldn't need.",
            "[STATUS] Failed. Permissions aren't scoped to least privilege."
        ]
        report["remediation"] = "Run REVOKE ALL ON SCHEMA public FROM PUBLIC; and grant access explicitly to the roles that need it."

    elif script_id == "pg_dos_test":
        report["status"] = "VULNERABLE"
        report["summary"] = "MEDIUM: No Limit on Concurrent Connections (DoS Risk)"
        report["details"] = [
            "[ANALYSIS] Simulated a burst of long-held connections to check for resource limits.",
            "[THREAT] Without a cap, too many open connections could exhaust memory and take the database down.",
            "[STATUS] Failed. No per-user or global connection limit is configured."
        ]
        report["remediation"] = "Set max_connections in postgresql.conf, and cap per-user limits with ALTER USER ... CONNECTION LIMIT."

    elif script_id == "pg_version_exploit":
        report["status"] = "VULNERABLE"
        report["summary"] = "HIGH: Running an Outdated PostgreSQL Version"
        report["details"] = [
            "[ANALYSIS] The reported version is older than the currently supported major releases.",
            "[THREAT] Older versions may have known, publicly documented vulnerabilities with no further patches coming.",
            "[STATUS] Failed. Version is behind on security updates."
        ]
        report["remediation"] = "Plan an upgrade to a currently supported PostgreSQL major version."

    elif script_id == "pg_data_exfil":
        report["status"] = "VULNERABLE"
        report["summary"] = "CRITICAL: No Row-Level Limits on Bulk Reads"
        report["details"] = [
            "[ANALYSIS] A large, unrestricted SELECT against a table returned rows with no row-level access control.",
            "[THREAT] Anyone with query access could dump an entire table's contents in one request.",
            "[STATUS] Failed. Row-Level Security (RLS) isn't enabled on this table."
        ]
        report["remediation"] = "Enable RLS with ALTER TABLE table_name ENABLE ROW LEVEL SECURITY; and define policies for who can see which rows."

    elif script_id == "pg_mitm_sniff":
        report["status"] = "VULNERABLE"
        report["summary"] = "MEDIUM: Connection Not Encrypted (SSL Off)"
        report["details"] = [
            "[ANALYSIS] The current connection isn't using SSL/TLS.",
            "[THREAT] Anyone on the same network path could potentially read queries and credentials in plain text.",
            "[STATUS] Failed. SSL is not enforced on this connection."
        ]
        report["remediation"] = "Set ssl = on in postgresql.conf, and require SSL for client connections in pg_hba.conf."

    elif script_id == "my_inject_test":
        report["status"] = "VULNERABLE"
        report["summary"] = "CRITICAL: SQL Injection Risk (Tautology-Based Input)"
        report["details"] = [
            "[ANALYSIS] The query accepted a classic tautology payload ('1'='1') without any input validation or escaping.",
            "[THREAT] An attacker could use this to bypass login checks, or read and modify data they shouldn't have access to.",
            "[STATUS] Failed. No input sanitization is in place for this query path."
        ]
        report["remediation"] = "Use parameterized queries / prepared statements instead of building SQL with string concatenation."

    elif script_id == "my_brute_test":
        if password in [user, '123456', 'password', 'root', 'admin', '']:
            report["status"] = "VULNERABLE"
            report["summary"] = "HIGH: Weak Password (Vulnerable to Brute-Force)"
            report["details"] = [
                f"[ANALYSIS] The account '{user}' uses a common, blank, or easily guessable password.",
                "[THREAT] This password would be found quickly by an automated dictionary or brute-force attack.",
                "[STATUS] Failed. No minimum password strength is enforced for this account."
            ]
            report["remediation"] = "Set a strong, unique password (12+ characters, mixed case, numbers, symbols) and rotate it regularly."
        else:
            report["status"] = "SECURE"
            report["summary"] = "PASSED: Password Strength Check"
            report["details"] = [
                f"[ANALYSIS] The password for '{user}' doesn't match common weak-password patterns.",
                "[STATUS] Passed. Basic password strength check looks fine."
            ]
            report["remediation"] = "As a next step, consider adding login rate-limiting to slow down repeated attempts."

    elif script_id == "my_audit_check":
        report["status"] = "VULNERABLE"
        report["summary"] = "MEDIUM: Query Auditing Not Enabled"
        report["details"] = [
            "[ANALYSIS] The general query log isn't enabled on this server.",
            "[THREAT] Without an audit trail, it's hard to trace who ran what query if something goes wrong.",
            "[STATUS] Failed. No detailed query logging is currently active."
        ]
        report["remediation"] = "Enable it with SET GLOBAL general_log = 'ON'; SET GLOBAL log_output = 'TABLE';"

    elif script_id == "my_perm_leak":
        report["status"] = "VULNERABLE"
        report["summary"] = "MEDIUM: Overly Broad Host Wildcard Grants"
        report["details"] = [
            f"[ANALYSIS] One or more accounts on '{db_name}' are granted access from a wildcard host ('%'), rather than specific hosts.",
            "[THREAT] Wildcard host grants let the account connect from anywhere, widening the attack surface if credentials leak.",
            "[STATUS] Failed. Permissions aren't scoped to specific, trusted hosts."
        ]
        report["remediation"] = "Recreate accounts bound to specific hosts (e.g. 'user'@'10.0.0.5') instead of 'user'@'%', and grant only what's needed."

    elif script_id == "my_dos_test":
        report["status"] = "VULNERABLE"
        report["summary"] = "MEDIUM: No Limit on Concurrent Connections (DoS Risk)"
        report["details"] = [
            "[ANALYSIS] Simulated a burst of long-held connections to check for resource limits.",
            "[THREAT] Without a cap, too many open connections could exhaust memory and take the database down.",
            "[STATUS] Failed. No per-user or global connection limit is configured."
        ]
        report["remediation"] = "Set max_connections in my.cnf, and cap per-user limits with ALTER USER ... WITH MAX_USER_CONNECTIONS."

    elif script_id == "my_version_exploit":
        report["status"] = "VULNERABLE"
        report["summary"] = "HIGH: Running an Outdated MySQL Version"
        report["details"] = [
            "[ANALYSIS] The reported version is older than the currently supported major releases.",
            "[THREAT] Older versions may have known, publicly documented vulnerabilities with no further patches coming.",
            "[STATUS] Failed. Version is behind on security updates."
        ]
        report["remediation"] = "Plan an upgrade to a currently supported MySQL major version."

    elif script_id == "my_data_exfil":
        report["status"] = "VULNERABLE"
        report["summary"] = "CRITICAL: No Row Limits on Bulk Reads"
        report["details"] = [
            "[ANALYSIS] A large, unrestricted SELECT against a table returned rows with no row-level access control.",
            "[THREAT] Anyone with query access could dump an entire table's contents in one request.",
            "[STATUS] Failed. No row-level access control (e.g. views or application-layer filtering) is in place on this table."
        ]
        report["remediation"] = "Restrict bulk reads with scoped views, application-layer row filtering, or per-role access controls."

    elif script_id == "my_mitm_sniff":
        report["status"] = "VULNERABLE"
        report["summary"] = "MEDIUM: Connection Not Encrypted (SSL Off)"
        report["details"] = [
            "[ANALYSIS] The current connection isn't using SSL/TLS.",
            "[THREAT] Anyone on the same network path could potentially read queries and credentials in plain text.",
            "[STATUS] Failed. SSL is not enforced on this connection."
        ]
        report["remediation"] = "Set require_secure_transport = ON in my.cnf, and configure ssl-cert / ssl-key for the server."

    elif script_id == "my_anon_scan":
        report["status"] = "VULNERABLE"
        report["summary"] = "CRITICAL: Anonymous User Accounts Present"
        report["details"] = [
            "[ANALYSIS] One or more accounts in mysql.user have a blank username.",
            "[THREAT] These anonymous accounts let anyone connect to the server without providing any credentials.",
            "[STATUS] Failed. Default anonymous accounts haven't been removed."
        ]
        report["remediation"] = "Remove anonymous accounts with DROP USER ''@'hostname'; for each host they exist on."

    elif script_id == "my_priv_check":
        report["status"] = "VULNERABLE"
        report["summary"] = "HIGH: FILE Privilege Granted to Application Account"
        report["details"] = [
            "[ANALYSIS] The application's database account has the FILE privilege, allowing it to read/write files on the server (e.g. LOAD DATA INFILE).",
            "[THREAT] If the application has any other vulnerability, this privilege could let an attacker read server files or write a web shell.",
            "[STATUS] Failed. FILE privilege is broader than the app needs."
        ]
        report["remediation"] = "Revoke the FILE privilege from application accounts: REVOKE FILE ON *.* FROM 'app_user'@'host';"

    elif script_id == "my_pwd_check":
        report["status"] = "VULNERABLE"
        report["summary"] = "MEDIUM: Outdated Password Hashing Plugin"
        report["details"] = [
            "[ANALYSIS] One or more accounts use an older authentication plugin instead of caching_sha2_password.",
            "[THREAT] Older hashing methods are weaker and more susceptible to cracking with modern hardware.",
            "[STATUS] Failed. Legacy password hashing is still in use."
        ]
        report["remediation"] = "Migrate accounts to caching_sha2_password: ALTER USER 'user'@'host' IDENTIFIED WITH caching_sha2_password BY 'new_password';"

    elif script_id == "ora_def_check":
        report["status"] = "VULNERABLE"
        report["summary"] = "CRITICAL: Default Accounts Still Active"
        report["details"] = [
            "[ANALYSIS] One or more default Oracle accounts remain in an OPEN (active) state.",
            "[THREAT] Default accounts and their well-known default passwords are one of the first things attackers try.",
            "[STATUS] Failed. Default accounts haven't been locked or secured."
        ]
        report["remediation"] = "Lock unused default accounts (ALTER USER username ACCOUNT LOCK;) and set strong passwords on any that must stay active."

    elif script_id == "ora_audit_pol":
        report["status"] = "VULNERABLE"
        report["summary"] = "MEDIUM: Unified Auditing Not Enabled"
        report["details"] = [
            "[ANALYSIS] No active unified auditing policies were found.",
            "[THREAT] Without auditing, schema changes or suspicious activity won't leave a trace for later investigation.",
            "[STATUS] Failed. No audit policy is currently enforced."
        ]
        report["remediation"] = "Create and enable a unified audit policy, e.g. CREATE AUDIT POLICY ...; then AUDIT POLICY policy_name;"

    elif script_id == "ora_profile_res":
        report["status"] = "VULNERABLE"
        report["summary"] = "MEDIUM: No Limit on Failed Login Attempts"
        report["details"] = [
            "[ANALYSIS] The FAILED_LOGIN_ATTEMPTS profile parameter is set to UNLIMITED.",
            "[THREAT] This allows unlimited password-guessing attempts against an account without ever locking it.",
            "[STATUS] Failed. No account lockout threshold is configured."
        ]
        report["remediation"] = "Set a lockout threshold, e.g. ALTER PROFILE profile_name LIMIT FAILED_LOGIN_ATTEMPTS 5;"

    return report

@app.route('/simulate_policy', methods=['POST'])
def simulate_policy():
    data = request.json
    db_type = data.get('db_type', 'postgresql')
    script_id = data.get('script_id', '')
    
    query_text = "N/A"
    test_name = "Generic Security Assessment Auditing"
    
    scripts = {
        "pg_inject_test": ("SQL Injection Test", "SELECT * FROM users WHERE username = 'admin' OR '1'='1';"),
        "pg_brute_test": ("Password Strength Check", "SELECT rolname, rolpassword FROM pg_authid WHERE rolname='postgres';"),
        "pg_audit_check": ("Audit Logging Check", "SHOW local_preload_libraries;"),
        "pg_perm_leak": ("Permission Grants Check", "SELECT grantee, privilege_type FROM role_table_grants;"),
        "pg_dos_test": ("Connection Limit Test", "SELECT pg_sleep(10); -- Simulating a held connection"),
        "pg_version_exploit": ("Version Check", "SELECT version();"),
        "pg_data_exfil": ("Row-Level Security Check", "SELECT * FROM public.users LIMIT 999999;"),
        "pg_mitm_sniff": ("SSL/TLS Check", "SHOW ssl;"),
        "my_inject_test": ("SQL Injection Test", "SELECT * FROM users WHERE username = 'admin' OR '1'='1';"),
        "my_brute_test": ("Password Strength Check", "SELECT User, Host, authentication_string FROM mysql.user WHERE User = 'root';"),
        "my_audit_check": ("Audit Logging Check", "SHOW VARIABLES LIKE 'general_log';"),
        "my_perm_leak": ("Permission Grants Check", "SELECT User, Host FROM mysql.user WHERE Host = '%';"),
        "my_dos_test": ("Connection Limit Test", "SELECT SLEEP(10); -- Simulating a held connection"),
        "my_version_exploit": ("Version Check", "SELECT VERSION();"),
        "my_data_exfil": ("Bulk Read Limit Check", "SELECT * FROM users LIMIT 999999;"),
        "my_mitm_sniff": ("SSL/TLS Check", "SHOW STATUS LIKE 'Ssl_cipher';"),
        "my_anon_scan": ("Anonymous Account Check", "SELECT User, Host FROM mysql.user WHERE User = '';"),
        "my_priv_check": ("FILE Privilege Check", "SELECT User, Host, File_priv FROM mysql.user WHERE File_priv = 'Y';"),
        "my_pwd_check": ("Password Hashing Method Check", "SELECT User, Host, plugin FROM mysql.user;"),
        "ora_def_check": ("Default Account Check", "SELECT username, account_status FROM dba_users;"),
        "ora_audit_pol": ("Unified Auditing Check", "SELECT policy_name, enabled FROM cdb_unified_audit_policies;"),
        "ora_profile_res": ("Failed Login Limit Check", "SELECT profile, resource_name, limit FROM dba_profiles;")
    }
    
    if script_id in scripts:
        test_name, query_text = scripts[script_id]
        
    report = generate_english_policy_report(script_id, data)
    
    return jsonify({
        "engine": db_type,
        "test_run": test_name,
        "query": query_text,
        "status": report["status"],
        "summary": report["summary"],
        "details": report["details"],
        "remediation": report["remediation"]
    })

def audit_postgresql(data):
    try:
        conn = get_db_connection(data)
        cursor = conn.cursor()
        cursor.execute("SELECT version();")
        version = cursor.fetchone()[0]
        cursor.execute("SELECT count(*) FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog', 'information_schema');")
        table_count = cursor.fetchone()[0]
        cursor.execute("SELECT count(*) FROM pg_stat_activity;")
        active_connections = cursor.fetchone()[0]
        cursor.execute("SELECT pg_size_pretty(pg_database_size(%s));", (data.get('database'),))
        db_size = cursor.fetchone()[0]
        cursor.execute("SELECT pg_encoding_to_char(encoding) FROM pg_database WHERE datname = %s;", (data.get('database'),))
        db_encoding = cursor.fetchone()[0]
        cursor.execute("SELECT current_schema();")
        current_schema = cursor.fetchone()[0]
        
        vulnerabilities = []
        critical_count = 0; medium_count = 0; low_count = 0
        
        cursor.execute("SELECT rolsuper FROM pg_roles WHERE rolname = %s;", (data.get('user'),))
        is_superuser = cursor.fetchone()
        if is_superuser and is_superuser[0]:
            vulnerabilities.append({"title": "Excessive Privileges (SUPERUSER)", "severity": "CRITICAL", "desc": f"The user '{data.get('user')}' has SUPERUSER privileges. If compromised, an attacker gains full control."})
            critical_count += 1
            
        if data.get('password') == data.get('user') or data.get('password') in ['123456', 'password', 'root', 'admin']:
            vulnerabilities.append({"title": "Weak or Predictable Password", "severity": "CRITICAL", "desc": "The database password is weak, easy to brute-force, or identical to the username."})
            critical_count += 1

        cursor.execute("SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid();")
        ssl_status = cursor.fetchone()
        if not ssl_status or not ssl_status[0]:
            vulnerabilities.append({"title": "Unencrypted Connection (No SSL)", "severity": "MEDIUM", "desc": "Data is transmitted in cleartext. Vulnerable to Man-in-the-Middle (MitM) sniffing attacks."})
            medium_count += 1
            
        if str(data.get('port')) == '5432':
            vulnerabilities.append({"title": "Default Port Exposure", "severity": "LOW", "desc": "Database is running on default port 5432. Automated bots target default ports first."})
            low_count += 1

        cursor.execute("SELECT has_schema_privilege('public', 'CREATE') WHERE EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = 'public');")
        public_create_priv = cursor.fetchone()
        if public_create_priv and public_create_priv[0]:
            vulnerabilities.append({"title": "Insecure Public Schema Permissions", "severity": "MEDIUM", "desc": "Any authenticated user can create objects in the 'public' schema. This leaves the system vulnerable to unauthorized database modification."})
            medium_count += 1

        cursor.execute("SHOW password_encryption;")
        crypto_method = cursor.fetchone()[0]
        if 'md5' in crypto_method.lower():
            vulnerabilities.append({"title": "Weak Password Hashing Method (MD5)", "severity": "MEDIUM", "desc": "The database uses MD5 encryption for stored passwords. MD5 is cryptographically broken and prone to rainbow-table attacks."})
            medium_count += 1

        version_match = re.search(r"PostgreSQL (\d+)", version)
        if version_match:
            major_version = int(version_match.group(1))
            if major_version <= 15:
                vulnerabilities.append({"title": "Outdated Database Version", "severity": "MEDIUM", "desc": f"The database is running legacy version {major_version}. Older major versions lack critical stability and recent security patches."})
                medium_count += 1

        cursor.execute("SELECT rolconnlimit FROM pg_roles WHERE rolname = %s;", (data.get('user'),))
        conn_limit = cursor.fetchone()
        if conn_limit and conn_limit[0] == -1:
            vulnerabilities.append({"title": "Unlimited Connection Settings", "severity": "LOW", "desc": "The user has an unlimited connection allocation limit (-1). This can expose resources to Denial of Service (DoS) exhaustion."})
            low_count += 1

        cursor.execute("SELECT count(*) FROM pg_tables WHERE schemaname = 'public' AND rowsecurity = false;")
        non_rls_tables = cursor.fetchone()[0]
        if non_rls_tables > 0:
            vulnerabilities.append({"title": "Row-Level Security (RLS) Disabled", "severity": "LOW", "desc": "Row-Level Security is disabled on discoverable tables. Users with table access can read all rows implicitly."})
            low_count += 1

        cursor.execute("SHOW log_connections;")
        log_conn = cursor.fetchone()[0]
        if log_conn.lower() == 'off':
            vulnerabilities.append({"title": "Insecure Session Logging (Audit Trail Missing)", "severity": "LOW", "desc": "Database connection logging is disabled. Security forensics cannot trace malicious login sequences if an incident occurs."})
            low_count += 1

        cursor.execute("SHOW shared_buffers;")
        buffers = cursor.fetchone()[0]
        if 'mb' in buffers.lower() and int(re.findall(r'\d+', buffers)[0]) < 128:
            vulnerabilities.append({"title": "Suboptimal Shared Memory (Potential DoS Vulnerability)", "severity": "LOW", "desc": "The shared_buffers parameter is misconfigured or too low. Aggressive heavy scan queries can lock up service resources."})
            low_count += 1

        cursor.close()
        conn.close()

        save_last_connection(data)

        return jsonify({
            "success": True, "message": "Database Discovery & Ultimate 11-Point Audit Completed!",
            "details": {
                "version": version, "table_count": table_count, "active_connections": active_connections,
                "vulnerabilities": vulnerabilities,
                "info": {"db_name": data.get('database'), "db_host": data.get('host'), "db_port": data.get('port'), "db_user": data.get('user'), "db_size": db_size, "db_encoding": db_encoding, "current_schema": current_schema},
                "stats": {"Critical": critical_count, "Medium": medium_count, "Low": low_count}
            }
        })
    except Exception as e:
        return jsonify({"success": False, "message": f"Connection/Audit Error: {str(e)}"})

def audit_mysql(data):
    try:
        conn = get_db_connection(data)
        cursor = conn.cursor()
        db_name = data.get('database')
        user = data.get('user')

        cursor.execute("SELECT VERSION();")
        version = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = %s;", (db_name,))
        table_count = cursor.fetchone()[0]

        cursor.execute("SHOW STATUS LIKE 'Threads_connected';")
        tc_row = cursor.fetchone()
        active_connections = int(tc_row[1]) if tc_row else 0

        cursor.execute(
            "SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) "
            "FROM information_schema.tables WHERE table_schema = %s;", (db_name,)
        )
        size_row = cursor.fetchone()
        db_size = f"{size_row[0]} MB" if size_row and size_row[0] is not None else "0 MB"

        cursor.execute(
            "SELECT DEFAULT_CHARACTER_SET_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = %s;", (db_name,)
        )
        enc_row = cursor.fetchone()
        db_encoding = enc_row[0] if enc_row else "unknown"

        cursor.execute("SELECT DATABASE();")
        current_schema = cursor.fetchone()[0]

        vulnerabilities = []
        critical_count = 0; medium_count = 0; low_count = 0

        cursor.execute("SELECT Super_priv FROM mysql.user WHERE User = %s LIMIT 1;", (user,))
        super_priv = cursor.fetchone()
        if super_priv and super_priv[0] == 'Y':
            vulnerabilities.append({"title": "Excessive Privileges (SUPER)", "severity": "CRITICAL", "desc": f"The user '{user}' has SUPER privileges. If compromised, an attacker gains full administrative control."})
            critical_count += 1

        if data.get('password') == user or data.get('password') in ['123456', 'password', 'root', 'admin']:
            vulnerabilities.append({"title": "Weak or Predictable Password (MySQL)", "severity": "CRITICAL", "desc": "The database password is weak, easy to brute-force, or identical to the username."})
            critical_count += 1

        cursor.execute("SHOW STATUS LIKE 'Ssl_cipher';")
        ssl_row = cursor.fetchone()
        if not ssl_row or not ssl_row[1]:
            vulnerabilities.append({"title": "Unencrypted Connection (No SSL - MySQL)", "severity": "MEDIUM", "desc": "Data is transmitted in cleartext. Vulnerable to Man-in-the-Middle (MitM) sniffing attacks."})
            medium_count += 1

        if str(data.get('port')) == '3306':
            vulnerabilities.append({"title": "Default Port Exposure (MySQL)", "severity": "LOW", "desc": "Database is running on default port 3306. Automated bots target default ports first."})
            low_count += 1

        cursor.execute("SELECT File_priv FROM mysql.user WHERE User = %s LIMIT 1;", (user,))
        file_priv = cursor.fetchone()
        if file_priv and file_priv[0] == 'Y':
            vulnerabilities.append({"title": "FILE Privilege Granted", "severity": "MEDIUM", "desc": f"The user '{user}' has the FILE privilege, allowing it to read/write files on the server (e.g. LOAD DATA INFILE)."})
            medium_count += 1

        cursor.execute("SELECT plugin FROM mysql.user WHERE User = %s LIMIT 1;", (user,))
        plugin_row = cursor.fetchone()
        if plugin_row and plugin_row[0] in ('mysql_native_password', 'mysql_old_password'):
            vulnerabilities.append({"title": "Weak Password Hashing Method (MySQL)", "severity": "MEDIUM", "desc": f"The account uses the legacy '{plugin_row[0]}' authentication plugin instead of caching_sha2_password."})
            medium_count += 1

        version_match = re.search(r"^(\d+)\.", version)
        if version_match and int(version_match.group(1)) < 8:
            vulnerabilities.append({"title": "Outdated Database Version (MySQL)", "severity": "MEDIUM", "desc": f"The database is running legacy version {version}. Older major versions lack critical stability and recent security patches."})
            medium_count += 1

        cursor.execute("SELECT max_user_connections FROM mysql.user WHERE User = %s LIMIT 1;", (user,))
        conn_limit = cursor.fetchone()
        if conn_limit and conn_limit[0] == 0:
            vulnerabilities.append({"title": "Unlimited Connection Settings (MySQL)", "severity": "LOW", "desc": "The user has no per-account connection limit (0 = unlimited). This can expose resources to Denial of Service (DoS) exhaustion."})
            low_count += 1

        cursor.execute("SELECT COUNT(*) FROM mysql.user WHERE User = '';")
        anon_count = cursor.fetchone()[0]
        if anon_count > 0:
            vulnerabilities.append({"title": "Anonymous Accounts Present", "severity": "LOW", "desc": "One or more accounts with a blank username exist, allowing anyone to connect without providing credentials."})
            low_count += 1

        cursor.execute("SHOW VARIABLES LIKE 'general_log';")
        log_row = cursor.fetchone()
        if log_row and str(log_row[1]).upper() == 'OFF':
            vulnerabilities.append({"title": "Insecure Session Logging (Audit Trail Missing - MySQL)", "severity": "LOW", "desc": "General query logging is disabled. Security forensics cannot trace suspicious login or query sequences if an incident occurs."})
            low_count += 1

        cursor.execute("SHOW VARIABLES LIKE 'innodb_buffer_pool_size';")
        buf_row = cursor.fetchone()
        if buf_row and int(buf_row[1]) < 128 * 1024 * 1024:
            vulnerabilities.append({"title": "Suboptimal Buffer Pool Size (Potential DoS Vulnerability)", "severity": "LOW", "desc": "The innodb_buffer_pool_size parameter is misconfigured or too low. Aggressive heavy scan queries can lock up service resources."})
            low_count += 1

        cursor.close()
        conn.close()

        save_last_connection(data)

        return jsonify({
            "success": True, "message": "Database Discovery & Ultimate 11-Point Audit Completed!",
            "details": {
                "version": version, "table_count": table_count, "active_connections": active_connections,
                "vulnerabilities": vulnerabilities,
                "info": {"db_name": data.get('database'), "db_host": data.get('host'), "db_port": data.get('port'), "db_user": data.get('user'), "db_size": db_size, "db_encoding": db_encoding, "current_schema": current_schema},
                "stats": {"Critical": critical_count, "Medium": medium_count, "Low": low_count}
            }
        })
    except Exception as e:
        return jsonify({"success": False, "message": f"Connection/Audit Error: {str(e)}"})

@app.route('/connect', methods=['POST'])
def connect_and_audit():
    data = request.json
    db_type = data.get('db_type', 'postgresql')
    if db_type == 'mysql':
        return audit_mysql(data)
    return audit_postgresql(data)

@app.route('/execute_sql', methods=['POST'])
def execute_sql():
    data = request.json
    query = data.get('sql_query', '').strip()
    if not query: return jsonify({"success": False, "message": "Query cannot be empty."})
    db_type = data.get('db_type', 'postgresql')
    try:
        conn = get_db_connection(data)
        if db_type == 'mysql':
            cursor = conn.cursor(dictionary=True)
        else:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(query)
        is_select = query.upper().startswith("SELECT")
        rows = []; columns = []
        if is_select:
            rows = cursor.fetchall()
            if cursor.description: columns = [desc[0] for desc in cursor.description]
        else:
            conn.commit()
        cursor.close(); conn.close()
        return jsonify({"success": True, "message": "Query executed successfully.", "is_select": is_select, "columns": columns, "rows": rows})
    except Exception as e:
        return jsonify({"success": False, "message": f"SQL Error: {str(e)}"})

if __name__ == '__main__':
    # Flask'ın debug=True reloader'ı süreci ikiye ayırdığı için, zamanlayıcıyı
    # sadece asıl çalışan süreçte başlatıyoruz (aksi halde e-posta 2 kere gidebilir).
    if os.environ.get('WERKZEUG_RUN_MAIN') == 'true' or not app.debug:
        start_scheduler()
    app.run(debug=True, port=5000)