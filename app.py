from flask import Flask, request, jsonify, render_template
import psycopg2
from psycopg2.extras import RealDictCursor
import re

app = Flask(__name__)

def get_db_connection(config):
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

# SIMULATED SECURITY AUDIT LOG DATA GENERATOR
def generate_audit_logs(script_id):
    if script_id == "pg_inject_test":
        return [
            "[CRITICAL] Input pattern query validation failed.",
            "[WARNING] Application layer input sanitizer bypass detected via logical tautology ('1'='1').",
            "[ADVISORY] Enforce parameterized Prepared Statements immediately to remediate SQL Injection risk vectors."
        ]
    elif script_id == "pg_brute_test":
        return [
            "[INFO] Evaluating authentication backend directory policies...",
            "[WARNING] High density dictionary enumeration susceptibility discovered on administrative user accounts.",
            "[ADVISORY] Configure robust account lockout triggers inside pg_hba.conf configuration mappings."
        ]
    elif script_id == "pg_audit_check":
        return [
            "[INFO] Checking local_preload_libraries directive strings...",
            "[CRITICAL] Operational policy audit framework failure: 'pgaudit' module extension is NOT initialized.",
            "[ADVISORY] Append 'pgaudit' under server startup parameters to ensure full structural transaction logging."
        ]
    elif script_id == "pg_perm_leak":
        return [
            "[INFO] Iterating structural privileges on enterprise schemas...",
            "[WARNING] Implicit read grants mapped to non-administrative global standard database identity clusters.",
            "[ADVISORY] Run REVOKE access definitions to restrict target infrastructure access vectors."
        ]
    elif script_id == "my_anon_scan":
        return [
            "[INFO] Auditing default system internal users catalog rows...",
            "[CRITICAL] Active anonymous user account map exposure uncovered (blank string identifier).",
            "[ADVISORY] Drop all legacy empty string accounts using 'DROP USER' operations."
        ]
    elif script_id == "my_priv_check":
        return [
            "[INFO] Validating data extraction payload permissions...",
            "[WARNING] Administrative FILE write flags allocated to web application runtime connector accounts.",
            "[ADVISORY] Disable global structural FILE privileges to prevent arbitrary backdoors initialization."
        ]
    elif script_id == "my_pwd_check":
        return [
            "[INFO] Checking crypt-hashing library configurations...",
            "[WARNING] Found older unhardened password authentication plugins active.",
            "[ADVISORY] Enforce modern 'caching_sha2_password' across all enterprise connections."
        ]
    elif script_id == "ora_def_check":
        return [
            "[INFO] Checking integrity state of dictionary baseline records...",
            "[CRITICAL] Default installation administrative user accounts remain in active configuration states.",
            "[ADVISORY] Lock default schema access parameters and change legacy package keys."
        ]
    elif script_id == "ora_audit_pol":
        return [
            "[INFO] Analyzing target monitoring cluster system tables...",
            "[WARNING] Critical database management events are bypassable under legacy logging rules.",
            "[ADVISORY] Initialize Oracle Unified Auditing control profiles on corporate nodes."
        ]
    elif script_id == "ora_profile_res":
        return [
            "[INFO] Evaluating parameter dictionary baseline policies...",
            "[WARNING] Account lock triggers configured with insecure infinite enumeration flags.",
            "[ADVISORY] Implement strong threshold criteria on FAILED_LOGIN_ATTEMPTS values."
        ]
    return ["[INFO] Evaluation completed. No explicit hardening exceptions caught."]

# NEW ROUTE: POLICY SIMULATION & DEFENSIVE COMPLIANCE AUDIT
@app.route('/simulate_policy', methods=['POST'])
def simulate_policy():
    data = request.json
    db_type = data.get('db_type', 'postgresql')
    script_id = data.get('script_id', '')
    
    # Extract query representation text
    query_text = "N/A"
    test_name = "Generic Compliance Audit"
    
    scripts = {
        "pg_inject_test": ("Simulate SQL Injection Blind Input Testing", "SELECT * FROM users WHERE username = 'admin' OR '1'='1';"),
        "pg_brute_test": ("Analyze Role Authentication Settings", "SELECT rolname, rolpassword FROM pg_authid WHERE rolname='postgres';"),
        "pg_audit_check": ("Audit Framework Trail Activation Status", "SHOW local_preload_libraries;"),
        "pg_perm_leak": ("Check Insecure Object Grants", "SELECT grantee, privilege_type FROM role_table_grants;"),
        "my_anon_scan": ("Simulate Anonymous User Identity Probing", "SELECT User, Host FROM mysql.user WHERE User = '';"),
        "my_priv_check": ("Verify File System Injection Access Privilege", "SELECT User, Host, File_priv FROM mysql.user WHERE File_priv = 'Y';"),
        "my_pwd_check": ("Audit Legacy Authentication Methods", "SELECT User, Host, plugin FROM mysql.user;"),
        "ora_def_check": ("Scan Default Institutional Roles", "SELECT username, account_status FROM dba_users;"),
        "ora_audit_pol": ("Evaluate Active Unified Auditing Configuration Schemes", "SELECT policy_name, enabled FROM cdb_unified_audit_policies;"),
        "ora_profile_res": ("Test Dictionary Connection Exhaustion Policies", "SELECT profile, resource_name, limit FROM dba_profiles;")
    }
    
    if script_id in scripts:
        test_name, query_text = scripts[script_id]
        
    logs = generate_audit_logs(script_id)
    
    return jsonify({
        "engine": db_type,
        "test_run": test_name,
        "query": query_text,
        "logs": logs
    })

# DATABASE CONNECTION & ULTIMATE SECURITY AUDIT ROUTE (11 VULNERABILITIES)
@app.route('/connect', methods=['POST'])
def connect_and_audit():
    data = request.json
    try:
        conn = get_db_connection(data)
        cursor = conn.cursor()
        
        # Metadata Discovery
        cursor.execute("SELECT version();")
        version = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT count(*) FROM information_schema.tables 
            WHERE table_schema NOT IN ('pg_catalog', 'information_schema');
        """)
        table_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT count(*) FROM pg_stat_activity;")
        active_connections = cursor.fetchone()[0]
        
        cursor.execute("SELECT pg_size_pretty(pg_database_size(%s));", (data.get('database'),))
        db_size = cursor.fetchone()[0]
        
        cursor.execute("SELECT pg_encoding_to_char(encoding) FROM pg_database WHERE datname = %s;", (data.get('database'),))
        db_encoding = cursor.fetchone()[0]
        
        cursor.execute("SELECT current_schema();")
        current_schema = cursor.fetchone()[0]
        
        # --- 11 CORE SİBER GÜVENLİK TARAMA DÖNGÜSÜ ---
        vulnerabilities = []
        critical_count = 0
        medium_count = 0
        low_count = 0
        
        # Kontrol 1: SUPERUSER Yetki Kontrolü
        cursor.execute("SELECT rolsuper FROM pg_roles WHERE rolname = %s;", (data.get('user'),))
        is_superuser = cursor.fetchone()
        if is_superuser and is_superuser[0]:
            vulnerabilities.append({
                "title": "Excessive Privileges (SUPERUSER)",
                "severity": "CRITICAL",
                "desc": f"The user '{data.get('user')}' has SUPERUSER privileges. If compromised, an attacker gains full control."
            })
            critical_count += 1
            
        # Kontrol 2: Zayıf Şifre Kontrolü
        if data.get('password') == data.get('user') or data.get('password') in ['123456', 'password', 'root', 'admin']:
            vulnerabilities.append({
                "title": "Weak or Predictable Password",
                "severity": "CRITICAL",
                "desc": "The database password is weak, easy to brute-force, or identical to the username."
            })
            critical_count += 1

        # Kontrol 3: SSL/TLS Şifreleme Durumu
        cursor.execute("SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid();")
        ssl_status = cursor.fetchone()
        if not ssl_status or not ssl_status[0]:
            vulnerabilities.append({
                "title": "Unencrypted Connection (No SSL)",
                "severity": "MEDIUM",
                "desc": "Data is transmitted in cleartext. Vulnerable to Man-in-the-Middle (MitM) sniffing attacks."
            })
            medium_count += 1
            
        # Kontrol 4: Standart Port Kullanımı
        if str(data.get('port')) == '5432':
            vulnerabilities.append({
                "title": "Default Port Exposure",
                "severity": "LOW",
                "desc": "Database is running on default port 5432. Automated bots target default ports first."
            })
            low_count += 1

        # Kontrol 5: Public Şeması İzin Kontrolü
        cursor.execute("""
            SELECT has_schema_privilege('public', 'CREATE') 
            WHERE EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = 'public');
        """)
        public_create_priv = cursor.fetchone()
        if public_create_priv and public_create_priv[0]:
            vulnerabilities.append({
                "title": "Insecure Public Schema Permissions",
                "severity": "MEDIUM",
                "desc": "Any authenticated user can create objects in the 'public' schema. This leaves the system vulnerable to unauthorized database modification."
            })
            medium_count += 1

        # Kontrol 6: Şifre Kriptolama Algoritması Kontrolü
        cursor.execute("SHOW password_encryption;")
        crypto_method = cursor.fetchone()[0]
        if 'md5' in crypto_method.lower():
            vulnerabilities.append({
                "title": "Weak Password Hashing Method (MD5)",
                "severity": "MEDIUM",
                "desc": "The database uses MD5 encryption for stored passwords. MD5 is cryptographically broken and prone to rainbow-table attacks."
            })
            medium_count += 1

        # Kontrol 7: Sürüm Güncelliği Kontrolü (Outdated Version)
        version_match = re.search(r"PostgreSQL (\d+)", version)
        if version_match:
            major_version = int(version_match.group(1))
            if major_version <= 15:
                vulnerabilities.append({
                    "title": "Outdated Database Version",
                    "severity": "MEDIUM",
                    "desc": f"The database is running legacy version {major_version}. Older major versions lack critical stability and recent security patches."
                })
                medium_count += 1

        # Kontrol 8: Sınırsız Bağlantı Limiti Kontrolü
        cursor.execute("SELECT rolconnlimit FROM pg_roles WHERE rolname = %s;", (data.get('user'),))
        conn_limit = cursor.fetchone()
        if conn_limit and conn_limit[0] == -1:
            vulnerabilities.append({
                "title": "Unlimited Connection Settings",
                "severity": "LOW",
                "desc": f"The user '{data.get('user')}' has an unlimited connection allocation limit (-1). This can expose resources to Denial of Service (DoS) exhaustion."
            })
            low_count += 1

        # Kontrol 9: Row-Level Security (RLS) Kontrolü
        cursor.execute("""
            SELECT count(*) FROM pg_tables 
            WHERE schemaname = 'public' AND rowsecurity = false;
        """)
        non_rls_tables = cursor.fetchone()[0]
        if non_rls_tables > 0:
            vulnerabilities.append({
                "title": "Row-Level Security (RLS) Disabled",
                "severity": "LOW",
                "desc": "Row-Level Security is disabled on discoverable tables. Users with table access can read all rows implicitly."
            })
            low_count += 1

        # Kontrol 10: Log Connections Kontrolü (Information Disclosure)
        cursor.execute("SHOW log_connections;")
        log_conn = cursor.fetchone()[0]
        if log_conn.lower() == 'off':
            vulnerabilities.append({
                "title": "Insecure Session Logging (Audit Trail Missing)",
                "severity": "LOW",
                "desc": "Database connection logging is disabled. Security forensics cannot trace malicious login sequences if an incident occurs."
            })
            low_count += 1

        # Kontrol 11: Shared Buffers Bellek Sıkılaştırma Taraması
        cursor.execute("SHOW shared_buffers;")
        buffers = cursor.fetchone()[0]
        if 'mb' in buffers.lower() and int(re.findall(r'\d+', buffers)[0]) < 128:
            vulnerabilities.append({
                "title": "Suboptimal Shared Memory (Potential DoS Vulnerability)",
                "severity": "LOW",
                "desc": "The shared_buffers parameter is misconfigured or too low. Aggressive heavy scan queries can lock up service resources."
            })
            low_count += 1

        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True, 
            "message": "Database Discovery & Ultimate 11-Point Audit Completed!", 
            "details": {
                "version": version,
                "table_count": table_count,
                "active_connections": active_connections,
                "vulnerabilities": vulnerabilities,
                "info": {
                    "db_name": data.get('database'),
                    "db_host": data.get('host'),
                    "db_port": data.get('port'),
                    "db_user": data.get('user'),
                    "db_size": db_size,
                    "db_encoding": db_encoding,
                    "current_schema": current_schema
                },
                "stats": {
                    "Critical": critical_count,
                    "Medium": medium_count,
                    "Low": low_count
                }
            }
        })
    except Exception as e:
        return jsonify({"success": False, "message": f"Connection/Audit Error: {str(e)}"})

# 2. GENERAL SQL EXECUTOR ROUTE
@app.route('/execute_sql', methods=['POST'])
def execute_sql():
    data = request.json
    query = data.get('sql_query', '').strip()
    if not query:
        return jsonify({"success": False, "message": "Query cannot be empty."})
    try:
        conn = get_db_connection(data)
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(query)
        is_select = query.upper().startswith("SELECT")
        rows = []
        columns = []
        if is_select:
            rows = cursor.fetchall()
            if cursor.description:
                columns = [desc[0] for desc in cursor.description]
        else:
            conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"success": True, "message": "Query executed successfully.", "is_select": is_select, "columns": columns, "rows": rows})
    except Exception as e:
        return jsonify({"success": False, "message": f"SQL Error: {str(e)}"})

if __name__ == '__main__':
    app.run(debug=True, port=5000)