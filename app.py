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

# 1. DATABASE CONNECTION & ULTIMATE SECURITY AUDIT ROUTE (11 VULNERABILITIES)
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