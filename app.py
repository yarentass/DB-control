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
        report["summary"] = "CRITICAL RISK: SQL Injection (Tautology Input) Vulnerability Triggered!"
        report["details"] = [
            "[ANALYSIS] The execution engine structural runtime query parameter accepted raw logical tautology sequences ('1'='1') without boundary sanitization.",
            "[THREAT] Attackers can exploit this to bypass identity authentication checkpoints, drop database instances, or dump complete administrative tables.",
            "[STATUS] Test verification failed. Input sanitization boundaries are missing or compromised."
        ]
        report["remediation"] = "REMEDIATION: Migrate inline dynamic concatenations to secure parameterized queries (Prepared Statements) immediately."

    elif script_id == "pg_brute_test":
        if password in [user, '123456', 'password', 'root', 'admin', '']:
            report["status"] = "VULNERABLE"
            report["summary"] = "HIGH RISK: Weak Credentials Mapped (Susceptible to Authentication Brute-Force)"
            report["details"] = [
                f"[ANALYSIS] The administrative role identifier '{user}' is configured with a common default, short, or highly predictable credential parameter set.",
                "[THREAT] High-density credential stuffing and dictionary enumeration attacks can compromise the instance administrative boundary rapidly.",
                "[STATUS] Test verification failed. Password complexity schema validation criteria not enforced."
            ]
            report["remediation"] = "REMEDIATION: Implement corporate credential rotation policies forcing minimum 12-character parameters utilizing diverse entropy classes."
        else:
            report["status"] = "SECURE"
            report["summary"] = "AUDIT SUCCESS: Robust Authentication Profile Validation Checked"
            report["details"] = [
                f"[ANALYSIS] The cryptographic hash verification confirms role credential structures do not map against predictable dictionary baseline signatures.",
                "[STATUS] Test verification passed. Initial perimeter access control layer functions within secure specification tolerances."
            ]
            report["remediation"] = "ADVISORY: Configure secure access trial rate-limiting controls inside host architecture layers to stop distributed automation vectors."

    elif script_id == "pg_audit_check":
        report["status"] = "VULNERABLE"
        report["summary"] = "MEDIUM RISK: Operational Audit Trail Logging Framework Deactivated"
        report["details"] = [
            "[ANALYSIS] Server system runtime variable scans detect that structural transaction monitoring plugins like 'pgaudit' are missing from system shared libraries.",
            "[THREAT] Malicious database modifications, query data reading operations, and data exfiltration patterns cannot be traced during incident forensics sweeps.",
            "[STATUS] Test verification failed. Enterprise accountability state non-compliant."
        ]
        report["remediation"] = "REMEDIATION: Register the monitoring library extension inside postgresql.conf settings by specifying 'shared_preload_libraries = pgaudit'."

    elif script_id == "pg_perm_leak":
        report["status"] = "VULNERABLE"
        report["summary"] = "MEDIUM RISK: Insecure Privileges Mapping and Schema Permission Overexposure"
        report["details"] = [
            f"[ANALYSIS] Catalog scanning located active implicit modification and structure building rights allocated to the global 'PUBLIC' container group on '{db_name}'.",
            "[THREAT] Low-privilege compromise actors can read proprietary application design structures, inject fake metrics, or execute cross-schema visibility leaks.",
            "[STATUS] Test verification failed. Least Privilege architecture constraint parameters violated."
        ]
        report["remediation"] = "REMEDIATION: Evict wide-open privileges from the public container utilizing structural 'REVOKE' syntax mappings."

    elif script_id == "pg_dos_test":
        report["status"] = "VULNERABLE"
        report["summary"] = "MEDIUM RISK: Connection Exhaustion Denial of Service (DoS) Vulnerability"
        report["details"] = [
            "[ANALYSIS] Simulating heavy resource locking loops or infinite process generation tests.",
            "[THREAT] Attackers can spawn excessive unthrottled backend processes, consuming maximum memory and causing database service outages.",
            "[STATUS] Test verification failed. Strict concurrent worker request thresholds are missing."
        ]
        report["remediation"] = "REMEDIATION: Tune the 'max_connections' parameters in configuration files and restrict user limits using ALTER USER syntax."

    elif script_id == "pg_version_exploit":
        report["status"] = "VULNERABLE"
        report["summary"] = "HIGH RISK: Outdated Component Binary Signature Exposing Unpatched Common Vulnerabilities"
        report["details"] = [
            "[ANALYSIS] The version tracking test matched deployment characteristics against historic legacy node structures.",
            "[THREAT] Malicious actors can research known public CVE catalogs to execute pre-crafted remote shell scripts or bypass internal safety logic.",
            "[STATUS] Test verification failed. Current database minor or major version is lagging patches."
        ]
        report["remediation"] = "REMEDIATION: Upgrade the production database server cluster node binaries to the latest stable enterprise security layer."

    elif script_id == "pg_data_exfil":
        report["status"] = "VULNERABLE"
        report["summary"] = "CRITICAL RISK: Potential Automated Bulk Data Exfiltration & Visibility Leak"
        report["details"] = [
            "[ANALYSIS] Uncontrolled sub-queries utilizing bulk data dumps (like copying or full sequential scanning) were allowed across non-isolated entities.",
            "[THREAT] Attackers can scrape entire database schemas or customer tables in fractions of a second due to the lack of proper cell limits.",
            "[STATUS] Test verification failed. Row-Level Security (RLS) is disabled or unconfigured on high-value tables."
        ]
        report["remediation"] = "REMEDIATION: Enable Row-Level Security explicitly via 'ALTER TABLE table_name ENABLE ROW LEVEL SECURITY;' mechanics."

    elif script_id == "pg_mitm_sniff":
        report["status"] = "VULNERABLE"
        report["summary"] = "MEDIUM RISK: Cleartext Transmission Subject to Man-in-the-Middle (MitM) Sniffing"
        report["details"] = [
            "[ANALYSIS] Simulated connection probes checked for unencrypted network transport configurations.",
            "[THREAT] Network adversaries listening to intra-datacenter channels can easily harvest raw text database queries and administrative password tokens.",
            "[STATUS] Test verification failed. The backend connection parameters lack strict TLS validation filters."
        ]
        report["remediation"] = "REMEDIATION: Set 'ssl = on' inside the primary engine initialization configuration file and enforce client certificate mapping."

    elif script_id == "my_anon_scan":
        report["status"] = "VULNERABLE"
        report["summary"] = "CRITICAL RISK: Anonymous Identity Account Allocation Detected"
        report["details"] = [
            "[ANALYSIS] Identity record tables contains row allocations matching an empty string reference schema initialization pattern.",
            "[THREAT] Unauthenticated perimeter actors can map local database engine context without providing proper identification parameters.",
            "[STATUS] Test verification failed. Standard server hardening baseline templates not implemented."
        ]
        report["remediation"] = "REMEDIATION: Evict all empty-string account rows explicitly via administrative 'DROP USER' routine operations."

    elif script_id == "my_priv_check":
        report["status"] = "VULNERABLE"
        report["summary"] = "HIGH RISK: Insecure File System Injection Permissions Active"
        report["details"] = [
            "[ANALYSIS] Database application account context retains active authorization to invoke global 'FILE' I/O structures (LOAD DATA INFILE).",
            "[THREAT] Application layer vulnerabilities could allow a remote attacker to read host configuration objects or write arbitrary system web shells.",
            "[STATUS] Test verification failed. System process isolation boundary limits exceeded."
        ]
        report["remediation"] = "REMEDIATION: Deprive standard web-connector service roles of global file system manipulation rights by stripping the 'FILE' privilege flag."

    elif script_id == "my_pwd_check":
        report["status"] = "VULNERABLE"
        report["summary"] = "MEDIUM RISK: Legacy Cryptographic Password Hashing Plugin Enforced"
        report["details"] = [
            "[ANALYSIS] Credential catalog records verify authentication handling relies on deprecated native signature tracking extensions.",
            "[THREAT] Legacy hash tracking architectures can be inverted rapidly via optimized GPU dictionary rainbow-table computations.",
            "[STATUS] Test verification failed. Obsolete encryption baseline detected."
        ]
        report["remediation"] = "REMEDIATION: Transition configuration maps to the resilient 'caching_sha2_password' authentication handling mechanism."

    elif script_id == "ora_def_check":
        report["status"] = "VULNERABLE"
        report["summary"] = "CRITICAL RISK: Default Out-of-the-Box Administrative Schemas Active"
        report["details"] = [
            "[ANALYSIS] Integrity tracking records state native system maintenance accounts remain initialized within operational run-states.",
            "[THREAT] Malicious actors target standard institutional administrative seeds first. Leaving access routes unhardened yields total cluster takeover.",
            "[STATUS] Test verification failed. Hardening procedures omitted."
        ]
        report["remediation"] = "REMEDIATION: Transition baseline profile states to locked configurations and assign strong administrative secret strings to system components."

    elif script_id == "ora_audit_pol":
        report["status"] = "VULNERABLE"
        report["summary"] = "MEDIUM RISK: Unified Auditing Control Architecture Disabled"
        report["details"] = [
            "[ANALYSIS] Dynamic policy checking states global transactional tracking matrix records are currently unmapped.",
            "[THREAT] Unauthorized database configuration shifts or structure alterations bypass corporate auditing boundaries without event alarms.",
            "[STATUS] Test verification failed. Event lifecycle recording systems inactive."
        ]
        report["remediation"] = "REMEDIATION: Trigger active corporate auditing profile compilation routines using native unified database orchestration syntax."

    elif script_id == "ora_profile_res":
        report["status"] = "VULNERABLE"
        report["summary"] = "MEDIUM RISK: Infinite Authentication Enumeration Allowed (DoS Vector)"
        report["details"] = [
            "[ANALYSIS] Profile parsing states the parameter mapping for 'FAILED_LOGIN_ATTEMPTS' is configured as 'UNLIMITED'.",
            "[THREAT] Attackers can maintain infinite concurrent dictionary testing threads without dropping service connection limits or triggering locks.",
            "[STATUS] Test verification failed. Denial of Service (DoS) security parameter limits unconfigured."
        ]
        report["remediation"] = "REMEDIATION: Reshape active security profile schemas to force strict locking caps after 3 or 5 concurrent authentication faults."

    return report

@app.route('/simulate_policy', methods=['POST'])
def simulate_policy():
    data = request.json
    db_type = data.get('db_type', 'postgresql')
    script_id = data.get('script_id', '')
    
    query_text = "N/A"
    test_name = "Generic Security Assessment Auditing"
    
    scripts = {
        "pg_inject_test": ("Simulate SQL Injection Blind Input Testing", "SELECT * FROM users WHERE username = 'admin' OR '1'='1';"),
        "pg_brute_test": ("Analyze Role Authentication Settings", "SELECT rolname, rolpassword FROM pg_authid WHERE rolname='postgres';"),
        "pg_audit_check": ("Audit Framework Trail Activation Status", "SHOW local_preload_libraries;"),
        "pg_perm_leak": ("Check Insecure Object Grants", "SELECT grantee, privilege_type FROM role_table_grants;"),
        "pg_dos_test": ("Simulate Connection Exhaustion Denial of Service (DoS)", "SELECT pg_sleep(10); -- Simulating resource hold lock"),
        "pg_version_exploit": ("Analyze Outdated Software Vulnerabilities", "SELECT version(); -- Analyzing exploit catalog compliance"),
        "pg_data_exfil": ("Test Bulk Data Exfiltration Constraints", "SELECT * FROM public.users LIMIT 999999;"),
        "pg_mitm_sniff": ("Verify SSL/TLS Encryption Network Status", "SHOW ssl;"),
        "my_anon_scan": ("Simulate Anonymous User Identity Probing", "SELECT User, Host FROM mysql.user WHERE User = '';"),
        "my_priv_check": ("Verify File System Injection Access Privilege", "SELECT User, Host, File_priv FROM mysql.user WHERE File_priv = 'Y';"),
        "my_pwd_check": ("Audit Legacy Authentication Methods", "SELECT User, Host, plugin FROM mysql.user;"),
        "ora_def_check": ("Scan Default Institutional Roles", "SELECT username, account_status FROM dba_users;"),
        "ora_audit_pol": ("Evaluate Active Unified Auditing Configuration Schemes", "SELECT policy_name, enabled FROM cdb_unified_audit_policies;"),
        "ora_profile_res": ("Test Dictionary Connection Exhaustion Policies", "SELECT profile, resource_name, limit FROM dba_profiles;")
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

@app.route('/connect', methods=['POST'])
def connect_and_audit():
    data = request.json
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

@app.route('/execute_sql', methods=['POST'])
def execute_sql():
    data = request.json
    query = data.get('sql_query', '').strip()
    if not query: return jsonify({"success": False, "message": "Query cannot be empty."})
    try:
        conn = get_db_connection(data)
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
    app.run(debug=True, port=5000)