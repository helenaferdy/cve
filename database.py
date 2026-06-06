import sqlite3
import json
import os
import datetime
import logging

DATABASE_PATH = "/opt/cve/cve_monitor.db"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

def get_db_connection():
    """Establishes and returns a connection to the SQLite database."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database and creates the necessary tables if they do not exist."""
    logger.info("Initializing database at %s", DATABASE_PATH)
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create system_sync_log table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS system_sync_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        last_success_run DATETIME NOT NULL,
        status TEXT NOT NULL,
        records_parsed INTEGER NOT NULL
    );
    """)
    
    # Create firewall_cves table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS firewall_cves (
        cve_id TEXT PRIMARY KEY,
        vendor TEXT NOT NULL,
        product TEXT NOT NULL,
        cvss_score REAL NOT NULL,
        severity TEXT NOT NULL,
        publish_date TEXT NOT NULL,
        summary TEXT NOT NULL,
        impacted_versions TEXT NOT NULL,
        conditions TEXT NOT NULL,
        remediation TEXT NOT NULL,
        sources TEXT NOT NULL,
        epss_score REAL DEFAULT 0.0,
        internet_scanning_active INTEGER DEFAULT 0,
        public_poc_exists INTEGER DEFAULT 0,
        malware_families TEXT DEFAULT '[]',
        first_seen_at TEXT DEFAULT NULL
    );
    """)
    
    # Create cve_validation_log table to record multi-pass validation audits
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cve_validation_log (
        cve_id TEXT PRIMARY KEY,
        stage_1_passed INTEGER NOT NULL,
        stage_2_passed INTEGER NOT NULL,
        stage_3_passed INTEGER NOT NULL,
        stage_4_passed INTEGER NOT NULL,
        details TEXT NOT NULL,
        validated_at TEXT NOT NULL
    );
    """)
    
    # Create an index on vendor for faster filtering
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cves_vendor ON firewall_cves(vendor);")

    # Schema migration: add first_seen_at if missing from older databases
    try:
        cursor.execute("ALTER TABLE firewall_cves ADD COLUMN first_seen_at TEXT DEFAULT NULL;")
    except sqlite3.OperationalError:
        pass  # Column already exists

    # Schema migration: add stage_5_passed if missing from older databases
    try:
        cursor.execute("ALTER TABLE cve_validation_log ADD COLUMN stage_5_passed INTEGER DEFAULT 0;")
    except sqlite3.OperationalError:
        pass  # Column already exists

    conn.commit()
    conn.close()
    logger.info("Database initialized successfully.")

def log_system_sync(last_success_run, status, records_parsed):
    """Logs the results of a scraper run in the system_sync_log table."""
    conn = get_db_connection()
    cursor = conn.cursor()
    # TODO(security): Parameterized query ensures complete SQL injection safety
    cursor.execute("""
        INSERT INTO system_sync_log (last_success_run, status, records_parsed)
        VALUES (?, ?, ?);
    """, (last_success_run, status, records_parsed))
    conn.commit()
    conn.close()

def get_last_sync_status():
    """Retrieves the latest record from the system_sync_log table."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT last_success_run, status, records_parsed 
        FROM system_sync_log 
        ORDER BY id DESC LIMIT 1;
    """)
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None

def save_cve(cve_data):
    """Inserts or updates a CVE entry in the database securely using parameterized queries."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Serialize JSON fields if they are passed as dict/list
    impacted_versions_json = (
        json.dumps(cve_data["impacted_versions"])
        if isinstance(cve_data["impacted_versions"], (dict, list))
        else cve_data["impacted_versions"]
    )
    conditions_json = (
        json.dumps(cve_data["conditions"])
        if isinstance(cve_data["conditions"], (dict, list))
        else cve_data["conditions"]
    )
    sources_json = (
        json.dumps(cve_data["sources"])
        if isinstance(cve_data["sources"], (dict, list))
        else cve_data["sources"]
    )
    malware_families_json = (
        json.dumps(cve_data.get("malware_families", []))
        if isinstance(cve_data.get("malware_families", []), (dict, list))
        else cve_data.get("malware_families", "[]")
    )

    # Check if this is a new CVE (for first_seen_at tracking)
    cursor.execute("SELECT cve_id FROM firewall_cves WHERE cve_id = ?;", (cve_data["cve_id"],))
    is_new = cursor.fetchone() is None
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    if is_new:
        cursor.execute("""
            INSERT INTO firewall_cves (
                cve_id, vendor, product, cvss_score, severity,
                publish_date, summary, impacted_versions, conditions, remediation, sources,
                epss_score, internet_scanning_active, public_poc_exists, malware_families,
                first_seen_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            cve_data["cve_id"],
            cve_data["vendor"],
            cve_data["product"],
            cve_data["cvss_score"],
            cve_data["severity"],
            cve_data["publish_date"],
            cve_data["summary"],
            impacted_versions_json,
            conditions_json,
            cve_data["remediation"],
            sources_json,
            cve_data.get("epss_score", 0.0),
            cve_data.get("internet_scanning_active", 0),
            cve_data.get("public_poc_exists", 0),
            malware_families_json,
            now,
        ))
    else:
        cursor.execute("""
            UPDATE firewall_cves SET
                vendor=?, product=?, cvss_score=?, severity=?,
                publish_date=?, summary=?, impacted_versions=?, conditions=?,
                remediation=?, sources=?, epss_score=?,
                internet_scanning_active=?, public_poc_exists=?, malware_families=?
            WHERE cve_id=?;
        """, (
            cve_data["vendor"],
            cve_data["product"],
            cve_data["cvss_score"],
            cve_data["severity"],
            cve_data["publish_date"],
            cve_data["summary"],
            impacted_versions_json,
            conditions_json,
            cve_data["remediation"],
            sources_json,
            cve_data.get("epss_score", 0.0),
            cve_data.get("internet_scanning_active", 0),
            cve_data.get("public_poc_exists", 0),
            malware_families_json,
            cve_data["cve_id"],
        ))

    conn.commit()
    conn.close()

def query_cves(vendors=None, conditions=None, search_query=None):
    """
    Queries CVE entries with optional filters using parameterized statements 
    and built-in SQLite JSON matching for conditions.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = "SELECT * FROM firewall_cves WHERE 1=1"
    params = []
    
    if vendors:
        placeholders = ",".join("?" for _ in vendors)
        query += f" AND vendor IN ({placeholders})"
        params.extend(vendors)
        
    if conditions:
        for cond in conditions:
            # Utilize modern SQLite built-in json_each to check array contents safely
            query += " AND EXISTS (SELECT 1 FROM json_each(conditions) WHERE value = ?)"
            params.append(cond)
            
    if search_query:
        query += " AND (cve_id LIKE ? OR summary LIKE ? OR remediation LIKE ?)"
        like_pattern = f"%{search_query}%"
        params.extend([like_pattern, like_pattern, like_pattern])
        
    query += " ORDER BY cvss_score DESC"
    
    logger.debug("Executing query: %s with params %s", query, params)
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    
    cves = []
    for row in rows:
        cve = dict(row)
        try:
            cve["impacted_versions"] = json.loads(cve["impacted_versions"])
        except Exception:
            pass
        try:
            cve["conditions"] = json.loads(cve["conditions"])
        except Exception:
            pass
        try:
            cve["sources"] = json.loads(cve["sources"])
        except Exception:
            pass
        try:
            cve["malware_families"] = json.loads(cve["malware_families"])
        except Exception:
            cve["malware_families"] = []
        cves.append(cve)
        
    return cves

def save_validation_log(cve_id, s1, s2, s3, s4, s5, details):
    """Saves or updates a validation audit trace log for a CVE securely using parameterized queries."""
    import datetime
    conn = get_db_connection()
    cursor = conn.cursor()
    
    validated_at = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    details_json = json.dumps(details) if isinstance(details, (dict, list)) else details
    
    cursor.execute("""
        INSERT INTO cve_validation_log (
            cve_id, stage_1_passed, stage_2_passed, stage_3_passed, stage_4_passed, stage_5_passed, details, validated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(cve_id) DO UPDATE SET
            stage_1_passed=excluded.stage_1_passed,
            stage_2_passed=excluded.stage_2_passed,
            stage_3_passed=excluded.stage_3_passed,
            stage_4_passed=excluded.stage_4_passed,
            stage_5_passed=excluded.stage_5_passed,
            details=excluded.details,
            validated_at=excluded.validated_at;
    """, (cve_id, int(s1), int(s2), int(s3), int(s4), int(s5), details_json, validated_at))
    conn.commit()
    conn.close()

def get_validation_log(cve_id):
    """Retrieves the validation log details for a given CVE ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cve_validation_log WHERE cve_id = ?;", (cve_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        res = dict(row)
        try:
            res["details"] = json.loads(res["details"])
        except Exception:
            pass
        return res
    return None

if __name__ == "__main__":
    init_db()
