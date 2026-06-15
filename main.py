import os
import json
import re
import time
import datetime
import logging
import requests  # noqa: F811
from typing import List, Optional
from fastapi import FastAPI, Request, Query, BackgroundTasks, HTTPException
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import database
import crawler

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

OP_ENDPOINT = "https://opencode.ai/zen/go/v1/chat/completions"
MODEL_ID = "deepseek-v4-flash"


def _load_api_key():
    cfgs = ["/opt/cve/config.conf", os.path.join(os.path.dirname(__file__), "config.conf")]
    for p in cfgs:
        if os.path.exists(p):
            with open(p) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("OPENCODE_API_KEY="):
                        return line.split("=", 1)[1].strip()
    return os.getenv("OPENCODE_API_KEY", "")


OP_KEY = _load_api_key()
if not OP_KEY:
    logger.warning("OPENCODE_API_KEY not found in config.conf or env — AI enrichment disabled")

app = FastAPI(
    title="CVE Monitor & Filtering Engine",
    description="Backend API and web UI serving CVE analytics for core firewall vendors",
    version="1.0.0"
)

# --- SECURITY: Rate Limiting Middleware ---
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 60     # requests per minute per IP
ip_history = {}

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    if request.url.path.startswith("/static"):
        return await call_next(request)
        
    now = time.time()
    timestamps = ip_history.get(client_ip, [])
    timestamps = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]
    ip_history[client_ip] = timestamps
    
    if len(timestamps) >= RATE_LIMIT_MAX:
        logger.warning("Rate limit exceeded for IP: %s on path: %s", client_ip, request.url.path)
        return JSONResponse(
            status_code=429,
            content={"detail": "Too many requests. Please wait before trying again."}
        )
        
    ip_history[client_ip].append(now)
    return await call_next(request)

# --- UTILS: Robust Semantic Version Matching ---
def parse_version(v_str: str) -> List[int]:
    if not v_str:
        return []
    v_clean = v_str.upper().replace("R", "")
    parts = re.findall(r"\d+", v_clean)
    return [int(p) for p in parts]

def version_compare(v1_parts: List[int], v2_parts: List[int]) -> int:
    max_len = max(len(v1_parts), len(v2_parts))
    v1_padded = v1_parts + [0] * (max_len - len(v1_parts))
    v2_padded = v2_parts + [0] * (max_len - len(v2_parts))
    
    for p1, p2 in zip(v1_padded, v2_padded):
        if p1 < p2:
            return -1
        elif p1 > p2:
            return 1
    return 0

def is_version_impacted(target_version: str, impacted_json: dict) -> bool:
    target_parts = parse_version(target_version)
    if not target_parts:
        return False
        
    min_str = impacted_json.get("min")
    max_str = impacted_json.get("max")
    fixed_str = impacted_json.get("fixed")
    min_parts = []
    
    if min_str:
        min_parts = parse_version(min_str)
        if min_parts:
            # Compare only overlapping parts — a major release like 7.4
            # covers all 7.4.x sub-versions, not just 7.4.0
            olap = min(len(target_parts), len(min_parts))
            if target_parts[:olap] < min_parts[:olap]:
                return False
            
    if fixed_str:
        fixed_parts = parse_version(fixed_str)
        if version_compare(target_parts, fixed_parts) >= 0:
            return False
            
    if max_str:
        max_parts = parse_version(max_str)
        if max_parts:
            if min_parts and version_compare(min_parts, max_parts) > 0:
                pass
            else:
                olap = min(len(target_parts), len(max_parts))
                if target_parts[:olap] > max_parts[:olap]:
                    return False
            
    return True

VENDOR_MAJOR_RELEASES = {
    "fortinet": [
        "FortiOS 7.6", "FortiOS 7.4", "FortiOS 7.2", "FortiOS 7.0",
        "FortiManager 7.6", "FortiManager 7.4", "FortiManager 7.2", "FortiManager 7.0",
        "FortiAnalyzer 7.6", "FortiAnalyzer 7.4", "FortiAnalyzer 7.2", "FortiAnalyzer 7.0",
        "FortiProxy 7.6", "FortiProxy 7.4", "FortiProxy 7.2", "FortiProxy 7.0",
        "FortiWeb 7.6", "FortiWeb 7.4", "FortiWeb 7.2",
        "FortiClientEMS 7.4", "FortiClientEMS 7.2",
        "FortiAuthenticator 8.0",
        "FortiSwitch 7.6", "FortiSwitch 7.4", "FortiSwitch 7.2",
        "FortiAP 7.6", "FortiAP 7.4", "FortiAP 7.2",
        "FortiNDR 7.4", "FortiNDR 7.2",
        "FortiMail 7.6", "FortiMail 7.4",
        "FortiVoice 7.2", "FortiVoice 7.0",
        "FortiSOAR 7.6", "FortiSOAR 7.4",
    ],
    "checkpoint": [
        "Gaia OS R82.10", "Gaia OS R82", "Gaia OS R81.20",
        "Gaia OS R81.10", "Gaia OS R81", "Gaia OS R80.40",
        "Gaia OS R80.30", "Gaia OS R80.20", "Gaia OS R80.10", "Gaia OS R80",
    ],
    "paloalto": [
        "PAN-OS 12.1", "PAN-OS 11.2", "PAN-OS 11.1", "PAN-OS 11.0",
        "PAN-OS 10.2", "PAN-OS 10.1", "PAN-OS 10.0", "PAN-OS 9.1", "PAN-OS 9.0", "PAN-OS 8.1",
        "GlobalProtect App 6.3", "GlobalProtect App 6.2",
    ],
    "cisco": [
        "FTD 10.x", "FTD 7.7", "FTD 7.6", "FTD 7.4", "FTD 7.3",
        "FTD 7.2", "FTD 7.1", "FTD 7.0", "FTD 6.7", "FTD 6.6",
        "ASA 9.20", "ASA 9.18", "ASA 9.16",
        "ISE 3.4", "ISE 3.3",
    ],
}

def get_impacted_releases(cve_record: dict) -> List[str]:
    import json
    vendor = cve_record.get("vendor", "")
    impacted_json = cve_record.get("impacted_versions", {})
    if isinstance(impacted_json, str):
        try:
            impacted_json = json.loads(impacted_json)
        except Exception:
            impacted_json = {}
            
    # If no version data at all (min/max/fixed all null/None), return empty
    if not impacted_json.get("min") and not impacted_json.get("max") and not impacted_json.get("fixed"):
        return []

    all_releases = VENDOR_MAJOR_RELEASES.get(vendor, [])
    impacted_list = []
    
    for release in all_releases:
        rel_clean = (
            release.replace("FortiOS ", "")
            .replace("FortiManager ", "")
            .replace("FortiAnalyzer ", "")
            .replace("FortiProxy ", "")
            .replace("FortiWeb ", "")
            .replace("FortiClientEMS ", "")
            .replace("FortiSandbox ", "")
            .replace("FortiAuthenticator ", "")
            .replace("FortiSwitch ", "")
            .replace("FortiAP ", "")
            .replace("FortiNDR ", "")
            .replace("FortiMail ", "")
            .replace("FortiVoice ", "")
            .replace("FortiSOAR ", "")
            .replace("Gaia OS ", "")
            .replace("PAN-OS ", "")
            .replace("GlobalProtect App ", "")
            .replace("FTD ", "")
            .replace("ASA ", "")
            .replace("SD-WAN ", "")
            .replace("ISE ", "")
            .replace(".x", ".0")
        )
        if is_version_impacted(rel_clean, impacted_json):
            impacted_list.append(release)
                
    return impacted_list

# --- API ENDPOINTS ---

class CVESchema(BaseModel):
    cve_id: str
    vendor: str
    product: str
    cvss_score: float
    severity: str
    publish_date: str
    summary: str
    impacted_versions: dict
    conditions: List[str]
    remediation: str
    sources: List[dict]
    impacted_releases: List[str]
    epss_score: float
    internet_scanning_active: int
    public_poc_exists: int
    malware_families: List[str]
    first_seen_at: Optional[str] = None


@app.get("/api/cves", response_model=List[CVESchema])
async def get_cves(
    vendor: Optional[List[str]] = Query(None),
    product: Optional[List[str]] = Query(None),
    condition: Optional[List[str]] = Query(None),
    search: Optional[str] = Query(None),
):
    """
    Fetches and filters CVEs by vendor, product, and search query.
    """
    try:
        cve_records = database.query_cves(
            vendors=vendor, 
            conditions=None,
            search_query=search
        )

        # Filter by product if specified
        if product:
            cve_records = [c for c in cve_records if c.get("product", "") in product]
            
        for cve in cve_records:
            cve["impacted_releases"] = get_impacted_releases(cve)
            
        return cve_records
    except Exception as e:
        logger.error("Database query failed: %s", str(e))
        raise HTTPException(
            status_code=500, 
            detail="An error occurred while fetching CVE records."
        )

@app.get("/api/cves/{cve_id}/validation")
async def get_cve_validation(cve_id: str):
    """
    Fetches the multi-pass validation log for a specific CVE ID.
    """
    try:
        log = database.get_validation_log(cve_id)
        if not log:
            raise HTTPException(
                status_code=404,
                detail=f"Validation log not found for CVE {cve_id}."
            )
        return log
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to fetch validation log for %s: %s", cve_id, str(e))
        raise HTTPException(
            status_code=500,
            detail="An error occurred while fetching the validation audit trace."
        )

@app.get("/api/status")
async def get_status():
    try:
        last_sync = database.get_last_sync_status()
        if not last_sync:
            return {
                "last_sync": "Never",
                "status": "No runs recorded",
                "records_parsed": 0,
                "next_sync_in": "4h 00m"
            }
            
        time_str = last_sync["last_success_run"].replace(" UTC", "")
        last_dt = datetime.datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
        
        next_dt = last_dt + datetime.timedelta(hours=4)
        now_dt = datetime.datetime.utcnow()
        
        remaining = next_dt - now_dt
        if remaining.total_seconds() <= 0:
            remaining_str = "Scheduled now"
        else:
            hours, remainder = divmod(int(remaining.total_seconds()), 3600)
            minutes, _ = divmod(remainder, 60)
            remaining_str = f"{hours}h {minutes}m"
            
        return {
            "last_sync": last_sync["last_success_run"],
            "status": last_sync["status"],
            "records_parsed": last_sync["records_parsed"],
            "next_sync_in": remaining_str
        }
    except Exception as e:
        logger.error("Failed to read system status: %s", str(e))
        raise HTTPException(
            status_code=500,
            detail="Could not retrieve system synchronization status."
        )

def run_sync_task():
    try:
        crawler.run_crawler()
    except Exception as e:
        logger.error("Background sync task failed: %s", str(e))

@app.post("/api/sync")
async def trigger_sync(background_tasks: BackgroundTasks):
    background_tasks.add_task(run_sync_task)
    return {"message": "Database synchronization triggered in the background."}

CONDITION_LABELS = {
    "pre_auth_exploit": "Pre-Authentication Exploit",
    "post_auth_required": "Post-Authentication Required",
    "mgmt_interface_exposed": "Management exposed",
    "api_enabled": "API / Automation Enabled",
    "telemetry_active": "Telemetry & Analytics Active",
    "ssl_vpn_enabled": "SSL VPN Enabled",
    "captive_portal_active": "Captive Portal Active",
    "ike_v2_processing": "IKEv2 VPN Active",
    "saml_sso_configured": "SAML SSO Configured",
    "ssl_decryption_active": "SSL/TLS Decryption Active",
    "ips_enabled": "IPS / Threat Prevention Enabled",
    "file_inspection_active": "File Inspection / Sandboxing",
    "dynamic_routing_active": "Dynamic Routing Active (BGP/OSPF)",
    "ha_clustering_enabled": "HA Clustering Enabled",
}


def generate_ai_enrichment(cve_record: dict) -> dict:
    if not OP_KEY:
        raise HTTPException(status_code=503, detail="OPENCODE_API_KEY not configured")

    cve_id = cve_record["cve_id"]
    vendor = cve_record.get("vendor", "")
    product = cve_record.get("product", "")
    severity = cve_record.get("severity", "Unknown")
    cvss_score = cve_record.get("cvss_score", 0.0)
    summary = cve_record.get("summary", "")
    impacted = cve_record.get("impacted_versions", {})
    if isinstance(impacted, str):
        try:
            impacted = json.loads(impacted)
        except Exception:
            impacted = {}
    conditions = cve_record.get("conditions", [])
    if isinstance(conditions, str):
        try:
            conditions = json.loads(conditions)
        except Exception:
            conditions = []
    remediation = cve_record.get("remediation", "")
    epss = cve_record.get("epss_score", 0.0)
    internet_active = cve_record.get("internet_scanning_active", 0)
    poc_exists = cve_record.get("public_poc_exists", 0)
    malware = cve_record.get("malware_families", [])
    if isinstance(malware, str):
        try:
            malware = json.loads(malware)
        except Exception:
            malware = []

    needs_severity = severity in ("Unknown", "", None)
    needs_cvss = cvss_score == 0.0
    needs_versions = not impacted.get("min") and not impacted.get("max") and not impacted.get("fixed")
    needs_conditions = not conditions
    needs_remediation = not remediation

    condition_labels = [CONDITION_LABELS.get(c, c) for c in conditions]
    malware_labels = ", ".join(malware) if malware else "none"
    epss_pct = f"{epss * 100:.1f}%" if epss else "unavailable"
    threat_context = []
    if internet_active:
        threat_context.append("Internet-wide scanning detected")
    if poc_exists:
        threat_context.append("Public PoC exists")
    threat_str = "; ".join(threat_context) if threat_context else "No known active exploitation"

    user_prompt = f"""CVE ID: {cve_id}
Vendor: {vendor}
Product: {product}
Severity: {severity}
CVSS Score: {cvss_score}
Summary: {summary}
Impacted Versions (min/max/fixed): {json.dumps(impacted)}
Conditions: {json.dumps(condition_labels) if condition_labels else 'none'}
Remediation: {remediation if remediation else 'none'}
EPSS Score: {epss_pct}
Threat Context: {threat_str}
Associated Threat Groups: {malware_labels}"""

    missing_hints = []
    if needs_severity:
        missing_hints.append("- ai_severity: estimate Critical/High/Medium/Low from the summary text")
    if needs_cvss:
        missing_hints.append("- ai_cvss_score: estimate a float 0.0-10.0 from the vulnerability description")
    if needs_versions:
        missing_hints.append("- ai_impacted_versions: extract version range as {{\"min\":...,\"max\":...,\"fixed\":...}} from the summary if any versions are mentioned")
    if needs_conditions:
        missing_hints.append("- ai_conditions: pick applicable condition keys from this list: [{conds}]".format(conds=", ".join(CONDITION_LABELS.keys())))
    if needs_remediation:
        missing_hints.append("- ai_remediation: suggest patching or mitigation steps based on the vulnerability type")

    missing_block = ""
    if missing_hints:
        missing_block = "\nAdditionally, some fields are missing from this CVE record. Fill ONLY the fields that are missing:\n" + "\n".join(missing_hints)

    system_prompt = f"""You are a cybersecurity CVE analyst engine. Your output must be a single valid JSON object with these fields:

- "ai_summary": A brief 2-3 sentence contextual insight. Do NOT restate the CVSS score, severity label, vendor/product name, affected version numbers, or prerequisite conditions. Instead, explain what this vulnerability actually enables an attacker to do, the real-world impact scenario, or why it's practically significant. Be technical but concise. If the CVE has threat groups associated, mention them and their known attack patterns. If EPSS is high or exploitation is active, emphasize the urgency.

- "ai_severity": STRING or null. Only provide if the original severity is Unknown.
- "ai_cvss_score": NUMBER or null. Only provide if the original CVSS is 0.0.
- "ai_impacted_versions": OBJECT with keys "min", "max", "fixed" or null. Only provide if original is empty.
- "ai_conditions": ARRAY of strings from the condition key list or null. Only provide if original is empty.
- "ai_remediation": STRING or null. Only provide if original remediation is empty.

IMPORTANT: For fields where the original data IS already present, set the value to null — do NOT overwrite good data.
{missing_block}

Return ONLY the JSON object, no other text."""

    payload = {
        "model": MODEL_ID,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.3,
        "max_tokens": 4096,
    }

    headers = {
        "Authorization": f"Bearer {OP_KEY}",
        "Content-Type": "application/json",
    }

    try:
        resp = requests.post(OP_ENDPOINT, json=payload, headers=headers, timeout=45)
        if resp.status_code == 429:
            logger.warning("[%s] OpenCode API rate limited, retrying after 5s...", cve_id)
            time.sleep(5)
            resp = requests.post(OP_ENDPOINT, json=payload, headers=headers, timeout=45)

        if resp.status_code != 200:
            logger.error("[%s] OpenCode API returned %d: %s", cve_id, resp.status_code, resp.text[:500])
            raise HTTPException(status_code=502, detail=f"OpenCode API error: {resp.status_code}")

        raw = resp.json()
        msg = raw.get("choices", [{}])[0].get("message", {})
        content = msg.get("content", "") or msg.get("reasoning_content", "")

        if not content:
            logger.error("[%s] OpenCode returned empty content. Full response: %s",
                         cve_id, json.dumps(raw, indent=2)[:1000])
            raise HTTPException(status_code=502, detail="AI returned empty response")

        if msg.get("reasoning_content") and not msg.get("content"):
            content = content.strip()
            json_match = re.search(r"\{[\s\S]*\}", content)
            if json_match:
                content = json_match.group(0)

        content = content.strip()
        if content.startswith("```"):
            content = re.sub(r"^```\w*\n?", "", content)
            content = re.sub(r"\n?```$", "", content)

        result = None
        for strategy in "json_loads", "largest_json", "first_json":
            try:
                if strategy == "json_loads":
                    result = json.loads(content)
                elif strategy == "largest_json":
                    matches = list(re.finditer(r"\{[\s\S]*?\}", content))
                    if matches:
                        longest = max(matches, key=lambda m: len(m.group(0)))
                        result = json.loads(longest.group(0))
                elif strategy == "first_json":
                    m = re.search(r"\{[\s\S]*?\}", content)
                    if m:
                        result = json.loads(m.group(0))
                if result and isinstance(result, dict) and "ai_summary" in result:
                    break
                result = None
            except Exception:
                pass

        if not result:
            raise json.JSONDecodeError("Could not extract valid JSON from AI response", content, 0)

        result["model_used"] = MODEL_ID
        return result

    except json.JSONDecodeError as e:
        logger.error("[%s] Failed to parse AI response as JSON: %s", cve_id, str(e)[:200])
        raise HTTPException(status_code=502, detail="AI response was not valid JSON")
    except requests.RequestException as e:
        logger.error("[%s] OpenCode API request failed: %s", cve_id, str(e))
        raise HTTPException(status_code=502, detail=f"OpenCode API unreachable: {str(e)}")


@app.get("/api/cves/{cve_id}/enrichment")
async def get_cve_enrichment(cve_id: str):
    try:
        enrichment = database.get_ai_enrichment(cve_id)
        if enrichment:
            return enrichment
        return {"cve_id": cve_id, "enriched": False}
    except Exception as e:
        logger.error("Failed to fetch enrichment for %s: %s", cve_id, str(e))
        raise HTTPException(status_code=500, detail="Failed to fetch enrichment data")


@app.post("/api/cves/{cve_id}/enrich")
async def enrich_single_cve(cve_id: str):
    try:
        all_cves = database.query_cves()
        cve_record = next((c for c in all_cves if c["cve_id"] == cve_id), None)
        if not cve_record:
            raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")

        existing = database.get_ai_enrichment(cve_id)
        if existing and existing.get("ai_summary"):
            return {"cve_id": cve_id, "message": "Already enriched", "enrichment": existing}

        enrichment = generate_ai_enrichment(cve_record)
        database.save_ai_enrichment(cve_id, enrichment)
        logger.info("[%s] AI enrichment generated and saved", cve_id)
        return {"cve_id": cve_id, "enrichment": enrichment, "generated": True}

    except HTTPException:
        raise
    except Exception as e:
        logger.error("[%s] Enrichment failed: %s", cve_id, str(e))
        raise HTTPException(status_code=500, detail=f"Enrichment failed: {str(e)}")


@app.post("/api/enrich/batch")
async def enrich_batch(background_tasks: BackgroundTasks):
    if not OP_KEY:
        raise HTTPException(status_code=503, detail="OPENCODE_API_KEY not configured")

    def _run_batch():
        unenriched = database.get_unenriched_cve_ids()
        total = len(unenriched)
        logger.info("Batch enrichment starting for %d CVEs", total)
        created = 0
        failed = 0

        all_cves = database.query_cves()
        cve_map = {c["cve_id"]: c for c in all_cves}

        batch_size = 5
        for batch_start in range(0, total, batch_size):
            batch = unenriched[batch_start:batch_start + batch_size]
            for cve_id in batch:
                try:
                    cve_record = cve_map.get(cve_id)
                    if not cve_record:
                        logger.warning("[%s] Skipped — not found in DB", cve_id)
                        continue
                    enrichment = generate_ai_enrichment(cve_record)
                    database.save_ai_enrichment(cve_id, enrichment)
                    created += 1
                    logger.info("[%s] Enriched (%d/%d)", cve_id, created + failed, total)
                except Exception as e:
                    failed += 1
                    logger.error("[%s] Enrichment failed: %s", cve_id, str(e))

            if batch_start + len(batch) < total:
                time.sleep(1.5)

        logger.info("Batch enrichment done: %d enriched, %d failed out of %d", created, failed, total)

    background_tasks.add_task(_run_batch)
    unenriched = database.get_unenriched_cve_ids()
    return {
        "message": f"Batch enrichment started for {len(unenriched)} un-enriched CVEs in background",
        "pending_count": len(unenriched),
    }

# --- STATIC FILES ROUTING ---
os.makedirs("/opt/cve/static", exist_ok=True)

@app.get("/")
async def read_index():
    index_path = "/opt/cve/static/index.html"
    if os.path.exists(index_path):
        response = FileResponse(index_path)
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        return response
    return JSONResponse(
        status_code=404,
        content={"message": "Frontend index.html is missing."}
    )

class NoCacheStaticFiles(StaticFiles):
    async def __call__(self, scope, receive, send):
        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = dict(message.get("headers", []))
                headers[b"cache-control"] = b"no-store, no-cache, must-revalidate"
                message["headers"] = list(headers.items())
            await send(message)
        await super().__call__(scope, receive, send_wrapper)

app.mount("/static", NoCacheStaticFiles(directory="/opt/cve/static"), name="static")
