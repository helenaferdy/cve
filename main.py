import os
import re
import time
import datetime
import logging
from typing import List, Optional
from fastapi import FastAPI, Request, Query, BackgroundTasks, HTTPException
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import database
import crawler

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

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
