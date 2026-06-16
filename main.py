import asyncio
import base64
import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

load_dotenv()

API_KEY          = os.getenv("URLSCAN_API_KEY", "")
ANTHROPIC_KEY    = os.getenv("ANTHROPIC_API_KEY", "")
VT_API_KEY       = os.getenv("VT_API_KEY", "")
URLSCAN_BASE     = "https://urlscan.io/api/v1"
ANTHROPIC_BASE   = "https://api.anthropic.com/v1"
VT_BASE          = "https://www.virustotal.com/api/v3"

app          = FastAPI(title="URLScan Phishing Triage")
engine       = create_engine("sqlite:///./scans.db", connect_args={"check_same_thread": False})
Base         = declarative_base()
SessionLocal = sessionmaker(bind=engine)


class ScanRecord(Base):
    __tablename__ = "scans"
    uuid           = Column(String,   primary_key=True)
    url            = Column(String)
    status         = Column(String,   default="pending")
    submitted_at   = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    verdict_score  = Column(Float,    nullable=True)
    verdict_label  = Column(String,   nullable=True)
    screenshot_url = Column(String,   nullable=True)
    result_url     = Column(String,   nullable=True)
    raw_result           = Column(Text,   nullable=True)
    page_domain          = Column(String, nullable=True)
    page_ip              = Column(String, nullable=True)
    original_url         = Column(String, nullable=True)   # pre-sanitization URL
    sanitization_method  = Column(String, nullable=True)   # 'heuristic' | 'hybrid' | None
    sanitization_details = Column(Text,   nullable=True)   # JSON {stripped:[...], kept:[...]}
    # URLScan parsed fields (from raw_result)
    page_title           = Column(String,  nullable=True)
    page_country         = Column(String,  nullable=True)
    page_asn             = Column(String,  nullable=True)
    page_asnname         = Column(String,  nullable=True)
    page_status          = Column(Integer, nullable=True)
    page_redirected      = Column(Boolean, nullable=True)
    tls_issuer           = Column(String,  nullable=True)
    verdict_categories   = Column(Text,    nullable=True)  # JSON list
    gsb_match            = Column(Boolean, nullable=True)
    redirect_count       = Column(Integer, nullable=True)
    # VirusTotal enrichment
    vt_domain_malicious  = Column(Float,  nullable=True)
    vt_domain_total      = Column(Float,  nullable=True)
    vt_domain_reputation = Column(Float,  nullable=True)
    vt_domain_categories = Column(Text,   nullable=True)  # JSON dict
    vt_domain_registrar  = Column(String, nullable=True)
    vt_domain_creation_date = Column(String, nullable=True)
    vt_ip_malicious      = Column(Float,  nullable=True)
    vt_ip_total          = Column(Float,  nullable=True)
    vt_ip_country        = Column(String, nullable=True)
    vt_ip_asn            = Column(String, nullable=True)
    vt_url_malicious     = Column(Float,  nullable=True)
    vt_url_total         = Column(Float,  nullable=True)
    vt_url_threat_names  = Column(Text,   nullable=True)  # JSON list
    vt_raw               = Column(Text,   nullable=True)   # full JSON blob from VT
    # RDAP enrichment
    rdap_registered_at   = Column(String,  nullable=True)
    rdap_expires_at      = Column(String,  nullable=True)
    rdap_registrar       = Column(String,  nullable=True)
    rdap_domain_age_days = Column(Integer, nullable=True)
    rdap_status          = Column(Text,    nullable=True)  # JSON list


Base.metadata.create_all(bind=engine)

# ── Schema migration: add new columns to existing DB ──────────────────────────
_NEW_COLUMNS = [
    ("page_title",              "TEXT"),
    ("page_country",            "TEXT"),
    ("page_asn",                "TEXT"),
    ("page_asnname",            "TEXT"),
    ("page_status",             "INTEGER"),
    ("page_redirected",         "BOOLEAN"),
    ("tls_issuer",              "TEXT"),
    ("verdict_categories",      "TEXT"),
    ("gsb_match",               "BOOLEAN"),
    ("redirect_count",          "INTEGER"),
    ("vt_domain_reputation",    "REAL"),
    ("vt_domain_categories",    "TEXT"),
    ("vt_domain_registrar",     "TEXT"),
    ("vt_domain_creation_date", "TEXT"),
    ("vt_ip_country",           "TEXT"),
    ("vt_ip_asn",               "TEXT"),
    ("vt_url_threat_names",     "TEXT"),
    ("rdap_registered_at",      "TEXT"),
    ("rdap_expires_at",         "TEXT"),
    ("rdap_registrar",          "TEXT"),
    ("rdap_domain_age_days",    "INTEGER"),
    ("rdap_status",             "TEXT"),
]
with engine.connect() as _conn:
    for _col, _type in _NEW_COLUMNS:
        try:
            _conn.execute(
                __import__("sqlalchemy").text(f"ALTER TABLE scans ADD COLUMN {_col} {_type}")
            )
        except Exception:
            pass  # column already exists


# ── URL Sanitization (heuristic + Claude hybrid) ──────────────────────────────

# Param names that are almost always tracking-only
_TRACKING_NAMES = {
    'utm_source','utm_medium','utm_campaign','utm_term','utm_content',
    'fbclid','gclid','msclkid','mc_eid','_ga','_gl',
    'ref','referrer','referral','track','tracking',
    'session','sess','sid','ssid',
    'uid','user_id','userid','u_id',
    'click_id','clickid','yclid','wbraid','gbraid',
    'od','trk','trkid','trking',
}


def _looks_hex(s: str) -> bool:
    return bool(re.fullmatch(r'[0-9a-fA-F]+', s))


def _looks_base64(s: str) -> bool:
    if len(s) < 12:
        return False
    return _decode_base64_blob(s) is not None


def _decode_base64_blob(s: str) -> Optional[bytes]:
    padded = s + '=' * (-len(s) % 4)
    decoders = (base64.b64decode, base64.urlsafe_b64decode)
    for decoder in decoders:
        try:
            decoded = decoder(padded)
            if len(decoded) >= 8:
                return decoded
        except Exception:
            continue
    return None


def _token_char_ratio(value: str, pattern: str) -> float:
    if not value:
        return 0.0
    matches = re.findall(pattern, value)
    total = sum(len(m) for m in matches)
    return total / len(value)


def _review_reason(value: str) -> str:
    if _decode_base64_blob(value):
        return "Encoded token-like value detected"
    if len(value) >= 24 and _token_char_ratio(value, r"[A-Za-z0-9_-]") >= 0.9:
        return "Long opaque token detected"
    if re.fullmatch(r"[0-9.]{7,}", value):
        return "IP-like or numeric identifier"
    return "Parameter purpose is unclear"


def _is_functional_key(key: str) -> bool:
    return key.lower() in {
        "page", "p", "lang", "locale", "view", "tab", "sort", "order",
        "q", "query", "search", "filter", "category", "id", "slug",
        "file", "download", "redirect", "target", "dest",
    }


def _recommended_review_action(key: str, value: str) -> str:
    if _decode_base64_blob(value):
        return "strip"
    if len(value) >= 24 and _token_char_ratio(value, r"[A-Za-z0-9_-]") >= 0.9 and not _is_functional_key(key):
        return "strip"
    if _is_functional_key(key):
        return "keep"
    return "review"


def _heuristic_classify(key: str, value: str) -> str:
    """Returns 'strip', 'keep', or 'ambiguous'."""
    k = key.lower()

    # Known tracking param names
    if k in _TRACKING_NAMES:
        return 'strip'

    # Long hex string (16+ chars) → session / user ID
    if _looks_hex(value) and len(value) >= 16:
        return 'strip'

    # UUID
    if re.fullmatch(
        r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
        value
    ):
        return 'strip'

    # Base64 blob
    if _looks_base64(value):
        return 'strip'

    # Compound value (dot or underscore delimited) containing hex segments
    sub_parts = re.split(r'[._]', value)
    if sum(1 for p in sub_parts if _looks_hex(p) and len(p) >= 8) >= 1:
        return 'strip'

    # Short purely-alphanumeric value → likely routing token, keep
    if len(value) <= 12 and re.fullmatch(r'[a-zA-Z0-9]+', value):
        return 'keep'

    # Contains a year-like pattern → likely campaign code, keep
    if re.search(r'20\d{2}', value):
        return 'keep'

    return 'ambiguous'


async def _claude_classify(url: str, ambiguous: dict) -> dict:
    """Ask Claude to classify ambiguous params."""
    if not ambiguous:
        return {"status": "skipped", "decisions": {}, "error": None}
    if not ANTHROPIC_KEY:
        return {"status": "unavailable", "decisions": {}, "error": "ANTHROPIC_API_KEY is not configured"}

    param_lines = '\n'.join(f'  "{k}": "{v}"' for k, v in ambiguous.items())
    prompt = (
        "You are a security analyst classifying URL query parameters.\n"
        "Determine whether each parameter below is tracking/personally-identifying "
        "or required for page functionality.\n\n"
        f"URL: {url}\n\nAmbiguous parameters:\n{param_lines}\n\n"
        "Respond ONLY with a JSON object mapping each key to \"strip\" or \"keep\".\n"
        "Rules:\n"
        "- strip: session IDs, user IDs, click tokens, analytics identifiers, "
        "encoded personal data, ad-network tokens\n"
        "- keep: page routing, content type, language, pagination, non-personal filters\n"
        "- When uncertain, prefer strip to protect privacy.\n"
        "Output ONLY the JSON object, no markdown fences, no explanation."
    )
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{ANTHROPIC_BASE}/messages",
                headers={
                    "x-api-key": ANTHROPIC_KEY,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-sonnet-4-20250514",
                    "max_tokens": 300,
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
        if resp.status_code == 200:
            text = resp.json()["content"][0]["text"].strip()
            text = re.sub(r'^```(?:json)?\s*|\s*```$', '', text, flags=re.MULTILINE).strip()
            result = json.loads(text)
            return {
                "status": "ok",
                "decisions": {k: result.get(k, 'keep') for k in ambiguous},
                "error": None,
            }
        return {
            "status": "error",
            "decisions": {},
            "error": f"Claude returned HTTP {resp.status_code}",
        }
    except Exception as exc:
        return {"status": "error", "decisions": {}, "error": f"{type(exc).__name__}: {exc}"}


def _build_sanitization_details(
    method: str,
    original_url: str,
    sanitized_url: str,
    strip_params: Dict[str, List[str]],
    keep_params: Dict[str, List[str]],
    review_params: Dict[str, Dict[str, Any]],
    errors: List[str],
) -> Dict[str, Any]:
    decisions: Dict[str, Dict[str, Any]] = {}
    for key, values in strip_params.items():
        decisions[key] = {"action": "strip", "value": values[0] if values else "", "source": method}
    for key, values in keep_params.items():
        decisions[key] = {"action": "keep", "value": values[0] if values else "", "source": method}
    for key, info in review_params.items():
        decisions[key] = info

    return {
        "method": method,
        "original_url": original_url,
        "sanitized_url": sanitized_url,
        "stripped": list(strip_params.keys()),
        "kept": list(keep_params.keys()),
        "review": [
            {
                "key": key,
                "value": info.get("value", ""),
                "reason": info.get("reason", "Parameter purpose is unclear"),
                "recommended_action": info.get("recommended_action", "review"),
                "source": info.get("source", "review"),
            }
            for key, info in review_params.items()
        ],
        "errors": errors,
        "requires_review": bool(review_params),
        "decisions": decisions,
    }


async def sanitize_url(
    url: str,
    manual_keep_params: Optional[List[str]] = None,
    manual_strip_params: Optional[List[str]] = None,
) -> tuple[str, bool, dict]:
    """
    Strip tracking params before submission.
    Handles both standard query strings (?k=v) and fragment-based query
    strings (#?k=v), which are common in phishing redirect URLs.
    Returns (sanitized_url, was_modified, details).
    details = {stripped: [...], kept: [...], method: 'heuristic'|'hybrid'}
    """
    try:
        parsed = urlparse(url)

        # Detect fragment-based query string: url#?param=value or url#param=value
        fragment_query = ""
        fragment_prefix = ""
        if parsed.fragment:
            frag = parsed.fragment
            if frag.startswith("?"):
                fragment_query  = frag[1:]   # strip leading ?
                fragment_prefix = "?"
            elif "=" in frag and not frag.startswith("/"):
                # bare fragment query string without leading ?
                fragment_query  = frag
                fragment_prefix = ""

        # Decide which query string to sanitize
        using_fragment = bool(fragment_query)
        raw_query = fragment_query if using_fragment else parsed.query

        if not raw_query:
            return url, False, {}

        params = parse_qs(raw_query, keep_blank_values=True)
        manual_keep = {p.lower() for p in (manual_keep_params or [])}
        manual_strip = {p.lower() for p in (manual_strip_params or [])}
        if manual_keep & manual_strip:
            conflict = ", ".join(sorted(manual_keep & manual_strip))
            raise ValueError(f"Conflicting manual decisions for: {conflict}")

        strip_params: dict = {}
        keep_params:  dict = {}
        ambiguous:    dict = {}
        review_params: dict = {}
        errors: List[str] = []

        for key, values in params.items():
            val = values[0] if values else ''
            lower_key = key.lower()
            if lower_key in manual_strip:
                strip_params[key] = values
                continue
            if lower_key in manual_keep:
                keep_params[key] = values
                continue
            cls = _heuristic_classify(key, val)
            if cls == 'strip':
                strip_params[key] = values
            elif cls == 'keep':
                keep_params[key] = values
            else:
                ambiguous[key] = val

        method = 'heuristic'

        if ambiguous:
            method = 'hybrid'
            claude_result = await _claude_classify(url, ambiguous)
            if claude_result["status"] == "ok":
                for key, decision in claude_result["decisions"].items():
                    if decision == 'strip':
                        strip_params[key] = params[key]
                    else:
                        keep_params[key] = params[key]
            else:
                if claude_result.get("error"):
                    errors.append(claude_result["error"])
                method = 'manual_review'
                for key, val in ambiguous.items():
                    review_params[key] = {
                        "action": "review",
                        "value": val,
                        "reason": _review_reason(val),
                        "recommended_action": _recommended_review_action(key, val),
                        "source": claude_result["status"],
                    }

        new_query = urlencode(keep_params, doseq=True)

        if using_fragment:
            # Rebuild fragment: restore prefix + remaining params
            new_fragment = (fragment_prefix + new_query) if new_query else ""
            sanitized = urlunparse(parsed._replace(fragment=new_fragment))
        else:
            sanitized = urlunparse(parsed._replace(query=new_query))
        details = _build_sanitization_details(
            method=method,
            original_url=url,
            sanitized_url=sanitized,
            strip_params=strip_params,
            keep_params=keep_params,
            review_params=review_params,
            errors=errors,
        )
        return sanitized, bool(strip_params), details

    except Exception as exc:
        details = {
            "method": "manual_review",
            "original_url": url,
            "sanitized_url": url,
            "stripped": [],
            "kept": [],
            "review": [],
            "errors": [f"{type(exc).__name__}: {exc}"],
            "requires_review": True,
            "decisions": {},
        }
        return url, False, details
def compute_verdict(result: dict, vt_data: Optional[dict] = None, rdap_data: Optional[dict] = None):
    """
    Scoring rubric (max 100):
      urlscan signals:
        +60  urlscan malicious flag
        +30  engine detections (×10 each, capped)
        +40  urlscan base score (capped)
        +10  domain redirect detected
        + 5  no HTTPS on final page
      VirusTotal signals:
        +20  VT domain flagged ≥3 engines
        +10  VT domain flagged 1–2 engines
        +20  VT IP flagged ≥3 engines
        +10  VT IP flagged 1–2 engines
        +15  VT URL flagged (any engine)
      RDAP signals:
        +25  domain registered <7 days ago
        +15  domain registered 7–30 days ago
        +10  domain registered 30–90 days ago
    Label: malicious ≥60 | suspicious 30–59 | safe <30
    """
    score    = 0.0
    verdicts = result.get("verdicts", {})
    overall  = verdicts.get("overall", {})

    if overall.get("malicious"):
        score += 60

    urlscan_score = overall.get("score", 0) or 0
    score += min(urlscan_score * 0.4, 40)

    engines = verdicts.get("engines", {})
    malicious_engines = engines.get("maliciousTotal", 0) or 0
    score += min(malicious_engines * 10, 30)

    page = result.get("page", {})
    final_url = page.get("url", "")
    if final_url and not final_url.startswith("https"):
        score += 5

    task = result.get("task", {})
    submitted_domain = task.get("domain", "")
    final_domain     = page.get("domain", "")
    if submitted_domain and final_domain and submitted_domain != final_domain:
        score += 10

    # VirusTotal boost
    if vt_data:
        domain_mal = vt_data.get("domain", {}).get("malicious", 0) or 0
        ip_mal     = vt_data.get("ip",     {}).get("malicious", 0) or 0
        url_mal    = max(
            (u.get("malicious", 0) or 0 for u in vt_data.get("urls", [])),
            default=0,
        )
        if domain_mal >= 3:   score += 20
        elif domain_mal >= 1: score += 10
        if ip_mal >= 3:       score += 20
        elif ip_mal >= 1:     score += 10
        if url_mal >= 1:      score += 15

    if rdap_data:
        age = rdap_data.get("domain_age_days")
        if age is not None:
            if age < 7:    score += 25
            elif age < 30: score += 15
            elif age < 90: score += 10

    score = min(score, 100)
    label = "malicious" if score >= 60 else "suspicious" if score >= 30 else "safe"
    return round(score, 1), label


def fmt_dt(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.strftime("%Y-%m-%dT%H:%M:%S") + "Z"
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + "Z"


def _write_result_to_db(uuid: str, data: dict, vt_data: Optional[dict] = None, rdap_data: Optional[dict] = None):
    score, label = compute_verdict(data, vt_data, rdap_data)
    page = data.get("page", {})
    db   = SessionLocal()
    rec  = db.query(ScanRecord).filter(ScanRecord.uuid == uuid).first()
    if rec:
        rec.status         = "complete"
        rec.verdict_score  = score
        rec.verdict_label  = label
        rec.screenshot_url = f"https://urlscan.io/screenshots/{uuid}.png"
        rec.result_url     = f"https://urlscan.io/result/{uuid}/"
        rec.raw_result     = json.dumps(data)
        rec.page_domain    = page.get("domain", "")
        rec.page_ip        = page.get("ip", "")
        # URLScan parsed fields
        rec.page_title     = page.get("title")
        rec.page_country   = page.get("country")
        rec.page_asn       = page.get("asn")
        rec.page_asnname   = page.get("asnname")
        rec.page_status    = page.get("status")
        rec.page_redirected = bool(page.get("redirected"))
        certs = data.get("lists", {}).get("certificates", [])
        rec.tls_issuer     = certs[0].get("issuer") if certs else None
        engine_verdicts    = data.get("verdicts", {}).get("engines", {})
        categories         = engine_verdicts.get("categories", [])
        rec.verdict_categories = json.dumps(categories) if categories else None
        gsb_matches        = data.get("meta", {}).get("processors", {}).get("gsb", {}).get("data", {}).get("matches", [])
        rec.gsb_match      = bool(gsb_matches)
        rec.redirect_count = data.get("stats", {}).get("redirects")
        if vt_data:
            domain_vt = vt_data.get("domain", {})
            rec.vt_domain_malicious     = domain_vt.get("malicious")
            rec.vt_domain_total         = domain_vt.get("total")
            rec.vt_domain_reputation    = domain_vt.get("reputation")
            cats = domain_vt.get("categories")
            rec.vt_domain_categories    = json.dumps(cats) if cats else None
            rec.vt_domain_registrar     = domain_vt.get("registrar")
            rec.vt_domain_creation_date = domain_vt.get("creation_date")
            ip_vt = vt_data.get("ip", {})
            rec.vt_ip_malicious         = ip_vt.get("malicious")
            rec.vt_ip_total             = ip_vt.get("total")
            rec.vt_ip_country           = ip_vt.get("country")
            rec.vt_ip_asn               = str(ip_vt.get("asn")) if ip_vt.get("asn") is not None else None
            url_results = vt_data.get("urls", [])
            if url_results:
                rec.vt_url_malicious    = url_results[0].get("malicious")
                rec.vt_url_total        = url_results[0].get("total")
                threat_names            = url_results[0].get("threat_names", [])
                rec.vt_url_threat_names = json.dumps(threat_names) if threat_names else None
            rec.vt_raw = json.dumps(vt_data)
        if rdap_data:
            rec.rdap_registered_at   = rdap_data.get("registered_at")
            rec.rdap_expires_at      = rdap_data.get("expires_at")
            rec.rdap_registrar       = rdap_data.get("registrar")
            rec.rdap_domain_age_days = rdap_data.get("domain_age_days")
            status = rdap_data.get("status", [])
            rec.rdap_status          = json.dumps(status) if status else None
        # Fallback: compute domain age from VT creation date if RDAP returned nothing
        if rec.rdap_domain_age_days is None and rec.vt_domain_creation_date:
            try:
                vt_dt = datetime.fromisoformat(rec.vt_domain_creation_date.replace("Z", "+00:00"))
                rec.rdap_domain_age_days = (datetime.now(timezone.utc) - vt_dt).days
            except Exception:
                pass
    db.commit()
    db.close()
    return score, label


# ── Background tasks ──────────────────────────────────────────────────────────
async def fetch_existing(uuid: str, delay: float = 0):
    """Fetch a completed result from urlscan. delay staggers parallel calls."""
    if delay:
        await asyncio.sleep(delay)
    headers = {"API-Key": API_KEY}
    for attempt in range(8):
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.get(f"{URLSCAN_BASE}/result/{uuid}/", headers=headers)
            if resp.status_code == 200:
                data    = resp.json()
                page    = data.get("page", {})
                domain  = page.get("domain", "")
                ip      = page.get("ip", "")
                vt_task   = asyncio.create_task(run_vt_enrichment(domain, ip, [page.get("url", "")])) if VT_API_KEY else None
                rdap_task = asyncio.create_task(_rdap_lookup_domain(domain))
                vt_data   = await vt_task if vt_task else None
                rdap_data = await rdap_task
                _write_result_to_db(uuid, data, vt_data, rdap_data)
                return True
            if resp.status_code == 404:
                await asyncio.sleep(5)
                continue
            if resp.status_code == 429:
                await asyncio.sleep(30)   # back off on rate limit
                continue
            if resp.status_code == 410:
                db = SessionLocal()
                rec = db.query(ScanRecord).filter(ScanRecord.uuid == uuid).first()
                if rec:
                    rec.status = "deleted"
                db.commit()
                db.close()
                return False
        except Exception:
            pass
        await asyncio.sleep(5 * (attempt + 1))
    return False


async def poll_one(uuid: str):
    """Wait for urlscan to finish a new scan, then persist the result."""
    headers = {"API-Key": API_KEY}
    await asyncio.sleep(30)          # urlscan needs ~30s minimum

    for attempt in range(30):
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(f"{URLSCAN_BASE}/result/{uuid}/", headers=headers)
            if resp.status_code == 200:
                data    = resp.json()
                page    = data.get("page", {})
                domain  = page.get("domain", "")
                ip      = page.get("ip", "")
                vt_task   = asyncio.create_task(run_vt_enrichment(domain, ip, [page.get("url", "")])) if VT_API_KEY else None
                rdap_task = asyncio.create_task(_rdap_lookup_domain(domain))
                vt_data   = await vt_task if vt_task else None
                rdap_data = await rdap_task
                _write_result_to_db(uuid, data, vt_data, rdap_data)
                return
            if resp.status_code == 410:
                db = SessionLocal()
                rec = db.query(ScanRecord).filter(ScanRecord.uuid == uuid).first()
                if rec:
                    rec.status = "deleted"
                db.commit()
                db.close()
                return
            if resp.status_code == 429:
                await asyncio.sleep(30)
                continue
        except Exception:
            pass
        await asyncio.sleep(10)

    db = SessionLocal()
    rec = db.query(ScanRecord).filter(ScanRecord.uuid == uuid).first()
    if rec and rec.status == "pending":
        rec.status = "timeout"
    db.commit()
    db.close()


# ── Models ────────────────────────────────────────────────────────────────────
class SubmitRequest(BaseModel):
    url:                 str
    visibility:          str = "public"
    manual_keep_params:  List[str] = Field(default_factory=list)
    manual_strip_params: List[str] = Field(default_factory=list)

class BulkSubmitRequest(BaseModel):
    urls:       List[str]
    visibility: str = "public"

class SaveSearchRequest(BaseModel):
    results: List[dict]
    query:   str = ""


# ── Endpoints ─────────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return FileResponse("static/index.html")


@app.post("/api/scan")
async def submit_scan(req: SubmitRequest, background_tasks: BackgroundTasks):
    if not API_KEY:
        raise HTTPException(500, "URLSCAN_API_KEY not set in .env")

    # ── Sanitize before submission ────────────────────────────────────────────
    clean_url, was_sanitized, san_details = await sanitize_url(
        req.url.strip(),
        manual_keep_params=req.manual_keep_params,
        manual_strip_params=req.manual_strip_params,
    )
    if san_details.get("requires_review"):
        return {
            "status": "review_required",
            "uuid": None,
            "url": clean_url,
            "sanitized": was_sanitized,
            "original_url": req.url.strip(),
            "result_url": None,
            "sanitization_details": san_details,
        }

    headers = {"API-Key": API_KEY, "Content-Type": "application/json"}
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(f"{URLSCAN_BASE}/scan/", headers=headers,
                                 json={"url": clean_url, "visibility": req.visibility})
    if resp.status_code not in (200, 201):
        try:    detail = resp.json().get("message", resp.text)
        except: detail = resp.text
        raise HTTPException(resp.status_code, detail)

    data       = resp.json()
    uuid       = data["uuid"]
    result_url = data.get("result", f"https://urlscan.io/result/{uuid}/")

    db = SessionLocal()
    db.merge(ScanRecord(
        uuid=uuid,
        url=clean_url,
        status="pending",
        result_url=result_url,
        original_url=req.url.strip() if was_sanitized else None,
        sanitization_method=san_details.get('method') if was_sanitized else None,
        sanitization_details=json.dumps(san_details) if was_sanitized else None,
    ))
    db.commit()
    db.close()

    background_tasks.add_task(poll_one, uuid)
    return {
        "uuid":                 uuid,
        "url":                  clean_url,
        "result_url":           result_url,
        "status":               "pending",
        "sanitized":            was_sanitized,
        "original_url":         req.url.strip() if was_sanitized else None,
        "sanitization_details": san_details if was_sanitized else None,
    }


@app.post("/api/scan/bulk")
async def bulk_scan(req: BulkSubmitRequest, background_tasks: BackgroundTasks):
    if not API_KEY:
        raise HTTPException(500, "URLSCAN_API_KEY not set in .env")
    results = []
    for url in req.urls:
        url = url.strip()
        if not url:
            continue
        try:
            r = await submit_scan(SubmitRequest(url=url, visibility=req.visibility), background_tasks)
            results.append({
                "url":       r["url"],
                "uuid":      r["uuid"],
                "status":    r["status"],
                "sanitized": r.get("sanitized", False),
                "original_url": r.get("original_url"),
                "sanitization_details": r.get("sanitization_details"),
            })
        except Exception:
            results.append({"url": url, "uuid": None, "status": "failed", "error": "Internal error while submitting scan"})
        await asyncio.sleep(1.2)
    sanitized_count = sum(1 for r in results if r.get("sanitized"))
    return {
        "submitted":       sum(1 for r in results if r["status"] == "pending"),
        "sanitized_count": sanitized_count,
        "results":         results,
    }


@app.get("/api/scans")
async def list_scans():
    db      = SessionLocal()
    records = db.query(ScanRecord).order_by(ScanRecord.submitted_at.desc()).limit(200).all()
    db.close()
    return [
        {
            "uuid":                  r.uuid,
            "url":                   r.url,
            "status":                r.status,
            "submitted_at":          fmt_dt(r.submitted_at),
            "verdict_score":         r.verdict_score,
            "verdict_label":         r.verdict_label,
            "result_url":            r.result_url,
            "screenshot_url":        r.screenshot_url,
            "page_domain":           r.page_domain,
            "page_ip":               r.page_ip,
            "page_title":            r.page_title,
            "page_country":          r.page_country,
            "page_asn":              r.page_asn,
            "page_asnname":          r.page_asnname,
            "page_status":           r.page_status,
            "page_redirected":       r.page_redirected,
            "tls_issuer":            r.tls_issuer,
            "verdict_categories":    json.loads(r.verdict_categories) if r.verdict_categories else None,
            "gsb_match":             r.gsb_match,
            "redirect_count":        r.redirect_count,
            "original_url":          r.original_url,
            "sanitization_method":   r.sanitization_method,
            "sanitization_details":  json.loads(r.sanitization_details) if r.sanitization_details else None,
            # VT enrichment
            "vt_domain_malicious":   r.vt_domain_malicious,
            "vt_domain_total":       r.vt_domain_total,
            "vt_domain_reputation":  r.vt_domain_reputation,
            "vt_domain_categories":  json.loads(r.vt_domain_categories) if r.vt_domain_categories else None,
            "vt_domain_registrar":   r.vt_domain_registrar,
            "vt_domain_creation_date": r.vt_domain_creation_date,
            "vt_ip_malicious":       r.vt_ip_malicious,
            "vt_ip_total":           r.vt_ip_total,
            "vt_ip_country":         r.vt_ip_country,
            "vt_ip_asn":             r.vt_ip_asn,
            "vt_url_malicious":      r.vt_url_malicious,
            "vt_url_total":          r.vt_url_total,
            "vt_url_threat_names":   json.loads(r.vt_url_threat_names) if r.vt_url_threat_names else None,
            # RDAP enrichment
            "rdap_registered_at":    r.rdap_registered_at,
            "rdap_expires_at":       r.rdap_expires_at,
            "rdap_registrar":        r.rdap_registrar,
            "rdap_domain_age_days":  r.rdap_domain_age_days,
            "rdap_status":           json.loads(r.rdap_status) if r.rdap_status else None,
        }
        for r in records
    ]


@app.get("/api/result/{uuid}")
async def get_result(uuid: str):
    db  = SessionLocal()
    rec = db.query(ScanRecord).filter(ScanRecord.uuid == uuid).first()
    db.close()
    if not rec:
        raise HTTPException(404, "Scan not found")
    return {
        "uuid": rec.uuid, "url": rec.url, "status": rec.status,
        "verdict_score": rec.verdict_score, "verdict_label": rec.verdict_label,
        "screenshot_url": rec.screenshot_url, "result_url": rec.result_url,
        "submitted_at": fmt_dt(rec.submitted_at),
    }


@app.post("/api/rescore")
async def rescore_all(background_tasks: BackgroundTasks):
    """Re-fetch full results for any record with a null score."""
    db      = SessionLocal()
    missing = db.query(ScanRecord).filter(
        ScanRecord.verdict_score == None,
        ScanRecord.uuid != None
    ).all()
    uuids = [r.uuid for r in missing]
    db.close()

    # stagger: 1.5s apart to avoid rate limits
    for i, uuid in enumerate(uuids):
        background_tasks.add_task(fetch_existing, uuid, i * 1.5)

    return {"queued": len(uuids), "uuids": uuids}


@app.get("/api/search")
async def search_scans(q: str, size: int = 20):
    if not API_KEY:
        raise HTTPException(500, "URLSCAN_API_KEY not set in .env")
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(f"{URLSCAN_BASE}/search/",
                                    headers={"API-Key": API_KEY},
                                    params={"q": q, "size": size})
        try:    data = resp.json()
        except: raise HTTPException(resp.status_code, f"urlscan API error {resp.status_code}")

        if resp.status_code != 200:
            msg = data.get("message") or data.get("description") or f"urlscan returned {resp.status_code}"
            raise HTTPException(resp.status_code, msg)

        return {
            "total": data.get("total", 0),
            "results": [
                {
                    "uuid":       r.get("_id"),
                    "url":        r.get("page", {}).get("url"),
                    "domain":     r.get("page", {}).get("domain"),
                    "ip":         r.get("page", {}).get("ip"),
                    "country":    r.get("page", {}).get("country"),
                    "date":       r.get("task", {}).get("time"),
                    "screenshot": r.get("screenshot"),
                    "result_url": r.get("result"),
                    "malicious":  r.get("verdicts", {}).get("overall", {}).get("malicious", False),
                    "score":      r.get("verdicts", {}).get("overall", {}).get("score", 0),
                }
                for r in data.get("results", [])
            ],
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/api/search/save")
async def save_search_results(req: SaveSearchRequest, background_tasks: BackgroundTasks):
    db = SessionLocal()
    saved = skipped = 0
    uuids_to_fetch = []

    for r in req.results:
        uuid = r.get("uuid")
        if not uuid:
            continue
        if db.query(ScanRecord).filter(ScanRecord.uuid == uuid).first():
            skipped += 1
            continue
        db.add(ScanRecord(
            uuid=uuid, url=r.get("url", ""), status="pending",
            submitted_at=datetime.now(timezone.utc),
            result_url=r.get("result_url", f"https://urlscan.io/result/{uuid}/"),
            screenshot_url=r.get("screenshot", ""),
        ))
        uuids_to_fetch.append(uuid)
        saved += 1

    db.commit()
    db.close()

    # stagger fetches 1.5s apart to avoid hitting urlscan rate limits
    for i, uuid in enumerate(uuids_to_fetch):
        background_tasks.add_task(fetch_existing, uuid, i * 1.5)

    return {"saved": saved, "skipped": skipped, "total": len(req.results)}


# ── RDAP helper ───────────────────────────────────────────────────────────────

async def _rdap_lookup_domain(domain: str) -> dict:
    if not domain:
        return {}
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            r = await client.get(f"https://rdap.org/domain/{domain}",
                                 headers={"Accept": "application/json"})
        if r.status_code != 200:
            return {}
        data = r.json()

        # Extract registration and expiration dates from events array
        events: dict[str, str] = {}
        for event in data.get("events", []):
            action = event.get("eventAction", "")
            date   = event.get("eventDate", "")
            if action and date:
                events[action] = date

        registered_at = events.get("registration")
        expires_at    = events.get("expiration")

        # Calculate domain age in days
        domain_age_days = None
        if registered_at:
            try:
                reg_dt = datetime.fromisoformat(registered_at.replace("Z", "+00:00"))
                domain_age_days = (datetime.now(timezone.utc) - reg_dt).days
            except Exception:
                pass

        # Extract registrar name from entities
        registrar = None
        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                vcard = entity.get("vcardArray", [])
                # vcardArray is ["vcard", [[type, params, kind, value], ...]]
                if len(vcard) > 1:
                    for entry in vcard[1]:
                        if entry[0] == "fn":
                            registrar = entry[3]
                            break
                if registrar:
                    break

        status = data.get("status", [])

        return {
            "registered_at":   registered_at,
            "expires_at":      expires_at,
            "registrar":       registrar,
            "domain_age_days": domain_age_days,
            "status":          status,
        }
    except Exception:
        return {}


# ── VirusTotal helpers ────────────────────────────────────────────────────────

def _vt_headers():
    return {"x-apikey": VT_API_KEY, "accept": "application/json"}


def _vt_score(attrs: dict) -> tuple[int, int]:
    """Return (malicious_count, total_engine_count) from a VT analysis stats dict."""
    stats     = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0) or 0
    total     = sum(stats.values()) if stats else 0
    return malicious, total


async def _vt_lookup_domain(domain: str) -> dict:
    if not domain or not VT_API_KEY:
        return {}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(f"{VT_BASE}/domains/{domain}", headers=_vt_headers())
        if r.status_code == 200:
            attrs = r.json().get("data", {}).get("attributes", {})
            mal, tot = _vt_score(attrs)
            creation_ts = attrs.get("creation_date")
            creation_date = (
                datetime.fromtimestamp(creation_ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                if creation_ts else None
            )
            return {"malicious": mal, "total": tot,
                    "reputation":     attrs.get("reputation"),
                    "categories":     attrs.get("categories", {}),
                    "tags":           attrs.get("tags", []),
                    "registrar":      attrs.get("registrar"),
                    "creation_date":  creation_date}
        return {"error": f"VT status {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}


async def _vt_lookup_ip(ip: str) -> dict:
    if not ip or not VT_API_KEY:
        return {}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(f"{VT_BASE}/ip_addresses/{ip}", headers=_vt_headers())
        if r.status_code == 200:
            attrs = r.json().get("data", {}).get("attributes", {})
            mal, tot = _vt_score(attrs)
            return {"malicious": mal, "total": tot,
                    "country":    attrs.get("country"),
                    "as_owner":   attrs.get("as_owner"),
                    "asn":        attrs.get("asn"),
                    "reputation": attrs.get("reputation")}
        return {"error": f"VT status {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}


async def _vt_lookup_url(url: str) -> dict:
    if not url or not VT_API_KEY:
        return {}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(f"{VT_BASE}/urls/{url_id}", headers=_vt_headers())
        if r.status_code == 200:
            attrs = r.json().get("data", {}).get("attributes", {})
            mal, tot = _vt_score(attrs)
            return {"url": url, "malicious": mal, "total": tot,
                    "final_url":    attrs.get("last_final_url"),
                    "title":        attrs.get("title"),
                    "threat_names": attrs.get("threat_names", [])}
        if r.status_code == 404:
            return {"url": url, "malicious": 0, "total": 0,
                    "note": "Not yet in VT database"}
        return {"url": url, "error": f"VT status {r.status_code}"}
    except Exception as e:
        return {"url": url, "error": str(e)}


async def run_vt_enrichment(domain: str, ip: str, urls: List[str]) -> dict:
    """Run all three VT lookups concurrently and return combined results."""
    domain_task = asyncio.create_task(_vt_lookup_domain(domain))
    ip_task     = asyncio.create_task(_vt_lookup_ip(ip))
    url_tasks   = [asyncio.create_task(_vt_lookup_url(u)) for u in urls[:5]]

    domain_result = await domain_task
    ip_result     = await ip_task
    url_results   = await asyncio.gather(*url_tasks)

    return {
        "domain": domain_result,
        "ip":     ip_result,
        "urls":   [r for r in url_results if r],
    }


# ── VT Endpoints ──────────────────────────────────────────────────────────────

@app.get("/api/vt/status")
async def vt_status():
    return {"configured": bool(VT_API_KEY)}


class VTLookupRequest(BaseModel):
    domain: Optional[str] = None
    ip:     Optional[str] = None
    urls:   List[str]  = []


@app.post("/api/vt/lookup")
async def vt_lookup(req: VTLookupRequest):
    if not VT_API_KEY:
        raise HTTPException(500, "VT_API_KEY not set in .env")
    result = await run_vt_enrichment(
        domain=req.domain or "",
        ip=req.ip or "",
        urls=req.urls,
    )
    return {
        "domain": result["domain"] if req.domain else None,
        "ip":     result["ip"]     if req.ip     else None,
        "urls":   result["urls"],
    }


@app.post("/api/vt/enrich/{uuid}")
async def vt_enrich(uuid: str):
    if not VT_API_KEY:
        raise HTTPException(500, "VT_API_KEY not set in .env")
    db  = SessionLocal()
    rec = db.query(ScanRecord).filter(ScanRecord.uuid == uuid).first()
    if not rec:
        db.close()
        raise HTTPException(404, "Scan not found")
    if rec.status != "complete":
        db.close()
        raise HTTPException(400, f"Scan is '{rec.status}' — enrichment requires a completed scan")

    domain   = rec.page_domain or ""
    ip       = rec.page_ip     or ""
    scan_url = rec.url         or ""

    vt_data = await run_vt_enrichment(domain, ip, [scan_url])

    # Recompute verdict using original urlscan result + fresh VT data + stored RDAP age
    raw_result = json.loads(rec.raw_result) if rec.raw_result else {}
    rdap_data  = {"domain_age_days": rec.rdap_domain_age_days} if rec.rdap_domain_age_days is not None else None
    score, label = compute_verdict(raw_result, vt_data, rdap_data)

    rec.verdict_score       = score
    rec.verdict_label       = label
    domain_vt = vt_data.get("domain", {})
    rec.vt_domain_malicious     = domain_vt.get("malicious")
    rec.vt_domain_total         = domain_vt.get("total")
    rec.vt_domain_reputation    = domain_vt.get("reputation")
    cats = domain_vt.get("categories")
    rec.vt_domain_categories    = json.dumps(cats) if cats else None
    rec.vt_domain_registrar     = domain_vt.get("registrar")
    rec.vt_domain_creation_date = domain_vt.get("creation_date")
    ip_vt = vt_data.get("ip", {})
    rec.vt_ip_malicious         = ip_vt.get("malicious")
    rec.vt_ip_total             = ip_vt.get("total")
    rec.vt_ip_country           = ip_vt.get("country")
    rec.vt_ip_asn               = str(ip_vt.get("asn")) if ip_vt.get("asn") is not None else None
    url_results = vt_data.get("urls", [])
    if url_results:
        rec.vt_url_malicious    = url_results[0].get("malicious")
        rec.vt_url_total        = url_results[0].get("total")
        threat_names            = url_results[0].get("threat_names", [])
        rec.vt_url_threat_names = json.dumps(threat_names) if threat_names else None
    rec.vt_raw = json.dumps(vt_data)
    db.commit()
    db.close()

    return {
        "uuid":          uuid,
        "verdict_score": score,
        "verdict_label": label,
        "vt":            vt_data,
    }


# ── RDAP Endpoints ────────────────────────────────────────────────────────────

@app.post("/api/rdap/enrich/{uuid}")
async def rdap_enrich(uuid: str):
    db  = SessionLocal()
    rec = db.query(ScanRecord).filter(ScanRecord.uuid == uuid).first()
    if not rec:
        db.close()
        raise HTTPException(404, "Scan not found")
    if rec.status != "complete":
        db.close()
        raise HTTPException(400, f"Scan is '{rec.status}' — enrichment requires a completed scan")

    domain    = rec.page_domain or ""
    rdap_data = await _rdap_lookup_domain(domain)

    if rdap_data:
        rec.rdap_registered_at   = rdap_data.get("registered_at")
        rec.rdap_expires_at      = rdap_data.get("expires_at")
        rec.rdap_registrar       = rdap_data.get("registrar")
        rec.rdap_domain_age_days = rdap_data.get("domain_age_days")
        status = rdap_data.get("status", [])
        rec.rdap_status          = json.dumps(status) if status else None

        # Recompute verdict with updated RDAP age
        raw_result   = json.loads(rec.raw_result) if rec.raw_result else {}
        vt_raw       = json.loads(rec.vt_raw) if rec.vt_raw else None
        score, label = compute_verdict(raw_result, vt_raw, rdap_data)
        rec.verdict_score = score
        rec.verdict_label = label

    db.commit()
    db.close()

    return {
        "uuid":              uuid,
        "domain":            domain,
        "rdap":              rdap_data,
        "verdict_score":     rec.verdict_score,
        "verdict_label":     rec.verdict_label,
    }


async def _rdap_enrich_one(uuid: str, delay: float = 0):
    """Background helper for bulk RDAP backfill."""
    if delay:
        await asyncio.sleep(delay)
    db  = SessionLocal()
    rec = db.query(ScanRecord).filter(ScanRecord.uuid == uuid).first()
    if not rec:
        db.close()
        return
    domain    = rec.page_domain or ""
    rdap_data = await _rdap_lookup_domain(domain)
    if rdap_data:
        rec.rdap_registered_at   = rdap_data.get("registered_at")
        rec.rdap_expires_at      = rdap_data.get("expires_at")
        rec.rdap_registrar       = rdap_data.get("registrar")
        rec.rdap_domain_age_days = rdap_data.get("domain_age_days")
        status = rdap_data.get("status", [])
        rec.rdap_status          = json.dumps(status) if status else None
        raw_result   = json.loads(rec.raw_result) if rec.raw_result else {}
        vt_raw       = json.loads(rec.vt_raw) if rec.vt_raw else None
        score, label = compute_verdict(raw_result, vt_raw, rdap_data)
        rec.verdict_score = score
        rec.verdict_label = label
    db.commit()
    db.close()


@app.post("/api/rdap/backfill")
async def rdap_backfill(background_tasks: BackgroundTasks):
    """Queue RDAP enrichment for all completed records that don't have it yet."""
    db    = SessionLocal()
    recs  = db.query(ScanRecord).filter(
        ScanRecord.status == "complete",
        ScanRecord.rdap_registered_at == None,
        ScanRecord.page_domain != None,
    ).all()
    uuids = [r.uuid for r in recs]
    db.close()

    for i, uuid in enumerate(uuids):
        background_tasks.add_task(_rdap_enrich_one, uuid, i * 1.0)

    return {"queued": len(uuids), "uuids": uuids}


app.mount("/static", StaticFiles(directory="static"), name="static")
