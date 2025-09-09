# src/cti.py
from __future__ import annotations
import os, json, time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, Optional, Iterable

from dotenv import load_dotenv
load_dotenv()

import requests

UA = {
    "User-Agent": "Mozilla/5.0",
}
TIMEOUT = 10.0
SESSION = requests.Session()
SESSION.headers.update(UA)

@dataclass
class CtiResult:
    ip: str
    source: str              # abuseipdb | talos | virustotal
    ok: bool
    data: Dict[str, Any]
    error: Optional[str] = None

class CtiCache:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            try:
                self._cache = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                self._cache = {}
        else:
            self._cache = {}

    def get(self, ip: str, source: str) -> Optional[Dict[str, Any]]:
        return self._cache.get(ip, {}).get(source)

    def put(self, ip: str, source: str, payload: Dict[str, Any]) -> None:
        self._cache.setdefault(ip, {})[source] = payload
        self.path.write_text(json.dumps(self._cache, ensure_ascii=False, indent=2), encoding="utf-8")

# --- NEW: AbuseIPDB official API
# --- NEW: AbuseIPDB official API (no scraping)
# def abuseipdb_lookup_api(ip: str, max_age_days: int = 90) -> CtiResult:
#     api_key = os.getenv("ABUSEIPDB_API_KEY")
#     if not api_key:
#         return CtiResult(ip, "abuseipdb", False, {}, error="ABUSEIPDB_API_KEY not set")

#     url = "https://api.abuseipdb.com/api/v2/check"
#     try:
#         r = SESSION.get(
#             url,
#             headers={"Key": api_key, "Accept": "application/json"},
#             params={"ipAddress": ip, "maxAgeInDays": max_age_days},
#             timeout=TIMEOUT
#         )
#         if r.status_code == 401:
#             return CtiResult(ip, "abuseipdb", False, {}, error="unauthorized")
#         if r.status_code == 429:
#             return CtiResult(ip, "abuseipdb", False, {}, error="rate_limited")
#         r.raise_for_status()

#         # Normalize keys to match ai_note.py expectations
#         data = r.json().get("data", {}) if r.headers.get("content-type","").startswith("application/json") else {}
#         normalized = {
#             "abuse_confidence_score": data.get("abuseConfidenceScore"),
#             "total_reports": data.get("totalReports"),
#             "country": data.get("countryCode") or data.get("countryName"),
#             "isp": data.get("isp"),
#         }
#         return CtiResult(ip, "abuseipdb", True, normalized)
#     except Exception as e:
#         return CtiResult(ip, "abuseipdb", False, {}, error=str(e))

# src/cti.py  (replace your abuseipdb_lookup_api with this)
def abuseipdb_lookup_api(ip: str, max_age_days: int = 90) -> CtiResult:
    api_key = (os.getenv("ABUSEIPDB_API_KEY") or "").strip().strip('"').strip("'")
    if not api_key:
        return CtiResult(ip, "abuseipdb", False, {}, error="ABUSEIPDB_API_KEY not set (need API v2 key)")

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": int(max_age_days),
        # "verbose": "true",  # optional
    }

    try:
        r = SESSION.get(url, headers=headers, params=params, timeout=TIMEOUT)

        # Non-200: surface AbuseIPDB's error details
        if r.status_code != 200:
            err_msg = f"{r.status_code}"
            try:
                js = r.json()
                if isinstance(js, dict) and "errors" in js and js["errors"]:
                    details = [e.get("detail") for e in js["errors"] if isinstance(e, dict)]
                    if details:
                        err_msg = f"{r.status_code}: " + " | ".join(d for d in details if d)
            except Exception:
                # Fall back to text snippet
                err_msg = f"{r.status_code}: {r.text[:300]}"

            # Friendly hints
            if "Authentication failed" in err_msg or "APIv2 key differs" in err_msg:
                err_msg += " (Check that you're using a valid AbuseIPDB **API v2** key.)"
            if r.status_code == 429:
                err_msg += " (Rate limited by AbuseIPDB.)"

            return CtiResult(ip, "abuseipdb", False, {}, error=err_msg)

        # 200 OK -> parse data
        try:
            data = r.json().get("data", {})
        except Exception:
            return CtiResult(ip, "abuseipdb", False, {}, error="Invalid JSON from AbuseIPDB")

        # Normalize keys your ai_note.py expects
        def _to_int(x):
            try:
                return int(x) if x is not None else None
            except Exception:
                return None

        normalized = {
            "abuse_confidence_score": _to_int(data.get("abuseConfidenceScore")),
            "total_reports": _to_int(data.get("totalReports")),
            "country": data.get("countryCode") or data.get("countryName"),
            "isp": data.get("isp"),
        }
        return CtiResult(ip, "abuseipdb", True, normalized)

    except Exception as e:
        return CtiResult(ip, "abuseipdb", False, {}, error=str(e))

# def talos_lookup(ip: str) -> CtiResult:
#     url = f"https://talosintelligence.com/reputation_center/lookup?search={ip}"
#     try:
#         r = SESSION.get(url, timeout=TIMEOUT); r.raise_for_status()
#         txt = r.text
#         # naive extraction (Talos has no public IP-reputation API)
#         def between(t: str, left: str, right: str):
#             i = t.find(left)
#             if i == -1: return None
#             j = t.find(right, i)
#             if j == -1: return None
#             return " ".join(t[i+len(left):j].split())
#         rep = between(txt, "Web Reputation", "</")
#         owner = between(txt, "Owner", "</")
#         data = {"web_reputation": rep, "owner": owner}
#         return CtiResult(ip, "talos", True, data)
#     except Exception as e:
#         return CtiResult(ip, "talos", False, {}, error=str(e))

# def virustotal_lookup(ip: str) -> CtiResult:
#     api_key = os.getenv("VT_API_KEY")
#     if not api_key:
#         return CtiResult(ip, "virustotal", False, {}, error="VT_API_KEY not set")
#     url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
#     try:
#         r = SESSION.get(url, headers={"x-apikey": api_key}, timeout=TIMEOUT); r.raise_for_status()
#         js = r.json()
#         stats = js.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
#         return CtiResult(ip, "virustotal", True, {"last_analysis_stats": stats})
#     except Exception as e:
#         return CtiResult(ip, "virustotal", False, {}, error=str(e))
def virustotal_lookup(ip: str) -> CtiResult:
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        return CtiResult(ip, "virustotal", False, {}, error="VT_API_KEY not set")

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    try:
        # small backoff (2 tries)
        for attempt in range(2):
            r = SESSION.get(url, headers=headers, timeout=TIMEOUT)
            if r.status_code == 429 and attempt == 0:
                time.sleep(2.0)         # brief backoff
                continue
            break

        if r.status_code == 429:
            return CtiResult(ip, "virustotal", False, {}, error="rate_limited (VT 429)")
        if r.status_code == 401:
            return CtiResult(ip, "virustotal", False, {}, error="unauthorized (check VT_API_KEY)")
        r.raise_for_status()

        js = r.json()
        stats = js.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return CtiResult(ip, "virustotal", True, {"last_analysis_stats": stats})
    except Exception as e:
        return CtiResult(ip, "virustotal", False, {}, error=str(e))

def enrich_ips(ips: Iterable[str], use_cache: bool = True, cache_path: Optional[Path] = None) -> Dict[str, Dict[str, Dict[str, Any]]]:
    cache = CtiCache(cache_path or (Path(__file__).resolve().parents[1] / ".cache" / "cti_cache.json"))
    out: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for ip in ips:
        out[ip] = {}
        for fn in (abuseipdb_lookup_api, virustotal_lookup):  # << use API version
            src = fn.__name__.split("_")[0]  # abuseipdb / talos / virustotal
            if use_cache:
                cached = cache.get(ip, src)
                if cached:
                    out[ip][src] = cached
                    continue
            res = fn(ip)
            payload = {"ok": res.ok, "data": res.data, "error": res.error}
            out[ip][src] = payload
            cache.put(ip, src, payload)
            time.sleep(0.6)  # polite delay
    return out
