from __future__ import annotations
import os, json, time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, Optional, Iterable

from dotenv import load_dotenv
load_dotenv()  # loads VT_API_KEY from .env if present

import requests
from bs4 import BeautifulSoup

# Tougher headers + session (still might be blocked; that's fine)
UA = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
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

def abuseipdb_lookup(ip: str) -> CtiResult:
    url = f"https://www.abuseipdb.com/check/{ip}"
    try:
        r = SESSION.get(url, timeout=TIMEOUT); r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")

        def grab(label: str) -> Optional[str]:
            lab = soup.find(string=lambda s: s and label in s)
            if not lab: return None
            val = lab.find_next("span")
            return val.text.strip() if val else None

        score_txt   = grab("Abuse Confidence Score")
        total_txt   = grab("Total Reports")
        country_txt = grab("Country")

        def to_int(x: Optional[str]) -> Optional[int]:
            if not x: return None
            x = x.replace("%", "").replace(",", "").strip()
            try: return int(x)
            except: return None

        data = {
            "abuse_confidence_score": to_int(score_txt),
            "total_reports": to_int(total_txt),
            "country": country_txt
        }
        return CtiResult(ip, "abuseipdb", True, data)
    except Exception as e:
        return CtiResult(ip, "abuseipdb", False, {}, error=str(e))

def talos_lookup(ip: str) -> CtiResult:
    url = f"https://talosintelligence.com/reputation_center/lookup?search={ip}"
    try:
        r = SESSION.get(url, timeout=TIMEOUT); r.raise_for_status()
        txt = r.text
        def between(t: str, left: str, right: str) -> Optional[str]:
            i = t.find(left)
            if i == -1: return None
            j = t.find(right, i)
            if j == -1: return None
            return t[i+len(left):j]
        rep = between(txt, "Web Reputation", "</")
        owner = between(txt, "Owner", "</")
        def clean(x): return " ".join(str(x).split()) if x else None
        data = {"web_reputation": clean(rep), "owner": clean(owner)}
        return CtiResult(ip, "talos", True, data)
    except Exception as e:
        return CtiResult(ip, "talos", False, {}, error=str(e))

def virustotal_lookup(ip: str) -> CtiResult:
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        return CtiResult(ip, "virustotal", False, {}, error="VT_API_KEY not set")
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    try:
        r = SESSION.get(url, headers={"x-apikey": api_key}, timeout=TIMEOUT); r.raise_for_status()
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
        for fn in (abuseipdb_lookup, talos_lookup, virustotal_lookup):
            src = fn.__name__.split("_")[0]
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
