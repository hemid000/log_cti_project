from __future__ import annotations
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Dict, List
from parser import AccessLogEntry

@dataclass
class IpStats:
    ip: str
    total: int
    err4xx: int
    err5xx: int
    error_rate: float
    methods: Dict[str, int]
    statuses: Dict[int, int]
    weird_methods: List[str]
    bad_user_agents: List[str]
    high_priority: bool

WEIRD_METHODS = {
    "TRACK","PROPFIND","SEARCH","INDEX","SSTP_DUPLEX_POST",
    "NVFYPLCD","THUNQMFS","BSCZ","GPEF","UNKNOWN"
}

MALICIOUS_UA_KEYWORDS = [
    "sqlmap", "nmap", "hydra", "nikto", "dirbuster", "wpscan", "curl",
    "masscan", "zgrab", "acunetix", "acunetix-agent"
]

def compute_ip_stats(entries: List[AccessLogEntry]) -> Dict[str, IpStats]:
    by_ip = defaultdict(list)
    for e in entries:
        by_ip[e.ip].append(e)

    out: Dict[str, IpStats] = {}
    for ip, rows in by_ip.items():
        total = len(rows)
        err4xx = sum(1 for r in rows if 400 <= r.status < 500)
        err5xx = sum(1 for r in rows if 500 <= r.status < 600)
        methods = Counter(r.method for r in rows)
        statuses = Counter(r.status for r in rows)
        error_rate = (err4xx + err5xx) / total if total else 0.0
        weird = sorted([m for m in methods if m in WEIRD_METHODS])

        uas = { (r.user_agent or "").lower() for r in rows }
        bad_hits = sorted({kw for kw in MALICIOUS_UA_KEYWORDS
                           if any(kw in ua for ua in uas)})
        high_priority = bool(bad_hits)

        out[ip] = IpStats(
            ip=ip, total=total, err4xx=err4xx, err5xx=err5xx,
            error_rate=error_rate, methods=dict(methods),
            statuses=dict(statuses), weird_methods=weird,
            bad_user_agents=bad_hits, high_priority=high_priority
        )
    return out

def pick_suspicious_ips(stats: Dict[str, IpStats]) -> List[str]:
    if not stats:
        return []
    totals = sorted(s.total for s in stats.values())
    median = totals[len(totals)//2]
    sus = []
    for ip, s in stats.items():
        if s.error_rate >= 0.01 or s.weird_methods or s.total >= 5 * max(1, median):
            sus.append(ip)
    return sorted(sus)

def compute_global_anomalies(entries: List[AccessLogEntry],
                             ip_stats: Dict[str, IpStats]) -> Dict[str, float | int]:
    total = len(entries)
    err4xx = sum(1 for e in entries if 400 <= e.status < 500)
    ok200 = sum(1 for e in entries if e.status == 200)
    unique = len(ip_stats)
    weird_ip_count = sum(1 for s in ip_stats.values() if s.weird_methods)

    ratio_404_200 = (err4xx / ok200) if ok200 else 0.0
    return {
        "total_requests": total,
        "unique_ips": unique,
        "err4xx": err4xx,
        "ok200": ok200,
        "ratio_404_200": ratio_404_200,
        "weird_method_ips": weird_ip_count,
    }
