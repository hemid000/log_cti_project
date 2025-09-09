from __future__ import annotations
from typing import Dict
from stats import IpStats

def ip_analyst_note(ip: str, s: IpStats, cti: Dict[str, dict]) -> str:
    reasons = []
    if s.high_priority:
        reasons.append("malicious tool user-agent observed")
    if s.weird_methods:
        reasons.append(f"uncommon HTTP methods ({', '.join(s.weird_methods)})")
    if s.error_rate >= 0.02:
        reasons.append(f"elevated error rate {s.error_rate:.1%}")
    if s.total >= 2000:
        reasons.append(f"high request volume ({s.total} hits)")

    ab = (cti.get("abuseipdb") or {})
    if ab.get("ok"):
        sc = (ab.get("data") or {}).get("abuse_confidence_score")
        if isinstance(sc, int):
            if sc >= 75:
                reasons.append(f"AbuseIPDB score {sc}% (high)")
            elif sc >= 25:
                reasons.append(f"AbuseIPDB score {sc}% (medium)")
    ta = (cti.get("talos") or {})
    if ta.get("ok"):
        rep = (ta.get("data") or {}).get("web_reputation")
        if rep and str(rep).lower() in {"questionable", "untrusted", "poor"}:
            reasons.append(f"Talos reputation {rep}")
    vt = (cti.get("virustotal") or {})
    if vt.get("ok"):
        mal = (vt.get("data") or {}).get("last_analysis_stats", {}).get("malicious")
        if isinstance(mal, int) and mal > 0:
            reasons.append(f"flagged by {mal} VirusTotal engines")

    risk = 0
    if s.high_priority: risk += 3
    if s.weird_methods: risk += 2
    if s.error_rate >= 0.02: risk += 2
    if s.total >= 2000: risk += 1
    if ab.get("ok") and isinstance((ab.get("data") or {}).get("abuse_confidence_score"), int):
        risk += ((ab["data"]["abuse_confidence_score"]) // 25)
    if vt.get("ok"):
        mal = (vt.get("data") or {}).get("last_analysis_stats", {}).get("malicious", 0)
        risk += min(mal, 3)

    level = "LOW"
    if risk >= 7: level = "HIGH"
    elif risk >= 4: level = "MEDIUM"

    if not reasons:
        reasons.append("multiple weak indicators that warrant monitoring")

    return f"IP {ip} risk = {level}: " + ", ".join(reasons[:-1]) + ("" if len(reasons)==1 else ", and ") + reasons[-1] + "."

def global_analyst_note(glob: Dict[str, float | int]) -> str:
    bits = []
    bits.append(f"{glob['total_requests']} total requests from {glob['unique_ips']} unique IPs")
    if glob["ratio_404_200"] > 0.05:
        bits.append(f"4xx/200 ratio is elevated at {glob['ratio_404_200']:.1%}")
    if glob["weird_method_ips"] > 0:
        bits.append(f"{glob['weird_method_ips']} IP(s) used uncommon HTTP methods")
    if len(bits) == 2 and "elevated" not in bits[1]:
        bits.append("no other strong global anomalies")
    return "Global view: " + "; ".join(bits) + "."
