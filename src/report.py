from __future__ import annotations
from pathlib import Path
from typing import Dict, List
from stats import IpStats

def ensure_reports_dir(root: Path) -> Path:
    out = root / "reports"
    out.mkdir(parents=True, exist_ok=True)
    return out

def render_text_report(suspicious_ips: List[str], ip_stats: Dict[str, IpStats],
                       cti: Dict[str, Dict[str, dict]], analyst_note: str | None = None,
                       global_note: str | None = None) -> str:
    lines = []
    lines.append("LOG ANALYSIS & CTI — Suspicious IPs Report")
    lines.append("=" * 60)
    lines.append("")

    if global_note:
        lines.append("Global Anomalies")
        lines.append("----------------")
        lines.append(global_note)
        lines.append("")

    if not suspicious_ips:
        lines.append("No suspicious IPs detected.")
    for ip in suspicious_ips:
        s = ip_stats[ip]
        prio = "  [HIGH PRIORITY]" if s.high_priority else ""
        lines.append(f"IP: {ip}{prio}")
        lines.append(f"  Requests: {s.total}")
        lines.append(f"  4xx: {s.err4xx}  |  5xx: {s.err5xx}  |  Error Rate: {s.error_rate:.2%}")
        if s.weird_methods:
            lines.append(f"  Weird Methods: {', '.join(s.weird_methods)}")
        if s.bad_user_agents:
            lines.append(f"  Malicious/Tool UAs: {', '.join(s.bad_user_agents)}")
        lines.append("  Methods: " + ", ".join(f"{k}:{v}" for k,v in sorted(s.methods.items(), key=lambda x: (-x[1], x[0]))))
        lines.append("  Statuses: " + ", ".join(f"{k}:{v}" for k,v in sorted(s.statuses.items(), key=lambda x: (-x[1], x[0]))))
        lines.append("  CTI:")
        for src, res in (cti.get(ip) or {}).items():
            ok = res.get("ok")
            lines.append(f"    - {src}: {'OK' if ok else 'ERR'}")
            if ok:
                for k,v in (res.get("data") or {}).items():
                    lines.append(f"        {k}: {v}")
            else:
                lines.append(f"        error: {res.get('error')}")
        lines.append("-" * 60)

    if analyst_note:
        lines.append("")
        lines.append("Analyst Note")
        lines.append("------------")
        lines.append(analyst_note)

    return "\n".join(lines)


def render_markdown_report(suspicious_ips: List[str], ip_stats: Dict[str, IpStats],
                           cti: Dict[str, Dict[str, dict]], analyst_note: str | None = None,
                           global_note: str | None = None) -> str:
    md = []
    md.append("# Log Analysis & CTI — Suspicious IPs Report\n")

    if global_note:
        md.append("## Global Anomalies\n")
        md.append(global_note + "\n")

    if not suspicious_ips:
        md.append("_No suspicious IPs detected._\n")
        return "\n".join(md)

    # Table summary
    md.append("## Suspicious IP Summary\n")
    md.append("| IP | Requests | 4xx | 5xx | Error Rate | Weird Methods | Tool UAs | Priority |")
    md.append("|---|---:|---:|---:|---:|---|---|---|")
    for ip in suspicious_ips:
        s = ip_stats[ip]
        md.append(
            f"| {ip} | {s.total} | {s.err4xx} | {s.err5xx} | {s.error_rate:.2%} | "
            f"{', '.join(s.weird_methods) if s.weird_methods else '-'} | "
            f"{', '.join(s.bad_user_agents) if s.bad_user_agents else '-'} | "
            f"{'HIGH' if s.high_priority else '—'} |"
        )

    # Detailed breakdown per IP
    for ip in suspicious_ips:
        s = ip_stats[ip]
        md.append(f"\n### {ip}\n")
        if s.high_priority:
            md.append("**Priority:** HIGH — malicious tool user-agent detected.\n")
        md.append("**Methods:**\n```\n" + ", ".join(f"{k}:{v}" for k,v in sorted(s.methods.items(), key=lambda x: (-x[1], x[0]))) + "\n```")
        md.append("**Statuses:**\n```\n" + ", ".join(f"{k}:{v}" for k,v in sorted(s.statuses.items(), key=lambda x: (-x[1], x[0]))) + "\n```")
        md.append("**CTI:**")
        for src, res in (cti.get(ip) or {}).items():
            ok = res.get("ok")
            md.append(f"- **{src}**: {'OK' if ok else 'ERR'}")
            if ok:
                data = res.get("data") or {}
                if data:
                    md.append("  ```")
                    for k, v in data.items():
                        md.append(f"  {k}: {v}")
                    md.append("  ```")
            else:
                md.append(f"  - error: {res.get('error')}")
        md.append("\n---\n")

    if analyst_note:
        md.append("## Analyst Note\n")
        md.append(analyst_note + "\n")

    return "\n".join(md)


def save_report(root: Path, content: str, name: str) -> Path:
    outdir = ensure_reports_dir(root)
    path = outdir / name
    path.write_text(content, encoding="utf-8")
    return path
