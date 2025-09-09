# src/main.py
from __future__ import annotations
import sys, argparse
from pathlib import Path
from parser import parse_log, unique_ips
from stats import compute_ip_stats, pick_suspicious_ips, compute_global_anomalies
from cti import enrich_ips
from report import render_text_report, render_markdown_report, save_report
from ai_note import ip_analyst_note, global_analyst_note
from ai_llm import generate_ai_note

def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Log Analysis + CTI + Bonus")
    p.add_argument("logfile", nargs="?", help="Path to access_log (defaults to data/access_log.txt)")
    p.add_argument("--top", type=int, default=5)
    p.add_argument("--no-cti", action="store_true")
    p.add_argument("--format", choices=["txt","md"], default="txt")
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--ai", action="store_true", help="Use AI to generate analyst note (requires API key)")  # NEW
    return p

def main():
    args = build_argparser().parse_args()
    root = Path(__file__).resolve().parents[1]
    log_path = Path(args.logfile) if args.logfile else (root / "data" / "access_log.txt")

    entries, skipped = parse_log(log_path)
    if not entries:
        print("[!] No entries parsed; exiting.")
        sys.exit(1)
    print(f"[i] Parsed: {len(entries)} (skipped: {skipped})")

    ip_stats = compute_ip_stats(entries)
    suspicious = pick_suspicious_ips(ip_stats)
    if args.limit and len(suspicious) > args.limit:
        suspicious = suspicious[:args.limit]

    # global anomalies
    global_anoms = compute_global_anomalies(entries, ip_stats)
    global_note = global_analyst_note(global_anoms)

    # CTI enrichment
    cti_results = {}
    if not args.no_cti and suspicious:
        print("[i] Running CTI lookups...")
        cti_results = enrich_ips(suspicious)

    # Analyst note
    note = None
    if suspicious:
        first = suspicious[0]
        s0 = ip_stats[first]
        if args.ai:
            # Try AI note first
            note = generate_ai_note(first, s0, cti_results.get(first, {}), global_anoms)
        if not note:
            # Fallback to heuristic
            note = ip_analyst_note(first, s0, cti_results.get(first, {}))

    # render + save report
    if args.format == "md":
        content = render_markdown_report(suspicious, ip_stats, cti_results, note, global_note)
        out = save_report(root, content, "report.md")
    else:
        content = render_text_report(suspicious, ip_stats, cti_results, note, global_note)
        out = save_report(root, content, "report.txt")

    print(f"[+] Report saved: {out}")

if __name__ == "__main__":
    main()
