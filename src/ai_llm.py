# src/ai_llm.py
from __future__ import annotations
import os, re, json
from typing import Dict, Optional
from stats import IpStats

try:
    import google.generativeai as genai
except Exception:
    genai = None  # we'll handle gracefully

def _summarize_cti(cti: Dict[str, dict]) -> str:
    lines = []
    for src, res in (cti or {}).items():
        if res.get("ok"):
            data = res.get("data") or {}
            if data:
                kv = ", ".join(f"{k}: {v}" for k, v in data.items())
                lines.append(f"{src}=OK({kv})")
            else:
                lines.append(f"{src}=OK")
        else:
            err = res.get("error")
            lines.append(f"{src}=ERR({err})" if err else f"{src}=ERR")
    return "; ".join(lines) if lines else "none"

def generate_ai_note(ip: str, s: IpStats, cti: Dict[str, dict],
                     global_anoms: Dict[str, float | int]) -> Optional[str]:
    """
    Use Gemini if GEMINI_API_KEY is set. Return a one-line analyst note.
    If key missing or request fails, return None so caller can fall back.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key or genai is None:
        return None

    # SAFELY read optional fields
    weird_methods = ", ".join(getattr(s, "weird_methods", []) or []) or "-"
    tool_uas      = ", ".join(getattr(s, "bad_user_agents", []) or []) or "-"
    # (You can add more samples here if you store them in IpStats down the line.)

    prompt = f"""
You are a security analyst. Given the log stats and CTI for IP {ip},
rate the risk as LOW, MEDIUM, or HIGH, and explain 2–4 reasons clearly.

GLOBAL:
- total_requests: {global_anoms.get('total_requests')}
- unique_ips: {global_anoms.get('unique_ips')}
- 4xx/200 ratio: {global_anoms.get('ratio_404_200'):.2%}

STATS:
- requests: {s.total}, 4xx: {s.err4xx}, 5xx: {s.err5xx}, error_rate: {s.error_rate:.2%}
- weird_methods: {weird_methods}
- tool_uas: {tool_uas}

CTI:
{_summarize_cti(cti)}

Output strictly in format:
"IP {ip} risk = <LOW|MEDIUM|HIGH>: <sentence with reasons>."
"""

    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-1.5-flash")
        resp = model.generate_content(prompt.strip())

        # Robust text extraction across SDK variants
        text = ""
        if hasattr(resp, "text") and resp.text:
            text = resp.text.strip()
        elif getattr(resp, "candidates", None):
            for c in resp.candidates:
                parts = getattr(getattr(c, "content", None), "parts", []) or []
                for p in parts:
                    t = getattr(p, "text", "") or ""
                    if t.strip():
                        text = t.strip()
                        break
                if text:
                    break

        if not text:
            return None

        # Force single-sentence and shape exactly like required
        line = re.split(r'(?<=[.!?])\s+', text)[0].strip()
        if not line.endswith("."):
            line += "."
        # If model didn't follow the exact prefix, coerce it:
        if not line.startswith(f"IP {ip} risk ="):
            # Try to find risk token; default LOW if none
            risk = "LOW"
            m = re.search(r'\b(LOW|MEDIUM|HIGH)\b', line.upper())
            if m: risk = m.group(1)
            line = f"IP {ip} risk = {risk}: {line}"
        return line
    except Exception:
        return None
