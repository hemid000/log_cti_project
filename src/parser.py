from __future__ import annotations
import json, re, sys
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, List, Tuple

@dataclass
class AccessLogEntry:
    ip: str
    timestamp: str
    method: str
    status: int
    uri: Optional[str] = None
    user_agent: Optional[str] = None

_CLF_RE = re.compile(
    r'(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+-\s+-\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+[^"]+"\s+(?P<status>\d{3})'
)

def _parse_json_line(line: str) -> Optional[AccessLogEntry]:
    if "{" not in line or "}" not in line:
        return None
    try:
        js = line[line.index("{"): line.rindex("}") + 1]
        obj = json.loads(js)
        meth = (obj.get("method") or "").strip().upper() or "UNKNOWN"
        stat = int(obj.get("status"))
        return AccessLogEntry(
            ip=obj.get("remote_addr"),
            timestamp=obj.get("timestamp"),
            method=meth,
            status=stat,
            uri=obj.get("uri"),
            user_agent=obj.get("user_agent"),
        )
    except Exception:
        return None

def _parse_clf_line(line: str) -> Optional[AccessLogEntry]:
    m = _CLF_RE.search(line)
    if not m: return None
    return AccessLogEntry(
        ip=m.group("ip"),
        timestamp=m.group("ts"),
        method=m.group("method"),
        status=int(m.group("status")),
    )

def parse_line(line: str) -> Optional[AccessLogEntry]:
    return _parse_json_line(line) or _parse_clf_line(line)

def parse_log(path: str | Path) -> Tuple[List[AccessLogEntry], int]:
    entries, skipped = [], 0
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                entry = parse_line(line)
                if entry: entries.append(entry)
                else: skipped += 1
    except FileNotFoundError:
        print(f"[!] File not found: {path}", file=sys.stderr)
        return [], 0
    return entries, skipped

def unique_ips(entries: List[AccessLogEntry]) -> List[str]:
    return sorted({e.ip for e in entries if e.ip})
