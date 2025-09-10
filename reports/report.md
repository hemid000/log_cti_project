# Log Analysis & CTI — Suspicious IPs Report

## General Anomalies

General view: 6778 total requests from 2 unique IPs; 2 IP(s) used uncommon HTTP methods; no other strong General anomalies.

## Suspicious IP Summary

| IP | Requests | 4xx | 5xx | Error Rate | Weird Methods | Tool User-Agents | Priority |
|---|---:|---:|---:|---:|---|---|:---:|
| 14.103.172.199 | 412 | 8 | 0 | 1.94% | UNKNOWN | - | — |
| 18.237.3.202 | 6366 | 19 | 20 | 0.61% | BSCZ, GPEF, INDEX, NVFYPLCD, PROPFIND, SEARCH, SSTP_DUPLEX_POST, THUNQMFS, TRACK, UNKNOWN | dirbuster, nikto, nmap | HIGH |

### 14.103.172.199

**Methods:**
```
GET:401, POST:9, UNKNOWN:2
```
**Statuses:**
```
200:300, 304:96, 101:8, 403:6, 400:2
```
**CTI:**
- **abuseipdb**: OK
  ```
  abuse_confidence_score: 100
  total_reports: 1381
  country: CN
  isp: Beijing Volcano Engine Technology Co., Ltd.
  ```
- **virustotal**: ERR
  - error: rate_limited (VT 429)

---


### 18.237.3.202

**Priority:** HIGH — tool User-Agents detected (dirbuster, nikto, nmap).

**Methods:**
```
GET:6291, OPTIONS:27, UNKNOWN:9, POST:8, PROPFIND:8, TRACE:4, TRACK:4, HEAD:3, DEBUG:2, INDEX:2, PUT:2, BSCZ:1, GPEF:1, NVFYPLCD:1, SEARCH:1, SSTP_DUPLEX_POST:1, THUNQMFS:1
```
**Statuses:**
```
200:6236, 304:45, 301:33, 500:20, 400:14, 204:12, 405:4, 101:1, 499:1
```
**CTI:**
- **abuseipdb**: OK
  ```
  abuse_confidence_score: 88
  total_reports: 38
  country: US
  isp: Amazon.com, Inc.
  ```
- **virustotal**: ERR
  - error: rate_limited (VT 429)

---

## AI Analyst Note

IP 14.103.172.199 risk = MEDIUM:  The high number of total reports (1381) on AbuseIPDB, despite an OK status, coupled with a rate limit hit on VirusTotal, suggests potential malicious activity that warrants further investigation; the relatively low error rate in recent stats is not enough to mitigate this concern.
