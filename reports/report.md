# Log Analysis & CTI — Suspicious IPs Report

## Global Anomalies

Global view: 6778 total requests from 2 unique IPs; 2 IP(s) used uncommon HTTP methods; no other strong global anomalies.

## Suspicious IP Summary

| IP | Requests | 4xx | 5xx | Error Rate | Weird Methods | Tool UAs | Priority |
|---|---:|---:|---:|---:|---|---|---|
| 14.103.172.199 | 412 | 8 | 0 | 1.94% | UNKNOWN | - | — |
| 18.237.3.202 | 6366 | 19 | 20 | 0.61% | BSCZ, DEBUG, GPEF, INDEX, NVFYPLCD, PROPFIND, SEARCH, SSTP_DUPLEX_POST, THUNQMFS, TRACE, TRACK, UNKNOWN | dirbuster, nikto, nmap | HIGH |

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

**Priority:** HIGH — malicious tool user-agent detected.

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

## Analyst Note

IP 14.103.172.199 risk = MEDIUM: uncommon HTTP methods (UNKNOWN), and AbuseIPDB score 100% (high).
