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
- **abuseipdb**: ERR
  - error: 403 Client Error: Forbidden for url: https://www.abuseipdb.com/check/14.103.172.199
- **talos**: ERR
  - error: 403 Client Error: Forbidden for url: https://talosintelligence.com/reputation_center/lookup?search=14.103.172.199
- **virustotal**: ERR
  - error: 429 Client Error: Too Many Requests for url: https://www.virustotal.com/api/v3/ip_addresses/14.103.172.199

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
- **abuseipdb**: ERR
  - error: 403 Client Error: Forbidden for url: https://www.abuseipdb.com/check/18.237.3.202
- **talos**: ERR
  - error: 403 Client Error: Forbidden for url: https://talosintelligence.com/reputation_center/lookup?search=18.237.3.202
- **virustotal**: ERR
  - error: 429 Client Error: Too Many Requests for url: https://www.virustotal.com/api/v3/ip_addresses/18.237.3.202

---

## Analyst Note

IP 14.103.172.199 risk = LOW: uncommon HTTP methods (UNKNOWN).
