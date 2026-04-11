# OWASP Top 10 (2021) — WAF Compliance Matrix

This matrix maps each OWASP Top 10 category to the AWS WAFv2 rules implemented in this module
and their equivalent controls in Imperva Cloud WAF.

| OWASP Category | Status | AWS WAFv2 Rules | Imperva Cloud WAF Equivalent |
|---|---|---|---|
| **A01 — Broken Access Control** | COVERED | CommonRuleSet (path traversal, LFI/RFI), RateLimit (brute force), GeoBlock | Imperva SecureSphere Access Control policies, Geo-blocking rules, Rate limiting policies |
| **A02 — Cryptographic Failures** | N/A | Not applicable at WAF layer (TLS termination is infrastructure) | Imperva SSL/TLS configuration, Certificate management |
| **A03 — Injection** | COVERED | CommonRuleSet (XSS, command injection), SQLiRuleSet (SQL injection), KnownBadInputs (JNDI/Log4Shell) | Imperva SQL Injection policy, Cross-Site Scripting policy, Custom signatures for JNDI |
| **A04 — Insecure Design** | N/A | Not applicable at WAF layer (requires application redesign) | Imperva API Security (schema validation), but fundamentally app-level |
| **A05 — Security Misconfiguration** | PARTIAL | CommonRuleSet (admin path probing, server info leaks), KnownBadInputs | Imperva Server Masking (hides server headers), Error page masking |
| **A06 — Vulnerable Components** | PARTIAL | KnownBadInputs (Log4Shell CVE-2021-44228, Spring4Shell CVE-2022-22965) | Imperva Virtual Patching, Emergency rules pushed within hours of CVE disclosure |
| **A07 — Auth Failures** | PARTIAL | RateLimit (credential stuffing), IPReputationList (botnet IPs) | Imperva Account Takeover Protection, Bot management, Advanced rate limiting |
| **A08 — Data Integrity** | PARTIAL | KnownBadInputs (deserialization patterns) | Imperva Data Loss Prevention (DLP), File upload inspection |
| **A09 — Logging & Monitoring** | COVERED | CloudWatch WAF Logging (all decisions), CloudWatch Dashboard (real-time metrics) | Imperva Security Events Dashboard, SIEM integration, Real-time alerts |
| **A10 — SSRF** | PARTIAL | CommonRuleSet (blocks common SSRF patterns in URI/headers/body) | Imperva SSRF protection rules, Custom security rules for internal IP blocking |

## Coverage Summary

| Coverage Level | Count | Categories |
|---|---|---|
| **COVERED** | 3 | A01, A03, A09 |
| **PARTIAL** | 5 | A05, A06, A07, A08, A10 |
| **N/A (App Layer)** | 2 | A02, A04 |

## Sensitivity Level Behavior

| Level | Managed Rules | Custom Rules (Rate/Geo/IP) | AnonymousIPList | Use Case |
|---|---|---|---|---|
| `low` | Count only | Count only (IP allow/block lists still enforce) | Count only | Initial deployment, traffic baselining |
| `medium` | Block (defaults) | Block | Count only | Standard production, most environments |
| `high` | Block (defaults) | Block (strict limits) | Block | High-security, post-tuning |

## Notes

- **PARTIAL** coverage means the WAF reduces risk but cannot fully prevent the attack class.
  Application-level controls (input validation, parameterized queries, CSP headers) remain essential.
- In `low` sensitivity, the module reports OWASP categories protected by managed, geo, and rate rules as **monitoring only** because those controls are baselining in count mode.
- **Imperva equivalents** are approximate mappings — Imperva Cloud WAF uses its own rule naming
  and may bundle protections differently than AWS managed rule groups.
- Imperva's **Virtual Patching** capability (A06) is a significant differentiator: Imperva pushes
  emergency rules for new CVEs within hours, while AWS managed rules may take longer to update.
- Imperva's **Account Takeover Protection** (A07) includes behavioral analysis beyond simple rate
  limiting, detecting credential stuffing even at low request rates.
