# Security Policy

## Reporting Security Vulnerabilities

The Aletheia team takes digital forensics integrity, cryptographic soundness, and software security with utmost seriousness. If you discover a vulnerability or potential attack vector in Aletheia (including parsers, smart contracts, Merkle tree construction, or API endpoints), please follow our responsible disclosure process.

### Disclosure Contact
* **Security Contact**: `security@aletheia-dedfir.org`
* **PGP Fingerprint**: `4A8E 2F19 8C02 D6B4 71E9  A083 91F5 E42B 08C1 5B93`
* **Response Window**: Initial acknowledgment within **24 hours**; triage assessment within **48 hours**.

Please **do not** report security vulnerabilities through public GitHub issues or discussions.

---

## Threat Surface & Scope

| Component | Scope | Primary Threat Considered |
|---|---|---|
| **EVM Smart Contracts** (`contracts/`) | `AletheiaRegistry.sol`, `ChronoTraceRegistry.sol` | Reentrancy, unauthorized custody transfer, Merkle verification bypass. |
| **Evidence Write-Guard** (`chronotrace/core/writeguard.py`) | OS permission lockdown | Privilege escalation, write-permission restoration, race conditions. |
| **Forensic Parsers** (`chronotrace/artifacts/`) | EVTX, `$MFT`, syslog, SQLite, prefetch | Memory exhaustion, parser remote code execution (RCE), malformed chunk injection. |
| **Integrity & Merkle Engine** (`chronotrace/integrity/`) | RFC 6962 tree builder, hasher | Length extension attacks, second-preimage collisions, domain separation violation. |
| **REST API Server** (`api/main.py`) | FastAPI endpoints | Multipart upload path traversal, denial of service via unbounded queries. |

---

## Vulnerability Severity Guidelines

We adhere to the Common Vulnerability Scoring System (CVSS v3.1):

- **Critical (CVSS 9.0–10.0)**: Ability to manipulate an evidence hash or timeline event without invalidating the Merkle root; remote code execution via untrusted evidence parsing.
- **High (CVSS 7.0–8.9)**: Unauthorized transfer of custody on-chain; bypass of OS-level write-quarantine.
- **Medium (CVSS 4.0–6.9)**: Parser crash/DoS via malformed file chunks; localized memory leaks.
- **Low (CVSS 0.1–3.9)**: Information disclosure of non-sensitive environmental parameters.

---

## Safe Harbor Policy
Activities conducted in good faith under this policy are considered authorized, and we will not initiate legal action against researchers who:
1. Provide reasonable time for remediation before public disclosure.
2. Avoid privacy violations, destruction of data, and interruption or degradation of production services.
3. Do not exploit security vulnerabilities beyond what is strictly necessary to prove existence.
