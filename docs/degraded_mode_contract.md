# Aletheia Degraded-Mode Operational Contract

## 1. Overview
In digital forensics and incident response, investigators frequently operate in hostile network environments, air-gapped forensic labs, or during major infrastructure outages. 

This document defines the **Operational Contract for Degraded and Offline Modes**, guaranteeing that Aletheia maintains mathematical integrity even when external services fail.

---

## 2. Failure Mode Decision Matrix

| Failure Mode | Direct Impact | System Fallback Behavior | Evidentiary Impact |
|---|---|---|---|
| **EVM RPC Endpoint Unreachable / Offline** | Cannot query on-chain registry or broadcast transactions. | **Offline Local Verification**: Compares local Merkle root against `manifest.json` and cached attestation receipts. Emits `STATUS_OFFLINE_VERIFIED`. | Local integrity remains 100% provable. Public on-chain verification is deferred until connectivity is restored. |
| **IPFS Gateway / Pinning Service Down** | Cannot download or pin decentralized evidence archives. | **Local `.wasp` Container Preservation**: All raw evidence, ledger entries, and sidecars are bundled into a self-contained, signed `.wasp` archive stored locally on write-blocked media. | Zero data loss. IPFS CID is computed deterministically and pinned asynchronously once nodes rejoin the DHT. |
| **RFC 3161 TSA Server Timeout** | Cannot fetch live trusted timestamp token over HTTP/TSP. | **Dual Local Hardware & Monotonic Clock Stamping**: Ingests hardware RTC timestamp paired with local monotonic microsecond counter. Flags record with `TSA_DEGRADED_LOCAL`. | Still admissible with corroborating system logs, but clearly flagged in court manifest. |
| **L2 Block Reorganization (Reorg)** | Transaction hash temporarily omitted from the canonical chain. | **64-Block Finality Window**: Aletheia marks transactions as `CONFIRMED_ON_CHAIN` only after 64 consecutive L2 blocks (Base epoch finality) have elapsed. | Eliminates the risk of presenting orphaned transactions in court. |
| **Corrupted or Malformed Evidence Records** | Parser encounters unexpected bytes, null characters, or invalid JSON. | **Fail-Closed Audit Logging**: Malformed lines are recorded in the case `warnings` list with byte offset and hex dump rather than silently dropped. | The integrity of valid events is preserved while ensuring full disclosure of parser anomalies. |

---

## 3. Air-Gapped / SCIF Forensic Acquisition Protocol

When acquiring evidence inside a Sensitive Compartmented Information Facility (SCIF) or air-gapped lab where internet connectivity is physically prohibited:
1. **Acquisition**: Run `python wasp.py acquire --offline` on the bare-metal machine.
2. **Local Write-Quarantine**: Locks OS permissions (`icacls` / `0o444`) and streams dual-hashes (SHA-256 + Blake3) directly to local storage.
3. **Offline Super-Timeline**: Generates `timeline.jsonl`, `events.sqlite`, and computes the RFC 6962 Merkle tree root locally.
4. **Deferred Blockchain Anchoring**: When the investigator exports the sealed `.wasp` container across an approved data-diode or airlock to an internet-connected machine:
   ```powershell
   python wasp.py anchor --case-bundle CASE-2026-LIVE.wasp --network "Base Mainnet (L2)"
   ```
   The on-chain transaction registers the pre-computed Merkle root, achieving immutable anchoring without ever exposing the sensitive analysis machine to the internet.
