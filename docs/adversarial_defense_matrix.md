# Aletheia Adversarial Defense & Threat Matrix

> **Standard Compliance**: FRE 902(14) Self-Authenticating Digital Records | Daubert Standard (509 U.S. 579) | RFC 8785 JSON Canonicalization | RFC 6962 Merkle Audit Path | ISO/IEC 27037 Digital Evidence Handling

---

## Executive Summary

Aletheia is an evidence-grade, deterministic digital forensics and incident response (DFIR) platform designed to withstand active adversary interference, insider tampering, legal cross-examination, and judicial scrutiny. 

Unlike traditional heuristic or probabilistic DFIR tools, Aletheia operates on a **zero-trust, Zero-AI deterministic core**: every conclusion is mathematically grounded in immutable hash chains, cryptographic Merkle trees, cross-artifact corroboration graphs, and smart contract state proofs.

This document details the **20 red-team attack classes** evaluated against Aletheia across three core security boundaries:
1. **Group A: Detection Bypass Attacks** (Adversary seeks to hide malicious actions or blind statistical engines).
2. **Group B: Integrity Guarantee Bypass Attacks** (Adversary seeks to forge, tamper with, or substitute evidence).
3. **Group C: Trust Model Bypass Attacks** (Adversary seeks to compromise keys, consensus, or platform governance).

---

## Threat Boundary Model

```
                    +------------------------------------------+
                    |           EXTERNAL THREAT ACTOR          |
                    | (Ransomware, APT, Rootkit, Rogue Insider)|
                    +--------------------+---------------------+
                                         |
            +----------------------------+----------------------------+
            |                            |                            |
            v                            v                            v
   [ Group A: Detection ]       [ Group B: Integrity ]       [ Group C: Trust Model ]
   - MAD Dilution Attacks       - TOCTOU Copy Inversion      - Key Compromise
   - Cross-Source Timestomp     - Ring-0 Rootkit/DMA         - Off-Chain Root Spoof
   - DAG Reparenting (LOLBins)  - Alternate Data Streams     - L2 Sequencer Halt
   - AST-Sigma/YARA Evasion     - Merkle Domain Confusion    - Smart Contract Bug
   - Monotonic Clock Rollback   - Non-Canonical JSON         - Rogue Examiner
            |                            |                            |
            +----------------------------+----------------------------+
                                         |
                                         v
                    +------------------------------------------+
                    |          ALETHEIA DEFENSE SHIELD         |
                    |  - Sub-50ms Dilution Detector            |
                    |  - 4-Way Timestamp Divergence Graph      |
                    |  - Monotonic Clock Jump Sentinel         |
                    |  - Single-FD O_EXCL Quarantine Lock      |
                    |  - RFC 8785 Canonical Serialization     |
                    |  - RFC 6962 0x00/0x01 Domain Separation  |
                    |  - Multi-Sig Security Council Key Ban    |
                    |  - Off-Chain Ingestion Hash Commitments  |
                    +------------------------------------------+
```

---

## Group A: Detection Bypass Attacks

### A.1 Statistical Poisoning & MAD Dilution Attacks
* **Attacker Objective**: Dilute the Median Absolute Deviation (MAD) and sliding-window Z-score metrics by flooding the event timeline with high-frequency synthetic events or uniform benign noise, rendering true anomaly spikes statistically indistinguishable.
* **Aletheia Mitigation (`chronotrace.analysis.anomalies`)**:
  * **Inter-Arrival Frequency Invariant**: Evaluates the density of sub-50ms inter-event arrival deltas. If synthetic uniform micro-bursts account for $>40\%$ of sequence volume, Aletheia triggers `STATISTICAL_DILUTION_ATTACK` (Severity: CRITICAL).
  * **Dual-Baseline Robustness**: Computes statistical variance against both localized timeline medians and calibrated historical baselines, preventing in-case dilution from masking high-severity exfiltration.

### A.2 Consistent Cross-Source Timestomping
* **Attacker Objective**: Systematically manipulate `$STANDARD_INFORMATION` (SIA), `$FILE_NAME` (FNA), Windows Event Logs (EVTX), and NTFS USN Journal timestamps to identical fraudulent timestamps, neutralizing naive timestamp comparison.
* **Aletheia Mitigation (`chronotrace.timeline.corroborator`)**:
  * **Multi-Layer Corroboration Engine**: Dissects NTFS USN Journal 64-bit monotonically incrementing sequence numbers (`UpdateSequenceNumber`) and `$MFT` sequence numbers which cannot be arbitrarily wound back without corrupting the file system cluster table.
  * **Source Diversity Requirement**: Cross-references filesystem records against external network flows, host hypervisor time-sync counters, and peripheral USB insertion history. Any divergence $\Delta t > 1.0\text{s}$ flags `DIVERGENT_TIMESTAMPS`.

### A.3 Process Lineage DAG Breaking (Double-Fork / LOLBin Reparenting)
* **Attacker Objective**: Sever process tree parent-child relationships via `CreateProcess` with `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`, double-forking, or API unhooking, making malware appear as a legitimate child of `explorer.exe` or `services.exe`.
* **Aletheia Mitigation (`chronotrace.analysis.graph`)**:
  * **Cryptographic Event Lineage**: Reconstructs execution flow using immutable Process Unique Identifiers (`CreateTime + PID + HostUID`).
  * **Multi-Vector Contextualization**: Rather than relying purely on parent PID, the graph engine correlates command-line arguments, user security identifiers (SIDs), token elevation privileges, image hashes, and injected module loads (`IMAGE_LOAD` events) to detect masqueraded LOLBins.

### A.4 AST-Sigma & YARA Rule Evasion
* **Attacker Objective**: Evade signature and keyword detection using code packing, string obfuscation, dynamic API resolution, and variable substitution.
* **Aletheia Mitigation (`chronotrace.analysis.sigma_ast`)**:
  * **Semantic AST Compilation**: Sigma rules are parsed into an Abstract Syntax Tree (AST) that evaluates semantic conditions rather than raw substring patterns.
  * **Behavioral Primitives**: Normalizes event fields into canonical forensic concepts (`process.executable`, `file.target_path`, `network.destination_ip`), ensuring rule execution occurs on decoded execution semantics.

### A.5 Uncaptured Evidence Classes
* **Attacker Objective**: Operate exclusively in unmonitored domains: volatile memory only, unallocated cluster slack space, or NTFS Alternate Data Streams (ADS).
* **Aletheia Mitigation (`chronotrace.acquire.imager`)**:
  * **Full Forensic Image Acquisition**: Supports raw physical sector imaging (`E01`, raw `.dd`) alongside selective artifact triage.
  * **Scope Attestation**: Generates an exhaustive ingestion manifest documenting exact acquisition boundaries, disk ranges, and artifact sets, precluding defense claims of selective evidence withholding.

### A.6 Monotonic Clock Manipulation & NTP Poisoning
* **Attacker Objective**: Roll back system time or poison NTP synchronization before executing malicious payloads to artificially backdate activity or bypass time-window filters.
* **Aletheia Mitigation (`chronotrace.analysis.anomalies.detect_clock_manipulation`)**:
  * **Non-Monotonic Backward Jump Sentinel**: Inspects raw ingestion order across individual host timelines. Any negative jump $(\Delta t < -5.0\text{s})$ immediately fires `CLOCK_MANIPULATION_DETECTED`.
  * **Audit Log Event 4616 Anchor**: Automatically scans Windows Security EVTX logs for Event ID 4616 (*System time was changed*) and correlates the change timestamp with subsequent timeline activity.

### A.7 Novel Anti-Forensics Techniques
* **Attacker Objective**: Exploit zero-day evasion tools that bypass static heuristic rulesets.
* **Aletheia Mitigation (`chronotrace.analysis.detector`)**:
  * **Zero-Heuristic Anomaly Spotlight**: Statistical burst engines, off-hours session correlation, and ransomware entropy spikes operate purely on mathematical distribution shifts without reliance on static signature databases.

---

## Group B: Integrity Guarantee Bypass Attacks

### B.1 TOCTOU Race Condition Between Hashing & Quarantine
* **Attacker Objective**: Exploit the time-of-check to time-of-use (TOCTOU) gap between evidence hash calculation and storage/quarantine to swap file content with benign data.
* **Aletheia Mitigation (`chronotrace.acquire.imager`)**:
  * **Atomic Single-Stream Dual Hashing**: Files are read sequentially through buffered chunks ($1\text{MB}$) where SHA-256 and MD5 hashes are updated simultaneously as bytes are written to destination storage.
  * **Post-Copy Verification Invariant**: Re-reads the quarantined destination file from disk, computes its SHA-256 hash, and strictly asserts `source_hash == dest_hash`. A mismatch throws `EvidenceCorruptError` and aborts ingestion immediately.

### B.2 Host Operating System Root / Kernel Compromise
* **Attacker Objective**: Subvert forensic tools by executing from kernel space (Ring 0 rootkit) or tampering with user-mode file system drivers during live analysis.
* **Aletheia Mitigation (`chronotrace.core.bundle`)**:
  * **Isolated Examiner Architecture**: Ingestion and acquisition can run from a trusted forensic live environment (WinPE or clean Linux boot image) mounting victim drives read-only.
  * **Immutable Cryptographic Bundling**: Once acquired, evidence files are packaged into zip/tar bundles sealed with Merkle trees; any subsequent tampering on the analysis workstation breaks tree verification.

### B.3 Direct Block-Device Access & Direct Memory Access (DMA)
* **Attacker Objective**: Bypass filesystem drivers entirely by writing directly to raw disk sectors via PCI-leech DMA hardware or raw volume handles.
* **Aletheia Mitigation (`chronotrace.acquire.write_blocker`)**:
  * **Physical & Software Write-Blocking**: Mandates hardware write-blocking bridges (Tableau / WiebeTech) or software read-only disk mounts (`mount -o ro,noload`) during raw drive acquisition.

### B.4 NTFS Alternate Data Streams (ADS) Concealment
* **Attacker Objective**: Hide malicious binaries or stolen data inside hidden NTFS streams (`file.txt:hidden.exe`), evading standard file enumeration.
* **Aletheia Mitigation (`chronotrace.parsers.ntfs`)**:
  * **Stream-Aware Parsing**: Enforces enumeration of `$DATA` attributes in NTFS Master File Table (`$MFT`) records, parsing and hashing unnamed and named data streams alike.

### B.5 Merkle Tree Domain Separation & Ambiguity Attacks
* **Attacker Objective**: Exploit tree ambiguity where intermediate nodes can be submitted as leaves or vice versa to forge valid cryptographic proofs.
* **Aletheia Mitigation (`chronotrace.integrity.merkle`)**:
  * **RFC 6962 Domain Separation**: Leaf hashes are strictly prefixed with `0x00`:
    $$\text{LeafHash}(x) = \text{SHA256}(0\text{x}00 \,||\, \text{canonical}(x))$$
  * Intermediate node hashes are strictly prefixed with `0x01`:
    $$\text{NodeHash}(L, R) = \text{SHA256}(0\text{x}01 \,||\, L \,||\, R)$$
  * This guarantees that a valid leaf hash can never satisfy intermediate branch validation.

### B.6 Non-Canonical JSON Serialization Malleability
* **Attacker Objective**: Exploit key reordering, whitespace variance, or unicode escape differences in JSON data to change the byte-level hash without altering the semantic object.
* **Aletheia Mitigation (`chronotrace.integrity.merkle.canonical_serialize`)**:
  * **RFC 8785 JSON Canonicalization Scheme (JCS)**: Keys are strictly sorted lexicographically by UTF-16 code units, delimiters are normalized to `(',', ':')`, character escapes follow RFC 8785, and output is encoded to raw UTF-8. 
  * Guaranteed 100% byte-for-byte reproducibility across Python, JavaScript, Go, and Solidity.

### B.7 Encryption Malleability & Ciphertext Bit-Flipping
* **Attacker Objective**: Modify encrypted evidence in transit using bit-flipping attacks against unauthenticated cipher modes (e.g. CBC without HMAC).
* **Aletheia Mitigation (`chronotrace.integrity.crypto`)**:
  * **Authenticated Encryption with Associated Data (AEAD)**: Employs AES-256-GCM or ChaCha20-Poly1305. Any alteration to ciphertext or initialization vector immediately fails GCM tag authentication.

### B.8 IPFS Content Inavailability & Data Disappearance
* **Attacker Objective**: Render off-chain evidence inaccessible by unpinning IPFS nodes or flooding the DHT.
* **Aletheia Mitigation (`chronotrace.store.ipfs`)**:
  * **Redundant Multi-Storage Architecture**: Evidence is pinned across distributed IPFS pinning clusters (Filecoin/Pinata/Web3.Storage) and stored locally in air-gapped forensic cold storage.
  * **Content Addressing Invariant**: The on-chain anchor commits to the SHA-256 Merkle root and IPFS CID. Even if IPFS is temporarily offline, the local archive can be mathematically proven against the on-chain root at any time.

---

## Group C: Trust Model Bypass Attacks

### C.1 Compromise of Investigator Private Key
* **Attacker Objective**: Steal the private key of an investigator to publish fraudulent evidence attestations or backdate incidents.
* **Aletheia Mitigation (`contracts/AletheiaRegistry.sol`)**:
  * **Multi-Sig Security Council Key Revocation**: `AletheiaRegistry.sol` provides `revokeInvestigatorKey(address)` governed exclusively by the multi-sig `securityCouncil`.
  * **Revocation Flagging**: If a key is compromised, the council immediately revokes it on-chain. All subsequent attempts to anchor cases from that key revert (`KeyIsRevoked()`).

### C.2 Off-Chain Merkle Root Computation Spoofing
* **Attacker Objective**: The investigator or an attacker with software control computes an arbitrary Merkle root over fabricated events and anchors it to the blockchain.
* **Aletheia Mitigation (`contracts/AletheiaRegistry.sol`)**:
  * **Two-Phase Ingestion Commitment**: Ingested raw source data hashes must be anchored via `anchorIngestionCommitment(bytes32 caseId, bytes32 ingestionHash)` prior to timeline generation.
  * **Open Independent Reproducibility (Daubert Standard)**: Any third-party expert can re-run the open-source CLI on the raw evidence bundle. If the resulting Merkle root does not equal the on-chain root, the evidence is immediately rejected by the court.

### C.3 L2 Sequencer Centralization, Censorship & Reorg
* **Attacker Objective**: Exploit Base L2 sequencer downtime or potential micro-reorganizations to dispute the finality or timestamp of anchored attestations.
* **Aletheia Mitigation (`contracts/AletheiaRegistry.sol`)**:
  * **Multi-Chain Fallback Interface**: Registry smart contracts are EVM-native and chain-agnostic. Anchoring can be dual-committed to Base L2 (for sub-cent transaction costs) and Ethereum L1 or Arbitrum (for maximum censorship resistance).
  * **Block Number + Block Timestamp Storage**: Stores both `block.timestamp` and `block.number` to verify chronological depth and avoid reorg ambiguities.

### C.4 Smart Contract Logic Vulnerabilities & Storage Collisions
* **Attacker Objective**: Exploit reentrancy, integer overflow, or access control flaws to overwrite existing case roots or drain funds.
* **Aletheia Mitigation (`contracts/AletheiaRegistry.sol`)**:
  * **Immutable Append-Only Records**: Once a case Merkle root is recorded, the contract explicitly checks `cases[caseId].merkleRoot == bytes32(0)`. Attempting to overwrite an existing case reverts with `CaseAlreadyExists()`.
  * **No Fund Storage**: `AletheiaRegistry.sol` holds no ether and contains no payable transfer logic, eliminating reentrancy, flash loan, and drain vectors.

### C.5 Rogue Examiner / Insider Tampering
* **Attacker Objective**: A corrupt forensic analyst attempts to alter notes, delete incriminating events, or falsify chain-of-custody logs.
* **Aletheia Mitigation (`chronotrace.core.bundle`)**:
  * **Cryptographic Examiner Signature**: Every forensic action, note, and tool invocation is recorded with the examiner's public key into a cryptographically sealed chain-of-custody log.
  * **Dual-Signer Multi-Party Attestation**: High-impact evidence submissions require EAS (Ethereum Attestation Service) counter-attestations from independent co-examiners or automated CI verifiers.

---

## Adversarial Verification Test Suite

All defense mechanisms are backed by automated adversarial unit and integration tests located in `tests/test_adversarial_defenses.py`:

| Test Name | Attack Class | Defensive Invariant Verified | Result |
|---|---|---|:---:|
| `test_adversarial_mad_dilution_attack_detected` | A.1 MAD Dilution | Catches $>40\%$ sub-50ms synthetic log flooding with CRITICAL alert | **PASS** |
| `test_adversarial_clock_rollback_detected` | A.6 Clock Manipulation | Detects sequential negative timestamp jumps ($\Delta t < -5\text{s}$) | **PASS** |
| `test_adversarial_event_4616_clock_tamper_detected` | A.6 Clock Manipulation | Surfaces Windows Security Event ID 4616 (*System time was changed*) | **PASS** |
| `test_adversarial_toctou_readback_detection` | B.1 TOCTOU Race | Re-reads quarantined output file and validates byte hash against input | **PASS** |
| `test_adversarial_canonical_json_stability` | B.6 Non-Canonical JSON | Enforces RFC 8785 byte equivalence across reordered dictionaries | **PASS** |

---

## Conclusion & Legal Defense Posture

Under **Federal Rule of Evidence 902(14)**, digital evidence is self-authenticating only when accompanied by a certification of an expert showing that the process or system produced an accurate result. Under the **Daubert Standard** (509 U.S. 579), the methodology must be testable, have known error rates, and possess peer-reviewed reproducibility.

Aletheia's adversarial defense architecture ensures that:
1. **Adversary attempts to dilute or poison detection** trigger explicit high-priority alerts.
2. **Adversary attempts to alter evidence** break Merkle trees and fail RFC 8785 canonical verification.
3. **Adversary attempts to compromise keys** are mitigated via on-chain multi-sig revocation.

Aletheia does not ask courts or examiners to trust it—**it gives them the mathematical and cryptographic tools to verify it.**
