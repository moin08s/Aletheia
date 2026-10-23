# Aletheia Adversarial Defense & Threat Matrix

> **Evidentiary Standard Mapping**: Designed to support authentication under FRE 902(14) (Self-Authenticating Electronic Data) | Daubert Standard (509 U.S. 579) | RFC 8785 JSON Canonicalization | RFC 6962 Merkle Audit Path | ISO/IEC 27037 Digital Evidence Handling

---

## Executive Summary

Aletheia is an evidence-grade, deterministic digital forensics and incident response (DFIR) platform designed to be **tamper-evident under documented trust assumptions**, supporting rigorous judicial scrutiny and expert cross-examination.

Unlike probabilistic or heuristic DFIR tools, Aletheia operates on a **zero-trust, Zero-AI deterministic core**: forensic conclusions are grounded in immutable hash chains, cryptographic Merkle trees with RFC 6962 domain separation, cross-artifact corroboration graphs, and EVM smart contract state proofs.

This document provides a systematic evaluation of **20 enumerated red-team attack classes** across three core security boundaries:
1. **Group A: Detection Bypass Attacks** (Adversary seeks to conceal malicious actions or blind statistical anomaly engines).
2. **Group B: Integrity Guarantee Bypass Attacks** (Adversary seeks to forge, tamper with, or substitute evidence).
3. **Group C: Trust Model Bypass Attacks** (Adversary seeks to compromise keys, consensus, or governance).

Every attack is categorized by its engineering status:
- `IMPLEMENTED`: Actively protected by verified code and automated unit/integration tests in the repository.
- `MANDATED (policy)`: Addressed via mandatory operational policy, trusted execution boundaries, or hardware controls.
- `OUT OF SCOPE`: External infrastructure dependencies (e.g., L2 sequencer liveness, decentralized pinning networks).
- `UNAUDITED ASSUMPTION / POLICY`: Follows standard security design practices, but awaiting third-party formal audit.

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
                    |  - Sub-50ms & CV Cadence Dilution Sentinel|
                    |  - 4-Way Timestamp Divergence Graph      |
                    |  - Non-Monotonic Backward & Forward Leap |
                    |  - Single-FD Streaming Atomic Hashing    |
                    |  - RFC 8785 Canonical Serialization     |
                    |  - RFC 6962 0x00/0x01 Domain Separation  |
                    |  - Multi-Sig Security Council Key Ban    |
                    |  - Off-Chain Ingestion Hash Commitments  |
                    |  - Mandatory Peer Co-Signer Verification |
                    +------------------------------------------+
```

---

## ⚠️ Residual Risk & Architectural Limitations

Forensic integrity guarantees depend strictly on documented trust assumptions. Aletheia does **not** defend against the following threat vectors:

1. **Active Ring-0 / Kernel Rootkit During Live Acquisition**:
   If an adversary controls the host kernel while live acquisition commands run, the kernel can spoof `read()` syscall responses. *Mitigation*: Live acquisition is untrusted; forensic standards mandate physical acquisition via cold boot or WinPE/Linux live forensic environment.
2. **Direct Memory Access (DMA) Without Hardware Write-Blocker**:
   An adversary with physical bus access (PCIe / Thunderbolt / FireWire) can modify disk controller firmware or write directly to flash blocks. *Mitigation*: Physical acquisition requires a hardware write-blocking bridge (Tableau / WiebeTech).
3. **Pre-Ingestion Host Admin Log Destruction**:
   If an administrator with elevated privileges disables the Windows Event Log service (`EventLog`) or executes disk wiping (`srm` / `shred`) *prior* to forensic engagement, Aletheia faithfully reports the absence of records. It cannot reconstruct data never recorded by the OS.
4. **Host Hypervisor / SMM / Firmware Compromise**:
   System Management Mode (SMM) rootkits or compromised hypervisors can manipulate hardware timers and physical memory below the operating system layer.
5. **Decentralized Network Partitioning**:
   If public IPFS gateways or the Base L2 sequencer experience sustained partition or outage, off-chain retrieval and on-chain anchoring must fall back to local air-gapped bundles and secondary EVM networks.

---

## Group A: Detection Bypass Attacks

### A.1 Statistical Poisoning & MAD Dilution Attacks
* **Status**: `IMPLEMENTED`
* **Attacker Objective**: Dilute the Median Absolute Deviation (MAD) and sliding-window Z-score metrics by flooding the event timeline with high-frequency synthetic events or uniform benign noise, rendering true anomaly spikes statistically indistinguishable.
* **Aletheia Mitigation (`chronotrace.analysis.anomalies.detect_statistical_dilution`)**:
  * **Inter-Arrival Frequency Invariant**: Evaluates the density of sub-50ms inter-event arrival deltas. If synthetic uniform micro-bursts account for $>40\%$ of sequence volume, Aletheia triggers `STATISTICAL_DILUTION_ATTACK` (Severity: CRITICAL).
  * **Synthetic Cadence & Low-Dispersion Sentinel**: Computes the Coefficient of Variation ($CV = \frac{\sigma}{\mu}$) over sequential inter-arrival times. Automated pacing (e.g., 60ms or 100ms script intervals) exhibits abnormally low variance ($CV < 0.20$, compared to stochastic natural activity where $CV \ge 0.80$), immediately firing `STATISTICAL_DILUTION_SYNTHETIC_CADENCE`.

### A.2 Consistent Cross-Source Timestomping
* **Status**: `IMPLEMENTED`
* **Attacker Objective**: Systematically manipulate `$STANDARD_INFORMATION` (SIA), `$FILE_NAME` (FNA), Windows Event Logs (EVTX), and NTFS USN Journal timestamps to identical fraudulent timestamps, neutralizing naive timestamp comparison.
* **Aletheia Mitigation (`chronotrace.timeline.corroborator`)**:
  * **Multi-Layer Corroboration Engine**: Dissects NTFS USN Journal 64-bit monotonically incrementing sequence numbers (`UpdateSequenceNumber`) and `$MFT` sequence numbers which cannot be arbitrarily wound back without corrupting the file system cluster table.
  * **Source Diversity Requirement**: Cross-references filesystem records against external network flows, host hypervisor time-sync counters, and peripheral USB insertion history. Any divergence $\Delta t > 1.0\text{s}$ flags `DIVERGENT_TIMESTAMPS`.

### A.3 Process Lineage DAG Breaking (Double-Fork / LOLBin Reparenting)
* **Status**: `IMPLEMENTED`
* **Attacker Objective**: Sever process tree parent-child relationships via `CreateProcess` with `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`, double-forking, or API unhooking, making malware appear as a legitimate child of `explorer.exe` or `services.exe`.
* **Aletheia Mitigation (`chronotrace.analysis.graph`)**:
  * **Cryptographic Event Lineage**: Reconstructs execution flow using immutable Process Unique Identifiers (`CreateTime + PID + HostUID`).
  * **Multi-Vector Contextualization**: Rather than relying purely on parent PID, the graph engine correlates command-line arguments, user security identifiers (SIDs), token elevation privileges, image hashes, and injected module loads (`IMAGE_LOAD` events) to detect masqueraded LOLBins.

### A.4 AST-Sigma & YARA Rule Evasion
* **Status**: `IMPLEMENTED`
* **Attacker Objective**: Evade signature and keyword detection using code packing, string obfuscation, dynamic API resolution, and variable substitution.
* **Aletheia Mitigation (`chronotrace.analysis.sigma_ast`)**:
  * **Semantic AST Compilation**: Sigma rules are parsed into an Abstract Syntax Tree (AST) that evaluates semantic conditions rather than raw substring patterns.
  * **Behavioral Primitives**: Normalizes event fields into canonical forensic concepts (`process.executable`, `file.target_path`, `network.destination_ip`), ensuring rule execution occurs on decoded execution semantics.

### A.5 Uncaptured Evidence Classes
* **Status**: `MANDATED (policy)`
* **Attacker Objective**: Operate exclusively in unmonitored domains: volatile memory only, unallocated cluster slack space, or NTFS Alternate Data Streams (ADS).
* **Aletheia Mitigation (`chronotrace.acquire.imager`)**:
  * **Full Forensic Image Acquisition**: Supports raw physical sector imaging (`E01`, raw `.dd`) alongside selective artifact triage.
  * **Scope Attestation**: Generates an exhaustive ingestion manifest documenting exact acquisition boundaries, disk ranges, and artifact sets, precluding defense claims of selective evidence withholding.

### A.6 Monotonic Clock Manipulation & NTP Poisoning
* **Status**: `IMPLEMENTED`
* **Attacker Objective**: Roll back system time or poison NTP synchronization before executing malicious payloads to artificially backdate activity or bypass time-window filters.
* **Aletheia Mitigation (`chronotrace.analysis.anomalies.detect_clock_manipulation`)**:
  * **Non-Monotonic Backward Jump Sentinel**: Inspects raw ingestion order across individual host timelines. Any negative jump $(\Delta t < -5.0\text{s})$ immediately fires `CLOCK_MANIPULATION_DETECTED`.
  * **Forward Leap Sentinel**: Sequential logs jumping forward by $>24.0\text{ hours}$ without an intervening system shutdown/reboot fire `CLOCK_FORWARD_LEAP_ANOMALY`.
  * **Audit Log Event 4616 Anchor**: Scans Windows Security EVTX logs for Event ID 4616 (*System time was changed*) and correlates the change timestamp with subsequent timeline activity.

### A.7 Novel Anti-Forensics Techniques
* **Status**: `IMPLEMENTED`
* **Attacker Objective**: Exploit zero-day evasion tools that bypass static heuristic rulesets.
* **Aletheia Mitigation (`chronotrace.analysis.detector`)**:
  * **Zero-Heuristic Anomaly Spotlight**: Statistical burst engines, off-hours session correlation, and ransomware entropy spikes operate purely on mathematical distribution shifts without reliance on static signature databases.

---

## Group B: Integrity Guarantee Bypass Attacks

### B.1 TOCTOU Race Condition Between Hashing & Quarantine
* **Status**: `IMPLEMENTED`
* **Attacker Objective**: Exploit the time-of-check to time-of-use (TOCTOU) gap between evidence hash calculation and storage/quarantine to swap file content with benign data.
* **Aletheia Mitigation (`chronotrace.acquire.hasher.stream_copy_and_hash`)**:
  * **Single-FD Streaming Atomic Hashing**: The source file is opened once as an open file descriptor (`f_src`). In a single unified buffer loop ($8\text{ MiB}$ chunks), data is read, fed to SHA-256/MD5 accumulators, and immediately written to destination file descriptor (`f_dst`). There is zero gap between reading, hashing, and writing.
  * **Post-Copy Disk Readback Verification**: After writing, the quarantined destination file is re-read from disk and its SHA-256 hash verified against the streaming digest. A mismatch raises `EvidenceCorruptError` and removes the file.

### B.2 Host Operating System Root / Kernel Compromise
* **Status**: `MANDATED (policy)`
* **Attacker Objective**: Subvert forensic tools by executing from kernel space (Ring 0 rootkit) or tampering with user-mode file system drivers during live analysis.
* **Aletheia Mitigation (`chronotrace.core.bundle`)**:
  * **Isolated Examiner Architecture**: Ingestion and acquisition must run from a trusted forensic live environment (WinPE or clean Linux boot image) mounting victim drives read-only.
  * **Immutable Cryptographic Bundling**: Once acquired, evidence files are packaged into `.wasp` containers sealed with Merkle trees and HMAC signatures.

### B.3 Direct Block-Device Access & Direct Memory Access (DMA)
* **Status**: `MANDATED (policy)`
* **Attacker Objective**: Bypass filesystem drivers entirely by writing directly to raw disk sectors via PCI-leech DMA hardware or raw volume handles.
* **Aletheia Mitigation (`chronotrace.acquire.write_blocker`)**:
  * **Physical & Software Write-Blocking**: Mandates hardware write-blocking bridges (Tableau / WiebeTech) or software read-only disk mounts (`mount -o ro,noload`) during raw drive acquisition.

### B.4 NTFS Alternate Data Streams (ADS) Concealment
* **Status**: `IMPLEMENTED`
* **Attacker Objective**: Hide malicious binaries or stolen data inside hidden NTFS streams (`file.txt:hidden.exe`), evading standard file enumeration.
* **Aletheia Mitigation (`chronotrace.parsers.ntfs`)**:
  * **Stream-Aware Parsing**: Enforces enumeration of `$DATA` attributes in NTFS Master File Table (`$MFT`) records, parsing and hashing unnamed and named data streams alike.

### B.5 Merkle Tree Domain Separation & Ambiguity Attacks
* **Status**: `IMPLEMENTED`
* **Attacker Objective**: Exploit tree ambiguity where intermediate nodes can be submitted as leaves or vice versa to forge valid cryptographic proofs.
* **Aletheia Mitigation (`chronotrace.integrity.merkle`)**:
  * **RFC 6962 Domain Separation**: Leaf hashes are strictly prefixed with `0x00`:
    $$\text{LeafHash}(x) = \text{SHA256}(0\text{x}00 \,||\, \text{canonical}(x))$$
  * Intermediate node hashes are strictly prefixed with `0x01`:
    $$\text{NodeHash}(L, R) = \text{SHA256}(0\text{x}01 \,||\, L \,||\, R)$$
  * Guarantees that a valid leaf hash can never satisfy intermediate branch validation.

### B.6 Non-Canonical JSON Serialization Malleability
* **Status**: `IMPLEMENTED`
* **Attacker Objective**: Exploit key reordering, whitespace variance, or unicode escape differences in JSON data to change the byte-level hash without altering the semantic object.
* **Aletheia Mitigation (`chronotrace.integrity.merkle.canonical_serialize`)**:
  * **RFC 8785 JSON Canonicalization Scheme (JCS)**: Keys are strictly sorted lexicographically by UTF-16 code units, delimiters are normalized to `(',', ':')`, character escapes follow RFC 8785, and output is encoded to raw UTF-8. 
  * Guaranteed 100% byte-for-byte reproducibility across Python, JavaScript, Go, and Solidity.

### B.7 Encryption Malleability & Ciphertext Bit-Flipping
* **Status**: `MANDATED (policy) / PLANNED`
* **Attacker Objective**: Modify encrypted evidence in transit using bit-flipping attacks against unauthenticated cipher modes (e.g. CBC without HMAC).
* **Aletheia Mitigation**:
  * **HMAC-SHA256 Container Sealing**: `.wasp` container archives are authenticated via HMAC-SHA256 over the canonical Merkle root.
  * **Policy Mandate**: Payload encryption-at-rest requires authenticated ciphers (AES-256-GCM / ChaCha20-Poly1305) when transmitting bundles over untrusted channels.

### B.8 IPFS Content Inavailability & Data Disappearance
* **Status**: `OUT OF SCOPE (external infrastructure)`
* **Attacker Objective**: Render off-chain evidence inaccessible by unpinning IPFS nodes or flooding the DHT.
* **Aletheia Mitigation (`chronotrace.store.ipfs`)**:
  * **Redundant Multi-Storage Architecture**: Evidence bundles are stored locally in air-gapped forensic storage and pinned to IPFS gateways.
  * **Content Addressing Invariant**: The on-chain anchor commits to the SHA-256 Merkle root and IPFS CID. If IPFS is temporarily offline, the local archive can still be mathematically authenticated against the on-chain root.

---

## Group C: Trust Model Bypass Attacks

### C.1 Compromise of Investigator Private Key
* **Status**: `IMPLEMENTED`
* **Attacker Objective**: Steal the private key of an investigator to publish fraudulent evidence attestations or backdate incidents.
* **Aletheia Mitigation (`contracts/AletheiaRegistry.sol`)**:
  * **Multi-Sig Security Council Key Revocation**: `AletheiaRegistry.sol` provides `revokeInvestigatorKey(address)` governed exclusively by the multi-sig `securityCouncil`.
  * **Revocation Flagging**: If a key is compromised, the council revokes it on-chain. All subsequent attempts to anchor cases or register proofs from that key revert (`RevokedInvestigatorCannotAct`).

### C.2 Off-Chain Merkle Root Computation Spoofing
* **Status**: `IMPLEMENTED`
* **Attacker Objective**: The investigator or an attacker with software control computes an arbitrary Merkle root over fabricated events and anchors it to the blockchain.
* **Aletheia Mitigation (`contracts/AletheiaRegistry.sol`)**:
  * **Two-Phase Ingestion Commitment**: Ingested raw source data hashes must be anchored via `anchorIngestionCommitment(bytes32 caseId, bytes32 ingestionHash)` prior to timeline generation.
  * **Independent Reproducibility**: Any third-party expert can re-run the open-source CLI on the raw evidence bundle. If the resulting Merkle root does not equal the on-chain root, the evidence does not match the on-chain commitment; authentication fails.

### C.3 L2 Sequencer Centralization, Censorship & Reorg
* **Status**: `OUT OF SCOPE (L2 consensus)`
* **Attacker Objective**: Exploit Base L2 sequencer downtime or potential micro-reorganizations to dispute the finality or timestamp of anchored attestations.
* **Aletheia Mitigation (`contracts/AletheiaRegistry.sol`)**:
  * **Chain-Agnostic Interface**: The smart contract is standard EVM Solidity and can be deployed directly to Ethereum L1, Arbitrum, Optimism, or Base.
  * **Block Number + Block Timestamp Storage**: Stores both `block.timestamp` and `block.number` to verify chronological depth.

### C.4 Smart Contract Logic Vulnerabilities & Storage Collisions
* **Status**: `UNAUDITED ASSUMPTION / POLICY`
* **Attacker Objective**: Exploit reentrancy, integer overflow, or access control flaws to overwrite existing case roots or drain funds.
* **Aletheia Mitigation (`contracts/AletheiaRegistry.sol`)**:
  * **Immutable Append-Only Records**: Once a case Merkle root is recorded, the contract explicitly checks `cases[caseId].registeredAt == 0`. Overwriting an existing case reverts with `CaseAlreadyExists()`.
  * **No Fund Storage**: `AletheiaRegistry.sol` holds no ether and contains no payable transfer logic, eliminating reentrancy, flash loan, and drain vectors.
  * **Notice**: While adhering to Solidity best practices, formal third-party audit verification is pending.

### C.5 Rogue Examiner / Insider Tampering
* **Status**: `IMPLEMENTED`
* **Attacker Objective**: A corrupt forensic analyst attempts to alter notes, delete incriminating events, or falsify chain-of-custody logs.
* **Aletheia Mitigation (`contracts/AletheiaRegistry.sol` & `chronotrace.core.bundle`)**:
  * **Cryptographic Examiner Signature**: Every forensic action is recorded with the examiner's public key into a cryptographically sealed chain-of-custody log.
  * **Mandatory Dual-Sign-Off**: `AletheiaRegistry.sol` provides `coSignCase(bytes32 caseId)` and `isDualSigned(bytes32 caseId)`. High-impact evidence submissions mandate independent peer-examiner co-signing before court submission.

---

## Adversarial Verification Test Suite

All implemented defense mechanisms are backed by automated adversarial unit and integration tests located in `tests/test_adversarial_defenses.py`:

| Test Name | Attack Class | Defensive Invariant Verified | Status | Result |
|---|---|---|:---:|:---:|
| `test_adversarial_mad_dilution_attack_detected` | A.1 MAD Dilution | Catches $>40\%$ sub-50ms synthetic log flooding with CRITICAL alert | `IMPLEMENTED` | **PASS** |
| `test_adversarial_60ms_paced_dilution_detected` | A.1 MAD Dilution | Catches 60ms-paced injection via low-dispersion CV check ($CV < 0.20$) | `IMPLEMENTED` | **PASS** |
| `test_adversarial_clock_rollback_detected` | A.6 Clock Manipulation | Detects sequential negative timestamp jumps ($\Delta t < -5\text{s}$) | `IMPLEMENTED` | **PASS** |
| `test_adversarial_clock_forward_leap_detected` | A.6 Clock Manipulation | Detects unexplained forward timestamp leaps ($> 24\text{ hours}$) | `IMPLEMENTED` | **PASS** |
| `test_adversarial_event_4616_clock_tamper_detected` | A.6 Clock Manipulation | Surfaces Windows Security Event ID 4616 (*System time was changed*) | `IMPLEMENTED` | **PASS** |
| `test_adversarial_toctou_readback_detection` | B.1 TOCTOU Race | Re-reads quarantined output file and validates byte hash against input | `IMPLEMENTED` | **PASS** |
| `test_adversarial_stream_copy_hasher_fd` | B.1 TOCTOU Race | Single-FD stream copy and multi-hash atomic loop without gap | `IMPLEMENTED` | **PASS** |
| `test_adversarial_canonical_json_stability` | B.6 Non-Canonical JSON | Enforces RFC 8785 byte equivalence across reordered dictionaries | `IMPLEMENTED` | **PASS** |
| `test_adversarial_dual_signed_attestation` | C.5 Rogue Insider | Verifies mandatory dual sign-off co-signing data model | `IMPLEMENTED` | **PASS** |

---

## Conclusion & Legal Defense Posture

Under **Federal Rule of Evidence 902(14)**, digital evidence is self-authenticating when accompanied by a certification of a qualified person showing that the process or system produced an accurate result. Under the **Daubert Standard** (509 U.S. 579), the methodology must be testable, have known error rates, and possess peer-reviewed reproducibility.

Aletheia's defense architecture ensures that:
1. **Adversary attempts to dilute or poison detection** trigger explicit high-priority alerts.
2. **Adversary attempts to alter evidence** break Merkle trees and fail RFC 8785 canonical verification.
3. **Adversary attempts to compromise keys** are mitigated via on-chain multi-sig revocation.

Aletheia does not claim absolute invulnerability; rather, it provides **verifiable tamper-evidence, explicit threat boundaries, and documented residual risk**.
