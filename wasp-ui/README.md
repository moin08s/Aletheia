# 🏛️ Aletheia Console (Frontend Web Interface)

The official single-page web console for **Aletheia: The Incorruptible Witness on Ethereum**.

Built with **React 19, TypeScript, and Vite**, connecting directly to the Aletheia FastAPI backend for real-time digital forensics, Web3 incident attestation, and on-chain tamper detection.

---

## 🌟 Key Features

1. **Super-Timeline & Breach Replay Scrubber**:
   - Scrub through incidents with automated sequential playback.
   - Live visual severity indicators on critical MITRE ATT&CK techniques.
2. **Web3 Attestation & Decentralized Chain of Custody**:
   - 1-Click anchoring to **Base Sepolia (L2)** and **IPFS / Filecoin**.
   - Direct deep-links to **EASScan** and **BaseScan**.
3. **1-Click On-Chain Tamper Verification**:
   - Compares local disk files and Merkle roots against immutable on-chain smart contract state.
   - Instantly raises a red alert if 1 byte of host evidence was modified.
4. **Zero-Knowledge (ZK) Selective Disclosure Proof Generator**:
   - Generates Groth16 / BN254 ZK-SNARK verification cards proving an exploit occurred without leaking private client IP addresses or employee PII.

---

## 🛠️ Development & Build

```powershell
# Install dependencies
npm install

# Run local development server
npm run dev

# Compile production bundle
npm run build
```
