# Contributing to Aletheia

Thank you for your interest in contributing to **Aletheia** (*The Incorruptible Witness on Ethereum*). 

Aletheia is a court-grade Digital Forensics and Incident Response (DeDFIR) system. Because digital evidence processed by this platform is designed for **court admissibility under FRE 902(14) and the Daubert Standard**, code quality and mathematical determinism standards are exceptionally strict.

---

## The Zero-LLM / Zero-AI Forensic Mandate

> [!IMPORTANT]
> **No generative AI or Large Language Model (LLM) components are permitted within forensic ingestion, normalization, timeline compilation, or scoring pipelines.**

Forensic analysis must be:
1. **Deterministic**: Given identical evidence bytes $E$, the engine must produce identical timeline $T$ and identical Merkle root $R$ across all operating systems.
2. **Mathematically Auditable**: An expert witness must be able to explain the exact mathematical formula (e.g. median absolute deviation, Z-score, RFC 6962 tree traversal) to a legal court without probabilistic uncertainty.

---

## Development Setup

### 1. Requirements
- Python 3.11, 3.12, or 3.13
- Node.js 18+ and npm (for `wasp-ui`)
- Git

### 2. Local Environment
```powershell
# Clone the repository
git clone https://github.com/moin08s/Aletheia.git
cd Aletheia

# Create and activate virtual environment
python -m venv .venv
# On Windows:
.venv\Scripts\Activate.ps1
# On POSIX:
source .venv/bin/activate

# Install dependencies
python -m pip install -r requirements.txt
```

### 3. Running Automated Tests
All pull requests must pass the complete automated test suite:
```powershell
python -m pytest -v
```

---

## Coding Guidelines

1. **Type Annotations**: All Python code must include static type annotations (`from __future__ import annotations`).
2. **Cross-Platform Compatibility**: Code must run identically on Windows 10/11, Ubuntu 22.04/24.04, and macOS. Use `pathlib.Path` exclusively instead of raw string path concatenation.
3. **Write-Quarantine Integrity**: Never modify or mutate evidence files in place. Read operations must treat evidence directories as read-only.
4. **Domain Separation**: All Merkle leaf calculations must prepend domain prefix `0x00`, and interior nodes must prepend `0x01` in accordance with RFC 6962.

---

## Pull Request Process

1. Fork the repository and create your branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. Write unit tests for all new parsers, detection rules, or API endpoints.
3. Ensure all tests pass (`python -m pytest`).
4. Commit your changes with conventional commit messages:
   - `feat(parser)`: add support for new artifact
   - `fix(integrity)`: address verification edge case
   - `docs(legal)`: expand Daubert compliance documentation
5. Push to your fork and submit a Pull Request to `main`.
