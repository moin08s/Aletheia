"""Deterministic Signed Case Bundle Engine for WASP (.wasp container).

Packages a forensic case workspace (evidence, custody ledger, index, derived artifacts,
TSA tokens, and reports) into an immutable, deterministically hashed, cryptographically
signed single-file '.wasp' or AES-256-GCM encrypted '.wasp.enc' bundle for courtroom submission.
"""

from __future__ import annotations
import hashlib
import hmac
import io
import json
import os
import tarfile
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from chronotrace.integrity.merkle import MerkleTree

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_AESGCM = True
except ImportError:
    AESGCM = None
    HAS_AESGCM = False


@dataclass
class BundleVerificationResult:
    """Outcome of verifying a .wasp container."""
    is_valid: bool
    case_id: str
    merkle_root: str
    files_checked: int
    signature_present: bool
    signature_valid: Optional[bool]
    is_encrypted: bool = False
    errors: List[str] = field(default_factory=list)
    manifest_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "case_id": self.case_id,
            "merkle_root": self.merkle_root,
            "files_checked": self.files_checked,
            "signature_present": self.signature_present,
            "signature_valid": self.signature_valid,
            "is_encrypted": self.is_encrypted,
            "errors": self.errors,
            "manifest_data": self.manifest_data,
        }


class CaseBundleManager:
    """Manages creation, signing, encryption, verification, and extraction of .wasp bundles."""

    MANIFEST_FILENAME = "bundle_manifest.json"
    ENC_MAGIC = b"WASPENC1"
    PBKDF2_ROUNDS = 100_000

    @staticmethod
    def _compute_key(secret_key: Optional[bytes] = None, passphrase: Optional[str] = None) -> Optional[bytes]:
        if secret_key:
            return secret_key
        if passphrase:
            return hashlib.sha256(passphrase.encode("utf-8")).digest()
        return None

    @classmethod
    def _derive_aes_key(cls, passphrase: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, cls.PBKDF2_ROUNDS, 32)

    @classmethod
    def encrypt_file(cls, input_path: Path, output_path: Path, passphrase: str) -> Path:
        """Encrypts an archive file using AES-256-GCM with PBKDF2 key derivation."""
        if not HAS_AESGCM or AESGCM is None:
            raise RuntimeError("cryptography package is required for AES-256-GCM encryption")

        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = cls._derive_aes_key(passphrase, salt)
        aesgcm = AESGCM(key)

        data = input_path.read_bytes()
        aad = cls.ENC_MAGIC + salt + nonce
        ciphertext = aesgcm.encrypt(nonce, data, aad)

        with open(output_path, "wb") as f:
            f.write(aad + ciphertext)

        return output_path

    @classmethod
    def decrypt_file(cls, input_path: Path, output_path: Path, passphrase: str) -> Path:
        """Decrypts a WASPENC1 archive using AES-256-GCM and verifies authentication tag."""
        if not HAS_AESGCM or AESGCM is None:
            raise RuntimeError("cryptography package is required for AES-256-GCM decryption")

        raw = input_path.read_bytes()
        magic_len = len(cls.ENC_MAGIC)
        if len(raw) < magic_len + 16 + 12 + 16 or not raw.startswith(cls.ENC_MAGIC):
            raise ValueError("File is not a valid WASP encrypted container (missing or invalid magic header)")

        salt = raw[magic_len : magic_len + 16]
        nonce = raw[magic_len + 16 : magic_len + 28]
        ciphertext = raw[magic_len + 28 :]
        aad = cls.ENC_MAGIC + salt + nonce

        key = cls._derive_aes_key(passphrase, salt)
        aesgcm = AESGCM(key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        except Exception as e:
            raise ValueError("Decryption failed: invalid passphrase or tampered ciphertext (AES-GCM authentication failed)") from e

        output_path.write_bytes(plaintext)
        return output_path

    @classmethod
    def export_bundle(
        cls,
        case_dir: str | Path,
        output_file: Optional[str | Path] = None,
        secret_key: Optional[bytes] = None,
        passphrase: Optional[str] = None,
        encrypt: bool = False,
    ) -> Path:
        """Package a case into an immutable, cryptographically signed, and optionally encrypted .wasp bundle."""
        case_root = Path(case_dir).resolve()
        case_json = case_root / "case.json"
        if not case_json.exists():
            raise FileNotFoundError(f"Invalid case directory (missing case.json): {case_root}")

        with open(case_json, "r", encoding="utf-8") as f:
            case_data = json.load(f)

        case_id = case_data.get("case_id", "CASE-UNKNOWN")

        ext = ".wasp.enc" if encrypt else ".wasp"
        if output_file is None:
            output_path = case_root.parent / f"{case_id}{ext}"
        else:
            output_path = Path(output_file).resolve()

        output_path.parent.mkdir(parents=True, exist_ok=True)

        # 1. Collect all valid case files (sorted for determinism)
        file_entries: Dict[str, Dict[str, Any]] = {}
        all_files: List[Path] = []

        for root, dirs, files in os.walk(case_root):
            dirs[:] = [d for d in dirs if d not in ("__pycache__", ".git", ".pytest_cache")]
            for file in sorted(files):
                if file.endswith((".pyc", ".tmp")) or file == output_path.name:
                    continue
                full_path = Path(root) / file
                all_files.append(full_path)

        all_files.sort(key=lambda p: str(p.relative_to(case_root)).replace("\\", "/"))

        # 2. Hash each file & build leaf hashes for Merkle Tree
        leaf_hashes: List[str] = []
        for file_path in all_files:
            rel_path = str(file_path.relative_to(case_root)).replace("\\", "/")
            hasher = hashlib.sha256()
            with open(file_path, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            file_hash = hasher.hexdigest()
            file_size = file_path.stat().st_size
            file_entries[rel_path] = {
                "sha256": file_hash,
                "size_bytes": file_size,
            }
            leaf_hashes.append(file_hash)

        # 3. Calculate Merkle Root
        merkle_root = MerkleTree.compute_root(leaf_hashes) if leaf_hashes else "0" * 64

        # 4. Compute cryptographic HMAC signature if key or passphrase provided
        key = cls._compute_key(secret_key, passphrase)
        signature = None
        if key:
            signature = hmac.new(key, merkle_root.encode("utf-8"), hashlib.sha256).hexdigest()

        # 5. Build bundle manifest
        manifest = {
            "format": "WASP_CONTAINER_V1",
            "case_id": case_id,
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "merkle_root": merkle_root,
            "total_files": len(file_entries),
            "signature": signature,
            "signature_algorithm": "HMAC-SHA256" if signature else None,
            "files": file_entries,
        }
        manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")

        # 6. Assemble deterministic tar.gz archive
        target_tar = output_path
        temp_tar = None
        if encrypt:
            temp_tar = Path(tempfile.mktemp(suffix=".tar.gz"))
            target_tar = temp_tar

        with tarfile.open(target_tar, "w:gz") as tar:
            ti_manifest = tarfile.TarInfo(name=cls.MANIFEST_FILENAME)
            ti_manifest.size = len(manifest_bytes)
            ti_manifest.mtime = 0
            ti_manifest.uid = 0
            ti_manifest.gid = 0
            ti_manifest.uname = ""
            ti_manifest.gname = ""
            tar.addfile(ti_manifest, io.BytesIO(manifest_bytes))

            for file_path in all_files:
                rel_path = str(file_path.relative_to(case_root)).replace("\\", "/")
                archive_name = f"case/{rel_path}"
                ti = tarfile.TarInfo(name=archive_name)
                ti.size = file_path.stat().st_size
                ti.mtime = 0
                ti.uid = 0
                ti.gid = 0
                ti.uname = ""
                ti.gname = ""
                with open(file_path, "rb") as f:
                    tar.addfile(ti, f)

        # 7. Apply AES-256-GCM encryption if requested
        if encrypt:
            if not passphrase:
                if temp_tar and temp_tar.exists():
                    temp_tar.unlink()
                raise ValueError("A passphrase is required to encrypt the .wasp container")
            cls.encrypt_file(temp_tar, output_path, passphrase)
            if temp_tar.exists():
                temp_tar.unlink()

        return output_path

    @classmethod
    def verify_bundle(
        cls,
        bundle_path: str | Path,
        secret_key: Optional[bytes] = None,
        passphrase: Optional[str] = None,
    ) -> BundleVerificationResult:
        """Verify the cryptographic integrity, Merkle root, and signature of a .wasp container."""
        bundle_file = Path(bundle_path).resolve()
        if not bundle_file.exists():
            return BundleVerificationResult(
                is_valid=False,
                case_id="",
                merkle_root="",
                files_checked=0,
                signature_present=False,
                signature_valid=False,
                errors=[f"Bundle file not found: {bundle_file}"],
            )

        # Check for AES-256-GCM encryption
        with open(bundle_file, "rb") as f:
            header = f.read(len(cls.ENC_MAGIC))

        is_encrypted = header == cls.ENC_MAGIC
        temp_decrypted = None
        verify_target = bundle_file

        if is_encrypted:
            if not passphrase:
                return BundleVerificationResult(
                    is_valid=False,
                    case_id="",
                    merkle_root="",
                    files_checked=0,
                    signature_present=False,
                    signature_valid=False,
                    is_encrypted=True,
                    errors=["Bundle is encrypted with AES-256-GCM; a valid passphrase is required for verification."],
                )
            try:
                temp_decrypted = Path(tempfile.mktemp(suffix=".tar.gz"))
                cls.decrypt_file(bundle_file, temp_decrypted, passphrase)
                verify_target = temp_decrypted
            except Exception as e:
                return BundleVerificationResult(
                    is_valid=False,
                    case_id="",
                    merkle_root="",
                    files_checked=0,
                    signature_present=False,
                    signature_valid=False,
                    is_encrypted=True,
                    errors=[f"Encrypted container verification failed: {e}"],
                )

        errors: List[str] = []
        files_checked = 0
        computed_leaves: List[str] = []

        try:
            with tarfile.open(verify_target, "r:gz") as tar:
                try:
                    manifest_ti = tar.getmember(cls.MANIFEST_FILENAME)
                    manifest_f = tar.extractfile(manifest_ti)
                    if manifest_f is None:
                        raise ValueError("Empty manifest in bundle")
                    manifest = json.loads(manifest_f.read().decode("utf-8"))
                except (KeyError, Exception) as exc:
                    return BundleVerificationResult(
                        is_valid=False,
                        case_id="",
                        merkle_root="",
                        files_checked=0,
                        signature_present=False,
                        signature_valid=False,
                        is_encrypted=is_encrypted,
                        errors=[f"Failed to read {cls.MANIFEST_FILENAME}: {exc}"],
                    )

                expected_files = manifest.get("files", {})
                expected_merkle = manifest.get("merkle_root", "")
                manifest_sig = manifest.get("signature")

                for rel_path, meta in expected_files.items():
                    archive_name = f"case/{rel_path}"
                    try:
                        member = tar.getmember(archive_name)
                    except KeyError:
                        errors.append(f"Missing file in archive: {rel_path}")
                        continue

                    f = tar.extractfile(member)
                    if f is None:
                        errors.append(f"Unable to read file in archive: {rel_path}")
                        continue

                    hasher = hashlib.sha256()
                    while chunk := f.read(65536):
                        hasher.update(chunk)
                    computed_hash = hasher.hexdigest()
                    computed_leaves.append(computed_hash)
                    files_checked += 1

                    if computed_hash != meta.get("sha256"):
                        errors.append(
                            f"Hash mismatch on {rel_path}: expected {meta.get('sha256')}, got {computed_hash}"
                        )

                computed_root = MerkleTree.compute_root(computed_leaves) if computed_leaves else "0" * 64
                if computed_root != expected_merkle:
                    errors.append(f"Merkle root mismatch: expected {expected_merkle}, computed {computed_root}")

                signature_present = bool(manifest_sig)
                signature_valid = None

                key = cls._compute_key(secret_key, passphrase)
                if signature_present and key:
                    expected_sig = hmac.new(key, computed_root.encode("utf-8"), hashlib.sha256).hexdigest()
                    if hmac.compare_digest(expected_sig, manifest_sig):
                        signature_valid = True
                    else:
                        signature_valid = False
                        errors.append("Cryptographic HMAC signature validation failed!")
                elif signature_present and not key:
                    signature_valid = None

                is_valid = len(errors) == 0 and (signature_valid is not False)

                return BundleVerificationResult(
                    is_valid=is_valid,
                    case_id=manifest.get("case_id", "UNKNOWN"),
                    merkle_root=computed_root,
                    files_checked=files_checked,
                    signature_present=signature_present,
                    signature_valid=signature_valid,
                    is_encrypted=is_encrypted,
                    errors=errors,
                    manifest_data=manifest,
                )

        except Exception as exc:
            return BundleVerificationResult(
                is_valid=False,
                case_id="",
                merkle_root="",
                files_checked=files_checked,
                signature_present=False,
                signature_valid=False,
                is_encrypted=is_encrypted,
                errors=[f"Corrupted or invalid archive: {exc}"],
            )
        finally:
            if temp_decrypted and temp_decrypted.exists():
                temp_decrypted.unlink()

    @classmethod
    def extract_bundle(
        cls,
        bundle_path: str | Path,
        target_dir: str | Path,
        verify_first: bool = True,
        secret_key: Optional[bytes] = None,
        passphrase: Optional[str] = None,
    ) -> Path:
        """Safely extract all files from a .wasp or .wasp.enc container into target_dir."""
        bundle_file = Path(bundle_path).resolve()
        target_path = Path(target_dir).resolve()

        if verify_first:
            res = cls.verify_bundle(bundle_file, secret_key=secret_key, passphrase=passphrase)
            if not res.is_valid:
                raise ValueError(f"Bundle integrity verification failed: {'; '.join(res.errors)}")

        target_path.mkdir(parents=True, exist_ok=True)

        with open(bundle_file, "rb") as f:
            header = f.read(len(cls.ENC_MAGIC))

        is_encrypted = header == cls.ENC_MAGIC
        temp_decrypted = None
        extract_source = bundle_file

        if is_encrypted:
            temp_decrypted = Path(tempfile.mktemp(suffix=".tar.gz"))
            cls.decrypt_file(bundle_file, temp_decrypted, passphrase or "")
            extract_source = temp_decrypted

        try:
            with tarfile.open(extract_source, "r:gz") as tar:
                for member in tar.getmembers():
                    if member.name.startswith("case/"):
                        sub_path = member.name[len("case/"):]
                        dest = target_path / sub_path
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        if member.isfile():
                            src = tar.extractfile(member)
                            if src:
                                with open(dest, "wb") as out:
                                    out.write(src.read())
        finally:
            if temp_decrypted and temp_decrypted.exists():
                temp_decrypted.unlink()

        return target_path
