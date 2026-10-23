"""Evidence acquisition and imaging with mandatory streaming SHA-256 hashing."""

from __future__ import annotations
import shutil
import tarfile
from pathlib import Path
from typing import Any, Dict, List, Optional
from chronotrace.core.case import Case
from chronotrace.core.errors import EvidenceCorruptError
from chronotrace.acquire.hasher import Hasher
from chronotrace.acquire.tsa import request_tsa_timestamp


class Imager:
    """Acquires forensic evidence with streaming hash verification and sidecar generation."""

    def __init__(self, case: Case):
        self.case = case

    def acquire_file(
        self,
        source_path: str | Path,
        output_filename: Optional[str] = None,
        evidence_id: str = "EV-0001",
        container_type: str = "raw",
        notes: str = "",
    ) -> Dict[str, Any]:
        """
        Copy an evidence file/image into the case evidence directory,
        computing streaming SHA-256 and writing sidecar hash files.
        """
        src = Path(source_path).resolve()
        if not src.exists():
            raise FileNotFoundError(f"Source evidence not found: {source_path}")

        out_name = output_filename or src.name
        dst = self.case.evidence_dir / out_name

        hasher = Hasher(extra_algorithms=self.case.config.acquire.hash_extra)

        # 1. Stream copy while hashing source
        src_hashes, size_bytes = hasher.stream_copy_and_hash(src, dst)

        # 2. Read-back verification pass
        dst_hashes, dst_size = hasher.hash_file(dst)
        if dst_hashes["sha256"] != src_hashes["sha256"] or dst_size != size_bytes:
            if dst.exists():
                dst.unlink()
            raise EvidenceCorruptError("Read-back verification failed: SHA-256 mismatch after copy")

        # 3. Write .sha256 sidecar file & RFC 3161 TSA timestamp token
        sidecar_path = self.case.evidence_dir / f"{out_name}.sha256"
        with open(sidecar_path, "w", encoding="utf-8") as f:
            f.write(f"{dst_hashes['sha256']}  {out_name}\n")

        ts_token = request_tsa_timestamp(dst_hashes["sha256"])
        ts_token_path = self.case.evidence_dir / f"{out_name}.tsr"
        try:
            with open(ts_token_path, "wb") as f:
                f.write(ts_token.token_bytes)
        except Exception:
            pass

        rel_path = f"evidence/{out_name}"

        # 4. Update Manifest
        if self.case.manifest:
            self.case.manifest.add_evidence(
                evidence_id=evidence_id,
                rel_path=rel_path,
                container=container_type,
                size_bytes=size_bytes,
                hashes=dst_hashes,
                source=str(src),
                verification_result="match",
                timestamp_token=ts_token.to_dict(),
            )
            self.case.manifest.save()

        # 5. Record in Custody Ledger
        if self.case.ledger:
            self.case.ledger.append_event(
                event_type="evidence_acquired",
                actor=self.case.examiner,
                payload={
                    "evidence_id": evidence_id,
                    "path": rel_path,
                    "sha256": dst_hashes["sha256"],
                    "size_bytes": size_bytes,
                    "source": str(src),
                    "notes": notes,
                    "timestamp_tsa": ts_token.to_dict(),
                },
            )

        return {
            "evidence_id": evidence_id,
            "path": rel_path,
            "size_bytes": size_bytes,
            "hashes": dst_hashes,
            "verification": "match",
            "timestamp_token": ts_token.to_dict(),
        }

    def acquire_directory_as_archive(
        self,
        source_dir: str | Path,
        archive_name: str = "evidence_archive.tar",
        output_filename: Optional[str] = None,
        evidence_id: str = "EV-0001",
        notes: str = "",
    ) -> Dict[str, Any]:
        """Archive a directory into a tarball inside the evidence folder with streaming SHA-256."""
        if output_filename:
            archive_name = output_filename

        src = Path(source_dir).resolve()
        if not src.is_dir():
            raise NotADirectoryError(f"Source is not a directory: {source_dir}")

        dst = self.case.evidence_dir / archive_name
        with tarfile.open(dst, "w") as tar:
            tar.add(src, arcname=src.name)

        hasher = Hasher(extra_algorithms=self.case.config.acquire.hash_extra)
        dst_hashes, size_bytes = hasher.hash_file(dst)

        # Write sidecar & timestamp token
        sidecar_path = self.case.evidence_dir / f"{archive_name}.sha256"
        with open(sidecar_path, "w", encoding="utf-8") as f:
            f.write(f"{dst_hashes['sha256']}  {archive_name}\n")

        ts_token = request_tsa_timestamp(dst_hashes["sha256"])
        ts_token_path = self.case.evidence_dir / f"{archive_name}.tsr"
        try:
            with open(ts_token_path, "wb") as f:
                f.write(ts_token.token_bytes)
        except Exception:
            pass

        rel_path = f"evidence/{archive_name}"

        if self.case.manifest:
            self.case.manifest.add_evidence(
                evidence_id=evidence_id,
                rel_path=rel_path,
                container="tar",
                size_bytes=size_bytes,
                hashes=dst_hashes,
                source=str(src),
                verification_result="match",
                timestamp_token=ts_token.to_dict(),
            )
            self.case.manifest.save()

        if self.case.ledger:
            self.case.ledger.append_event(
                event_type="evidence_acquired",
                actor=self.case.examiner,
                payload={
                    "evidence_id": evidence_id,
                    "path": rel_path,
                    "sha256": dst_hashes["sha256"],
                    "size_bytes": size_bytes,
                    "source": str(src),
                    "notes": notes,
                    "timestamp_tsa": ts_token.to_dict(),
                },
            )

        return {
            "evidence_id": evidence_id,
            "path": rel_path,
            "size_bytes": size_bytes,
            "hashes": dst_hashes,
            "verification": "match",
            "timestamp_token": ts_token.to_dict(),
        }
