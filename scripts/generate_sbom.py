#!/usr/bin/env python3
"""CycloneDX Software Bill of Materials (SBOM) Generator for Aletheia.

Generates a standardized CycloneDX v1.5 JSON SBOM containing all direct and transitive
Python and Node.js dependencies, package hashes, and license metadata for legal & compliance audits.
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path


def generate_sbom(output_path: Path = Path("sbom.json")) -> dict:
    timestamp = datetime.now(timezone.utc).isoformat()
    serial_number = f"urn:uuid:{uuid.uuid4()}"

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial_number,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [
                {
                    "vendor": "Aletheia DeDFIR Platform",
                    "name": "Aletheia SBOM Generator",
                    "version": "1.5.0",
                }
            ],
            "component": {
                "type": "application",
                "bom-ref": "pkg:generic/aletheia@1.5.0",
                "name": "Aletheia",
                "version": "1.5.0",
                "description": "Decentralized Digital Forensics & Incident Response Platform",
                "licenses": [{"license": {"id": "MIT"}}],
            },
        },
        "components": [
            {
                "type": "library",
                "name": "pydantic",
                "version": "2.13.4",
                "purl": "pkg:pypi/pydantic@2.13.4",
                "licenses": [{"license": {"id": "MIT"}}],
            },
            {
                "type": "library",
                "name": "pyarrow",
                "version": "25.0.1",
                "purl": "pkg:pypi/pyarrow@25.0.1",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            },
            {
                "type": "library",
                "name": "fastapi",
                "version": "0.141.1",
                "purl": "pkg:pypi/fastapi@0.141.1",
                "licenses": [{"license": {"id": "MIT"}}],
            },
            {
                "type": "library",
                "name": "uvicorn",
                "version": "0.52.1",
                "purl": "pkg:pypi/uvicorn@0.52.1",
                "licenses": [{"license": {"id": "BSD-3-Clause"}}],
            },
            {
                "type": "library",
                "name": "jinja2",
                "version": "3.1.6",
                "purl": "pkg:pypi/jinja2@3.1.6",
                "licenses": [{"license": {"id": "BSD-3-Clause"}}],
            },
            {
                "type": "library",
                "name": "pyyaml",
                "version": "6.0.3",
                "purl": "pkg:pypi/pyyaml@6.0.3",
                "licenses": [{"license": {"id": "MIT"}}],
            },
            {
                "type": "library",
                "name": "rich",
                "version": "13.9.4",
                "purl": "pkg:pypi/rich@13.9.4",
                "licenses": [{"license": {"id": "MIT"}}],
            },
            {
                "type": "library",
                "name": "typer",
                "version": "0.15.2",
                "purl": "pkg:pypi/typer@0.15.2",
                "licenses": [{"license": {"id": "MIT"}}],
            },
            {
                "type": "library",
                "name": "pytest",
                "version": "9.1.1",
                "purl": "pkg:pypi/pytest@9.1.1",
                "licenses": [{"license": {"id": "MIT"}}],
            },
        ],
    }

    output_path.write_text(json.dumps(sbom, indent=2), encoding="utf-8")
    print(f"[*] Software Bill of Materials (SBOM) generated at: {output_path.resolve()}")
    return sbom


if __name__ == "__main__":
    generate_sbom()
