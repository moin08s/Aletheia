"""Adversarial Parser Fuzzing & Malformed Input Robustness Tests.

Bombards forensic artifact parsers with randomized bytes, null bytes,
corrupted headers, and boundary lengths to verify parser crash resilience and graceful error handling.
"""

import os
import random
from pathlib import Path
from chronotrace.core.case import Case


def test_syslog_parser_fuzzing_robustness(tmp_path: Path):
    """Verify Linux syslog / auth.log parser handles malformed garbage bytes without crashing."""
    case_dir = tmp_path / "CASE-FUZZ-SYSLOG"
    case = Case.create(case_id="CASE-FUZZ-SYSLOG", out_dir=case_dir)

    # Generate fuzzed log lines with random ASCII and binary noise
    fuzzed_lines = []
    for _ in range(50):
        # Mix of null bytes, random bytes, oversized strings, and partial dates
        noise = os.urandom(random.randint(10, 200)).replace(b"\n", b" ")
        partial_ts = "Mar 11 02:" + str(random.randint(10, 59)) + ":00"
        fuzzed_lines.append(f"{partial_ts} HOSTNAME sshd[123]: {noise.decode('latin1')}\n")

    fuzz_file = tmp_path / "fuzzed_auth.log"
    fuzz_file.write_text("".join(fuzzed_lines), encoding="utf-8", errors="replace")

    case.acquire(fuzz_file, output_filename="fuzzed_auth.log", evidence_id="EV-FUZZ-01")

    # Ingestion & extraction must complete without unhandled exceptions
    events = case.extract(profile="all")
    assert isinstance(events, list)


def test_evtx_jsonl_parser_fuzzing_robustness(tmp_path: Path):
    """Verify EVTX jsonl parser handles malformed JSON, missing fields, and type mismatches gracefully."""
    case_dir = tmp_path / "CASE-FUZZ-EVTX"
    case = Case.create(case_id="CASE-FUZZ-EVTX", out_dir=case_dir)

    # Malformed JSON lines: truncated JSON, null characters, missing required schema fields
    fuzzed_content = (
        '{"TimeCreated": "2024-03-11T02:14:07Z", "EventID": 4624}\n'
        '{"TimeCreated": "NOT_A_TIMESTAMP", "EventID": "INVALID"}\n'
        '{"BROKEN_JSON_TRUNCATED: \n'
        '\x00\x00\x00\x01\n'
        '{"TimeCreated": "2024-03-11T02:16:00Z", "EventID": 4688, "NewProcessName": null}\n'
        '{"TimeCreated": "2024-03-11T02:18:00Z", "EventID": 999999, "Complex": {"nested": [1, 2, 3]}}\n'
    )

    fuzz_evtx = tmp_path / "fuzzed_Security.jsonl"
    fuzz_evtx.write_text(fuzzed_content, encoding="utf-8", errors="replace")

    case.acquire(fuzz_evtx, output_filename="fuzzed_Security.jsonl", evidence_id="EV-FUZZ-02")
    events = case.extract(profile="all")
    assert isinstance(events, list)
