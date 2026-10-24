"""Network flow and connection log parser (Zeek conn.log & Suricata EVE JSON).

Extracts network flow connections, DNS queries, and security alerts,
normalizing them into canonical forensic events with C2 threat tagging.
"""

from __future__ import annotations
import datetime
import json
from typing import Iterator, Optional, Dict, Any

from chronotrace.extract.base import ArtifactPlugin
from chronotrace.extract.registry import register_plugin
from chronotrace.core.models import Event
from chronotrace.ingest.evidence_view import EvidenceFile, EvidenceView
from chronotrace.normalize.normalizer import create_event
from chronotrace.normalize.timezone import unix_to_datetime

SUSPICIOUS_C2_PORTS = {
    4444: "Metasploit Default Listener",
    1337: "Elite/Backdoor Default",
    8888: "Suspicious HTTP Alternative Proxy",
    9001: "Tor Onion Routing Relay",
    9050: "Tor SOCKS Proxy",
    7777: "Common Reverse Shell Port",
    6667: "IRC Botnet Protocol",
}


@register_plugin
class NetworkLogPlugin(ArtifactPlugin):
    """Parses network flow logs (Zeek conn.log, Suricata EVE JSON, NetFlow)."""

    name: str = "network_logs"
    version: str = "1.0.0"
    capabilities: list[str] = ["timeline", "network", "c2_detection"]
    applies_to: list[str] = ["all", "linux", "windows", "pcap"]
    parallel_safe: bool = True

    def parse(self, source: EvidenceView) -> Iterator[Event]:
        for ef in source.files():
            path_lower = ef.virtual_path.lower()
            if "conn.log" in path_lower or "zeek" in path_lower or "bro" in path_lower:
                yield from self._parse_zeek_conn(ef)
            elif "eve.json" in path_lower or "suricata" in path_lower:
                yield from self._parse_suricata_eve(ef)

    def _parse_zeek_conn(self, ef: EvidenceFile) -> Iterator[Event]:
        """Parse Zeek TSV conn.log format."""
        fields = []
        try:
            with ef.open_read() as f:
                for line in f:
                    line_str = line.decode("utf-8", errors="ignore").strip()
                    if not line_str:
                        continue
                    if line_str.startswith("#fields"):
                        fields = line_str.split()[1:]
                        continue
                    if line_str.startswith("#"):
                        continue

                    parts = line_str.split("\t")
                    if len(parts) < len(fields):
                        parts = line_str.split()
                    if len(parts) != len(fields):
                        continue

                    row = dict(zip(fields, parts))
                    yield from self._convert_zeek_row(ef, row)
        except Exception:
            return

    def _convert_zeek_row(self, ef: EvidenceFile, row: Dict[str, str]) -> Iterator[Event]:
        ts_str = row.get("ts", "")
        try:
            ts_float = float(ts_str)
            dt = unix_to_datetime(ts_float)
        except (ValueError, TypeError):
            return

        src_ip = row.get("id.orig_h", "0.0.0.0")
        src_port = row.get("id.orig_p", "0")
        dest_ip = row.get("id.resp_h", "0.0.0.0")
        dest_port_str = row.get("id.resp_p", "0")
        proto = row.get("proto", "tcp").upper()
        service = row.get("service", "-")
        orig_bytes_str = row.get("orig_bytes", "0")
        resp_bytes_str = row.get("resp_bytes", "0")

        try:
            dest_port = int(dest_port_str)
        except ValueError:
            dest_port = 0

        orig_bytes = int(orig_bytes_str) if orig_bytes_str.isdigit() else 0
        resp_bytes = int(resp_bytes_str) if resp_bytes_str.isdigit() else 0

        tags = ["NETWORK", proto]
        threat_level = "LOW"
        rationale = f"Outbound connection {src_ip}:{src_port} -> {dest_ip}:{dest_port} ({proto})"

        if dest_port in SUSPICIOUS_C2_PORTS:
            tags.append("THREAT:SUSPICIOUS_C2_PORT")
            threat_level = "HIGH"
            rationale += f" [ALERT: Known C2 port {dest_port} ({SUSPICIOUS_C2_PORTS[dest_port]})]"

        # Flag mass exfiltration bursts (> 10 MB uploaded)
        if orig_bytes > 10 * 1024 * 1024:
            tags.append("ANOMALY:EXFILTRATION_BURST")
            threat_level = "CRITICAL"
            rationale += f" [ALERT: Mass outbound transfer of {orig_bytes / (1024*1024):.1f} MB]"

        yield create_event(
            timestamp_utc=dt,
            action="NETWORK_CONNECT",
            action_class="network",
            timestamp_type="connected",
            artifact=f"Zeek:conn:{ef.virtual_path}",
            plugin=self.name,
            evidence_id=ef.evidence_id,
            evidence_sha256=ef.sha256,
            object_path=f"{dest_ip}:{dest_port}",
            object_type="network_socket",
            rationale=rationale,
            raw_data={
                "src_ip": src_ip,
                "src_port": src_port,
                "dest_ip": dest_ip,
                "dest_port": dest_port,
                "protocol": proto,
                "service": service,
                "orig_bytes": orig_bytes,
                "resp_bytes": resp_bytes,
                "threat_level": threat_level,
            },
            tags=tags,
        )

    def _parse_suricata_eve(self, ef: EvidenceFile) -> Iterator[Event]:
        """Parse Suricata EVE JSON format."""
        try:
            with ef.open_read() as f:
                for line in f:
                    line_str = line.decode("utf-8", errors="ignore").strip()
                    if not line_str:
                        continue
                    try:
                        record = json.loads(line_str)
                    except json.JSONDecodeError:
                        continue

                    yield from self._convert_suricata_record(ef, record)
        except Exception:
            return

    def _convert_suricata_record(self, ef: EvidenceFile, record: Dict[str, Any]) -> Iterator[Event]:
        ts_str = record.get("timestamp", "")
        if not ts_str:
            return

        try:
            dt = datetime.datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return

        event_type = record.get("event_type", "flow")
        src_ip = record.get("src_ip", "0.0.0.0")
        src_port = record.get("src_port", 0)
        dest_ip = record.get("dest_ip", "0.0.0.0")
        dest_port = record.get("dest_port", 0)
        proto = str(record.get("proto", "TCP")).upper()

        tags = ["NETWORK", "SURICATA", event_type.upper()]
        rationale = f"Suricata {event_type} {src_ip}:{src_port} -> {dest_ip}:{dest_port} ({proto})"

        alert_info = record.get("alert", {})
        threat_level = "LOW"
        if alert_info:
            threat_level = "HIGH"
            sig = alert_info.get("signature", "Unknown Alert")
            tags.append("THREAT:SURICATA_ALERT")
            rationale += f" [ALERT: {sig}]"

        if dest_port in SUSPICIOUS_C2_PORTS:
            tags.append("THREAT:SUSPICIOUS_C2_PORT")
            if threat_level != "CRITICAL":
                threat_level = "HIGH"
            rationale += f" [ALERT: Known C2 port {dest_port}]"

        yield create_event(
            timestamp_utc=dt,
            action="NETWORK_CONNECT",
            action_class="network",
            timestamp_type="connected",
            artifact=f"Suricata:eve:{ef.virtual_path}",
            plugin=self.name,
            evidence_id=ef.evidence_id,
            evidence_sha256=ef.sha256,
            object_path=f"{dest_ip}:{dest_port}",
            object_type="network_flow",
            rationale=rationale,
            raw_data={
                "src_ip": src_ip,
                "src_port": src_port,
                "dest_ip": dest_ip,
                "dest_port": dest_port,
                "protocol": proto,
                "event_type": event_type,
                "threat_level": threat_level,
            },
            tags=tags,
        )
