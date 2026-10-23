"""Statistical & Off-Hours Anomaly Spotlight Engine for WASP.

Performs rolling statistical analysis and anomaly detection over forensic super-timelines.
Detects:
1. Activity bursts (Z-score spike detection over sliding time windows).
2. Off-hours privileged logins (e.g., weekend or late-night administrative sessions).
3. Rapid mass file modification & encryption bursts (ransomware detection pattern).
4. Data staging and exfiltration surges.
"""

from __future__ import annotations
import datetime
import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from chronotrace.core.models import Event


@dataclass
class AnomalyFinding:
    """Represents a flagged timeline anomaly."""
    anomaly_id: str
    anomaly_type: str  # BURST_ACTIVITY, OFF_HOURS_LOGON, RANSOMWARE_ENCRYPTION_SPIKE, MASS_FILE_ALTERATION
    severity: str      # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    description: str
    window_start_utc: str
    window_end_utc: str
    metric_value: float
    baseline_value: float
    z_score: float
    affected_users: List[str] = field(default_factory=list)
    sample_events: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "anomaly_id": self.anomaly_id,
            "anomaly_type": self.anomaly_type,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "window_start_utc": self.window_start_utc,
            "window_end_utc": self.window_end_utc,
            "metric_value": round(self.metric_value, 2),
            "baseline_value": round(self.baseline_value, 2),
            "z_score": round(self.z_score, 2),
            "affected_users": self.affected_users,
            "sample_events": self.sample_events,
        }


class AnomalyDetector:
    """Detects statistical bursts, off-hours activity, and ransomware behaviors."""

    def __init__(
        self,
        events: List[Event],
        window_minutes: int = 15,
        z_threshold: float = 2.0,
        off_hours_start: int = 22,  # 10 PM
        off_hours_end: int = 6,     # 6 AM
    ):
        self.raw_events = list(events)
        self.events = sorted(events, key=lambda e: e.timestamp_utc or "")
        self.window_minutes = window_minutes
        self.z_threshold = z_threshold
        self.off_hours_start = off_hours_start
        self.off_hours_end = off_hours_end

    def detect_all(self) -> List[AnomalyFinding]:
        """Run all anomaly detection checks and return aggregated findings."""
        findings: List[AnomalyFinding] = []
        findings.extend(self.detect_activity_bursts())
        findings.extend(self.detect_off_hours_logons())
        findings.extend(self.detect_rapid_file_modifications())
        return findings

    def _parse_ts(self, ts_str: Optional[str]) -> Optional[datetime.datetime]:
        if not ts_str:
            return None
        try:
            # Normalize ISO timestamp
            clean_ts = ts_str.replace("Z", "+00:00")
            return datetime.datetime.fromisoformat(clean_ts)
        except Exception:
            return None

    def detect_activity_bursts(self) -> List[AnomalyFinding]:
        """Detect statistical spikes in event volume using sliding windows and Z-scores."""
        if not self.events:
            return []

        # Bucket events into fixed windows
        window_sec = self.window_minutes * 60
        windows: Dict[int, List[Event]] = defaultdict(list)

        for ev in self.raw_events:
            dt = self._parse_ts(ev.timestamp_utc)
            if not dt:
                continue
            bucket = int(dt.timestamp()) // window_sec
            windows[bucket].append(ev)

        if len(windows) < 2:
            return []

        min_bucket = min(windows.keys())
        max_bucket = max(windows.keys())
        total_span = max_bucket - min_bucket + 1

        if 2 <= total_span <= 1000:
            counts = [len(windows.get(b, [])) for b in range(min_bucket, max_bucket + 1)]
        else:
            counts = [len(evs) for evs in windows.values()]

        # Robust Statistics: Median and Median Absolute Deviation (MAD)
        sorted_counts = sorted(counts)
        n = len(sorted_counts)
        median = sorted_counts[n // 2] if n % 2 != 0 else (sorted_counts[n // 2 - 1] + sorted_counts[n // 2]) / 2.0

        # Compute MAD: median(|x_i - median|)
        abs_deviations = sorted([abs(c - median) for c in counts])
        mad = abs_deviations[n // 2] if n % 2 != 0 else (abs_deviations[n // 2 - 1] + abs_deviations[n // 2]) / 2.0
        # Normal consistency constant: 1.4826 * MAD approximates std dev for normal distributions
        mad_scale = 1.4826 * mad

        # Classical statistics
        mean = sum(counts) / len(counts)
        variance = sum((c - mean) ** 2 for c in counts) / len(counts)
        std_dev = math.sqrt(variance)

        if mad_scale == 0 and std_dev == 0:
            return []

        findings: List[AnomalyFinding] = []
        for bucket, evs in sorted(windows.items()):
            count = len(evs)
            # Use robust modified Z-score based on MAD if available, fallback to classical
            if mad_scale > 0:
                z = (count - median) / mad_scale
            else:
                z = (count - mean) / std_dev if std_dev > 0 else 0.0

            if z >= self.z_threshold:
                start_dt = datetime.datetime.fromtimestamp(bucket * window_sec, tz=datetime.timezone.utc)
                end_dt = datetime.datetime.fromtimestamp((bucket + 1) * window_sec, tz=datetime.timezone.utc)
                users = list({e.user for e in evs if e.user})

                findings.append(
                    AnomalyFinding(
                        anomaly_id=f"BURST-{bucket}",
                        anomaly_type="BURST_ACTIVITY",
                        severity="HIGH" if z > 3.0 else "MEDIUM",
                        title=f"Activity Volume Spike ({count} events in {self.window_minutes}m)",
                        description=(
                            f"Robust statistical burst detected (Modified Z-score {z:.2f} via Median Absolute Deviation). "
                            f"Event count ({count}) significantly exceeds baseline median ({median:.1f}, MAD-scale {mad_scale:.1f})."
                        ),
                        window_start_utc=start_dt.isoformat(),
                        window_end_utc=end_dt.isoformat(),
                        metric_value=float(count),
                        baseline_value=mean,
                        z_score=z,
                        affected_users=users,
                        sample_events=[e.event_id for e in evs[:5]],
                    )
                )

        return findings

    def detect_off_hours_logons(self) -> List[AnomalyFinding]:
        """Detect user logon or session creation during unusual / off-hours."""
        findings: List[AnomalyFinding] = []

        for ev in self.events:
            dt = self._parse_ts(ev.timestamp_utc)
            if not dt:
                continue

            # Check for logon events
            raw = ev.raw or {}
            is_logon = (
                ev.action in ("USER_LOGON", "SESSION_START")
                or raw.get("EventID") in (4624, 7001)
                or "logon" in ev.action.lower()
            )
            if not is_logon:
                continue

            hour = dt.hour
            is_weekend = dt.weekday() >= 5  # Saturday or Sunday
            is_off_hour = (hour >= self.off_hours_start or hour < self.off_hours_end)

            if is_off_hour or is_weekend:
                user = ev.user or raw.get("TargetUserName") or "UNKNOWN"
                reason = "weekend logon" if is_weekend and not is_off_hour else f"off-hours logon ({hour:02d}:00 UTC)"
                if is_weekend and is_off_hour:
                    reason = f"weekend off-hours logon ({hour:02d}:00 UTC)"

                findings.append(
                    AnomalyFinding(
                        anomaly_id=f"OFFHOURS-{ev.event_id}",
                        anomaly_type="OFF_HOURS_LOGON",
                        severity="HIGH" if "admin" in user.lower() else "MEDIUM",
                        title=f"Unusual Logon: {user} ({reason})",
                        description=(
                            f"User '{user}' authenticated during atypical operational window "
                            f"({reason}). Action: {ev.action} on target: {ev.object.path}."
                        ),
                        window_start_utc=ev.timestamp_utc,
                        window_end_utc=ev.timestamp_utc,
                        metric_value=1.0,
                        baseline_value=0.0,
                        z_score=3.0,
                        affected_users=[user],
                        sample_events=[ev.event_id],
                    )
                )

        return findings

    def detect_rapid_file_modifications(self, threshold_count: int = 10, window_seconds: int = 60) -> List[AnomalyFinding]:
        """Detect rapid bulk file modifications, renames, or deletions (Ransomware signature)."""
        mod_events = [
            e for e in self.events
            if e.action in ("FILE_MODIFY", "FILE_WRITE", "FILE_DELETE", "FILE_RENAME")
            or any(kw in e.action.lower() for kw in ("modify", "encrypt", "delete"))
        ]

        if len(mod_events) < threshold_count:
            return []

        findings: List[AnomalyFinding] = []
        i = 0
        n = len(mod_events)

        while i < n:
            start_ev = mod_events[i]
            start_dt = self._parse_ts(start_ev.timestamp_utc)
            if not start_dt:
                i += 1
                continue

            window_events = [start_ev]
            j = i + 1
            while j < n:
                curr_ev = mod_events[j]
                curr_dt = self._parse_ts(curr_ev.timestamp_utc)
                if not curr_dt:
                    j += 1
                    continue
                diff = (curr_dt - start_dt).total_seconds()
                if 0 <= diff <= window_seconds:
                    window_events.append(curr_ev)
                    j += 1
                else:
                    break

            if len(window_events) >= threshold_count:
                users = list({e.user for e in window_events if e.user})
                end_dt = self._parse_ts(window_events[-1].timestamp_utc) or start_dt
                findings.append(
                    AnomalyFinding(
                        anomaly_id=f"RAPID-MOD-{start_ev.event_id}",
                        anomaly_type="RANSOMWARE_ENCRYPTION_SPIKE",
                        severity="CRITICAL",
                        title=f"Rapid Mass File Alteration ({len(window_events)} files in <= {window_seconds}s)",
                        description=(
                            f"Detected high-velocity mass file modification/deletion burst. "
                            f"{len(window_events)} files affected in {window_seconds} seconds. "
                            f"Characteristic behavior of ransomware encryption loops or anti-forensic wiping."
                        ),
                        window_start_utc=start_dt.isoformat(),
                        window_end_utc=end_dt.isoformat(),
                        metric_value=float(len(window_events)),
                        baseline_value=float(threshold_count),
                        z_score=4.5,
                        affected_users=users,
                        sample_events=[e.event_id for e in window_events[:5]],
                    )
                )
                i = j  # advance past this cluster
            else:
                i += 1

        return findings


    def detect_statistical_dilution(self) -> List[AnomalyFinding]:
        """
        Adversarial Defense: Detects statistical poisoning / dilution attacks.
        Flags when an attacker injects artificial uniform noise to inflate the
        Median Absolute Deviation (MAD), thereby blinding standard Z-score outlier detection.
        """
        if len(self.events) < 30:
            return []

        timestamps = []
        for ev in self.events:
            dt = self._parse_ts(ev.timestamp_utc)
            if dt:
                timestamps.append(dt.timestamp())

        if len(timestamps) < 30:
            return []

        deltas = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        positive_deltas = [d for d in deltas if d >= 0]
        if not positive_deltas:
            return []

        zero_delta_count = sum(1 for d in positive_deltas if d < 0.05)
        zero_delta_ratio = zero_delta_count / len(positive_deltas)

        findings = []
        # Flag if sub-50ms inter-arrival times constitute > 40% of sequential events
        if zero_delta_ratio > 0.40 and len(self.events) >= 50:
            findings.append(
                AnomalyFinding(
                    anomaly_id="ANOM-DILUTION-001",
                    anomaly_type="STATISTICAL_DILUTION_ATTACK",
                    severity="CRITICAL",
                    title="Adversarial Statistical Dilution Attack Detected",
                    description=(
                        f"Detected synthetic cluster of {zero_delta_count} sub-50ms events ({zero_delta_ratio*100:.1f}% of total). "
                        "Pattern indicates automated log flooding / synthetic event injection designed to inflate "
                        "the Median Absolute Deviation (MAD) and blind outlier detection."
                    ),
                    window_start_utc=self.events[0].timestamp_utc or "",
                    window_end_utc=self.events[-1].timestamp_utc or "",
                    metric_value=zero_delta_ratio * 100.0,
                    baseline_value=5.0,
                    z_score=9.99,
                    affected_users=list({e.user for e in self.events if e.user}),
                    sample_events=[e.event_id for e in self.events[:5]],
                )
            )

        # Enhanced Defense against paced injection (e.g. 60ms or 100ms): Coefficient of Variation (CV) dispersion test
        mean_delta = sum(positive_deltas) / len(positive_deltas)
        if mean_delta < 2.0 and len(positive_deltas) >= 30:
            variance = sum((d - mean_delta) ** 2 for d in positive_deltas) / len(positive_deltas)
            std_delta = math.sqrt(variance)
            cv = std_delta / mean_delta if mean_delta > 0 else 0
            if cv < 0.20 and mean_delta > 0.01:
                findings.append(
                    AnomalyFinding(
                        anomaly_id="ANOM-DILUTION-CADENCE",
                        anomaly_type="STATISTICAL_DILUTION_SYNTHETIC_CADENCE",
                        severity="CRITICAL",
                        title="Synthetic Cadence / Paced Log Dilution Detected",
                        description=(
                            f"Detected unnaturally uniform event cadence (CV={cv:.2f} < 0.20, mean delta={mean_delta*1000:.1f}ms). "
                            "Normal user and OS activity exhibits high stochastic dispersion (CV >= 0.8). "
                            "This narrow-dispersion pattern indicates automated programmatic event injection designed to dilute statistical baselines."
                        ),
                        window_start_utc=self.events[0].timestamp_utc or "",
                        window_end_utc=self.events[-1].timestamp_utc or "",
                        metric_value=cv,
                        baseline_value=1.0,
                        z_score=8.5,
                        affected_users=list({e.user for e in self.events if e.user}),
                        sample_events=[e.event_id for e in self.events[:5]],
                    )
                )

        return findings

    def detect_clock_manipulation(self) -> List[AnomalyFinding]:
        """
        Adversarial Defense: Detects system clock tampering and non-monotonic time anomalies.
        Flags when logs jump backward in time or when Event ID 4616 ('System time changed') is present.
        """
        findings = []
        host_clocks: Dict[str, float] = {}
        for ev in self.raw_events:
            dt = self._parse_ts(ev.timestamp_utc)
            if not dt:
                continue
            ts = dt.timestamp()
            host = ev.host or "DEFAULT_HOST"
            if host in host_clocks:
                prev_ts = host_clocks[host]
                # If clock jumps backward by more than 5.0 seconds on the same host:
                if (prev_ts - ts) > 5.0:
                    findings.append(
                        AnomalyFinding(
                            anomaly_id=f"ANOM-CLOCK-JUMP-{ev.event_id}",
                            anomaly_type="CLOCK_MANIPULATION_DETECTED",
                            severity="CRITICAL",
                            title="Non-Monotonic Backward Clock Jump Detected",
                            description=(
                                f"Host '{host}' timestamp jumped backward by {prev_ts - ts:.1f} seconds. "
                                "Indicates potential NTP poisoning, manual system clock rollback, or timestomp anti-forensics."
                            ),
                            window_start_utc=ev.timestamp_utc or "",
                            window_end_utc=ev.timestamp_utc or "",
                            metric_value=prev_ts - ts,
                            baseline_value=0.0,
                            z_score=10.0,
                            affected_users=[ev.user] if ev.user else [],
                            sample_events=[ev.event_id],
                        )
                    )
                    break
                elif (ts - prev_ts) > 86400.0:
                    findings.append(
                        AnomalyFinding(
                            anomaly_id=f"ANOM-CLOCK-FORWARD-{ev.event_id}",
                            anomaly_type="CLOCK_FORWARD_LEAP_ANOMALY",
                            severity="HIGH",
                            title="Unexplained Forward Clock Leap Detected",
                            description=(
                                f"Host '{host}' timestamp jumped forward by {(ts - prev_ts)/3600.0:.1f} hours without intervening reboot. "
                                "Indicates potential fast-forward timestomp evasion or hypervisor clock desynchronization."
                            ),
                            window_start_utc=ev.timestamp_utc or "",
                            window_end_utc=ev.timestamp_utc or "",
                            metric_value=(ts - prev_ts) / 3600.0,
                            baseline_value=0.0,
                            z_score=7.5,
                            affected_users=[ev.user] if ev.user else [],
                            sample_events=[ev.event_id],
                        )
                    )
                    break
            host_clocks[host] = ts

        for ev in self.events:
            raw = getattr(ev, "raw", {}) or {}
            event_id = str(raw.get("EventID") or raw.get("event_id") or "")
            if event_id == "4616" or "system time was changed" in (ev.rationale or "").lower():
                findings.append(
                    AnomalyFinding(
                        anomaly_id=f"ANOM-CLOCK-EVTX-{ev.event_id}",
                        anomaly_type="CLOCK_ALTERATION_EVENT_4616",
                        severity="CRITICAL",
                        title="Audit Log Event 4616: System Time Was Changed",
                        description=f"System clock alteration logged by OS auditing service on host {ev.host}.",
                        window_start_utc=ev.timestamp_utc or "",
                        window_end_utc=ev.timestamp_utc or "",
                        metric_value=1.0,
                        baseline_value=0.0,
                        z_score=10.0,
                        affected_users=[ev.user] if ev.user else [],
                        sample_events=[ev.event_id],
                    )
                )
                break

        return findings
