"""User Intent & Provenance Verification Engine for ChronoTrace.

Distinguishes legitimate user-authorized transfers from malicious background/remote drains
by correlating on-chain transaction events with local host telemetry (human input,
browser extension history, session types, and hardware passkeys).
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from chronotrace.core.models import Event


def _parse_ts(ts_str: str) -> Optional[datetime]:
    try:
        clean = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


@dataclass
class IntentAssessment:
    tx_hash: str
    is_authorized_user: bool
    human_provenance_score: float  # 0.0 (Pure Attacker Drain) to 1.0 (Confirmed Human User)
    verdict: str  # "LEGITIMATE_USER_TRANSFER", "UNAUTHORIZED_ATTACKER_DRAIN", "SUSPICIOUS_TRANSFER"
    corroborating_signals: List[str] = field(default_factory=list)
    risk_factors: List[str] = field(default_factory=list)
    host_evidence_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tx_hash": self.tx_hash,
            "is_authorized_user": self.is_authorized_user,
            "human_provenance_score": round(self.human_provenance_score, 2),
            "verdict": self.verdict,
            "corroborating_signals": self.corroborating_signals,
            "risk_factors": self.risk_factors,
            "host_evidence_ids": self.host_evidence_ids,
        }


class UserIntentAnalyzer:
    """Analyzes whether a blockchain transfer was executed by the legitimate user or an attacker."""

    def __init__(self, time_window_seconds: int = 120):
        self.time_window_seconds = time_window_seconds

    def evaluate_transfer(
        self,
        tx_hash: str,
        tx_timestamp_utc: str,
        host_events: List[Event],
    ) -> IntentAssessment:
        tx_dt = _parse_ts(tx_timestamp_utc)
        if not tx_dt:
            raise ValueError(f"Invalid transaction timestamp: {tx_timestamp_utc}")

        score = 0.0
        corroborating_signals: List[str] = []
        risk_factors: List[str] = []
        evidence_ids: List[str] = []

        # Track evidence signals within proximity window
        has_wallet_extension_ui = False
        has_active_user_session = False
        has_human_input = False
        has_suspicious_headless_process = False
        has_remote_session = False

        for ev in host_events:
            ev_dt = _parse_ts(ev.timestamp_utc)
            if not ev_dt:
                continue

            delta = abs((ev_dt - tx_dt).total_seconds())
            if delta > self.time_window_seconds:
                continue

            evidence_ids.append(ev.event_id)

            # 1. Browser Wallet Extension Navigation (e.g. MetaMask, Phantom, Coinbase Wallet)
            obj_path = (ev.object.path or "").lower() if ev.object else ""
            if "chrome-extension://" in obj_path or "moz-extension://" in obj_path or "wallet" in obj_path:
                has_wallet_extension_ui = True

            # 2. Human Interactive Session (LogonType 2=Interactive, 11=CachedInteractive)
            action = (ev.action or "").upper()
            if "INTERACTIVE_LOGON" in action or "USER_ACTIVITY" in action:
                has_active_user_session = True

            # 3. Human Physical Input (Mouse, Keyboard, Window focus)
            if "MOUSE_CLICK" in action or "KEYSTROKE" in action or "WINDOW_FOCUS" in action or "UI_INTERACTION" in action:
                has_human_input = True

            # 4. Red Flag: Headless / Script process (PowerShell, CMD, Python, Curl) without browser UI
            if "HEADLESS" in action or "REVERSE_SHELL" in action or "SCRIPT_EXEC" in action:
                has_suspicious_headless_process = True

            # 5. Red Flag: Remote Network Session (LogonType 3=Network, 10=RemoteInteractive / RDP)
            if "NETWORK_LOGON" in action or "REMOTE_SESSION" in action:
                has_remote_session = True

        # Compute Provenance Score
        if has_wallet_extension_ui:
            score += 0.40
            corroborating_signals.append("Corroborated with Browser Wallet Extension UI activity in foreground")

        if has_human_input:
            score += 0.35
            corroborating_signals.append("Active human input (mouse/keyboard/window focus) detected at transfer time")

        if has_active_user_session:
            score += 0.25
            corroborating_signals.append("Matching local interactive user desktop session (Session 1)")

        # Penalize for Attack Indicators
        if has_suspicious_headless_process:
            score -= 0.50
            risk_factors.append("Headless script or automated background process active at transaction time")

        if has_remote_session and not has_human_input:
            score -= 0.40
            risk_factors.append("Executed via remote network logon session with zero local human interaction")

        # Normalize score between 0.0 and 1.0
        final_score = max(0.0, min(1.0, score))

        if final_score >= 0.70:
            verdict = "LEGITIMATE_USER_TRANSFER"
            is_authorized = True
        elif final_score <= 0.30:
            verdict = "UNAUTHORIZED_ATTACKER_DRAIN"
            is_authorized = False
            if not risk_factors:
                risk_factors.append("Zero human input or browser wallet activity during blockchain broadcast")
        else:
            verdict = "SUSPICIOUS_TRANSFER"
            is_authorized = False
            risk_factors.append("Inconclusive human telemetry; manual verification required")

        return IntentAssessment(
            tx_hash=tx_hash,
            is_authorized_user=is_authorized,
            human_provenance_score=final_score,
            verdict=verdict,
            corroborating_signals=corroborating_signals,
            risk_factors=risk_factors,
            host_evidence_ids=list(set(evidence_ids)),
        )
