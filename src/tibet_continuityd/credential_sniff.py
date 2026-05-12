"""
Credential-request-without-context sniff (v0.6.11+).

Inbound-side primitive that complements the SAM extension:
- SAM (outbound, see SSM §13): secret used safely under bounded auth
- credential-request-without-context (inbound, this module):
  credential demanded suspiciously, without a prior causal path

This is the "JWT-sniff" pattern Jasper described on 12 May 2026:
    "wie vraagt om een JWT als ik niks open, ik zie het causaal
     verband niet"

The principle is pure causal topology, no ML:

    Legitimate credential flows have a causal pre-path:
       challenge envelope arrives  →  response envelope returns

    Spear-phishing / stale-probe patterns do NOT:
       credential demand arrives   →  no prior context

    The latter triggers a triage event in the audit chain.

No false-positive trade-off via thresholding — we look at presence
or absence of a sealed challenge envelope addressed to the
requested path, within a configurable causal-window.

Example trigger paths (extensible):
    /auth/token           OAuth2 client_credentials grant
    /oauth/token          Generic OAuth2 token endpoint
    /api/login            Form-based credential exchange
    /credentials          Generic credential request
    /sso/jwt              JWT-issue endpoint
    /v1/auth              REST API auth endpoint

Plus this module is intentionally not coupled to a specific HTTP
framework. Callers feed it events; it returns verdicts.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# Default paths that warrant context-checking. Implementations MAY
# extend this set or replace it with policy from environment / config.
DEFAULT_CREDENTIAL_PATHS = frozenset({
    "/auth/token",
    "/oauth/token",
    "/oauth2/token",
    "/api/login",
    "/api/auth/login",
    "/credentials",
    "/sso/jwt",
    "/v1/auth",
    "/v1/auth/token",
    "/.well-known/oauth-authorization-server",
})


class CredentialRequestVerdict(Enum):
    """Outcome of a credential-request context check."""
    PASS = "pass"                # prior challenge observed, request OK
    SUSPICIOUS = "suspicious"    # no prior challenge in window
    NOT_CREDENTIAL = "not-credential"  # path not in credential-set
    POLICY_BYPASS = "policy-bypass"    # explicitly allowed per config


@dataclass
class ChallengeRecord:
    """Sealed challenge envelope that was observed arriving.

    A credential request is judged 'with context' if a matching
    challenge record exists within the causal-window.
    """
    intent: str                     # e.g. "verify_age", "session_start"
    reply_to: str                   # endpoint or AINS-DID
    received_at: float              # unix seconds
    sender_did: Optional[str] = None
    challenge_hash: Optional[str] = None


@dataclass
class CredentialRequestEvent:
    """An inbound credential request to be checked."""
    path: str                       # request URL path
    method: str                     # POST / GET / etc.
    source: str                     # IP / AINS-DID / "unknown"
    occurred_at: float = field(default_factory=time.time)
    body_hint: Optional[str] = None  # e.g. "grant_type=client_credentials"


@dataclass
class SniffResult:
    """Verdict + reasoning for a credential request."""
    verdict: CredentialRequestVerdict
    path: str
    source: str
    occurred_at: float
    matched_challenge: Optional[ChallengeRecord] = None
    reason: str = ""

    def to_dict(self) -> dict:
        d = {
            "verdict": self.verdict.value,
            "path": self.path,
            "source": self.source,
            "occurred_at": self.occurred_at,
            "reason": self.reason,
        }
        if self.matched_challenge:
            d["matched_challenge"] = {
                "intent": self.matched_challenge.intent,
                "reply_to": self.matched_challenge.reply_to,
                "received_at": self.matched_challenge.received_at,
            }
        return d


class CredentialRequestObserver:
    """Tracks recent sealed-challenge arrivals and judges credential
    requests against them.

    Causal-window: by default, a challenge envelope within the last
    300 seconds (5 min) counts as context. Configurable via the
    `causal_window_sec` constructor argument.

    Memory model: in-memory ring of recent challenges, capped at
    `max_recent` (default 1024). For longer retention, an
    implementation can persist out-of-band; this module is
    intentionally small.
    """

    def __init__(
        self,
        causal_window_sec: float = 300.0,
        credential_paths: Optional[frozenset[str]] = None,
        max_recent: int = 1024,
        policy_bypass_paths: Optional[frozenset[str]] = None,
    ):
        self.causal_window_sec = causal_window_sec
        self.credential_paths = (
            credential_paths
            if credential_paths is not None
            else DEFAULT_CREDENTIAL_PATHS
        )
        self.max_recent = max_recent
        self.policy_bypass_paths = policy_bypass_paths or frozenset()
        self._recent_challenges: list[ChallengeRecord] = []

    def observe_challenge(self, record: ChallengeRecord) -> None:
        """Record that a sealed challenge envelope arrived."""
        self._recent_challenges.append(record)
        # Trim — keep newest max_recent
        if len(self._recent_challenges) > self.max_recent:
            self._recent_challenges = self._recent_challenges[
                -self.max_recent:
            ]

    def check_request(
        self,
        event: CredentialRequestEvent,
    ) -> SniffResult:
        """Judge a credential request against the recent-challenge cache."""
        # Path filter — only credential-paths trigger the check
        if event.path not in self.credential_paths:
            return SniffResult(
                verdict=CredentialRequestVerdict.NOT_CREDENTIAL,
                path=event.path,
                source=event.source,
                occurred_at=event.occurred_at,
                reason="path not in credential-set",
            )

        # Policy bypass (= operator says "yes I know, this is OK")
        if event.path in self.policy_bypass_paths:
            return SniffResult(
                verdict=CredentialRequestVerdict.POLICY_BYPASS,
                path=event.path,
                source=event.source,
                occurred_at=event.occurred_at,
                reason="path explicitly in policy_bypass_paths",
            )

        # Look for a matching challenge in the causal window
        cutoff = event.occurred_at - self.causal_window_sec
        matched: Optional[ChallengeRecord] = None
        for ch in reversed(self._recent_challenges):
            if ch.received_at < cutoff:
                continue
            # Match on reply_to or sender_did approximately ==
            # request path or source
            if (
                ch.reply_to == event.path
                or ch.reply_to.endswith(event.path)
                or ch.sender_did == event.source
            ):
                matched = ch
                break

        if matched:
            age = event.occurred_at - matched.received_at
            return SniffResult(
                verdict=CredentialRequestVerdict.PASS,
                path=event.path,
                source=event.source,
                occurred_at=event.occurred_at,
                matched_challenge=matched,
                reason=(
                    f"prior sealed challenge intent='{matched.intent}'"
                    f" arrived {age:.1f}s ago"
                ),
            )

        return SniffResult(
            verdict=CredentialRequestVerdict.SUSPICIOUS,
            path=event.path,
            source=event.source,
            occurred_at=event.occurred_at,
            reason=(
                f"no sealed challenge for '{event.path}' from "
                f"'{event.source}' within {self.causal_window_sec}s "
                f"causal window"
            ),
        )

    def stats(self) -> dict:
        """Quick stats — useful for daemon health endpoints."""
        return {
            "recent_challenges_count": len(self._recent_challenges),
            "causal_window_sec": self.causal_window_sec,
            "credential_paths_count": len(self.credential_paths),
            "policy_bypass_paths_count": len(self.policy_bypass_paths),
        }


__all__ = [
    "DEFAULT_CREDENTIAL_PATHS",
    "CredentialRequestVerdict",
    "ChallengeRecord",
    "CredentialRequestEvent",
    "SniffResult",
    "CredentialRequestObserver",
]
