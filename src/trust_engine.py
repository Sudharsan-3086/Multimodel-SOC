"""
trust_engine.py
----------------
Implements the paper's Dynamic Evidence Trust Scoring model.

Definition
==========
For an evidence item e_j observed at time t_j and evaluated at the current
investigation time t, the trust weight is:

    W(e_j, t) = W0(e_j) * D(e_j, t) * S(e_j) * V(e_j)

Where:

  W0(e_j)  Base source-reliability prior in [0, 1], keyed by telemetry
           source class (e.g. kernel-level Sysmon telemetry is trusted
           more than a heuristic network IDS signature).

  D(e_j,t) Exponential temporal decay term:
                D = exp( -lambda_s * max(0, t - t_j) )
           lambda_s is a per-source decay constant (in units of 1/minute).
           Fresh evidence stays near 1.0; stale evidence decays toward 0,
           modelling the intuition that older observations are less
           reliable indicators of the *current* state of a host.

  S(e_j)   Corroboration multiplier:
                S = 1 + alpha * min(n_corroborators, C_max)
           Every additional, independent piece of evidence that
           corroborates e_j (same host/actor/indicator, different source)
           increases trust, with diminishing returns capped at C_max.

  V(e_j)   Verification multiplier from the Evidence Verification Agent,
           in [V_min, 1 + V_bonus]. Contradicted evidence is penalised
           below 1.0; actively confirmed evidence (e.g. cross-checked
           against a second independent telemetry source or a threat-intel
           lookup) is boosted above 1.0.

Final weights are clipped to [0, W_MAX] to keep the aggregate risk score
bounded and interpretable.

Composite Incident Risk Score
==============================
Given a set of evidence items E = {e_1 .. e_n} attached to an incident,
each with a severity/impact prior I(e_j) in [0,1] (how bad this indicator
would be if fully trusted), the aggregate incident risk is a
trust-weighted, saturating combination:

    R(E) = 1 - PRODUCT_j ( 1 - I(e_j) * W(e_j, t) )

This is the standard "noisy-OR" aggregation: independent pieces of
evidence each contribute a probability of "this incident is a true
positive/high severity", and the overall risk saturates toward 1.0 as
more high-trust, high-impact evidence accumulates, without exceeding 1.0
the way a naive sum would.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


W_MAX = 1.5          # absolute ceiling on a single evidence weight
V_MIN = 0.15         # floor applied to actively contradicted evidence
V_BONUS_MAX = 0.5    # max multiplicative bonus for actively confirmed evidence
ALPHA_CORROBORATION = 0.15
C_MAX_CORROBORATORS = 4


class SourceClass(str, Enum):
    SYSMON = "sysmon"
    WINDOWS_EVENT_LOG = "windows_event_log"
    SURICATA = "suricata"
    THREAT_INTEL = "threat_intel"
    ANALYST = "analyst"
    UNKNOWN = "unknown"


# Base reliability priors W0(e_j) per source class, and per-minute decay
# constants lambda_s. Kernel/EDR-grade telemetry (Sysmon) is weighted
# highest and decays slowest; signature-based network alerts are
# noisier and decay faster; unauthenticated/unknown sources are most
# conservative.
SOURCE_PRIORS: Dict[SourceClass, Dict[str, float]] = {
    SourceClass.SYSMON: {"w0": 0.92, "lambda_per_min": 0.0009},
    SourceClass.WINDOWS_EVENT_LOG: {"w0": 0.80, "lambda_per_min": 0.0012},
    SourceClass.SURICATA: {"w0": 0.72, "lambda_per_min": 0.0020},
    SourceClass.THREAT_INTEL: {"w0": 0.85, "lambda_per_min": 0.0004},
    SourceClass.ANALYST: {"w0": 0.97, "lambda_per_min": 0.0002},
    SourceClass.UNKNOWN: {"w0": 0.45, "lambda_per_min": 0.0035},
}


class VerificationStatus(str, Enum):
    UNVERIFIED = "unverified"
    CONFIRMED = "confirmed"          # cross-checked & corroborated
    CONTRADICTED = "contradicted"    # conflicts with other evidence
    INCONCLUSIVE = "inconclusive"


@dataclass
class EvidenceItem:
    evidence_id: str
    source: SourceClass
    description: str
    raw: Dict[str, Any]
    observed_at: datetime
    impact_prior: float = 0.5          # I(e_j) in [0,1]
    corroborators: List[str] = field(default_factory=list)
    verification_status: VerificationStatus = VerificationStatus.UNVERIFIED
    verification_note: Optional[str] = None

    # populated by TrustEngine.score()
    trust_weight: Optional[float] = None
    decay_factor: Optional[float] = None
    corroboration_factor: Optional[float] = None
    verification_factor: Optional[float] = None


@dataclass
class TrustBreakdown:
    evidence_id: str
    w0_base: float
    decay_factor: float
    corroboration_factor: float
    verification_factor: float
    trust_weight: float
    minutes_elapsed: float


class TrustEngine:
    """Computes dynamic trust weights W(e_j) and aggregate incident risk R(E)."""

    def __init__(self, now: Optional[datetime] = None) -> None:
        self.now = now or datetime.now(timezone.utc)

    # ------------------------------------------------------------------
    def _verification_multiplier(self, item: EvidenceItem) -> float:
        if item.verification_status == VerificationStatus.CONFIRMED:
            return 1.0 + V_BONUS_MAX
        if item.verification_status == VerificationStatus.CONTRADICTED:
            return V_MIN
        if item.verification_status == VerificationStatus.INCONCLUSIVE:
            return 0.75
        return 1.0  # unverified: neutral

    def _decay_factor(self, item: EvidenceItem, lambda_per_min: float) -> float:
        observed = item.observed_at
        if observed.tzinfo is None:
            observed = observed.replace(tzinfo=timezone.utc)
        elapsed_min = max(0.0, (self.now - observed).total_seconds() / 60.0)
        return math.exp(-lambda_per_min * elapsed_min), elapsed_min

    def score(self, item: EvidenceItem) -> TrustBreakdown:
        """Compute W(e_j, t) for a single evidence item and mutate it in place."""
        priors = SOURCE_PRIORS.get(item.source, SOURCE_PRIORS[SourceClass.UNKNOWN])
        w0 = priors["w0"]
        decay, elapsed_min = self._decay_factor(item, priors["lambda_per_min"])

        n_corrob = min(len(item.corroborators), C_MAX_CORROBORATORS)
        corroboration = 1.0 + ALPHA_CORROBORATION * n_corrob

        verification = self._verification_multiplier(item)

        raw_weight = w0 * decay * corroboration * verification
        weight = max(0.0, min(W_MAX, raw_weight))

        item.trust_weight = weight
        item.decay_factor = decay
        item.corroboration_factor = corroboration
        item.verification_factor = verification

        return TrustBreakdown(
            evidence_id=item.evidence_id,
            w0_base=w0,
            decay_factor=round(decay, 4),
            corroboration_factor=round(corroboration, 4),
            verification_factor=round(verification, 4),
            trust_weight=round(weight, 4),
            minutes_elapsed=round(elapsed_min, 2),
        )

    def score_all(self, items: List[EvidenceItem]) -> List[TrustBreakdown]:
        return [self.score(item) for item in items]

    # ------------------------------------------------------------------
    @staticmethod
    def aggregate_risk(items: List[EvidenceItem]) -> float:
        """
        Noisy-OR aggregation of trust-weighted, impact-scaled evidence into
        a single incident risk score in [0, 1]:

            R(E) = 1 - PRODUCT_j (1 - I(e_j) * clamp(W(e_j), 0, 1))
        """
        survival = 1.0
        for item in items:
            w = item.trust_weight if item.trust_weight is not None else 0.0
            w_clamped = max(0.0, min(1.0, w))
            contribution = max(0.0, min(1.0, item.impact_prior * w_clamped))
            survival *= (1.0 - contribution)
        return round(1.0 - survival, 4)

    @staticmethod
    def risk_tier(risk: float) -> str:
        if risk >= 0.85:
            return "CRITICAL"
        if risk >= 0.65:
            return "HIGH"
        if risk >= 0.35:
            return "MEDIUM"
        if risk >= 0.15:
            return "LOW"
        return "INFORMATIONAL"
