"""
agent_orchestrator.py
-----------------------
Multi-agent state machine implementing the paper's "Master Triage Loop":

    TRIAGE -> INVESTIGATE -> VERIFY -> {loop back to INVESTIGATE | CONCLUDE}

Three specialized async agents cooperate over shared short-term memory and
a shared knowledge graph:

  1. TriageAgent
       Performs rapid initial severity classification of the incoming
       incident/alert using rule-based heuristics blended with an
       (optionally LLM-backed) reasoning summary.

  2. InvestigationAgent (Graph Agent)
       Expands the knowledge graph from the entry point outward, ingesting
       related telemetry, and computes candidate attack paths across
       hosts / users / processes / network indicators.

  3. EvidenceVerificationAgent
       Runs the Dynamic Evidence Trust Scoring engine over all evidence
       gathered so far, assigns verification status (confirmed /
       contradicted / inconclusive) based on graph corroboration, and
       computes the aggregate incident risk score R(E).

The Orchestrator drives the loop: after each VERIFY phase it decides
whether the aggregate risk / evidence coverage is conclusive enough to
stop, or whether another INVESTIGATE pass (deeper graph expansion) is
warranted - up to a configurable iteration cap, guaranteeing termination.

A lightweight, dependency-free "reasoning engine" backs natural-language
summaries. If OPENAI_API_KEY (or LITELLM-compatible envs) is present, a
real LLM call is attempted via `httpx`; otherwise, and on any failure /
timeout, a deterministic templated summary is produced instead so the
system remains fully functional offline and within serverless timeouts.
"""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from . import mock_data
from .graph_engine import GraphEngine
from .memory import LongTermMemory, ShortTermMemory
from .trust_engine import EvidenceItem, SourceClass, TrustEngine, VerificationStatus

MAX_LOOP_ITERATIONS = int(os.getenv("MAX_TRIAGE_ITERATIONS", "3"))
LLM_TIMEOUT_SECONDS = float(os.getenv("LLM_TIMEOUT_SECONDS", "6"))


class InvestigationState(str, Enum):
    TRIAGE = "TRIAGE"
    INVESTIGATE = "INVESTIGATE"
    VERIFY = "VERIFY"
    CONCLUDE = "CONCLUDE"


# ---------------------------------------------------------------------------
# Reasoning engine: optional real LLM call with a deterministic offline
# fallback. Never raises; always returns a usable string within budget.
# ---------------------------------------------------------------------------
class ReasoningEngine:
    def __init__(self) -> None:
        self.api_key = os.getenv("OPENAI_API_KEY", "").strip() or os.getenv("LITELLM_API_KEY", "").strip()
        self.model = os.getenv("LLM_MODEL", "gpt-4o-mini")
        self.base_url = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1/chat/completions")
        self.enabled = bool(self.api_key)

    async def summarize(self, system_prompt: str, user_prompt: str, fallback: str) -> str:
        if not self.enabled:
            return fallback
        try:
            import httpx

            async with httpx.AsyncClient(timeout=LLM_TIMEOUT_SECONDS) as client:
                resp = await client.post(
                    self.base_url,
                    headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                    json={
                        "model": self.model,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt},
                        ],
                        "max_tokens": 300,
                        "temperature": 0.2,
                    },
                )
                resp.raise_for_status()
                data = resp.json()
                return data["choices"][0]["message"]["content"].strip()
        except Exception:
            # Any network error, timeout, auth failure, or serverless egress
            # restriction gracefully degrades to the deterministic summary.
            return fallback


# ---------------------------------------------------------------------------
# Agents
# ---------------------------------------------------------------------------
@dataclass
class AgentContext:
    incident_id: str
    incident: Dict[str, Any]
    graph: GraphEngine
    stm: ShortTermMemory
    ltm: LongTermMemory
    trust_engine: TrustEngine
    reasoning: ReasoningEngine
    evidence_by_id: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    evidence_items: Dict[str, EvidenceItem] = field(default_factory=dict)
    ingested_ids: set = field(default_factory=set)


_SOURCE_MAP = {
    "sysmon": SourceClass.SYSMON,
    "windows_event_log": SourceClass.WINDOWS_EVENT_LOG,
    "suricata": SourceClass.SURICATA,
}

_SEVERITY_IMPACT_HINTS = {
    "lsass": 0.95,
    "cobalt strike": 0.95,
    "mimikatz": 0.95,
    "exfil": 0.9,
    "encoded": 0.7,
    "rundll32": 0.65,
    "powershell": 0.5,
    "smb2": 0.45,
}


def _impact_prior_for(evidence: Dict[str, Any]) -> float:
    text = " ".join(str(v) for v in evidence.values()).lower()
    best = 0.3
    for keyword, score in _SEVERITY_IMPACT_HINTS.items():
        if keyword in text and score > best:
            best = score
    return best


class TriageAgent:
    """Rapid initial severity classification of the incoming incident."""

    name = "TriageAgent"

    async def run(self, ctx: AgentContext) -> Dict[str, Any]:
        incident = ctx.incident
        initial_alert_id = incident.get("initial_alert")
        initial_alert = ctx.evidence_by_id.get(initial_alert_id, {})

        signature = initial_alert.get("signature", "unknown signature")
        severity_raw = initial_alert.get("severity", 2)
        rule_based_priority = "P1 - CRITICAL" if severity_raw == 1 else "P2 - HIGH"

        fallback = (
            f"Initial triage: incident {incident.get('incident_id')} triggered by '{signature}' "
            f"on host {incident.get('entry_host')} involving user {incident.get('entry_user')}. "
            f"Rule-based priority assigned: {rule_based_priority}. Escalating to graph-based "
            f"investigation to establish full attack path and blast radius."
        )
        summary = await ctx.reasoning.summarize(
            system_prompt=(
                "You are a SOC Tier-1 triage analyst. Summarize the incident in 2-3 sentences "
                "and assign a priority (P1-P4)."
            ),
            user_prompt=str(incident),
            fallback=fallback,
        )

        ctx.stm.record(self.name, "triage_summary", summary)
        ctx.stm.add_hypothesis(
            f"Entry point {incident.get('entry_host')} was compromised via {signature}."
        )

        return {
            "state": InvestigationState.TRIAGE.value,
            "priority": rule_based_priority,
            "summary": summary,
            "initial_alert_id": initial_alert_id,
        }


class InvestigationAgent:
    """Graph Agent: expands the knowledge graph and maps candidate attack paths."""

    name = "InvestigationAgent"

    async def run(self, ctx: AgentContext, expansion_depth: int) -> Dict[str, Any]:
        incident = ctx.incident
        pool_ids: List[str] = incident.get("evidence_pool", [])

        # Each investigation pass "expands" further into the evidence pool,
        # simulating progressively deeper graph traversal / pivoting.
        batch_size = max(1, len(pool_ids) // MAX_LOOP_ITERATIONS + 1)
        start = len(ctx.ingested_ids)
        newly_ingested: List[str] = []

        for eid in pool_ids:
            if eid in ctx.ingested_ids:
                continue
            if len(newly_ingested) >= batch_size * expansion_depth - start:
                break
            evidence = ctx.evidence_by_id.get(eid)
            if not evidence:
                continue
            ctx.graph.ingest_evidence(evidence)
            ctx.ingested_ids.add(eid)
            newly_ingested.append(eid)

            source_class = _SOURCE_MAP.get(evidence.get("source"), SourceClass.UNKNOWN)
            observed_at = _parse_ts(evidence.get("timestamp"))
            item = EvidenceItem(
                evidence_id=eid,
                source=source_class,
                description=evidence.get("description", evidence.get("signature", "")),
                raw=evidence,
                observed_at=observed_at,
                impact_prior=_impact_prior_for(evidence),
            )
            ctx.evidence_items[eid] = item

        entry_host = incident.get("entry_host")
        attack_path: Optional[List[str]] = None
        dc_candidates = [n for n, d in ctx.graph.g.nodes(data=True) if d.get("type") == "host" and n != entry_host]
        for target in dc_candidates:
            path = ctx.graph.find_attack_path(entry_host, target)
            if path and (attack_path is None or len(path) > len(attack_path)):
                attack_path = path

        centrality = ctx.graph.high_centrality_nodes(top_n=5)

        fallback = (
            f"Investigation pass {expansion_depth}/{MAX_LOOP_ITERATIONS}: ingested "
            f"{len(newly_ingested)} new evidence items ({len(ctx.ingested_ids)}/{len(pool_ids)} total). "
            f"Graph now has {ctx.graph.g.number_of_nodes()} nodes / {ctx.graph.g.number_of_edges()} edges. "
            + (f"Candidate attack path: {' -> '.join(attack_path)}." if attack_path else
               "No lateral-movement path to a second host established yet.")
        )
        summary = await ctx.reasoning.summarize(
            system_prompt=(
                "You are a SOC investigation agent reasoning over a knowledge graph of hosts, "
                "users, processes and network indicators. Summarize the attack narrative so far "
                "in 2-4 sentences."
            ),
            user_prompt=f"Newly ingested evidence: {newly_ingested}. Attack path: {attack_path}.",
            fallback=fallback,
        )

        ctx.stm.record(self.name, f"graph_expansion_pass_{expansion_depth}", summary)
        if attack_path:
            ctx.stm.add_hypothesis(f"Lateral movement path established: {' -> '.join(attack_path)}")

        return {
            "state": InvestigationState.INVESTIGATE.value,
            "pass_number": expansion_depth,
            "newly_ingested_evidence": newly_ingested,
            "total_ingested": len(ctx.ingested_ids),
            "evidence_pool_size": len(pool_ids),
            "attack_path": attack_path,
            "high_centrality_nodes": centrality,
            "summary": summary,
        }


class EvidenceVerificationAgent:
    """Runs Dynamic Evidence Trust Scoring and corroboration analysis."""

    name = "EvidenceVerificationAgent"

    async def run(self, ctx: AgentContext) -> Dict[str, Any]:
        items = list(ctx.evidence_items.values())

        # Corroboration: two pieces of evidence corroborate one another if
        # they share a host/user/ip AND fall within a 30-minute window -
        # approximated here via the graph's shared-neighbor structure.
        for item in items:
            neighbors_of_host = self._related_evidence_ids(ctx, item)
            item.corroborators = [e for e in neighbors_of_host if e != item.evidence_id]

            if len(item.corroborators) >= 2:
                item.verification_status = VerificationStatus.CONFIRMED
                item.verification_note = f"Corroborated by {len(item.corroborators)} independent evidence item(s)."
            elif len(item.corroborators) == 1:
                item.verification_status = VerificationStatus.INCONCLUSIVE
                item.verification_note = "Single corroborating source; treat as provisional."
            else:
                item.verification_status = VerificationStatus.UNVERIFIED
                item.verification_note = "No independent corroboration found yet."

        breakdowns = ctx.trust_engine.score_all(items)
        risk = ctx.trust_engine.aggregate_risk(items)
        tier = ctx.trust_engine.risk_tier(risk)

        fallback = (
            f"Verification pass complete over {len(items)} evidence items. "
            f"{sum(1 for i in items if i.verification_status == VerificationStatus.CONFIRMED)} confirmed, "
            f"{sum(1 for i in items if i.verification_status == VerificationStatus.INCONCLUSIVE)} inconclusive, "
            f"{sum(1 for i in items if i.verification_status == VerificationStatus.UNVERIFIED)} unverified. "
            f"Aggregate trust-weighted incident risk: {risk} ({tier})."
        )
        summary = await ctx.reasoning.summarize(
            system_prompt=(
                "You are a SOC evidence-verification agent. Given trust scores and verification "
                "statuses, summarize confidence in the incident verdict in 2-3 sentences."
            ),
            user_prompt=f"Risk={risk} Tier={tier} N_items={len(items)}",
            fallback=fallback,
        )

        ctx.stm.record(self.name, "verification_summary", summary)

        return {
            "state": InvestigationState.VERIFY.value,
            "risk_score": risk,
            "risk_tier": tier,
            "evidence_breakdown": [b.__dict__ for b in breakdowns],
            "verification_detail": [
                {
                    "evidence_id": i.evidence_id,
                    "status": i.verification_status.value,
                    "note": i.verification_note,
                    "corroborators": i.corroborators,
                }
                for i in items
            ],
            "summary": summary,
        }

    @staticmethod
    def _related_evidence_ids(ctx: AgentContext, item: EvidenceItem) -> List[str]:
        related: set = set()
        raw = item.raw
        anchor_values = {v for v in [raw.get("host"), raw.get("user"), raw.get("dest_ip"), raw.get("src_ip")] if v}
        for other_id, other in ctx.evidence_by_id.items():
            if other_id == item.evidence_id or other_id not in ctx.ingested_ids:
                continue
            other_values = {v for v in [other.get("host"), other.get("user"), other.get("dest_ip"), other.get("src_ip")] if v}
            if anchor_values & other_values:
                related.add(other_id)
        return sorted(related)


def _parse_ts(ts: Optional[str]) -> datetime:
    if not ts:
        return datetime.now(timezone.utc)
    try:
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Orchestrator: the Master Triage Loop
# ---------------------------------------------------------------------------
class Orchestrator:
    """
    Drives TRIAGE -> INVESTIGATE -> VERIFY -> {loop | CONCLUDE}.

    Continuation criterion: keep looping (more graph expansion + evidence
    ingestion) while the risk score sits in an "ambiguous" band (MEDIUM
    tier) or while unverified evidence still dominates, up to
    MAX_LOOP_ITERATIONS - guaranteeing termination even on pathological
    graphs.
    """

    def __init__(self) -> None:
        self.reasoning = ReasoningEngine()

    async def investigate(self, incident_id: str) -> Dict[str, Any]:
        started = time.monotonic()
        incident = mock_data.get_incident(incident_id)
        if incident is None:
            raise ValueError(f"Unknown incident_id '{incident_id}'")

        ctx = AgentContext(
            incident_id=incident_id,
            incident=incident,
            graph=GraphEngine(),
            stm=ShortTermMemory(),
            ltm=LongTermMemory(),
            trust_engine=TrustEngine(),
            reasoning=self.reasoning,
            evidence_by_id=mock_data.get_all_evidence_by_id(),
        )

        triage_agent = TriageAgent()
        investigation_agent = InvestigationAgent()
        verification_agent = EvidenceVerificationAgent()

        timeline: List[Dict[str, Any]] = []

        triage_result = await triage_agent.run(ctx)
        timeline.append(triage_result)

        iteration = 0
        verify_result: Dict[str, Any] = {}
        investigate_result: Dict[str, Any] = {}

        while iteration < MAX_LOOP_ITERATIONS:
            iteration += 1
            investigate_result = await investigation_agent.run(ctx, expansion_depth=iteration)
            timeline.append(investigate_result)

            verify_result = await verification_agent.run(ctx)
            timeline.append(verify_result)

            tier = verify_result["risk_tier"]
            coverage_complete = investigate_result["total_ingested"] >= investigate_result["evidence_pool_size"]

            should_continue = (tier in ("MEDIUM", "LOW")) and not coverage_complete
            if not should_continue:
                break
            # simulate real async agent work (I/O-bound in production)
            await asyncio.sleep(0)

        ctx.ltm.remember(
            text=f"Incident {incident_id}: {incident.get('title')} concluded with risk "
            f"{verify_result.get('risk_score')} ({verify_result.get('risk_tier')}).",
            metadata={"incident_id": incident_id, "risk_tier": verify_result.get("risk_tier")},
        )

        conclude_result = self._conclude(ctx, verify_result, investigate_result, iteration)
        timeline.append(conclude_result)

        elapsed_ms = round((time.monotonic() - started) * 1000, 2)

        return {
            "incident_id": incident_id,
            "incident_title": incident.get("title"),
            "iterations_run": iteration,
            "elapsed_ms": elapsed_ms,
            "reasoning_backend": "llm" if self.reasoning.enabled else "offline-deterministic",
            "graph_backend": ctx.graph.backend,
            "final_state": InvestigationState.CONCLUDE.value,
            "verdict": conclude_result,
            "timeline": timeline,
            "agent_transcript": ctx.stm.transcript(),
            "working_hypotheses": ctx.stm.working_hypotheses,
            "graph_snapshot": ctx.graph.to_dict(),
        }

    def _conclude(
        self,
        ctx: AgentContext,
        verify_result: Dict[str, Any],
        investigate_result: Dict[str, Any],
        iterations: int,
    ) -> Dict[str, Any]:
        tier = verify_result.get("risk_tier", "INFORMATIONAL")
        risk = verify_result.get("risk_score", 0.0)
        attack_path = investigate_result.get("attack_path")

        response_playbook = self._recommend_actions(tier, attack_path)

        return {
            "state": InvestigationState.CONCLUDE.value,
            "risk_score": risk,
            "risk_tier": tier,
            "confirmed_evidence_count": sum(
                1 for v in verify_result.get("verification_detail", []) if v["status"] == "confirmed"
            ),
            "attack_path": attack_path,
            "recommended_actions": response_playbook,
            "iterations_run": iterations,
        }

    @staticmethod
    def _recommend_actions(tier: str, attack_path: Optional[List[str]]) -> List[str]:
        actions = []
        if tier in ("CRITICAL", "HIGH"):
            actions.append("Isolate affected endpoint(s) from the network immediately.")
            actions.append("Force credential reset for all implicated accounts.")
            actions.append("Escalate to Tier-3 / Incident Response for forensic imaging.")
        if attack_path and len(attack_path) > 1:
            actions.append(
                f"Contain lateral-movement path: {' -> '.join(attack_path)} "
                "(review firewall/segmentation rules between these assets)."
            )
        if tier == "MEDIUM":
            actions.append("Open a formal investigation ticket and continue monitoring for 24h.")
        if tier in ("LOW", "INFORMATIONAL"):
            actions.append("Log for trend analysis; no immediate action required.")
        actions.append("Update detection rules/signatures based on confirmed indicators.")
        return actions
