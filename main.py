"""
main.py
--------
Standalone FastAPI entrypoint.

Local run:
    uvicorn main:app --reload

Container / Render run:
    uvicorn main:app --host 0.0.0.0 --port $PORT
"""

from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from src import mock_data
from src.agent_orchestrator import Orchestrator
from src.graph_engine import GraphEngine

APP_START_TIME = time.time()

app = FastAPI(
    title="Graph-Grounded SOC Multi-Agent Orchestrator",
    description=(
        "Reference implementation of 'Graph-Grounded Multi-Agent Orchestration with "
        "Dynamic Evidence Trust Scoring for Autonomous SOC Incident Investigation and "
        "Response'. Runs fully offline against mock SOC telemetry by default."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Process-lifetime singletons. In serverless (Vercel) mode each cold start
# gets a fresh instance, which is expected and fine: state is scoped per
# investigation request, not accumulated globally.
_orchestrator = Orchestrator()
_demo_graph = GraphEngine()
_demo_graph.ingest_many(list(mock_data.get_all_evidence_by_id().values()))


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------
class InvestigateRequest(BaseModel):
    incident_id: str = Field(..., description="Incident identifier, e.g. 'INC-1001'")


class InvestigateResponse(BaseModel):
    incident_id: str
    incident_title: Optional[str]
    iterations_run: int
    elapsed_ms: float
    reasoning_backend: str
    graph_backend: str
    final_state: str
    verdict: Dict[str, Any]
    timeline: List[Dict[str, Any]]
    agent_transcript: List[Dict[str, Any]]
    working_hypotheses: List[str]
    graph_snapshot: Dict[str, Any]


class HealthResponse(BaseModel):
    status: str
    uptime_seconds: float
    graph_backend: str
    reasoning_backend: str
    known_incidents: List[str]
    version: str


class GraphQueryResponse(BaseModel):
    query: str
    node_count: int
    edge_count: int
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/health", response_model=HealthResponse, tags=["system"])
async def health() -> HealthResponse:
    """Liveness/readiness probe. Never touches external services."""
    return HealthResponse(
        status="ok",
        uptime_seconds=round(time.time() - APP_START_TIME, 2),
        graph_backend=_demo_graph.backend,
        reasoning_backend="llm" if _orchestrator.reasoning.enabled else "offline-deterministic",
        known_incidents=[i["incident_id"] for i in mock_data.list_incidents()],
        version="1.0.0",
    )


@app.post("/api/investigate", response_model=InvestigateResponse, tags=["investigation"])
async def investigate(payload: InvestigateRequest) -> Dict[str, Any]:
    """
    Runs the full Master Triage Loop (Triage -> Investigate -> Verify ->
    Conclude) for the given incident_id against the mock SOC telemetry
    fixtures, and returns the complete investigation report including
    per-evidence trust breakdowns, the reconstructed attack path, the
    aggregate risk score, and recommended response actions.
    """
    try:
        result = await _orchestrator.investigate(payload.incident_id)
    except ValueError as exc:
        known = [i["incident_id"] for i in mock_data.list_incidents()]
        raise HTTPException(
            status_code=404,
            detail=f"{exc}. Known incident_ids: {known}",
        ) from exc
    return result


@app.get("/api/graph/query", response_model=GraphQueryResponse, tags=["graph"])
async def graph_query(
    q: str = Query(..., description="Keyword to match against node ids/types or edge relations"),
) -> Dict[str, Any]:
    """
    Keyword query over the demo knowledge graph (pre-populated with all
    mock telemetry at startup). For a graph scoped to a single
    investigation's evidence, call /api/investigate first and inspect the
    returned `graph_snapshot`.
    """
    result = _demo_graph.query(q)
    return {
        "query": q,
        "node_count": len(result.nodes),
        "edge_count": len(result.edges),
        "nodes": result.nodes,
        "edges": result.edges,
    }


@app.get("/api/incidents", tags=["investigation"])
async def list_incidents() -> List[Dict[str, Any]]:
    """Convenience endpoint: list the mock incidents available to investigate."""
    return mock_data.list_incidents()


@app.get("/", tags=["system"])
async def root() -> Dict[str, str]:
    return {
        "service": "soc-multi-agent-orchestrator",
        "docs": "/docs",
        "health": "/api/health",
        "investigate": "POST /api/investigate {\"incident_id\": \"INC-1001\"}",
        "graph_query": "/api/graph/query?q=powershell",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")), reload=True)
