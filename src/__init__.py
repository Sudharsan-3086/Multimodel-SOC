"""
SOC Multi-Agent Orchestration package.

Implements a reference architecture for:
  "Graph-Grounded Multi-Agent Orchestration with Dynamic Evidence Trust
   Scoring for Autonomous SOC Incident Investigation and Response"

Modules:
  mock_data.py           - synthetic SOC telemetry fixtures
  trust_engine.py         - dynamic evidence trust / risk scoring math
  graph_engine.py          - knowledge graph reasoning & attack path mapping
  memory.py                - short/long term memory + lightweight vector store
  agent_orchestrator.py    - multi-agent state machine (Master Triage Loop)
"""

__version__ = "1.0.0"
