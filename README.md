# Graph-Grounded SOC Multi-Agent Orchestrator

Production-ready reference implementation of **"Graph-Grounded Multi-Agent
Orchestration with Dynamic Evidence Trust Scoring for Autonomous SOC
Incident Investigation and Response."**

Runs fully offline out of the box against bundled mock Windows Event Log,
Sysmon, and Suricata telemetry — no cloud accounts, API keys, or external
databases required. Optional integrations (LLM reasoning, external graph
DB, external vector DB) are auto-detected via environment variables and
fall back cleanly to in-memory / deterministic implementations when unset.

## 1. Architecture

```
Client ──> FastAPI (/api/investigate) ──> Orchestrator (Master Triage Loop)
                                              │
                     ┌────────────────────────┼────────────────────────┐
                     ▼                        ▼                        ▼
              TriageAgent          InvestigationAgent          EvidenceVerificationAgent
           (rule-based +            (GraphEngine / NetworkX:      (TrustEngine: dynamic
            optional LLM             attack-path mapping,          evidence trust scoring
            severity summary)        entity graph expansion)       W(e_j) + risk score R(E))
                     │                        │                        │
                     └────────────► ShortTermMemory / LongTermMemory ◄─┘
                                    (per-run scratchpad + vector recall)
```

**Master Triage Loop (state machine):**

```
TRIAGE ──> INVESTIGATE ──> VERIFY ──┬──> (risk ambiguous & evidence remains) ──> INVESTIGATE
                                     └──> CONCLUDE  (bounded by MAX_TRIAGE_ITERATIONS, default 3)
```

### Dynamic Evidence Trust Scoring

For evidence item `e_j` observed at `t_j`, evaluated at time `t`:

```
W(e_j, t) = W0(e_j) · D(e_j, t) · S(e_j) · V(e_j)

  W0(e_j)   source-reliability prior (Sysmon 0.92, WinEventLog 0.80, Suricata 0.72, ...)
  D(e_j,t)  = exp(-λ_s · Δt)              temporal decay
  S(e_j)    = 1 + α · min(n_corroborators, C_max)   corroboration multiplier
  V(e_j)    verification multiplier: contradicted → 0.15, confirmed → 1.5, else neutral
```

Aggregate incident risk uses noisy-OR combination of trust-weighted,
impact-scaled evidence:

```
R(E) = 1 - Π_j ( 1 - I(e_j) · clamp(W(e_j), 0, 1) )
```

See `src/trust_engine.py` for the full implementation and docstring.

## 2. Repository Structure

```
├── api/
│   └── index.py             # Vercel ASGI Handler Entrypoint
├── src/
│   ├── agent_orchestrator.py # Multi-agent state machine & Master Triage Loop
│   ├── trust_engine.py       # Dynamic evidence trust & risk score math
│   ├── graph_engine.py       # Knowledge graph reasoning & attack path mapping
│   ├── memory.py             # Short/long-term memory + lightweight vector store
│   └── mock_data.py          # Pre-packaged SOC log telemetry fixtures
├── main.py                   # Standalone FastAPI server (Render / local)
├── requirements.txt
├── vercel.json                # Vercel configuration
├── render.yaml                 # Render Blueprint configuration
└── Dockerfile                  # Container spec for Render / generic Docker
```

## 3. Local Setup & Execution

```bash
# 1. Clone / unzip the project, then:
cd soc-orchestrator
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the server (auto-reload for development)
uvicorn main:app --reload

# Server is now live at http://127.0.0.1:8000
# Interactive API docs: http://127.0.0.1:8000/docs
```

### Try it out

```bash
# Health check
curl http://127.0.0.1:8000/api/health

# List available mock incidents
curl http://127.0.0.1:8000/api/incidents

# Run a full investigation (Triage -> Investigate -> Verify -> Conclude)
curl -X POST http://127.0.0.1:8000/api/investigate \
  -H "Content-Type: application/json" \
  -d '{"incident_id": "INC-1001"}'

# Query the pre-populated demo knowledge graph
curl "http://127.0.0.1:8000/api/graph/query?q=powershell"
```

`POST /api/investigate` returns the full report: per-evidence trust-score
breakdowns, verification status, the reconstructed attack path, the
aggregate `risk_score` / `risk_tier`, recommended response actions, the
agent transcript, and a graph snapshot.

## 4. Optional Configuration (all optional — safe defaults if unset)

| Variable | Effect if set | Fallback if unset |
|---|---|---|
| `OPENAI_API_KEY` / `LITELLM_API_KEY` | Agents call a real LLM (`LLM_MODEL`, default `gpt-4o-mini`) for narrative summaries | Deterministic templated summaries |
| `LLM_BASE_URL` | Override chat-completions endpoint (any OpenAI-compatible / LiteLLM proxy) | `https://api.openai.com/v1/chat/completions` |
| `LLM_TIMEOUT_SECONDS` | Max seconds to wait on an LLM call before falling back | `6` |
| `GRAPH_DB_URI` | Attempt to use an external graph backend | In-memory NetworkX graph |
| `VECTOR_DB_URL` | Reserved for a future external vector DB integration | In-memory NumPy cosine-similarity store with offline hashing embeddings |
| `MAX_TRIAGE_ITERATIONS` | Cap on Master Triage Loop passes | `3` |
| `CORS_ORIGINS` | Comma-separated allowed origins | `*` |

The system is fully functional and deterministic with **zero** environment
variables set — this is the default/expected mode for grading, demos, and
serverless cold starts with no network egress.

## 5. Deployment — Vercel (serverless)

```bash
npm i -g vercel        # if not already installed
cd soc-orchestrator
vercel login
vercel --prod
```

`vercel.json` routes all paths to `api/index.py`, which re-exports the
same `app` object used by `main.py`, so serverless and containerized
deployments expose an identical API surface. `maxDuration` is set to 30s
per invocation; the offline reasoning fallback keeps each investigation
well under that budget even without an LLM key configured.

**Validate:**
```bash
curl https://<your-project>.vercel.app/api/health
curl -X POST https://<your-project>.vercel.app/api/investigate \
  -H "Content-Type: application/json" -d '{"incident_id": "INC-1001"}'
```

## 6. Deployment — Render (long-running container)

**Option A — Blueprint (recommended):**
```bash
git init && git add -A && git commit -m "Initial commit"
git remote add origin <your-repo-url>
git push -u origin main
```
Then in the Render dashboard: **New > Blueprint**, point it at your repo —
`render.yaml` provisions the web service automatically
(`uvicorn main:app --host 0.0.0.0 --port $PORT`, health check on
`/api/health`).

**Option B — Manual Docker service:**
```bash
docker build -t soc-orchestrator .
docker run -p 8000:8000 -e PORT=8000 soc-orchestrator
```

**Validate:**
```bash
curl https://<your-service>.onrender.com/api/health
```

## 7. Notes on the Mock Environment

- `src/mock_data.py` ships one fully-connected incident scenario
  (`INC-1001`): encoded PowerShell launched from Word → C2 beacon →
  LSASS memory dump → lateral authentication to a domain controller —
  spanning Windows Event Log, Sysmon, and Suricata sources so all three
  telemetry families and the corroboration logic in
  `EvidenceVerificationAgent` are exercised end-to-end.
- Extend it by adding new entries to `WINDOWS_EVENT_LOGS` / `SYSMON_EVENTS`
  / `SURICATA_ALERTS` and a corresponding `INCIDENTS[...]` bundle — no
  other code changes are required for a new incident to become
  investigable via `/api/investigate`.
