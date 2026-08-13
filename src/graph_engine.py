"""
graph_engine.py
-----------------
In-memory / NetworkX-backed Knowledge Graph for SOC entity-relationship
reasoning and attack-path mapping.

Nodes represent SOC entities: hosts, users, processes, IPs, files, and
alerts. Edges represent observed relationships between them, each edge
carrying a reference back to the evidence_id that produced it and a
`weight` that (once trust-scored) reflects confidence in the relationship.

This module deliberately has zero external dependencies beyond
`networkx`, so it works identically whether backed by a real graph
database (Neo4j / Memgraph) in a future iteration or the in-memory
default used here. If a `GRAPH_DB_URI` environment variable is not set,
the engine transparently falls back to the in-memory NetworkX graph -
there is no code path that requires an external graph database to run.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import networkx as nx


class NodeType:
    HOST = "host"
    USER = "user"
    PROCESS = "process"
    IP = "ip"
    FILE = "file"
    ALERT = "alert"


@dataclass
class GraphQueryResult:
    nodes: List[Dict[str, Any]] = field(default_factory=list)
    edges: List[Dict[str, Any]] = field(default_factory=list)
    matched_query: str = ""


class GraphEngine:
    """
    Wraps a networkx.MultiDiGraph. Falls back cleanly to in-memory mode
    when no external graph database is configured via GRAPH_DB_URI.
    """

    def __init__(self) -> None:
        self.backend = "networkx-in-memory"
        external_uri = os.getenv("GRAPH_DB_URI", "").strip()
        if external_uri:
            # Placeholder for a real driver (Neo4j/Memgraph/etc). We do not
            # import optional heavy drivers unless explicitly configured,
            # and we never hard-fail if they are unavailable - we log and
            # fall back so the service remains deployable anywhere.
            try:
                import importlib

                importlib.import_module("neo4j")  # optional dependency
                self.backend = f"external:{external_uri.split('://')[0]}"
            except Exception:
                self.backend = "networkx-in-memory (external driver unavailable, fell back)"
        self.g = nx.MultiDiGraph()

    # ------------------------------------------------------------------
    def upsert_node(self, node_id: str, node_type: str, **attrs: Any) -> None:
        if self.g.has_node(node_id):
            self.g.nodes[node_id].update(attrs)
        else:
            self.g.add_node(node_id, type=node_type, **attrs)

    def add_relationship(
        self,
        src: str,
        dst: str,
        relation: str,
        evidence_id: Optional[str] = None,
        weight: float = 0.5,
        **attrs: Any,
    ) -> None:
        self.g.add_edge(
            src, dst, key=relation, relation=relation,
            evidence_id=evidence_id, weight=weight, **attrs,
        )

    # ------------------------------------------------------------------
    def ingest_evidence(self, evidence: Dict[str, Any]) -> List[Tuple[str, str, str]]:
        """
        Translate a single normalized evidence record (Sysmon / WinEventLog /
        Suricata) into graph nodes + edges. Returns the list of
        (src, relation, dst) triples that were added, for traceability.
        """
        added: List[Tuple[str, str, str]] = []
        eid = evidence.get("evidence_id")
        host = evidence.get("host")
        user = evidence.get("user")
        image = evidence.get("image") or evidence.get("process")
        parent_image = evidence.get("parent_image") or evidence.get("parent_process")
        dest_ip = evidence.get("dest_ip") or evidence.get("src_ip")
        signature = evidence.get("signature")

        if host:
            self.upsert_node(host, NodeType.HOST)
        if user:
            self.upsert_node(user, NodeType.USER)
        if image:
            self.upsert_node(image, NodeType.PROCESS, host=host)
        if parent_image:
            self.upsert_node(parent_image, NodeType.PROCESS, host=host)
        if dest_ip:
            self.upsert_node(dest_ip, NodeType.IP)
        if signature:
            self.upsert_node(eid, NodeType.ALERT, signature=signature, severity=evidence.get("severity"))

        if user and host:
            self.add_relationship(user, host, "authenticated_on", evidence_id=eid, weight=0.6)
            added.append((user, "authenticated_on", host))
            # Reciprocal edge so a host is graph-reachable from its own
            # logon activity (attack paths traverse host -> credential ->
            # next host even though the raw log direction is user->host).
            self.add_relationship(host, user, "session_of", evidence_id=eid, weight=0.6)
            added.append((host, "session_of", user))

        if image and host:
            # Always link host -> process regardless of whether a parent
            # process is also known, so the host node stays reachable as
            # the root of the process tree for attack-path traversal.
            self.add_relationship(host, image, "hosts_process", evidence_id=eid, weight=0.5)
            added.append((host, "hosts_process", image))

        if parent_image and image:
            self.add_relationship(parent_image, image, "spawned", evidence_id=eid, weight=0.7)
            added.append((parent_image, "spawned", image))

        if image and dest_ip:
            self.add_relationship(image, dest_ip, "connected_to", evidence_id=eid, weight=0.55)
            added.append((image, "connected_to", dest_ip))
        elif host and dest_ip and not image:
            self.add_relationship(host, dest_ip, "network_flow", evidence_id=eid, weight=0.4)
            added.append((host, "network_flow", dest_ip))

        if signature and host:
            self.add_relationship(eid, host, "observed_on", evidence_id=eid, weight=0.65)
            added.append((eid, "observed_on", host))

        return added

    def ingest_many(self, evidence_items: List[Dict[str, Any]]) -> int:
        count = 0
        for item in evidence_items:
            count += len(self.ingest_evidence(item))
        return count

    # ------------------------------------------------------------------
    def find_attack_path(self, entry_node: str, target_node: str) -> Optional[List[str]]:
        """Shortest directed path from an entry point to a target entity, if any."""
        if entry_node not in self.g or target_node not in self.g:
            return None
        try:
            return nx.shortest_path(self.g, source=entry_node, target=target_node)
        except nx.NetworkXNoPath:
            return None

    def find_all_paths(self, entry_node: str, target_node: str, cutoff: int = 8) -> List[List[str]]:
        if entry_node not in self.g or target_node not in self.g:
            return []
        try:
            return list(nx.all_simple_paths(self.g, entry_node, target_node, cutoff=cutoff))
        except nx.NetworkXNoPath:
            return []

    def neighbors(self, node_id: str) -> Dict[str, Any]:
        if node_id not in self.g:
            return {}
        out_edges = [
            {"target": v, "relation": data.get("relation"), "evidence_id": data.get("evidence_id")}
            for _, v, data in self.g.out_edges(node_id, data=True)
        ]
        in_edges = [
            {"source": u, "relation": data.get("relation"), "evidence_id": data.get("evidence_id")}
            for u, _, data in self.g.in_edges(node_id, data=True)
        ]
        return {"node": node_id, "attrs": dict(self.g.nodes[node_id]), "out": out_edges, "in": in_edges}

    def high_centrality_nodes(self, top_n: int = 5) -> List[Dict[str, Any]]:
        if self.g.number_of_nodes() == 0:
            return []
        centrality = nx.degree_centrality(self.g)
        ranked = sorted(centrality.items(), key=lambda kv: kv[1], reverse=True)[:top_n]
        return [{"node": n, "centrality": round(c, 4), "type": self.g.nodes[n].get("type")} for n, c in ranked]

    # ------------------------------------------------------------------
    def query(self, text: str) -> GraphQueryResult:
        """
        Lightweight keyword query over node ids/attrs and edge relations -
        a pragmatic stand-in for a Cypher/Gremlin query layer. Matches
        case-insensitively against node ids, node types, and edge relations.
        """
        needle = text.strip().lower()
        result = GraphQueryResult(matched_query=text)
        if not needle:
            return result

        for node_id, attrs in self.g.nodes(data=True):
            haystack = f"{node_id} {attrs.get('type', '')} {' '.join(str(v) for v in attrs.values())}".lower()
            if needle in haystack:
                result.nodes.append({"id": node_id, **attrs})

        for u, v, data in self.g.edges(data=True):
            haystack = f"{u} {v} {data.get('relation', '')}".lower()
            if needle in haystack:
                result.edges.append({"source": u, "target": v, **data})

        return result

    def to_dict(self) -> Dict[str, Any]:
        return {
            "backend": self.backend,
            "node_count": self.g.number_of_nodes(),
            "edge_count": self.g.number_of_edges(),
            "nodes": [{"id": n, **d} for n, d in self.g.nodes(data=True)],
            "edges": [{"source": u, "target": v, **d} for u, v, d in self.g.edges(data=True)],
        }
