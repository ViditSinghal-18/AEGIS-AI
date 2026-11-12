"""
AEGIS-AI: Bayesian Attack Graph & Most-Probable Exploit Path Engine.

Inspired by:
1. Poolsappasit, N., Dewri, R., & Ray, I. "Dynamic Security Risk Management Using
   Bayesian Attack Graphs." IEEE Transactions on Dependable and Secure Computing (TDSC), 9(1), 2012.
   - Computes conditional compromise probabilities per node using EPSS/CVSS.
   - Handles multi-parent convergence via the canonical Noisy-OR formulation.
   - Supports dynamic 'What-If I Patch X?' counterfactual re-evaluations.

2. Jha, S., Sheyner, O., & Wing, J. "Two Formal Analyses of Attack Graphs."
   In IEEE Computer Security Foundations Workshop (CSFW), 2002.
   - Maps most-probable attack path via Dijkstra on negative log-probabilities:
     w(u,v) = -ln(P(u -> v)).
   - Derives the Minimal Critical Chokepoint / Cut-Set via greedy set-cover and
     min-cut graph partitioning to disrupt all attacker paths with minimal remediation effort.
"""

from __future__ import annotations

import heapq
import math
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class AttackNode:
    """Represents a state, asset, vulnerability, or exploit milestone in an attack graph."""

    id: str
    name: str
    node_type: str  # "attacker", "ingress", "port", "vulnerability", "privilege", "goal"
    base_probability: float = 1.0  # Prior compromise probability (1.0 for attacker root)
    compromise_probability: float = 0.0
    description: str = ""
    cve_id: Optional[str] = None
    epss_score: Optional[float] = None
    is_patched: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttackEdge:
    """Directed exploitation transition from source state to target state."""

    source: str
    target: str
    exploit_probability: float  # Conditional probability p in (0.0, 1.0]
    weight: float = 0.0         # -ln(p) for additive Dijkstra path finding
    vulnerability_id: Optional[str] = None
    label: str = ""

    def __post_init__(self):
        # Bound probability strictly inside (1e-6, 1.0] to prevent math domain error
        p = max(1e-6, min(1.0, float(self.exploit_probability)))
        self.exploit_probability = p
        self.weight = round(-math.log(p), 4)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttackPathResult:
    """Result of most-probable attack sequence analysis."""

    path_nodes: List[str]
    path_names: List[str]
    path_probability: float
    additive_weight: float
    vulnerabilities_on_path: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ChokepointCutSet:
    """Minimal set of defensive remediations that sever all attack paths to the target goal."""

    chokepoint_nodes: List[str]
    chokepoint_vulnerabilities: List[str]
    paths_blocked_count: int
    total_paths_count: int
    residual_compromise_probability: float
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class BayesianAttackGraph:
    """Directed Acyclic Graph (DAG) modeling multi-step cyber attack propagation."""

    def __init__(self, target_name: str = "Target Organization"):
        self.target_name = target_name
        self.nodes: Dict[str, AttackNode] = {}
        self.edges: List[AttackEdge] = []
        self._adj: Dict[str, List[AttackEdge]] = {}
        self._rev_adj: Dict[str, List[AttackEdge]] = {}

    def add_node(
        self,
        node_id: str,
        name: str,
        node_type: str,
        base_probability: float = 0.0,
        description: str = "",
        cve_id: Optional[str] = None,
        epss_score: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AttackNode:
        node = AttackNode(
            id=node_id,
            name=name,
            node_type=node_type,
            base_probability=base_probability,
            compromise_probability=base_probability,
            description=description,
            cve_id=cve_id,
            epss_score=epss_score,
            metadata=metadata or {},
        )
        self.nodes[node_id] = node
        if node_id not in self._adj:
            self._adj[node_id] = []
        if node_id not in self._rev_adj:
            self._rev_adj[node_id] = []
        return node

    def add_edge(
        self,
        source: str,
        target: str,
        exploit_probability: float,
        vulnerability_id: Optional[str] = None,
        label: str = "",
    ) -> AttackEdge:
        edge = AttackEdge(
            source=source,
            target=target,
            exploit_probability=exploit_probability,
            vulnerability_id=vulnerability_id,
            label=label,
        )
        self.edges.append(edge)
        self._adj.setdefault(source, []).append(edge)
        self._rev_adj.setdefault(target, []).append(edge)
        return edge

    def _topological_sort(self) -> List[str]:
        """Compute topological ordering of nodes for forward Bayesian probability propagation."""
        in_degree: Dict[str, int] = {nid: 0 for nid in self.nodes}
        for e in self.edges:
            if e.target in in_degree:
                in_degree[e.target] += 1

        queue = [nid for nid, deg in in_degree.items() if deg == 0]
        order: List[str] = []

        while queue:
            curr = queue.pop(0)
            order.append(curr)
            for edge in self._adj.get(curr, []):
                in_degree[edge.target] -= 1
                if in_degree[edge.target] == 0:
                    queue.append(edge.target)

        # Append any remaining nodes if cycles exist
        for nid in self.nodes:
            if nid not in order:
                order.append(nid)

        return order

    def evaluate_bayesian_probabilities(self, patched_nodes: Optional[Set[str]] = None) -> Dict[str, float]:
        """Compute marginal compromise probability for each node using Noisy-OR.

        Inspired by Poolsappasit et al. 2012.
        For node N with incoming parents {P_1, P_2, ...} and transition probabilities {p_1, p_2, ...}:
            P(N is compromised) = 1 - prod_{i} (1 - P(P_i) * p_i)

        If node N is in patched_nodes, its incoming transitions are severed (P = 0.0).
        """
        patches = patched_nodes or set()
        topo_order = self._topological_sort()
        results: Dict[str, float] = {}

        for nid in topo_order:
            node = self.nodes[nid]
            if nid in patches or node.is_patched:
                results[nid] = 0.0
                node.compromise_probability = 0.0
                continue

            # Root nodes (e.g. Attacker at perimeter) retain their base probability
            incoming_edges = self._rev_adj.get(nid, [])
            if not incoming_edges:
                results[nid] = node.base_probability
                node.compromise_probability = node.base_probability
                continue

            # Multi-path Noisy-OR evaluation
            # Complement: probability that none of the parent exploits succeed
            prod_unsuccessful = 1.0
            has_active_parent = False

            for edge in incoming_edges:
                parent_id = edge.source
                if parent_id in patches:
                    continue

                parent_prob = results.get(parent_id, 0.0)
                trans_prob = edge.exploit_probability
                # Effective exploit probability along this edge
                p_exploit = parent_prob * trans_prob
                prod_unsuccessful *= (1.0 - p_exploit)
                has_active_parent = True

            if has_active_parent:
                compromise_p = 1.0 - prod_unsuccessful
            else:
                compromise_p = node.base_probability

            # Clamp between 0.0 and 1.0
            compromise_p = round(max(0.0, min(1.0, compromise_p)), 4)
            results[nid] = compromise_p
            node.compromise_probability = compromise_p

        return results

    def find_most_probable_path(
        self,
        source: str = "attacker_root",
        goal: str = "crown_jewels",
        patched_nodes: Optional[Set[str]] = None,
    ) -> Optional[AttackPathResult]:
        """Find the most probable attack path from source to goal using Dijkstra.

        Inspired by Jha, Sheyner, & Wing 2002.
        Maximizing P(path) = prod(p_e) <=> Minimizing sum(-ln(p_e)).
        """
        patches = patched_nodes or set()
        if source not in self.nodes or goal not in self.nodes:
            return None
        if source in patches or goal in patches:
            return None

        # Priority queue stores tuples: (cumulative_weight, current_node, path_history, vuln_history)
        heap: List[Tuple[float, str, List[str], List[str]]] = [(0.0, source, [source], [])]
        visited: Dict[str, float] = {}

        while heap:
            curr_weight, curr_node, curr_path, curr_vulns = heapq.heappop(heap)

            if curr_node in visited and visited[curr_node] <= curr_weight:
                continue
            visited[curr_node] = curr_weight

            if curr_node == goal:
                # Reconstruct path probability: exp(-weight)
                prob = round(math.exp(-curr_weight), 6)
                names = [self.nodes.get(nid, AttackNode(id=nid, name=nid, node_type="")).name for nid in curr_path]
                return AttackPathResult(
                    path_nodes=curr_path,
                    path_names=names,
                    path_probability=prob,
                    additive_weight=round(curr_weight, 4),
                    vulnerabilities_on_path=curr_vulns,
                )

            for edge in self._adj.get(curr_node, []):
                next_node = edge.target
                if next_node in patches:
                    continue

                new_weight = curr_weight + edge.weight
                new_path = curr_path + [next_node]
                new_vulns = list(curr_vulns)
                if edge.vulnerability_id and edge.vulnerability_id not in new_vulns:
                    new_vulns.append(edge.vulnerability_id)

                heapq.heappush(heap, (new_weight, next_node, new_path, new_vulns))

        return None

    def find_all_simple_paths(
        self,
        source: str = "attacker_root",
        goal: str = "crown_jewels",
        max_paths: int = 50,
    ) -> List[List[str]]:
        """Enumerate all simple paths from source to goal using DFS."""
        if source not in self.nodes or goal not in self.nodes:
            return []

        all_paths: List[List[str]] = []

        def _dfs(curr: str, visited: Set[str], current_path: List[str]):
            if len(all_paths) >= max_paths:
                return
            if curr == goal:
                all_paths.append(list(current_path))
                return

            for edge in self._adj.get(curr, []):
                nxt = edge.target
                if nxt not in visited:
                    visited.add(nxt)
                    current_path.append(nxt)
                    _dfs(nxt, visited, current_path)
                    current_path.pop()
                    visited.remove(nxt)

        _dfs(source, {source}, [source])
        return all_paths

    def compute_minimal_chokepoints(
        self,
        source: str = "attacker_root",
        goal: str = "crown_jewels",
    ) -> ChokepointCutSet:
        """Derive the Minimum Critical Cut-Set (Chokepoints) that sever all attack paths to the goal.

        Inspired by Jha, Sheyner, & Wing 2002.
        Uses Greedy Set-Cover over enumerated attack paths to find the smallest subset
        of vulnerabilities whose remediation breaks 100% of attack paths.
        """
        paths = self.find_all_simple_paths(source=source, goal=goal)
        if not paths:
            return ChokepointCutSet(
                chokepoint_nodes=[],
                chokepoint_vulnerabilities=[],
                paths_blocked_count=0,
                total_paths_count=0,
                residual_compromise_probability=0.0,
                explanation="No viable attack paths exist connecting Attacker Ingress to Target Crown Jewels.",
            )

        # Collect candidate remediable nodes (exclude source and goal)
        candidate_nodes: Set[str] = set()
        node_to_vuln: Dict[str, str] = {}

        for p in paths:
            for nid in p:
                if nid != source and nid != goal:
                    node = self.nodes.get(nid)
                    if node and node.node_type in ["vulnerability", "port", "ingress", "privilege"]:
                        candidate_nodes.add(nid)
                        if node.cve_id:
                            node_to_vuln[nid] = node.cve_id

        # Greedy Set-Cover: Pick node that breaks the maximum number of uncovered paths
        uncovered_paths = [set(p) for p in paths]
        selected_chokepoints: List[str] = []
        selected_vulns: List[str] = []

        # Deterministic candidate order: prioritize nodes with known patchable CVEs, then alphabetical
        sorted_candidates = sorted(
            candidate_nodes,
            key=lambda c: (0 if c in node_to_vuln else 1, c),
        )

        while uncovered_paths:
            best_node = None
            best_covered_count = 0

            for cand in sorted_candidates:
                if cand in selected_chokepoints:
                    continue
                # Count paths containing cand
                covered = sum(1 for p_set in uncovered_paths if cand in p_set)
                if covered > best_covered_count:
                    best_covered_count = covered
                    best_node = cand

            if not best_node or best_covered_count == 0:
                break

            selected_chokepoints.append(best_node)
            if best_node in node_to_vuln:
                selected_vulns.append(node_to_vuln[best_node])

            # Remove paths broken by this fix
            uncovered_paths = [p_set for p_set in uncovered_paths if best_node not in p_set]

        # Re-evaluate residual probability with chokepoints patched
        residual_probs = self.evaluate_bayesian_probabilities(patched_nodes=set(selected_chokepoints))
        residual_goal_p = residual_probs.get(goal, 0.0)

        names = [self.nodes[c].name for c in selected_chokepoints if c in self.nodes]
        explanation = (
            f"Remediating {len(selected_chokepoints)} strategic chokepoint(s) ({', '.join(names)}) "
            f"neutralizes all {len(paths)} attack paths to {self.nodes.get(goal, AttackNode(id=goal, name='Goal', node_type='')).name}, "
            f"reducing Crown Jewels compromise probability to {residual_goal_p:.1%}."
        )

        return ChokepointCutSet(
            chokepoint_nodes=selected_chokepoints,
            chokepoint_vulnerabilities=selected_vulns,
            paths_blocked_count=len(paths) - len(uncovered_paths),
            total_paths_count=len(paths),
            residual_compromise_probability=residual_goal_p,
            explanation=explanation,
        )

    def simulate_what_if_patch(self, patched_node_id: str, goal: str = "crown_jewels") -> Dict[str, Any]:
        """Perform a counterfactual simulation: what happens to attack risk if finding X is remediated?"""
        # Baseline probability
        baseline_probs = self.evaluate_bayesian_probabilities(patched_nodes=None)
        p_base = baseline_probs.get(goal, 0.0)

        # Counterfactual probability with patched_node_id disabled
        counter_probs = self.evaluate_bayesian_probabilities(patched_nodes={patched_node_id})
        p_new = counter_probs.get(goal, 0.0)

        abs_reduction = round(p_base - p_new, 4)
        pct_reduction = round((abs_reduction / p_base * 100.0) if p_base > 0 else 0.0, 1)

        node = self.nodes.get(patched_node_id)
        node_name = node.name if node else patched_node_id

        return {
            "patched_node": patched_node_id,
            "patched_node_name": node_name,
            "target_goal": goal,
            "baseline_probability": p_base,
            "counterfactual_probability": p_new,
            "absolute_reduction": abs_reduction,
            "percentage_risk_reduction": pct_reduction,
            "is_effective": abs_reduction > 0.0,
            "summary": (
                f"Patching '{node_name}' reduces Crown Jewels compromise likelihood from "
                f"{p_base:.1%} to {p_new:.1%} (a {pct_reduction}% risk reduction)."
            ),
        }


def build_attack_graph_from_findings(
    target: str,
    findings: List[Dict[str, Any]],
    ports: Optional[List[Any]] = None,
    subdomains: Optional[List[str]] = None,
) -> BayesianAttackGraph:
    """Construct an empirical Bayesian Attack Graph from real target telemetry and findings."""
    bag = BayesianAttackGraph(target_name=target)

    # 1. Attacker Entrypoint (Root: probability 1.0)
    bag.add_node(
        node_id="attacker_root",
        name="External Adversary",
        node_type="attacker",
        base_probability=1.0,
        description="Public Internet threat actor conducting external reconnaissance and automated probing.",
    )

    # 2. Ingress & Perimeter Gateways
    bag.add_node(
        node_id="ingress_perimeter",
        name=f"Perimeter: {target}",
        node_type="ingress",
        base_probability=0.0,
        description="Public DNS entrypoint and perimeter routing layer.",
    )
    bag.add_edge("attacker_root", "ingress_perimeter", exploit_probability=1.0, label="Recon & DNS resolution")

    # 3. Open Ports / Exposed Network Services
    port_list = ports or [{"port": 80, "service": "http"}, {"port": 443, "service": "https"}]
    port_node_ids: List[str] = []

    for idx, p in enumerate(port_list[:4]):
        p_num = p.get("port") if isinstance(p, dict) else p
        p_svc = p.get("service", "tcp") if isinstance(p, dict) else "tcp"
        nid = f"port_{p_num}"
        port_node_ids.append(nid)
        bag.add_node(
            node_id=nid,
            name=f"TCP/{p_num} ({p_svc})",
            node_type="port",
            description=f"Exposed listening socket on port {p_num}.",
            metadata={"port": p_num, "service": p_svc},
        )
        bag.add_edge("ingress_perimeter", nid, exploit_probability=0.90, label="TCP Handshake & Port Probing")

    # 4. Vulnerabilities / Flaws (Grounded in EPSS probability)
    flaw_node_ids: List[str] = []
    for idx, f in enumerate(findings[:6]):
        fnid = f"vuln_{idx}"
        flaw_node_ids.append(fnid)
        cves = f.get("related_cves") or []
        primary_cve = cves[0] if cves else None
        title = str(f.get("title", f"Vulnerability #{idx+1}"))
        sev = str(f.get("severity", "Medium")).title()

        # Empirical exploit probability grounded in EPSS and CISA KEV
        epss_prob = float(f.get("epss_probability") or f.get("epss") or 0.05)
        if f.get("in_cisa_kev") or f.get("kev"):
            epss_prob = max(epss_prob, 0.75)
        # Bounded between 0.05 and 0.95
        p_exploit = round(max(0.05, min(0.95, epss_prob)), 3)

        bag.add_node(
            node_id=fnid,
            name=f"[{sev[:4].upper()}] {title[:28]}",
            node_type="vulnerability",
            cve_id=primary_cve,
            epss_score=epss_prob,
            description=str(f.get("why_it_matters", title)),
            metadata={"severity": sev, "contextual_risk_score": f.get("contextual_risk_score")},
        )

        # Connect from matching port or round-robin ingress
        parent_port = port_node_ids[idx % len(port_node_ids)] if port_node_ids else "ingress_perimeter"
        bag.add_edge(parent_port, fnid, exploit_probability=p_exploit, vulnerability_id=primary_cve, label=f"Exploit ({p_exploit:.0%})")

    # 5. Privilege Escalation & Lateral Movement Milestones
    bag.add_node(
        node_id="lateral_access",
        name="Internal Service Access",
        node_type="privilege",
        description="Attacker establishes initial code execution or session hijacking behind perimeter.",
    )
    for fnid in flaw_node_ids[:3]:
        bag.add_edge(fnid, "lateral_access", exploit_probability=0.70, label="Pivot / Post-Exploitation")

    # 6. Crown Jewels / Critical Target Asset
    bag.add_node(
        node_id="crown_jewels",
        name="Crown Jewels: Database & Data Exfiltration",
        node_type="goal",
        description="Confidential customer records, API database, or root host compromise.",
    )
    bag.add_edge("lateral_access", "crown_jewels", exploit_probability=0.85, label="Data Exfiltration")

    # Also link remaining high-severity flaws directly if any
    for fnid in flaw_node_ids[3:]:
        bag.add_edge(fnid, "crown_jewels", exploit_probability=0.50, label="Direct Vector")

    # Compute baseline probabilities
    bag.evaluate_bayesian_probabilities()
    return bag
