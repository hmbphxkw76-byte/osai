# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Agent Behavior DAG — 工具调用图建模 + 状态转移分析.

Models agent tool-call sequences as a directed acyclic graph (DAG),
enabling:
  1. Tool invocation sequence tracking (nodes = tool calls, edges = order)
  2. Cycle detection (infinite loops / recursive agent patterns)
  3. Critical path analysis (longest tool chain = max blast radius)
  4. State transfer visualization (conversation turn → tool → result → next turn)

Non-LLM guarantee: pure graph algorithms (topological sort, cycle detection),
zero ML/model dependencies.

Academic basis:
  - OWASP LLM06: Excessive Agency — high in-degree tools amplify blast radius
  - MITRE ATT&CK T1059: multi-step execution chains
  - RedAmon ai_surface_recon.py: cross-reference workload patterns
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolCallNode:
    """A single tool invocation in the agent's execution trace.

    Attributes:
        tool_name: Name of the invoked tool.
        input_fingerprint: SHA256 fingerprint of normalized input args.
        output_fingerprint: SHA256 fingerprint of normalized output.
        duration_ms: Wall-clock execution time.
        error_class: Error classification (from error_class.py).
        conversation_turn: Which conversation round this occurred in.
        sequence_index: Position in the overall tool-call sequence.
        tool_hash: Tool schema hash (from MCPProbe / AgentProbe).
    """

    tool_name: str = ""
    input_fingerprint: str = ""
    output_fingerprint: str = ""
    duration_ms: int = 0
    error_class: str = ""
    conversation_turn: int = 0
    sequence_index: int = 0
    tool_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "input_fingerprint": self.input_fingerprint,
            "output_fingerprint": self.output_fingerprint,
            "duration_ms": self.duration_ms,
            "error_class": self.error_class,
            "conversation_turn": self.conversation_turn,
            "sequence_index": self.sequence_index,
            "tool_hash": self.tool_hash,
        }

    @staticmethod
    def compute_input_fingerprint(args: dict[str, Any]) -> str:
        """Compute SHA256 fingerprint of tool input arguments."""
        canonical = json.dumps(args, sort_keys=True, ensure_ascii=True, default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]


@dataclass
class AgentStateNode:
    """An agent state in the conversation flow.

    Represents a single conversation turn: the tools pending at this turn,
    the responses received, and the state transition to the next turn.
    """

    turn_index: int = 0
    tools_called: list[str] = field(default_factory=list)
    tool_call_count: int = 0
    error_count: int = 0
    total_duration_ms: int = 0
    user_input_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "turn_index": self.turn_index,
            "tools_called": self.tools_called,
            "tool_call_count": self.tool_call_count,
            "error_count": self.error_count,
            "total_duration_ms": self.total_duration_ms,
        }


@dataclass
class AgentBehaviorDAG:
    """Directed graph of agent tool-call sequences.

    Nodes = ToolCallNode (tool invocations)
    Edges = sequential dependencies (tool A → tool B)

    Provides:
      - cycle_detected: whether the agent entered an infinite loop
      - critical_path: longest chain of tool calls
      - tool_call_fanout: per-tool invocation count
    """

    nodes: list[ToolCallNode] = field(default_factory=list)
    # adjacency: index → list of successor indices
    edges: dict[int, list[int]] = field(default_factory=dict)
    # per-turn state tracking
    turns: list[AgentStateNode] = field(default_factory=list)

    def add_node(self, node: ToolCallNode) -> int:
        """Add a tool call node. Returns node index."""
        idx = len(self.nodes)
        self.nodes.append(node)
        if idx > 0:
            # Auto-link sequential: prev → current
            self.edges.setdefault(idx - 1, []).append(idx)

        # Track per-turn state
        turn_idx = node.conversation_turn
        while len(self.turns) <= turn_idx:
            self.turns.append(AgentStateNode(turn_index=len(self.turns)))

        turn = self.turns[turn_idx]
        turn.tools_called.append(node.tool_name)
        turn.tool_call_count += 1
        turn.total_duration_ms += node.duration_ms
        if node.error_class and node.error_class != "success":
            turn.error_count += 1

        return idx

    def add_edge(self, from_idx: int, to_idx: int) -> None:
        """Add a custom edge (beyond sequential auto-linking)."""
        self.edges.setdefault(from_idx, []).append(to_idx)

    @property
    def cycle_detected(self) -> bool:
        """True if the graph contains a cycle (infinite agent loop).

        Uses Kahn's algorithm (BFS topological sort).
        """
        n = len(self.nodes)
        if n < 1:
            return False

        in_degree = [0] * n
        for u, successors in self.edges.items():
            for v in successors:
                in_degree[v] += 1

        queue: deque[int] = deque(i for i in range(n) if in_degree[i] == 0)
        visited = 0

        while queue:
            u = queue.popleft()
            visited += 1
            for v in self.edges.get(u, []):
                in_degree[v] -= 1
                if in_degree[v] == 0:
                    queue.append(v)

        return visited != n

    @property
    def critical_path(self) -> list[ToolCallNode]:
        """Longest path through the DAG (max blast radius chain).

        Uses DP on topological order. If cycles exist, returns empty.
        """
        if self.cycle_detected or not self.nodes:
            return []

        n = len(self.nodes)

        # Topological order (Kahn)
        in_degree = [0] * n
        for u, successors in self.edges.items():
            for v in successors:
                in_degree[v] += 1

        queue: deque[int] = deque(i for i in range(n) if in_degree[i] == 0)
        topo: list[int] = []

        while queue:
            u = queue.popleft()
            topo.append(u)
            for v in self.edges.get(u, []):
                in_degree[v] -= 1
                if in_degree[v] == 0:
                    queue.append(v)

        # DP: longest path length ending at each node
        dp = [1] * n
        prev = [-1] * n

        for u in topo:
            for v in self.edges.get(u, []):
                if dp[u] + 1 > dp[v]:
                    dp[v] = dp[u] + 1
                    prev[v] = u

        # Reconstruct longest path
        end = max(range(n), key=lambda i: dp[i])
        path: list[int] = []
        while end != -1:
            path.append(end)
            end = prev[end]
        path.reverse()

        return [self.nodes[i] for i in path]

    @property
    def tool_call_fanout(self) -> dict[str, int]:
        """Per-tool invocation count (fan-out = blast radius indicator)."""
        counts: dict[str, int] = defaultdict(int)
        for node in self.nodes:
            counts[node.tool_name] += 1
        return dict(counts)

    @property
    def unique_tools(self) -> int:
        """Number of distinct tools called."""
        return len({n.tool_name for n in self.nodes})

    @property
    def error_rate(self) -> float:
        """Proportion of tool calls that resulted in errors."""
        if not self.nodes:
            return 0.0
        errors = sum(
            1 for n in self.nodes
            if n.error_class and n.error_class != "success" and n.error_class != ""
        )
        return errors / len(self.nodes)

    @property
    def avg_tool_duration_ms(self) -> float:
        """Average tool execution time."""
        if not self.nodes:
            return 0.0
        return sum(n.duration_ms for n in self.nodes) / len(self.nodes)

    @property
    def max_fanout_tool(self) -> tuple[str, int]:
        """Tool with highest invocation count."""
        fanout = self.tool_call_fanout
        if not fanout:
            return ("", 0)
        return max(fanout.items(), key=lambda x: x[1])

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edge_count": sum(len(v) for v in self.edges.values()),
            "turns": [t.to_dict() for t in self.turns],
            "cycle_detected": self.cycle_detected,
            "critical_path_length": len(self.critical_path),
            "critical_path_tools": [n.tool_name for n in self.critical_path],
            "tool_call_fanout": self.tool_call_fanout,
            "unique_tools": self.unique_tools,
            "error_rate": round(self.error_rate, 3),
            "avg_tool_duration_ms": round(self.avg_tool_duration_ms, 1),
            "max_fanout_tool": self.max_fanout_tool[0],
            "max_fanout_count": self.max_fanout_tool[1],
        }

    def summary(self) -> str:
        lines = [
            "AgentBehaviorDAG Summary:",
            f"  Tool calls: {len(self.nodes)} ({self.unique_tools} unique)",
            f"  Conversation turns: {len(self.turns)}",
            f"  Cycle detected: {self.cycle_detected}",
            f"  Critical path length: {len(self.critical_path)}",
            f"  Error rate: {self.error_rate:.1%}",
            f"  Avg duration: {self.avg_tool_duration_ms:.0f}ms",
            f"  Max fanout: {self.max_fanout_tool[0]} ({self.max_fanout_tool[1]}×)",
        ]
        return "\n".join(lines)


def build_dag_from_probe_results(
    active_results: list[dict[str, Any]],
) -> AgentBehaviorDAG:
    """Build an AgentBehaviorDAG from AgentProbe active probe results.

    Args:
        active_results: List of probe result dicts from AgentProbe._active_agent_probe().

    Returns:
        Populated AgentBehaviorDAG.
    """
    dag = AgentBehaviorDAG()

    for i, result in enumerate(active_results):
        # Infer conversation turn from URL grouping
        url = result.get("url", "")
        turn_idx = hash(url) % 100  # Simple heuristic; real impl uses turn metadata

        node = ToolCallNode(
            tool_name=url.rsplit("/", 1)[-1] if "/" in url else url,
            input_fingerprint=ToolCallNode.compute_input_fingerprint(
                {"payload": result.get("payload", ""), "method": result.get("method", "GET")}
            ),
            output_fingerprint=result.get("fingerprint", ""),
            duration_ms=result.get("duration_ms", 0),
            error_class=result.get("error_class", ""),
            conversation_turn=turn_idx if turn_idx < 10 else i % 10,
            sequence_index=i,
        )
        dag.add_node(node)

    return dag
