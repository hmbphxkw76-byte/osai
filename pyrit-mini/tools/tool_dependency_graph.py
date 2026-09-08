# Tool Dependency Graph - MCP/Agent Tool Relationship Modeling
"""tool_dependency_graph - Data structures for modeling tool dependencies.

Provides graph-based data structures for representing tool relationships:
    1. ToolNode: Individual tool with metadata
    2. ToolEdge: Dependency relationship between tools
    3. ToolDependencyGraph: Complete graph with analysis methods

Used by tool_chain_analyzer for deep dependency analysis.

Reference: MCPSec chains scanner, InjecAgent (arXiv:2307.00929)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ToolNode:
    """Node representing a single tool in the dependency graph."""
    name: str
    description: str = ""
    category: str = "unknown"
    risk_level: str = "low"
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_high_risk(self) -> bool:
        return self.risk_level in ("high", "critical")


@dataclass
class ToolEdge:
    """Edge representing a dependency relationship between tools."""
    source: str  # Source tool name
    target: str  # Target tool name
    dependency_type: str = "calls"  # calls, data_flow, requires, extends
    weight: float = 1.0  # Edge weight (0.0-1.0)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolDependencyGraph:
    """Graph of tool dependencies for attack chain analysis.

    Supports:
        - Adding tools as nodes
        - Adding dependencies as edges
        - Finding attack paths (chains of dependent tools)
        - Identifying critical nodes (high-connectivity tools)
    """
    nodes: dict[str, ToolNode] = field(default_factory=dict)
    edges: list[ToolEdge] = field(default_factory=list)

    def add_tool(self, tool: ToolNode) -> None:
        """Add a tool node to the graph."""
        self.nodes[tool.name] = tool

    def add_dependency(
        self,
        source: str,
        target: str,
        dep_type: str = "calls",
        weight: float = 1.0,
    ) -> None:
        """Add a dependency edge between tools."""
        if source in self.nodes and target in self.nodes:
            self.edges.append(ToolEdge(
                source=source,
                target=target,
                dependency_type=dep_type,
                weight=weight,
            ))

    def get_dependencies(self, tool_name: str) -> list[str]:
        """Get all tools that the given tool depends on."""
        return [e.target for e in self.edges if e.source == tool_name]

    def get_dependents(self, tool_name: str) -> list[str]:
        """Get all tools that depend on the given tool."""
        return [e.source for e in self.edges if e.target == tool_name]

    def find_attack_paths(
        self,
        start_tool: str,
        max_depth: int = 3,
    ) -> list[list[str]]:
        """Find all attack paths starting from a given tool.

        Args:
            start_tool: Starting tool name
            max_depth: Maximum path length

        Returns:
            List of paths (each path is a list of tool names)
        """
        paths: list[list[str]] = []

        def _dfs(current: str, path: list[str], depth: int) -> None:
            if depth >= max_depth:
                return

            deps = self.get_dependencies(current)
            if not deps:
                if len(path) > 1:
                    paths.append(list(path))
                return

            for dep in deps:
                if dep not in path:  # Avoid cycles
                    path.append(dep)
                    _dfs(dep, path, depth + 1)
                    path.pop()

        _dfs(start_tool, [start_tool], 0)
        return paths

    def get_critical_tools(self) -> list[str]:
        """Identify critical tools (high connectivity)."""
        connectivity: dict[str, int] = {}

        for edge in self.edges:
            connectivity[edge.source] = connectivity.get(edge.source, 0) + 1
            connectivity[edge.target] = connectivity.get(edge.target, 0) + 1

        if not connectivity:
            return []

        avg_connectivity = sum(connectivity.values()) / len(connectivity)
        return [
            name for name, count in connectivity.items()
            if count > avg_connectivity
        ]

    def get_high_risk_paths(self) -> list[list[str]]:
        """Find paths containing high-risk tools."""
        high_risk_tools = {name for name, node in self.nodes.items() if node.is_high_risk}
        all_paths: list[list[str]] = []

        for tool_name in self.nodes:
            paths = self.find_attack_paths(tool_name)
            for path in paths:
                if any(t in high_risk_tools for t in path):
                    all_paths.append(path)

        return all_paths

    @property
    def tool_count(self) -> int:
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        return len(self.edges)


def build_graph_from_tools(tools: list[dict[str, Any]]) -> ToolDependencyGraph:
    """Build a dependency graph from a list of tool definitions.

    Args:
        tools: List of tool dicts with 'name', 'description', and optional 'dependencies'

    Returns:
        ToolDependencyGraph
    """
    graph = ToolDependencyGraph()

    # Add all tools as nodes
    for tool in tools:
        node = ToolNode(
            name=tool.get("name", ""),
            description=tool.get("description", ""),
            category=tool.get("category", "unknown"),
            risk_level=tool.get("risk_level", "low"),
            metadata=tool.get("metadata", {}),
        )
        graph.add_tool(node)

    # Add dependencies as edges
    for tool in tools:
        deps = tool.get("dependencies", [])
        if isinstance(deps, list):
            for dep in deps:
                if isinstance(dep, str) and dep in graph.nodes:
                    graph.add_dependency(tool["name"], dep)

    return graph
