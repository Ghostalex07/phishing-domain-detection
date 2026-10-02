"""Group similar domain pairs into clusters using graph connected components."""

import argparse
import logging
import re
from collections import defaultdict, deque
from pathlib import Path

from .cli import (
    PipelineError,
    add_common_args,
    config_logging,
    raise_csv_field_limit,
    resolve_input,
    resolve_path,
    run_step,
)
from .hostname import normalize_label, safe_cell
from .similarity import load_pairs

logger = logging.getLogger(__name__)

DEFAULT_INPUT = "similar_pairs.csv"
DEFAULT_OUTPUT = "clusters.txt"

# Written by write_clusters, read back by parse_clusters. Both live here so the
# format has a single owner.
_CLUSTER_RE = re.compile(r"^Cluster \d+:\s*(.+)$")


def build_graph(pairs: list[tuple[str, str, float]]) -> dict[str, set[str]]:
    """Build an undirected adjacency list from the similar pairs."""
    graph: dict[str, set[str]] = defaultdict(set)
    for name1, name2, _ in pairs:
        graph[name1].add(name2)
        graph[name2].add(name1)
    return dict(graph)


def connected_components(graph: dict[str, set[str]]) -> list[set[str]]:
    """Return the connected components of ``graph`` using breadth-first search."""
    visited: set[str] = set()
    clusters: list[set[str]] = []

    for start in graph:
        if start in visited:
            continue

        component: set[str] = set()
        queue = deque([start])
        visited.add(start)

        while queue:
            node = queue.popleft()
            component.add(node)
            for neighbor in graph[node]:
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)

        clusters.append(component)

    return clusters


def write_clusters(path: Path, clusters: list[set[str]]) -> None:
    """Write one cluster of domains per line, member names sorted.

    ``", "`` is an unambiguous separator here because every member has been
    validated as a DNS label, and a label can contain neither a comma nor a
    newline. Control characters are stripped again on the way out so that the
    format cannot be broken by a name that arrived from somewhere unvalidated.
    """
    with path.open("w", encoding="utf-8") as fh:
        for index, cluster in enumerate(clusters, start=1):
            members = ", ".join(sorted(safe_cell(member) for member in cluster))
            fh.write(f"Cluster {index}: {members}\n")


def parse_clusters(path: Path) -> list[list[str]]:
    """Read back the cluster list produced by :func:`write_clusters`.

    Lines that do not match the cluster format are skipped, so a stray blank or
    hand-written line is ignored rather than aborting the step. Members *are*
    validated, and an invalid one is fatal rather than skipped: silently dropping
    a member would leave a cluster that no longer matches what the file says, and
    that cluster then becomes a base domain in the analyst's report.

    Raises:
        PipelineError: if a member is not a valid DNS label.
    """
    clusters: list[list[str]] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            match = _CLUSTER_RE.match(line.strip())
            if not match:
                continue
            members = []
            for raw in match.group(1).split(","):
                member = normalize_label(raw)
                if member is None:
                    raise PipelineError(f"{path}: bad cluster member {raw.strip()!r}")
                members.append(member)
            clusters.append(members)
    return clusters


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    add_common_args(parser)
    parser.add_argument("--input", type=Path, default=None,
                        help=f"Similar pairs CSV (default: <data-dir>/{DEFAULT_INPUT})")
    parser.add_argument("--output", type=Path, default=None,
                        help=f"Output cluster list (default: <data-dir>/{DEFAULT_OUTPUT})")
    args = parser.parse_args(argv)
    config_logging(args.verbose)
    raise_csv_field_limit()

    def step() -> None:
        input_path = resolve_input(args.data_dir, DEFAULT_INPUT, args.input)
        output_path = resolve_path(args.data_dir, DEFAULT_OUTPUT, args.output)
        pairs = load_pairs(input_path)
        logger.info("Loaded %d edges from %s", len(pairs), input_path)
        graph = build_graph(pairs)
        clusters = connected_components(graph)
        write_clusters(output_path, clusters)
        logger.info(
            "Built %d clusters (from %d nodes) -> %s", len(clusters), len(graph), output_path
        )

    return run_step(step)


if __name__ == "__main__":
    raise SystemExit(main())
