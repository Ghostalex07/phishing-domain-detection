"""Group similar domain pairs into clusters using graph connected components."""

import argparse
import csv
import logging
from collections import defaultdict, deque
from pathlib import Path

from .cli import add_common_args, config_logging, resolve_path

logger = logging.getLogger(__name__)

DEFAULT_INPUT = "similar_pairs.csv"
DEFAULT_OUTPUT = "clusters.txt"


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
    """Write one cluster of domains per line, member names sorted."""
    with path.open("w", encoding="utf-8") as fh:
        for index, cluster in enumerate(clusters, start=1):
            members = ", ".join(sorted(cluster))
            fh.write(f"Cluster {index}: {members}\n")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    add_common_args(parser)
    parser.add_argument("--input", type=Path, default=None,
                        help=f"Similar pairs CSV (default: <data-dir>/{DEFAULT_INPUT})")
    parser.add_argument("--output", type=Path, default=None,
                        help=f"Output cluster list (default: <data-dir>/{DEFAULT_OUTPUT})")
    args = parser.parse_args(argv)
    config_logging(args.verbose)

    input_path = resolve_path(args.data_dir, DEFAULT_INPUT, args.input)
    output_path = resolve_path(args.data_dir, DEFAULT_OUTPUT, args.output)

    pairs: list[tuple[str, str, float]] = []
    with input_path.open("r", newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            pairs.append((row["name1"], row["name2"], float(row["similarity"])))

    logger.info("Loaded %d edges from %s", len(pairs), input_path)
    graph = build_graph(pairs)
    clusters = connected_components(graph)
    write_clusters(output_path, clusters)
    logger.info("Built %d clusters (from %d nodes) -> %s", len(clusters), len(graph), output_path)


if __name__ == "__main__":
    main()