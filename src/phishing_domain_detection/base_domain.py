"""Pick a representative base domain for every cluster of similar names."""

import argparse
import csv
import logging
import re
from pathlib import Path

from .cli import add_common_args, config_logging, resolve_path

logger = logging.getLogger(__name__)

DEFAULT_CLUSTERS = "clusters.txt"
DEFAULT_DOMAINS = "domains_clean.csv"
DEFAULT_OUTPUT = "base_domains.csv"
CSV_FIELDS = ("cluster_id", "base_domain", "members")

_CLUSTER_RE = re.compile(r"^Cluster \d+:\s*(.+)$")


def parse_clusters(path: Path) -> list[list[str]]:
    """Read the cluster list produced by :func:`clustering.write_clusters`."""
    clusters: list[list[str]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            match = _CLUSTER_RE.match(line.strip())
            if match:
                clusters.append([member.strip() for member in match.group(1).split(",")])
    return clusters


def load_frequencies(path: Path) -> dict[str, int]:
    """Load ``name -> count`` from the clean domains CSV."""
    frequencies: dict[str, int] = {}
    with path.open("r", newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            frequencies[row["name"]] = int(row["count"])
    return frequencies


def select_base_domain(members: list[str], frequency: dict[str, int]) -> str:
    """Choose the base domain: the shortest name, most common on ties."""
    return min(members, key=lambda member: (len(member), -frequency.get(member, 0)))


def select_base_domains(
    clusters: list[list[str]], frequency: dict[str, int]
) -> list[tuple[str, list[str]]]:
    """Return ``(base_domain, sorted_members)`` for every cluster."""
    return [(select_base_domain(cluster, frequency), sorted(cluster)) for cluster in clusters]


def save_base_domains(path: Path, rows: list[tuple[str, list[str]]]) -> None:
    """Persist a base-domain ``([], ...)`` pair per row plus a cluster id."""
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(CSV_FIELDS)
        for index, (base, members) in enumerate(rows, start=1):
            writer.writerow([index, base, "|".join(members)])


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    add_common_args(parser)
    parser.add_argument("--clusters", type=Path, default=None,
                        help=f"Cluster list (default: <data-dir>/{DEFAULT_CLUSTERS})")
    parser.add_argument("--domains", type=Path, default=None,
                        help=f"Clean domains CSV (default: <data-dir>/{DEFAULT_DOMAINS})")
    parser.add_argument("--output", type=Path, default=None,
                        help=f"Output CSV (default: <data-dir>/{DEFAULT_OUTPUT})")
    args = parser.parse_args(argv)
    config_logging(args.verbose)

    clusters_path = resolve_path(args.data_dir, DEFAULT_CLUSTERS, args.clusters)
    domains_path = resolve_path(args.data_dir, DEFAULT_DOMAINS, args.domains)
    output_path = resolve_path(args.data_dir, DEFAULT_OUTPUT, args.output)

    clusters = parse_clusters(clusters_path)
    frequency = load_frequencies(domains_path)
    rows = select_base_domains(clusters, frequency)
    save_base_domains(output_path, rows)
    logger.info("Selected %d base domains -> %s", len(rows), output_path)


if __name__ == "__main__":
    main()