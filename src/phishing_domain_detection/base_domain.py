"""Pick a representative base domain for every cluster of similar names."""

from __future__ import annotations

import argparse
import csv
import logging
from pathlib import Path

from .cli import (
    PipelineError,
    add_common_args,
    config_logging,
    raise_csv_field_limit,
    require_fields,
    resolve_input,
    resolve_path,
    run_step,
)
from .clustering import parse_clusters
from .hostname import normalize_label, safe_cell
from .preprocess import load_counts

logger = logging.getLogger(__name__)

DEFAULT_CLUSTERS = "clusters.txt"
DEFAULT_DOMAINS = "domains_clean.csv"
DEFAULT_OUTPUT = "base_domains.csv"
CSV_FIELDS = ("cluster_id", "base_domain", "members")


def load_base_domains(path: Path) -> list[str]:
    """Read the ``base_domain`` column of the base domains CSV.

    Validated like every other reader: this file is the input step 6 compares new
    registrations against, so an unvalidated ``base_domain`` cell is a direct
    path into the analyst-facing report.

    Raises:
        PipelineError: if the header is missing a column or a cell is not a valid
            DNS label.
    """
    bases: list[str] = []
    with path.open("r", newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        require_fields(reader.fieldnames, ("base_domain",), path)
        for row in reader:
            base = normalize_label(row["base_domain"])
            if base is None:
                raise PipelineError(f"{path}: bad base_domain {row['base_domain']!r}")
            bases.append(base)
    return bases


def select_base_domain(members: list[str], frequency: dict[str, int]) -> str:
    """Choose the representative name for a cluster.

    The policy is *shortest name wins, most frequent breaks ties*. The base
    domain is the label step 6 compares new registrations against, so the
    shortest member is the one most likely to be the canonical spelling rather
    than a decoration bolted onto it (``ad-digital`` over ``pazdigital``).
    Certificate Transparency frequency is only a tie-breaker: it reflects how
    many certificates a name appears in, which is a noisy proxy for legitimacy.

    Args:
        members: Names in the cluster.
        frequency: ``name -> count`` from the clean domains CSV.

    Returns:
        The chosen base domain. Ties are broken deterministically by the sort
        order of ``members``.

    Raises:
        PipelineError: if the cluster has no usable member, which would otherwise
            write an empty ``base_domain`` cell into the report.
    """
    usable = [member for member in members if member and member.strip()]
    if not usable:
        raise PipelineError("cannot select a base domain from an empty cluster")
    return min(usable, key=lambda member: (len(member), -frequency.get(member, 0), member))


def select_base_domains(
    clusters: list[list[str]], frequency: dict[str, int]
) -> list[tuple[str, list[str]]]:
    """Return ``(base_domain, sorted_members)`` for every cluster."""
    return [(select_base_domain(cluster, frequency), sorted(cluster)) for cluster in clusters]


def save_base_domains(path: Path, rows: list[tuple[str, list[str]]]) -> None:
    """Persist one ``(base_domain, members)`` pair per row, tagged with a cluster id.

    Members are joined with ``"|"`` into a single cell so the file stays a
    three-column CSV.
    """
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(CSV_FIELDS)
        for index, (base, members) in enumerate(rows, start=1):
            writer.writerow(
                [index, safe_cell(base), "|".join(safe_cell(member) for member in members)]
            )


def main(argv: list[str] | None = None) -> int:
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
    raise_csv_field_limit()

    def step() -> None:
        clusters_path = resolve_input(args.data_dir, DEFAULT_CLUSTERS, args.clusters)
        domains_path = resolve_input(args.data_dir, DEFAULT_DOMAINS, args.domains)
        output_path = resolve_path(args.data_dir, DEFAULT_OUTPUT, args.output)
        clusters = parse_clusters(clusters_path)
        counts = load_counts(domains_path)
        rows = select_base_domains(clusters, {name: entry.count for name, entry in counts.items()})
        save_base_domains(output_path, rows)
        logger.info("Selected %d base domains -> %s", len(rows), output_path)

    return run_step(step)


if __name__ == "__main__":
    raise SystemExit(main())
