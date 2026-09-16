"""Normalize raw domains and count occurrences of their primary label."""

import argparse
import csv
import logging
from pathlib import Path

from .cli import add_common_args, config_logging, resolve_path

logger = logging.getLogger(__name__)

DEFAULT_INPUT = "domains_raw.txt"
DEFAULT_OUTPUT = "domains_clean.csv"
CSV_FIELDS = ("name", "domain", "count")


def count_labels(domains: list[str]) -> dict[str, dict[str, int | str]]:
    """Count how many times each primary label appears in the raw domain list.

    Only the first label of a registrable domain is kept as the ``name`` (e.g.
    ``google.com`` -> ``google``). This mirrors how similarity is later computed.

    Returns:
        A mapping ``name -> {"domain": ..., "count": ...}`` where ``domain`` is
        the first full domain seen for that name.
    """
    counts: dict[str, dict[str, int | str]] = {}
    for line in domains:
        domain = line.strip().lower()
        if not domain:
            continue
        labels = domain.split(".")
        if len(labels) < 2:
            continue
        name = labels[0]
        entry = counts.setdefault(name, {"domain": domain, "count": 0})
        entry["count"] = int(entry["count"]) + 1
    return counts


def save_counts(path: Path, counts: dict[str, dict[str, int | str]]) -> None:
    """Persist the label counts as CSV sorted alphabetically by name."""
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(CSV_FIELDS)
        for name in sorted(counts):
            data = counts[name]
            writer.writerow([name, data["domain"], data["count"]])


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    add_common_args(parser)
    parser.add_argument("--input", type=Path, default=None,
                        help=f"Raw domain list (default: <data-dir>/{DEFAULT_INPUT})")
    parser.add_argument("--output", type=Path, default=None,
                        help=f"Output CSV (default: <data-dir>/{DEFAULT_OUTPUT})")
    args = parser.parse_args(argv)
    config_logging(args.verbose)

    input_path = resolve_path(args.data_dir, DEFAULT_INPUT, args.input)
    output_path = resolve_path(args.data_dir, DEFAULT_OUTPUT, args.output)

    with input_path.open("r", encoding="utf-8") as fh:
        counts = count_labels(fh.readlines())
    save_counts(output_path, counts)
    logger.info("Preprocessed %d unique names -> %s", len(counts), output_path)


if __name__ == "__main__":
    main()