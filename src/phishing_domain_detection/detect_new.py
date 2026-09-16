"""Flag new registrations that closely match an identified base domain."""

import argparse
import csv
import logging
from pathlib import Path

import Levenshtein

from .cli import add_common_args, config_logging, resolve_path

logger = logging.getLogger(__name__)

DEFAULT_BASES = "base_domains.csv"
DEFAULT_NEW = "new_domains.txt"
DEFAULT_OUTPUT = "suspect_domains.csv"
DEFAULT_THRESHOLD = 0.75
CSV_FIELDS = ("new_domain", "matched_base", "similarity")


def load_base_domains(path: Path) -> list[str]:
    """Read the ``base_domain`` column of the base domains CSV."""
    bases: list[str] = []
    with path.open("r", newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            bases.append(row["base_domain"].strip().lower())
    return bases


def load_new_domains(path: Path) -> list[tuple[str, str]]:
    """Read new registrations as ``(full_domain, second_level_name)`` pairs."""
    domains: list[tuple[str, str]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            domain = line.strip().lower()
            if not domain:
                continue
            labels = domain.split(".")
            if len(labels) < 2:
                continue
            domains.append((domain, ".".join(labels[:-1])))
    return domains


def find_suspects(
    new_domains: list[tuple[str, str]],
    base_domains: list[str],
    threshold: float = DEFAULT_THRESHOLD,
) -> list[tuple[str, str, float]]:
    """Return new domains whose name is close to a base domain.

    A domain is flagged if its Levenshtein ratio exceeds ``threshold`` or if the
    base name is a substring of it (a common typosquatting trick).
    """
    suspects: list[tuple[str, str, float]] = []
    for full_domain, name in new_domains:
        for base in base_domains:
            score = Levenshtein.ratio(name, base)
            if score >= threshold or base in name:
                suspects.append((full_domain, base, round(score, 2)))
    return suspects


def save_suspects(path: Path, suspects: list[tuple[str, str, float]]) -> None:
    """Persist the flagged domains as CSV."""
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(CSV_FIELDS)
        writer.writerows(suspects)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    add_common_args(parser)
    parser.add_argument("--bases", type=Path, default=None,
                        help=f"Base domains CSV (default: <data-dir>/{DEFAULT_BASES})")
    parser.add_argument("--new", type=Path, default=None,
                        help=f"New domain list (default: <data-dir>/{DEFAULT_NEW})")
    parser.add_argument("--output", type=Path, default=None,
                        help=f"Output CSV (default: <data-dir>/{DEFAULT_OUTPUT})")
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD,
                        help=f"Minimum similarity score (default: {DEFAULT_THRESHOLD})")
    args = parser.parse_args(argv)
    config_logging(args.verbose)

    bases_path = resolve_path(args.data_dir, DEFAULT_BASES, args.bases)
    new_path = resolve_path(args.data_dir, DEFAULT_NEW, args.new)
    output_path = resolve_path(args.data_dir, DEFAULT_OUTPUT, args.output)

    base_domains = load_base_domains(bases_path)
    new_domains = load_new_domains(new_path)
    logger.info("Loaded %d base domains and %d new domains", len(base_domains), len(new_domains))
    suspects = find_suspects(new_domains, base_domains, args.threshold)
    save_suspects(output_path, suspects)
    logger.info("Flagged %d suspect domains -> %s", len(suspects), output_path)


if __name__ == "__main__":
    main()