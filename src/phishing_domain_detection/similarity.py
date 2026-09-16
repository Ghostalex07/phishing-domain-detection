"""Find pairs of domain names that look similar via the Levenshtein ratio."""

import argparse
import csv
import logging
from itertools import combinations
from pathlib import Path

import Levenshtein

from .cli import add_common_args, config_logging, resolve_path

logger = logging.getLogger(__name__)

DEFAULT_INPUT = "domains_clean.csv"
DEFAULT_OUTPUT = "similar_pairs.csv"
DEFAULT_THRESHOLD = 0.8
CSV_FIELDS = ("name1", "name2", "similarity")


def load_names(path: Path) -> list[str]:
    """Read the ``name`` column of the clean domains CSV."""
    with path.open("r", newline="", encoding="utf-8") as fh:
        return [row["name"] for row in csv.DictReader(fh)]


def find_similar_pairs(
    names: list[str], threshold: float = DEFAULT_THRESHOLD
) -> list[tuple[str, str, float]]:
    """Return every pair whose Levenshtein ratio meets ``threshold``.

    Note: this is an O(n^2) all-pairs comparison. It is adequate for a few
    thousand names but does not scale to millions of domains.
    """
    pairs: list[tuple[str, str, float]] = []
    for name1, name2 in combinations(names, 2):
        score = Levenshtein.ratio(name1, name2)
        if score >= threshold:
            pairs.append((name1, name2, round(score, 2)))
    return pairs


def save_pairs(path: Path, pairs: list[tuple[str, str, float]]) -> None:
    """Persist the similar pairs as CSV."""
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(CSV_FIELDS)
        writer.writerows(pairs)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    add_common_args(parser)
    parser.add_argument("--input", type=Path, default=None,
                        help=f"Clean domains CSV (default: <data-dir>/{DEFAULT_INPUT})")
    parser.add_argument("--output", type=Path, default=None,
                        help=f"Output CSV (default: <data-dir>/{DEFAULT_OUTPUT})")
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD,
                        help=f"Minimum similarity score (default: {DEFAULT_THRESHOLD})")
    args = parser.parse_args(argv)
    config_logging(args.verbose)

    input_path = resolve_path(args.data_dir, DEFAULT_INPUT, args.input)
    output_path = resolve_path(args.data_dir, DEFAULT_OUTPUT, args.output)

    names = load_names(input_path)
    logger.info("Loaded %d names from %s", len(names), input_path)
    pairs = find_similar_pairs(names, args.threshold)
    save_pairs(output_path, pairs)
    logger.info("Found %d similar pairs -> %s", len(pairs), output_path)


if __name__ == "__main__":
    main()