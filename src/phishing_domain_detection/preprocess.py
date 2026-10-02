"""Normalize raw domains and count occurrences of their primary label."""

from __future__ import annotations

import argparse
import csv
import logging
from dataclasses import dataclass
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
from .hostname import normalize, normalize_label, safe_cell

logger = logging.getLogger(__name__)

DEFAULT_INPUT = "domains_raw.txt"
DEFAULT_OUTPUT = "domains_clean.csv"
CSV_FIELDS = ("name", "domain", "count")


@dataclass(frozen=True, slots=True)
class DomainCount:
    """How often a primary label was seen, and the first domain it appeared in.

    Immutable so that incrementing a count is an explicit rebind rather than an
    in-place mutation of a dict, which is what made the old code carry a
    ``count`` that was sometimes ``int`` and sometimes ``str``.
    """

    domain: str
    count: int

    def bump(self) -> DomainCount:
        """Return a copy with the count incremented by one."""
        return DomainCount(domain=self.domain, count=self.count + 1)


def count_labels(domains: list[str]) -> dict[str, DomainCount]:
    """Count how many times each primary label appears in the raw domain list.

    Only the first label of a registrable domain becomes the ``name`` (so
    ``google.com`` yields ``google``), because that is the token the similarity
    and clustering steps compare.

    Lines that are not hostnames are skipped and counted, not fatal: this is the
    first stage to touch bulk scraped text, so one bad line among thousands
    should not cost the analyst the whole run. They are skipped *validated*,
    which is what stops a formula-shaped line from surviving into the CSV.

    Args:
        domains: Raw lines as read from ``domains_raw.txt``.

    Returns:
        A mapping ``name -> DomainCount``.
    """
    counts: dict[str, DomainCount] = {}
    skipped = 0
    for line in domains:
        domain = normalize(line)
        if domain is None:
            skipped += 1
            continue
        name = domain.split(".")[0]
        entry = counts.get(name)
        counts[name] = entry.bump() if entry else DomainCount(domain=domain, count=1)
    if skipped:
        logger.warning("Skipped %d line(s) that are not valid hostnames", skipped)
    return counts


def load_counts(path: Path) -> dict[str, DomainCount]:
    """Read ``domains_clean.csv`` back into the in-memory model.

    This is the single boundary where the on-disk ``str`` becomes an ``int``;
    every other module gets :class:`DomainCount` and never casts. Every column
    arrives from :mod:`csv` as a string, ``count`` included.

    Both string columns are re-validated here. A stage output is a normal input
    to the next stage, so a hand-edited or synced-from-somewhere-else CSV must
    be treated as untrusted: failing closed is better than letting a tampered
    ``name`` propagate into every downstream cluster and report.

    Raises:
        PipelineError: if the header is wrong, a ``count`` is not a number, or a
            ``name``/``domain`` cell is not a valid DNS label or hostname.
    """
    counts: dict[str, DomainCount] = {}
    with path.open("r", newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        require_fields(reader.fieldnames, CSV_FIELDS, path)
        for row in reader:
            try:
                count = int(row["count"])
            except (TypeError, ValueError) as exc:
                raise PipelineError(
                    f"{path}: bad count {row['count']!r} for name {row['name']!r}"
                ) from exc
            name = normalize_label(row["name"])
            if name is None:
                raise PipelineError(f"{path}: bad name {row['name']!r}")
            domain = normalize(row["domain"])
            if domain is None:
                raise PipelineError(f"{path}: bad domain {row['domain']!r}")
            counts[name] = DomainCount(domain=domain, count=count)
    return counts


def load_names(path: Path) -> list[str]:
    """Read the ``name`` column of the clean domains CSV, in file order.

    Order matters: :func:`phishing_domain_detection.similarity.find_similar_pairs`
    emits pairs in input order, so the resulting CSV must stay stable.
    """
    return list(load_counts(path))


def save_counts(path: Path, counts: dict[str, DomainCount]) -> None:
    """Persist the label counts as CSV sorted alphabetically by name."""
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(CSV_FIELDS)
        for name in sorted(counts):
            entry = counts[name]
            writer.writerow([safe_cell(name), safe_cell(entry.domain), entry.count])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    add_common_args(parser)
    parser.add_argument("--input", type=Path, default=None,
                        help=f"Raw domain list (default: <data-dir>/{DEFAULT_INPUT})")
    parser.add_argument("--output", type=Path, default=None,
                        help=f"Output CSV (default: <data-dir>/{DEFAULT_OUTPUT})")
    args = parser.parse_args(argv)
    config_logging(args.verbose)
    raise_csv_field_limit()

    def step() -> None:
        input_path = resolve_input(args.data_dir, DEFAULT_INPUT, args.input)
        output_path = resolve_path(args.data_dir, DEFAULT_OUTPUT, args.output)
        with input_path.open("r", encoding="utf-8", errors="replace") as fh:
            counts = count_labels(fh.readlines())
        save_counts(output_path, counts)
        logger.info("Preprocessed %d unique names -> %s", len(counts), output_path)

    return run_step(step)


if __name__ == "__main__":
    raise SystemExit(main())
