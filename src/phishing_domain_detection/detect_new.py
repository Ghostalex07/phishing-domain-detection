"""Flag new registrations that closely match an identified base domain."""

from __future__ import annotations

import argparse
import csv
import logging
from pathlib import Path

from rapidfuzz.distance import Indel

from .base_domain import load_base_domains
from .cli import (
    add_common_args,
    config_logging,
    raise_csv_field_limit,
    resolve_input,
    resolve_path,
    resolve_threshold,
    run_step,
)
from .hostname import normalize, safe_cell

logger = logging.getLogger(__name__)

DEFAULT_BASES = "base_domains.csv"
DEFAULT_NEW = "new_domains.txt"
DEFAULT_OUTPUT = "suspect_domains.csv"
DEFAULT_THRESHOLD = 0.75
CSV_FIELDS = ("new_domain", "matched_base", "similarity")

# A base of fewer characters than this can be a substring of almost any name,
# so the substring shortcut below would flag most of the list instead of the
# typosquats it is meant to catch.
MIN_SUBSTRING_BASE = 4


def load_new_domains(path: Path) -> list[tuple[str, str]]:
    """Read new registrations as ``(full_domain, name)`` pairs.

    ``name`` is the host with its TLD removed (``login.example.org`` ->
    ``login.example``), which is the token compared against base domains.
    Keeping the subdomains is deliberate: the rest of the pipeline works on
    registrable domains, but here the extra labels are signal, not noise.

    Lines that are not plausible hostnames are rejected and counted. Besides
    discarding junk, this is what keeps spreadsheet formula prefixes
    (``=``, ``+``, ``-``, ``@``) out of the CSV written by :func:`save_suspects`,
    where a spreadsheet application would evaluate them as formulas.

    Returns:
        Accepted ``(full_domain, name)`` pairs, in file order.
    """
    domains: list[tuple[str, str]] = []
    rejected: list[str] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not line.strip():
                continue
            candidate = normalize(line)
            if candidate is None:
                rejected.append(line.strip())
                continue
            labels = candidate.split(".")
            if len(labels) < 2:
                rejected.append(line.strip())
                continue
            domains.append((candidate, ".".join(labels[:-1])))
    if rejected:
        # Rendered with !r and truncated: these lines were rejected precisely
        # because they are not hostnames, so they may contain newlines, ANSI
        # escapes or megabytes of text, and logging them raw would let an input
        # file forge or wipe out log lines on the operator's terminal.
        shown = ", ".join(_short_repr(line) for line in rejected[:5])
        logger.warning(
            "Ignored %d line(s) in %s that are not valid domains: %s%s",
            len(rejected),
            path,
            shown,
            "..." if len(rejected) > 5 else "",
        )
    return domains


_REJECT_REPR_WIDTH = 80


def _short_repr(value: str) -> str:
    """Return a quoted, length-capped rendering of a rejected input line."""
    text = repr(value)
    if len(text) > _REJECT_REPR_WIDTH:
        text = text[: _REJECT_REPR_WIDTH - 3] + "..."
    return text


def find_suspects(
    new_domains: list[tuple[str, str]],
    base_domains: list[str],
    threshold: float = DEFAULT_THRESHOLD,
) -> list[tuple[str, str, float]]:
    """Return new domains whose name resembles a base domain.

    A domain is flagged when its similarity ratio reaches ``threshold``, or when
    the base name appears inside it - the ``<brand>-login`` / ``<brand>-secure``
    shape that scores poorly against the brand on its own. The substring route
    is limited to bases of at least :data:`MIN_SUBSTRING_BASE` characters so a
    short base cannot match every name that happens to contain it.

    A base domain present in the seed list is not reported against itself, and
    each domain is reported once, against its highest-scoring base, so consumers
    of the CSV never see duplicate rows for one registration.

    Note:
        For a substring match the reported ``similarity`` is the real ratio, which
        may sit below ``threshold``. Filter on ``similarity`` alone and you will
        miss those.

    Args:
        new_domains: ``(full_domain, name)`` pairs from :func:`load_new_domains`.
        base_domains: Base domain labels to compare against.
        threshold: Minimum similarity ratio, in ``(0.0, 1.0]``.

    Returns:
        ``(new_domain, matched_base, score)`` triples, one per flagged domain, in
        the order the domains were read.
    """
    best: dict[str, tuple[str, float]] = {}
    for full_domain, name in new_domains:
        for base in base_domains:
            if base == name:
                continue
            score = Indel.normalized_similarity(name, base)
            if score < threshold and not (
                len(base) >= MIN_SUBSTRING_BASE and base in name
            ):
                continue
            current = best.get(full_domain)
            if current is None or score > current[1]:
                best[full_domain] = (base, round(score, 2))
            else:
                logger.debug(
                    "%s matches %s (%.2f) but %s is better (%.2f)",
                    full_domain, base, score, current[0], current[1],
                )
    return [(domain, base, score) for domain, (base, score) in best.items()]


def save_suspects(path: Path, suspects: list[tuple[str, str, float]]) -> None:
    """Persist the flagged domains as CSV.

    This is the file an analyst opens, so it is the last place a spreadsheet
    formula could take effect. Both string columns are re-checked here as well as
    at their readers: ``new_domain`` comes from :func:`load_new_domains` and
    ``matched_base`` from :func:`~phishing_domain_detection.base_domain.load_base_domains`,
    and neither should have to be trusted twice.
    """
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(CSV_FIELDS)
        for domain, base, score in suspects:
            writer.writerow([safe_cell(domain), safe_cell(base), score])


def main(argv: list[str] | None = None) -> int:
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
    raise_csv_field_limit()

    def step() -> None:
        resolve_threshold(args.threshold, "--threshold")
        bases_path = resolve_input(args.data_dir, DEFAULT_BASES, args.bases)
        new_path = resolve_input(args.data_dir, DEFAULT_NEW, args.new)
        output_path = resolve_path(args.data_dir, DEFAULT_OUTPUT, args.output)
        base_domains = load_base_domains(bases_path)
        new_domains = load_new_domains(new_path)
        logger.info(
            "Loaded %d base domains and %d new domains",
            len(base_domains),
            len(new_domains),
        )
        suspects = find_suspects(new_domains, base_domains, args.threshold)
        save_suspects(output_path, suspects)
        logger.info("Flagged %d suspect domains -> %s", len(suspects), output_path)

    return run_step(step)


if __name__ == "__main__":
    raise SystemExit(main())
