"""Find pairs of domain names that look similar by normalized edit distance."""

import argparse
import csv
import logging
from pathlib import Path

import numpy as np
from rapidfuzz import process
from rapidfuzz.distance import Indel

from .cli import (
    PipelineError,
    add_common_args,
    config_logging,
    raise_csv_field_limit,
    require_fields,
    resolve_input,
    resolve_path,
    resolve_threshold,
    run_step,
)
from .hostname import normalize_label, safe_cell
from .preprocess import load_names

logger = logging.getLogger(__name__)

DEFAULT_INPUT = "domains_clean.csv"
DEFAULT_OUTPUT = "similar_pairs.csv"
DEFAULT_THRESHOLD = 0.8
CSV_FIELDS = ("name1", "name2", "similarity")

# Rows scored per batch. The comparison is inherently O(n^2), but doing it one
# pair at a time is what makes it slow: 256 was both the fastest and the
# leanest option measured (better cache locality than wider bands).
BLOCK_SIZE = 256

# Hard ceiling on how many pairs may be retained in memory. The score matrix is
# bounded by BLOCK_SIZE * n, but the result list is not bounded at all by the
# algorithm, and it is the dominant term: a few thousand mutually-similar names
# produce millions of pairs, and an attacker who registers a spread of typo
# variants against one brand controls exactly that. The run must fail loudly
# rather than silently drop matches, because an analyst acting on a truncated
# report is worse off than one whose run stopped.
MAX_PAIRS = 1_000_000


def find_similar_pairs(
    names: list[str], threshold: float = DEFAULT_THRESHOLD, max_pairs: int = MAX_PAIRS
) -> list[tuple[str, str, float]]:
    """Return every pair whose similarity ratio reaches ``threshold``.

    The score is the Indel (unweighted longest common subsequence) normalized
    similarity, which is what the classic ``Levenshtein.ratio`` reports, so the
    pairs and scores match the definition this project has always used. Scoring
    them through :meth:`rapidfuzz.distance.Indel.normalized_similarity` in
    vectorised batches is roughly 28x faster than doing it one pair at a time.

    The full n x n score matrix is never materialised: rows are scored in bands
    of :data:`BLOCK_SIZE`, which bounds that term at ``O(BLOCK_SIZE * n)``. The
    returned list is a second, separate cost of ``O(pairs)`` and is the larger
    of the two in the worst case, which is why :data:`MAX_PAIRS` exists.

    Note: ``process.cdist``'s ``score_cutoff`` is deliberately not used. It is a
    pre-filter that drops pairs scoring exactly ``threshold``, which silently
    loses a large share of the borderline matches; the ``>=`` comparison below
    is exact and cheap.

    Args:
        names: Labels to compare, in the order they should appear in the output.
        threshold: Minimum similarity ratio, in ``(0.0, 1.0]``.
        max_pairs: Ceiling on retained pairs; see :data:`MAX_PAIRS`.

    Returns:
        ``(name1, name2, score)`` triples in the same order an
        ``itertools.combinations`` scan would produce, so the CSV stays stable.

    Raises:
        PipelineError: if the pair ceiling would be exceeded. Never truncates.
    """
    pairs: list[tuple[str, str, float]] = []
    count = len(names)
    if count < 2:
        return pairs

    total = count * (count - 1) // 2
    logger.info(
        "Comparing %d pairs in bands of %d (threshold %.2f)", total, BLOCK_SIZE, threshold
    )
    columns = np.arange(count)
    for start in range(0, count, BLOCK_SIZE):
        stop = min(start + BLOCK_SIZE, count)
        scores = process.cdist(
            names[start:stop],
            names,
            scorer=Indel.normalized_similarity,
            dtype=np.float64,
        )
        # Global row indices, not band-local ones: `columns > rows` is what keeps
        # each unordered pair to a single row, and using band-local indices would
        # re-emit cross-band pairs.
        rows = np.arange(start, stop)[:, None]
        matches = (scores >= threshold) & (columns[np.newaxis, :] > rows)
        for row, col in zip(*np.nonzero(matches), strict=True):
            pairs.append(
                (
                    names[start + int(row)],
                    names[int(col)],
                    round(float(scores[row, col]), 2),
                )
            )
        # Checked per band rather than at the end: by the time a full list of
        # millions of tuples exists, the memory that caused the problem is already
        # allocated.
        if len(pairs) > max_pairs:
            raise PipelineError(
                f"more than {max_pairs} similar pairs among {count} names; "
                f"raise --max-pairs or narrow the input"
            )
        logger.debug("band %d-%d/%d -> %d pair(s) so far", start, stop, count, len(pairs))
    return pairs


def load_pairs(path: Path) -> list[tuple[str, str, float]]:
    """Read back the pairs written by :func:`save_pairs`.

    The name columns are re-validated: a stage output is an ordinary input to the
    next stage, so it is untrusted and gets the same treatment as scraped text.

    Raises:
        PipelineError: if the header is wrong, a similarity is not a number, or a
            name is not a valid DNS label.
    """
    pairs: list[tuple[str, str, float]] = []
    with path.open("r", newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        require_fields(reader.fieldnames, CSV_FIELDS, path)
        for row in reader:
            try:
                score = float(row["similarity"])
            except (TypeError, ValueError) as exc:
                raise PipelineError(
                    f"{path}: bad similarity {row['similarity']!r} for pair "
                    f"({row['name1']!r}, {row['name2']!r})"
                ) from exc
            name1 = _checked_label(row["name1"], path)
            name2 = _checked_label(row["name2"], path)
            pairs.append((name1, name2, score))
    return pairs


def _checked_label(value: str, path: Path) -> str:
    """Return ``value`` as a valid DNS label or raise :class:`PipelineError`."""
    label = normalize_label(value)
    if label is None:
        raise PipelineError(f"{path}: bad name {value!r}")
    return label


def save_pairs(path: Path, pairs: list[tuple[str, str, float]]) -> None:
    """Persist the similar pairs as CSV."""
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(CSV_FIELDS)
        for name1, name2, score in pairs:
            writer.writerow([safe_cell(name1), safe_cell(name2), score])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    add_common_args(parser)
    parser.add_argument("--input", type=Path, default=None,
                        help=f"Clean domains CSV (default: <data-dir>/{DEFAULT_INPUT})")
    parser.add_argument("--output", type=Path, default=None,
                        help=f"Output CSV (default: <data-dir>/{DEFAULT_OUTPUT})")
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD,
                        help=f"Minimum similarity score (default: {DEFAULT_THRESHOLD})")
    parser.add_argument("--max-pairs", type=int, default=MAX_PAIRS,
                        help=f"Refuse to hold more than this many pairs "
                             f"(default: {MAX_PAIRS})")
    args = parser.parse_args(argv)
    config_logging(args.verbose)
    raise_csv_field_limit()

    def step() -> None:
        resolve_threshold(args.threshold, "--threshold")
        input_path = resolve_input(args.data_dir, DEFAULT_INPUT, args.input)
        output_path = resolve_path(args.data_dir, DEFAULT_OUTPUT, args.output)
        names = load_names(input_path)
        logger.info("Loaded %d names from %s", len(names), input_path)
        pairs = find_similar_pairs(names, args.threshold, args.max_pairs)
        save_pairs(output_path, pairs)
        logger.info("Found %d similar pairs -> %s", len(pairs), output_path)

    return run_step(step)


if __name__ == "__main__":
    raise SystemExit(main())
