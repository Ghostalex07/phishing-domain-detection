"""Run the whole detection pipeline end to end with a single command."""

from __future__ import annotations

import argparse
import logging
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from . import (
    base_domain,
    clustering,
    detect_new,
    extract_domains,
    preprocess,
    similarity,
)
from .cli import (
    add_common_args,
    config_logging,
    raise_csv_field_limit,
    resolve_input,
    resolve_threshold,
    run_step,
)

logger = logging.getLogger(__name__)

TOTAL_STEPS = 6


@contextmanager
def step(number: int) -> Iterator[None]:
    """Log how long a pipeline step took, including when it fails."""
    started = time.perf_counter()
    try:
        yield
    finally:
        logger.info("[%d/%d] finished in %.2fs", number, TOTAL_STEPS, time.perf_counter() - started)


def run_pipeline(
    data_dir: Path,
    pair_threshold: float = similarity.DEFAULT_THRESHOLD,
    detect_threshold: float = detect_new.DEFAULT_THRESHOLD,
) -> None:
    """Execute steps 1-6 in order, chaining data structures in memory.

    Args:
        data_dir: Directory holding all input/output dataset files.
        pair_threshold: Minimum ratio for two names to become similar.
        detect_threshold: Minimum ratio for a new domain to be flagged.

    Raises:
        PipelineError: if a threshold is out of range or a required input is
            missing.
    """
    resolve_threshold(pair_threshold, "--pair-threshold")
    resolve_threshold(detect_threshold, "--detect-threshold")

    # 1 - Extract registrable domains from the crt.sh JSON dump.
    with step(1):
        records = extract_domains.load_records(
            resolve_input(data_dir, extract_domains.DEFAULT_INPUT, None)
        )
        domains = extract_domains.extract_domains(records)
        extract_domains.save_domains(data_dir / extract_domains.DEFAULT_OUTPUT, domains)
        logger.info("Extracted %d domains -> %s", len(domains), extract_domains.DEFAULT_OUTPUT)

    # 2 - Normalize and count primary labels.
    with step(2):
        counts = preprocess.count_labels(sorted(domains))
        preprocess.save_counts(data_dir / preprocess.DEFAULT_OUTPUT, counts)
        logger.info("Preprocessed %d names -> %s", len(counts), preprocess.DEFAULT_OUTPUT)

    # 3 - Detect lexically similar pairs.
    with step(3):
        pairs = similarity.find_similar_pairs(sorted(counts), pair_threshold)
        similarity.save_pairs(data_dir / similarity.DEFAULT_OUTPUT, pairs)
        logger.info("Found %d similar pairs -> %s", len(pairs), similarity.DEFAULT_OUTPUT)

    # 4 - Group pairs into clusters (connected components).
    with step(4):
        clusters = clustering.connected_components(clustering.build_graph(pairs))
        clustering.write_clusters(data_dir / clustering.DEFAULT_OUTPUT, clusters)
        logger.info("Built %d clusters -> %s", len(clusters), clustering.DEFAULT_OUTPUT)

    # 5 - Select a representative base domain per cluster.
    with step(5):
        frequency = {name: entry.count for name, entry in counts.items()}
        selected = base_domain.select_base_domains([sorted(c) for c in clusters], frequency)
        base_domain.save_base_domains(data_dir / base_domain.DEFAULT_OUTPUT, selected)
        logger.info(
            "Selected %d base domains -> %s", len(selected), base_domain.DEFAULT_OUTPUT
        )

    # 6 - Flag new registrations that resemble a base domain.
    with step(6):
        new_path = data_dir / detect_new.DEFAULT_NEW
        if not new_path.is_file():
            logger.warning(
                "No %s in %s - writing an empty suspect report instead of failing",
                detect_new.DEFAULT_NEW,
                data_dir,
            )
            detect_new.save_suspects(data_dir / detect_new.DEFAULT_OUTPUT, [])
            return
        new_domains = detect_new.load_new_domains(new_path)
        suspects = detect_new.find_suspects(
            new_domains, [base for base, _ in selected], detect_threshold
        )
        detect_new.save_suspects(data_dir / detect_new.DEFAULT_OUTPUT, suspects)
        logger.info("Flagged %d suspect domains -> %s", len(suspects), detect_new.DEFAULT_OUTPUT)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    add_common_args(parser)
    pair_default = similarity.DEFAULT_THRESHOLD
    detect_default = detect_new.DEFAULT_THRESHOLD
    parser.add_argument("--pair-threshold", type=float, default=pair_default,
                        help=f"Similarity threshold for step 3 (default: {pair_default})")
    parser.add_argument("--detect-threshold", type=float, default=detect_default,
                        help=f"Detection threshold for step 6 (default: {detect_default})")
    args = parser.parse_args(argv)
    config_logging(args.verbose)
    raise_csv_field_limit()

    def run() -> None:
        started = time.perf_counter()
        run_pipeline(args.data_dir, args.pair_threshold, args.detect_threshold)
        logger.info("Pipeline complete in %.2fs", time.perf_counter() - started)

    return run_step(run)


if __name__ == "__main__":
    raise SystemExit(main())
