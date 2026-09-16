"""Run the whole detection pipeline end to end with a single command."""

import argparse
import logging
from pathlib import Path

from . import base_domain, clustering, detect_new, extract_domains, preprocess, similarity
from .cli import add_common_args, config_logging

logger = logging.getLogger(__name__)


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
    """
    # 1 - Extract registrable domains from the crt.sh JSON dump.
    records = extract_domains.load_records(data_dir / extract_domains.DEFAULT_INPUT)
    domains = extract_domains.extract_domains(records)
    extract_domains.save_domains(data_dir / extract_domains.DEFAULT_OUTPUT, domains)
    logger.info("[1/6] Extracted %d domains -> %s", len(domains), extract_domains.DEFAULT_OUTPUT)

    # 2 - Normalize and count primary labels.
    counts = preprocess.count_labels(sorted(domains))
    preprocess.save_counts(data_dir / preprocess.DEFAULT_OUTPUT, counts)
    logger.info("[2/6] Preprocessed %d names -> %s", len(counts), preprocess.DEFAULT_OUTPUT)

    # 3 - Detect lexically similar pairs.
    pairs = similarity.find_similar_pairs(sorted(counts), pair_threshold)
    similarity.save_pairs(data_dir / similarity.DEFAULT_OUTPUT, pairs)
    logger.info("[3/6] Found %d similar pairs -> %s", len(pairs), similarity.DEFAULT_OUTPUT)

    # 4 - Group pairs into clusters (connected components).
    clusters = clustering.connected_components(clustering.build_graph(pairs))
    clustering.write_clusters(data_dir / clustering.DEFAULT_OUTPUT, clusters)
    logger.info("[4/6] Built %d clusters -> %s", len(clusters), clustering.DEFAULT_OUTPUT)

    # 5 - Select a representative base domain per cluster.
    frequency = {name: int(info["count"]) for name, info in counts.items()}
    cluster_members = [sorted(cluster) for cluster in clusters]
    selected = base_domain.select_base_domains(cluster_members, frequency)
    base_domain.save_base_domains(data_dir / base_domain.DEFAULT_OUTPUT, selected)
    logger.info("[5/6] Selected %d base domains -> %s", len(selected), base_domain.DEFAULT_OUTPUT)

    # 6 - Flag new registrations that resemble a base domain.
    new_domains = detect_new.load_new_domains(data_dir / detect_new.DEFAULT_NEW)
    suspects = detect_new.find_suspects(
        new_domains, [base for base, _ in selected], detect_threshold
    )
    detect_new.save_suspects(data_dir / detect_new.DEFAULT_OUTPUT, suspects)
    logger.info("[6/6] Flagged %d suspect domains -> %s", len(suspects), detect_new.DEFAULT_OUTPUT)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    add_common_args(parser)
    parser.add_argument("--pair-threshold", type=float, default=similarity.DEFAULT_THRESHOLD,
                        help=f"Similarity threshold for step 3 (default: {similarity.DEFAULT_THRESHOLD})")
    parser.add_argument("--detect-threshold", type=float, default=detect_new.DEFAULT_THRESHOLD,
                        help=f"Detection threshold for step 6 (default: {detect_new.DEFAULT_THRESHOLD})")
    args = parser.parse_args(argv)
    config_logging(args.verbose)

    run_pipeline(args.data_dir, args.pair_threshold, args.detect_threshold)


if __name__ == "__main__":
    main()