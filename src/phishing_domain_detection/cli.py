"""Shared helpers used by every command-line tool in this package."""

import argparse
import logging
from pathlib import Path

DEFAULT_DATA_DIR = Path(__file__).resolve().parents[2] / "data"

LOG_FORMAT = "%(asctime)s | %(levelname)-7s | %(message)s"


def add_common_args(parser: argparse.ArgumentParser) -> None:
    """Attach the flags shared by every subcommand (data dir + verbosity)."""
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=DEFAULT_DATA_DIR,
        help=f"Directory containing the dataset files (default: {DEFAULT_DATA_DIR})",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug-level logging",
    )


def resolve_path(data_dir: Path, filename: str, override: Path | None) -> Path:
    """Return ``override`` if provided, otherwise ``data_dir / filename``."""
    return override if override is not None else data_dir / filename


def config_logging(verbose: bool = False) -> None:
    """Configure the package logger with human-friendly output."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format=LOG_FORMAT, datefmt="%H:%M:%S")