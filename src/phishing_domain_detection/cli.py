"""Shared helpers used by every command-line tool in this package."""

import argparse
import csv
import logging
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

# Relative to the current directory on purpose: it works the same for an
# editable checkout, a wheel install and a plain `git clone`, whereas deriving it
# from __file__ breaks as soon as the package is installed somewhere else.
DEFAULT_DATA_DIR = Path("data")

LOG_FORMAT = "%(asctime)s | %(levelname)-7s | %(message)s"

logger = logging.getLogger(__name__)


class PipelineError(Exception):
    """A failure the user can act on: missing file, malformed data, bad flag."""


def add_common_args(parser: argparse.ArgumentParser) -> None:
    """Attach the flags shared by every subcommand (data dir + verbosity)."""
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=DEFAULT_DATA_DIR,
        help=f"Directory containing the dataset files, relative to the current "
        f"directory (default: {DEFAULT_DATA_DIR})",
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


def resolve_input(data_dir: Path, filename: str, override: Path | None) -> Path:
    """Resolve a path that must already exist.

    Raises:
        PipelineError: if the file is missing, naming the path and the flags that
            would point somewhere else.
    """
    path = resolve_path(data_dir, filename, override)
    if not path.is_file():
        raise PipelineError(
            f"input file not found: {path}\n"
            f"  create it, or pass --input / --data-dir to point somewhere else"
        )
    return path


def require_fields(
    fieldnames: Sequence[str] | None, expected: Sequence[str], path: Path
) -> None:
    """Validate a CSV header before its rows are read.

    Raises:
        PipelineError: listing every column of ``expected`` that is absent, so a
            truncated or hand-edited CSV fails with a useful message instead of a
            ``KeyError`` from deep inside a loop.
    """
    missing = [name for name in expected if name not in (fieldnames or ())]
    if missing:
        raise PipelineError(f"{path}: missing CSV column(s): {', '.join(missing)}")


def resolve_threshold(value: float, flag: str) -> float:
    """Validate a similarity threshold.

    Raises:
        PipelineError: if ``value`` is outside ``(0.0, 1.0]``; ``0`` would return
            every pair and anything above ``1`` would silently return none.
    """
    if not 0.0 < value <= 1.0:
        raise PipelineError(f"{flag} must be in (0.0, 1.0], got {value}")
    return value


def run_step(step: Callable[[], None]) -> int:
    """Run one pipeline step and turn expected failures into an exit code.

    Genuine bugs and ``KeyboardInterrupt`` still propagate with their traceback;
    the handlers here cover the failures a user can actually cause or act on.
    Note what is deliberately *not* caught: :class:`ValueError`. A malformed
    file should be rejected at its reader (the ``encoding='utf-8',
    errors='replace'`` arguments on every reader, plus explicit validation), and
    a ``ValueError`` that still reaches here is a bug in this code, which must
    stay visible rather than be reported as bad input.

    Returns:
        ``0`` on success, ``1`` after logging a :class:`PipelineError`, an
        ``OSError`` or a malformed-input ``csv.Error``.
    """
    try:
        step()
    except PipelineError as exc:
        logger.error("%s", exc)
        return 1
    except OSError as exc:
        logger.error("I/O error: %s", exc)
        return 1
    except csv.Error as exc:
        logger.error("Malformed CSV: %s", exc)
        return 1
    return 0


def raise_csv_field_limit() -> None:
    """Raise :func:`csv.field_size_limit` to its maximum.

    The stdlib default rejects any field over 128 KiB, which is small enough to
    be reachable by a scraped domain list and would otherwise fail a whole run
    over one long line.
    """
    limit = sys.maxsize
    while True:
        try:
            csv.field_size_limit(limit)
            return
        except OverflowError:
            limit //= 10


def config_logging(verbose: bool = False) -> None:
    """Configure the package logger with human-friendly output.

    ``force=True`` is required: :func:`logging.basicConfig` is a no-op when the
    root logger already has handlers, which silently ignored ``--verbose``
    whenever something else configured logging first.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format=LOG_FORMAT, datefmt="%H:%M:%S", force=True)
