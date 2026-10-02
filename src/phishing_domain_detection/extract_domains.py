"""Extract registrable domains from crt.sh Certificate Transparency records."""

import argparse
import json
import logging
from pathlib import Path
from typing import Any

from .cli import (
    PipelineError,
    add_common_args,
    config_logging,
    raise_csv_field_limit,
    resolve_input,
    resolve_path,
    run_step,
)
from .hostname import normalize, registrable_domain, safe_cell

logger = logging.getLogger(__name__)

DEFAULT_INPUT = "crtsh_raw.json"
DEFAULT_OUTPUT = "domains_raw.txt"


def extract_domains(records: list[dict[str, Any]]) -> set[str]:
    """Reduce every name found in the records to its registrable domain.

    Each ``name_value`` field packs several newline-separated names into one
    string, and crt.sh mixes real hostnames with URLs, disclaimers and mail
    addresses. Anything that is not a plausible hostname is dropped, and
    wildcard entries are reduced to the apex domain they cover.

    Args:
        records: Certificate Transparency entries as parsed from the crt.sh dump.

    Returns:
        A set of unique, lowercased registrable domains, so ``www.tiffany.com``
        becomes ``tiffany.com`` and ``*.bank.com.au`` becomes ``bank.com.au``.
    """
    domains: set[str] = set()
    dropped = 0
    for entry in records:
        if not isinstance(entry, dict):
            logger.warning("Skipping CT record of unexpected type %s", type(entry).__name__)
            continue
        name_value = entry.get("name_value")
        if not isinstance(name_value, str) or not name_value:
            continue
        for value in name_value.splitlines():
            candidate = normalize(value)
            if candidate is None:
                dropped += 1
                continue
            domain = registrable_domain(candidate)
            if domain is not None:
                domains.add(domain)
    logger.debug("Discarded %d name(s) that are not valid hostnames", dropped)
    return domains


def load_records(path: Path) -> list[dict[str, Any]]:
    """Read the crt.sh JSON dump from ``path``.

    Raises:
        PipelineError: if the file is not valid JSON, or its top level is not the
            array of records crt.sh returns. An error object instead of an array
            is how crt.sh reports rate limiting, and iterating a dict would
            otherwise yield its keys and fail with a confusing ``AttributeError``.
    """
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            payload = json.load(fh)
    except json.JSONDecodeError as exc:
        raise PipelineError(f"{path}: invalid JSON ({exc})") from exc
    if not isinstance(payload, list):
        raise PipelineError(
            f"{path}: expected a JSON array of CT records, got {type(payload).__name__}"
        )
    return payload


def save_domains(path: Path, domains: set[str]) -> None:
    """Write one domain per line, alphabetically sorted.

    Run through :func:`safe_cell` like every other writer, so this file stays
    inert if it is opened in a spreadsheet or fed to a later stage that trusts it
    on the strength of having been written here.
    """
    with path.open("w", encoding="utf-8") as fh:
        fh.writelines(f"{safe_cell(domain)}\n" for domain in sorted(domains))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    add_common_args(parser)
    parser.add_argument("--input", type=Path, default=None,
                        help=f"Raw crt.sh JSON dump (default: <data-dir>/{DEFAULT_INPUT})")
    parser.add_argument("--output", type=Path, default=None,
                        help=f"Output domain list (default: <data-dir>/{DEFAULT_OUTPUT})")
    args = parser.parse_args(argv)
    config_logging(args.verbose)
    raise_csv_field_limit()

    def step() -> None:
        input_path = resolve_input(args.data_dir, DEFAULT_INPUT, args.input)
        output_path = resolve_path(args.data_dir, DEFAULT_OUTPUT, args.output)
        logger.info("Loading CT records from %s", input_path)
        records = load_records(input_path)
        domains = extract_domains(records)
        save_domains(output_path, domains)
        logger.info("Extracted %d unique domains -> %s", len(domains), output_path)

    return run_step(step)


if __name__ == "__main__":
    raise SystemExit(main())
