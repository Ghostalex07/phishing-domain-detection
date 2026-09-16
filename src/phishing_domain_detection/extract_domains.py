"""Extract registrable domains from crt.sh Certificate Transparency records."""

import argparse
import json
import logging
import re
from pathlib import Path

from .cli import add_common_args, config_logging, resolve_path

logger = logging.getLogger(__name__)

DEFAULT_INPUT = "crtsh_raw.json"
DEFAULT_OUTPUT = "domains_raw.txt"

_FQDN_RE = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$")


def extract_domains(records: list[dict]) -> set[str]:
    """Reduce every parsed name to its registrable domain (last two labels).

    Args:
        records: List of Certificate Transparency entries as parsed from the
            crt.sh JSON dump.

    Returns:
        A set of unique, lowercased registrable domains (e.g. ``www.tiffany.com``
        becomes ``tiffany.com``).
    """
    domains: set[str] = set()
    for entry in records:
        name_value = entry.get("name_value")
        if not name_value:
            continue
        for value in name_value.splitlines():
            value = value.strip().lower()
            if _FQDN_RE.match(value):
                labels = value.split(".")
                if len(labels) >= 2:
                    domains.add(f"{labels[-2]}.{labels[-1]}")
    return domains


def load_records(path: Path) -> list[dict]:
    """Read the crt.sh JSON dump from ``path``."""
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def save_domains(path: Path, domains: set[str]) -> None:
    """Write one domain per line, alphabetically sorted."""
    with path.open("w", encoding="utf-8") as fh:
        fh.writelines(f"{domain}\n" for domain in sorted(domains))


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    add_common_args(parser)
    parser.add_argument("--input", type=Path, default=None,
                        help=f"Raw crt.sh JSON dump (default: <data-dir>/{DEFAULT_INPUT})")
    parser.add_argument("--output", type=Path, default=None,
                        help=f"Output domain list (default: <data-dir>/{DEFAULT_OUTPUT})")
    args = parser.parse_args(argv)
    config_logging(args.verbose)

    input_path = resolve_path(args.data_dir, DEFAULT_INPUT, args.input)
    output_path = resolve_path(args.data_dir, DEFAULT_OUTPUT, args.output)

    logger.info("Loading CT records from %s", input_path)
    records = load_records(input_path)
    domains = extract_domains(records)
    save_domains(output_path, domains)
    logger.info("Extracted %d unique domains -> %s", len(domains), output_path)


if __name__ == "__main__":
    main()