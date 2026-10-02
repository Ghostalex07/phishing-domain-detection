"""Hostname validation and registrable-domain (eTLD+1) computation.

This module is the single source of truth for what a hostname is and what a
single DNS label is. Every stage that reads or writes a domain-derived string
validates through it: :mod:`extract_domains` (step 1, Certificate Transparency
input), :mod:`preprocess` (step 2), :mod:`similarity` (step 3),
:mod:`clustering` (step 4), :mod:`base_domain` (step 5) and :mod:`detect_new`
(step 6, analyst-supplied seed list).

Keeping one definition is what makes the project's security invariant checkable:
because every reader validates and every writer also runs :func:`safe_cell`, no
cell reaching a generated CSV or a line-oriented format can start with a
spreadsheet formula prefix, and no input cell can inject an extra record.
"""

import re

# A hostname: dot-separated labels of letters/digits/hyphens ending in an
# alphabetic TLD. Deliberately stricter than RFC 1123 - it exists to reject the
# prose, URLs and disclaimer text that crt.sh mixes into ``name_value``.
_LABEL = r"[a-z0-9]([a-z0-9-]*[a-z0-9])?"
_FQDN_RE = re.compile(rf"^{_LABEL}(\.{_LABEL})*\.[a-z]{{2,}}$")
_LABEL_RE = re.compile(rf"^{_LABEL}$")

# Characters that would either end a line early or make a spreadsheet evaluate a
# cell as a formula. ``=`` ``+`` ``-`` ``@`` are the classic CSV injection
# prefixes; the C0 range covers embedded newlines and NUL, which would otherwise
# let one input cell forge extra records in a line-oriented format such as
# clusters.txt.
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
DANGEROUS_PREFIXES = ("=", "+", "-", "@")

# Public suffixes made of more than one label. Without this table the
# "last two labels" rule turns ``bank.com.au`` into ``com.au``, silently losing
# the actual domain. This is a deliberately small, curated set rather than the
# full Public Suffix List: it needs no network access and no extra dependency,
# and it covers the multi-part suffixes that dominate real Certificate
# Transparency data. Add entries here as new cases show up.
MULTI_LABEL_SUFFIXES = frozenset(
    {
        # United Kingdom
        "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk",
        "ac.uk", "gov.uk", "nhs.uk", "police.uk",
        # Australia / New Zealand
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
        "asn.au", "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
        # Americas
        "com.br", "net.br", "org.br", "gov.br", "edu.br",
        "com.mx", "org.mx", "gob.mx", "edu.mx",
        "com.ar", "com.co", "com.pe", "com.ve", "com.uy", "com.ec",
        "co.cr", "co.in",
        # Asia / Middle East / Africa
        "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
        "com.hk", "com.tw", "com.sg", "com.my", "com.ph", "com.vn", "com.pk",
        "com.sa", "com.eg", "com.ng", "com.gh", "co.za", "co.ke", "co.jp",
        "co.kr", "co.il", "co.th", "com.tr", "com.bh", "com.kw", "com.qa",
    }
)


def normalize(value: str) -> str | None:
    """Return ``value`` as a bare lowercase hostname, or ``None`` if it is not one.

    Wildcard and leading-dot prefixes are stripped: crt.sh reports wildcard
    certificates as ``*.example.com``, and the wildcard covers the apex domain,
    so the apex is the name worth analysing. A trailing dot is dropped for the
    same reason.

    Args:
        value: One candidate string, typically a line of a ``name_value`` field.

    Returns:
        The normalized hostname, or ``None`` when the input is not a plausible
        hostname (prose, URLs, spreadsheet formulas, bare TLDs, ...).
    """
    candidate = value.strip().lower()
    while candidate.startswith(("*.", ".")):
        candidate = candidate[2:] if candidate.startswith("*.") else candidate[1:]
    candidate = candidate.rstrip(".")
    if not candidate or not _FQDN_RE.match(candidate):
        return None
    return candidate


def normalize_label(value: str) -> str | None:
    """Return ``value`` as a bare lowercase DNS label, or ``None`` if it is not one.

    The similarity, clustering and base-domain stages work on a single label
    (``ad-digital`` from ``ad-digital.com``), not a full hostname, so they need
    their own validator: :func:`normalize` demands a TLD and would reject them.

    Args:
        value: One candidate string, e.g. a ``name`` cell from a stage output.

    Returns:
        The normalized label, or ``None`` when it is not a plausible DNS label.
        Comma, quote, bracket and whitespace characters are all rejected, so a
        validated label is safe to join or to write into a line-oriented file.
    """
    candidate = value.strip().lower()
    if not candidate or not _LABEL_RE.match(candidate):
        return None
    return candidate


def safe_cell(value: str) -> str:
    """Neutralize a string that is about to be written to CSV or a line format.

    This is the second of two defences, not the first. Callers should validate at
    the reader boundary with :func:`normalize` or :func:`normalize_label`, which
    reject bad input outright; this exists so that a future writer cannot forget
    that and quietly ship a live formula to an analyst's spreadsheet.

    Control characters are dropped and a ``'`` is prepended to the four
    spreadsheet formula prefixes. Prefixing rather than stripping matters:
    ``-`` is legal inside a real domain label, so silently removing it would
    corrupt legitimate data.

    Args:
        value: The string to be written.

    Returns:
        A string that is inert in a spreadsheet and cannot add lines to a text
        format. For already-validated input this is the identity function.
    """
    cleaned = _CONTROL_RE.sub("", value)
    if cleaned.startswith(DANGEROUS_PREFIXES):
        return "'" + cleaned
    return cleaned


def registrable_domain(value: str) -> str | None:
    """Reduce a hostname to its registrable domain (eTLD+1).

    Uses the last two labels, or the last three when the trailing pair is a
    known multi-part public suffix, so ``www.bank.com.au`` becomes
    ``bank.com.au`` rather than ``com.au``.

    Args:
        value: A hostname, ideally already normalized by :func:`normalize`.

    Returns:
        The registrable domain, or ``None`` if ``value`` has fewer than two
        labels or contains an empty one (``a..com``).
    """
    labels = value.split(".")
    if len(labels) < 2 or not all(labels):
        return None
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])
