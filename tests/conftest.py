"""Fixtures and output invariants shared by the whole test suite.

The invariant helpers live here rather than in a test module so that every test
can assert the same thing about a generated file. There is exactly one definition
of "clean output"; a second copy would drift, and a drifted invariant checks
nothing. The tests that exercise the helpers themselves are in
``test_invariants.py``.

Nothing here touches ``data/``: every helper takes a ``tmp_path`` directory.
"""

import csv
import io
import re

import pytest

#: The four characters a spreadsheet treats as the start of a formula. Quoting
#: the CSV does not help, because Excel and LibreOffice evaluate the cell whether
#: or not it is quoted - so this is checked on the parsed cell, not on the raw
#: line.
FORMULA_PREFIXES = ("=", "+", "-", "@")

#: Every file a pipeline run produces, listed explicitly rather than globbed so
#: that a stage which silently stops writing its output is itself noticed.
OUTPUT_FILES = (
    "domains_raw.txt",
    "domains_clean.csv",
    "similar_pairs.csv",
    "clusters.txt",
    "base_domains.csv",
    "suspect_domains.csv",
)

#: clusters.txt is written and read by :mod:`clustering`, but re-declared here on
#: purpose: an independent grammar catches a writer that stopped matching its own
#: reader, which a shared regex would hide.
_CLUSTER_RECORD = re.compile(r"^Cluster (\d+): (.+)$")

#: Control characters other than the CR and LF that separate records. A NUL, tab
#: or escape byte inside a record is how a forged record or a terminal hijack gets
#: in. CR and LF are excluded here because their per-cell handling is stricter:
#: a CSV may only contain one inside a quoted field, and a line format may not
#: contain one at all.
_CONTROL = re.compile(r"[\x00-\x09\x0b\x0c\x0e-\x1f\x7f]")


def _fail(path, message):
    """Raise an AssertionError naming the file, so a failure says what to open."""
    raise AssertionError(f"{path}: {message}")


def _assert_inert_cell(cell, path, where):
    if cell.startswith(FORMULA_PREFIXES):
        _fail(path, f"{where} starts a spreadsheet formula: {cell!r}")
    found = _CONTROL.search(cell)
    if found:
        _fail(path, f"{where} contains the control character {found.group()!r}: {cell!r}")


def _check_csv(path):
    """Every record must be flat: one physical line, uniform width, inert cells.

    A cell holding a newline is the forgery mechanism itself. Quoted, it survives
    a naive ``split(",")`` and becomes an extra record further down the pipeline;
    unquoted, the stdlib reader already splits it, which is why the field count is
    compared against the header instead of trusting the row to look well formed.

    The raw text is screened before parsing because :func:`csv.reader` raises
    ``csv.Error`` on a NUL, and a check that dies with a non-AssertionError tells
    the reader far less than a check that names the offending byte.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    found = _CONTROL.search(text)
    if found:
        _fail(path, f"contains the control character {found.group()!r}")
    rows = list(csv.reader(io.StringIO(text, newline="")))
    if not rows:
        _fail(path, "expected a header row, found an empty file")
    header = rows[0]
    for number, row in enumerate(rows, start=1):
        if len(row) != len(header):
            _fail(path, f"row {number} has {len(row)} field(s), expected {len(header)}")
        for column, cell in zip(header, row, strict=True):
            if "\n" in cell or "\r" in cell:
                _fail(path, f"row {number} column {column} spans lines: {cell!r}")
            _assert_inert_cell(cell, path, f"row {number} column {column}")


def _check_domain_list(path):
    """domains_raw.txt: one domain per line, and no line can act on the reader.

    Only the properties a writer can guarantee. Each line has to survive the
    screen for a formula prefix and a control character, and nothing may open a
    second record - which is what the newline case buys, since ``safe_cell``
    strips the newline and so leaves exactly one line behind.

    Whether a line is a *hostname* is deliberately not checked here:
    :func:`assert_bare_hostnames` makes that promise, and only a clean run can
    keep it.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    for number, line in enumerate(text.splitlines(), start=1):
        _assert_inert_cell(line, path, f"line {number}")


def assert_bare_hostnames(path):
    """domains_raw.txt holds nothing but registrable domains, one per line.

    This is a stronger promise than :func:`assert_output_invariant`, and the two
    are deliberately separate. ``save_domains`` sanitizes but does not validate,
    so a hostile domain handed straight to it survives as a :func:`safe_cell`
    result that is inert yet still not a hostname - ``'=cmd|'/c calc'!A1`` keeps
    its space, and ``absbook\\nCluster 999: x`` becomes ``absbookCluster 999: x``.
    Screening those would mean failing the writer for the reader's job.

    Step 2 is where they die: ``count_labels`` skips anything
    :func:`hostname.normalize` rejects, so a clean run keeps this promise while a
    direct call to ``save_domains`` cannot. ``test_preprocess`` pins the skip.

    Raises:
        AssertionError: naming the file and the offending line.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    for number, line in enumerate(text.splitlines(), start=1):
        if not line or line != line.strip():
            _fail(path, f"line {number} is not a bare hostname: {line!r}")
        if " " in line or "\t" in line:
            _fail(path, f"line {number} holds more than one token: {line!r}")


def _check_clusters(path):
    """clusters.txt: contiguous records, one per line, every member inert.

    The indices must run 1..N with no gap. That is what catches a forged record:
    a member carrying a newline appends ``Cluster 999: x`` after the real
    ``Cluster 1: y``, and ``999`` breaks the run. Checking each member's grammar
    alone would not notice, because the forged member is itself a valid label -
    and a grammar check would also flag :func:`hostname.safe_cell`'s own output,
    which is inert by construction.

    Note what a member grammar deliberately cannot assert: that the members are
    real labels. That is a reader's job, and ``write_clusters`` may be handed a
    value no reader produced.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    indices = []
    for number, line in enumerate(text.splitlines(), start=1):
        match = _CLUSTER_RECORD.match(line)
        if not match:
            _fail(path, f"line {number} is not a cluster record: {line!r}")
        indices.append(int(match.group(1)))
        for member in match.group(2).split(", "):
            _assert_inert_cell(member, path, f"line {number} member")
    if indices != list(range(1, len(indices) + 1)):
        _fail(path, f"cluster ids are not contiguous from 1: {indices}")


_CHECKS = {
    "clusters.txt": _check_clusters,
    "domains_raw.txt": _check_domain_list,
}


def assert_output_invariant(path):
    """Fail unless ``path`` is free of formula cells and forged records.

    Args:
        path: One generated output file. Its name selects the checks, so an
            unknown file is an error rather than a silent pass.

    Raises:
        AssertionError: naming the file and the offending record.
    """
    check = _CHECKS.get(path.name) or (_check_csv if path.suffix == ".csv" else None)
    if check is None:
        raise ValueError(f"no invariant defined for {path.name}")
    check(path)


def assert_data_dir_is_clean(data_dir):
    """Check every output file present in ``data_dir``.

    Files that were not produced are skipped rather than required: a run that
    stops early is expected to have written fewer files, and the caller asserts
    separately that the ones it cares about are missing.

    Args:
        data_dir: A directory holding pipeline output. Nothing outside it is read.
    """
    for name in OUTPUT_FILES:
        path = data_dir / name
        if path.exists():
            assert_output_invariant(path)


@pytest.fixture
def check_outputs():
    """Return the data-dir invariant, bound to nothing in particular.

    Exposed as a fixture so that no test module has to import the helpers and so
    that the set of files checked cannot drift between modules.
    """
    return assert_data_dir_is_clean
