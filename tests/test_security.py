"""Regression tests for the security hardening pass.

Grouped by the property under test rather than by module, because the properties
are what has to stay true:

* **every reader validates** - a stage output is an ordinary input to the next
  stage, so all four readers refuse tampered cells rather than trusting them;
* **every writer sanitizes** - defence in depth, so a writer handed a hostile
  value directly still cannot ship a formula;
* **the pair ceiling fails loudly** - never truncates;
* **nothing becomes a traceback or a forged log line** - a bad byte or a hostile
  line is one log line, never a stack trace and never a second fake one.
"""

import csv
import re
import sys

import pytest
from conftest import FORMULA_PREFIXES, assert_bare_hostnames, assert_output_invariant

from phishing_domain_detection import (
    base_domain,
    clustering,
    detect_new,
    extract_domains,
    preprocess,
    similarity,
)
from phishing_domain_detection.cli import PipelineError, raise_csv_field_limit
from phishing_domain_detection.hostname import safe_cell

#: What a real log line looks like. A rejected input line that managed to break
#: out of its own log record would show up here as a line without this prefix.
LOG_LINE = re.compile(r"^\d{2}:\d{2}:\d{2} \| (DEBUG|INFO|WARNING|ERROR)")

#: Control characters that must never survive into a log line. ``\n`` is excluded
#: because it legitimately ends a log record; the rest either repaint the terminal
#: or let a record overwrite the one before it.
UNPRINTABLE = "\r\x00\x0b\x0c\x1b\x7f"

# --------------------------------------------------------------------------
# Reader matrix.
#
# One table of tampered cells, run through every reader. The readers differ in
# which column they consume and in whether the file is CSV or a line format, so
# each payload is rendered per format and the same logical cell goes through both.
# --------------------------------------------------------------------------

#: Payloads that must reach a reader's own validator and become a PipelineError.
#: Every one of these is a string that is not a single DNS label, so a reader that
#: let it through would hand a live formula or a record forger to the next stage.
LABEL_PAYLOADS = [
    "=",
    "+",
    "-",
    "@",
    "=cmd|'/c calc'!A1",
    "+SUM(1+1)",
    "-2+3",
    "@sum(1+1)",
    '=HYPERLINK("http://evil.example","click")',
    '"quoted"',
    "a'b",
    "a(b)c",
    "a[b]c",
    "a{b}c",
    "a;b",
    "a|b",
    "a b",
    "a\tb",
    "a\rb",
    "a\x0bb",
    "a\x0cb",
    "a\x1bb",
    "a\x7fb",
    "-leading",
    "trailing-",
    "[a]",
    "a.b",
    "a.b.c",
    "   ",
]

#: filename -> (reader, template with a single {cell} placeholder)
#:
#: Only the column the reader actually consumes is templated. ``cluster_id`` in
#: base_domains.csv is a positional label and is never compared against anything,
#: so it is not part of the contract.
CSV_READERS = {
    preprocess.DEFAULT_OUTPUT: (
        preprocess.load_counts,
        "name,domain,count\n{cell},absbook.com,1\n",
    ),
    similarity.DEFAULT_OUTPUT: (
        similarity.load_pairs,
        "name1,name2,similarity\nabsbook,{cell},0.9\n",
    ),
    base_domain.DEFAULT_OUTPUT: (
        base_domain.load_base_domains,
        "cluster_id,base_domain,members\n1,{cell},absbook\n",
    ),
}


#: A payload list for clusters.txt. A CR is excluded because the file is read
#: with universal newlines, so it becomes a record separator before any validator
#: sees it; ``test_a_line_break_cannot_forge_a_cluster_record`` covers that case at
#: the writer, which is the only place it can be caught.
CLUSTER_MEMBER_PAYLOADS = [
    payload for payload in LABEL_PAYLOADS if payload != "a\rb"
]

#: A payload list for a cluster whose only member is hostile. A whitespace-only
#: value collapses the record to ``Cluster 1:`` once stripped, which is not a
#: record at all and is skipped rather than rejected.
ONLY_MEMBER_PAYLOADS = [
    payload for payload in CLUSTER_MEMBER_PAYLOADS if payload.strip()
]


def _csv_cell(value):
    """Render ``value`` as one CSV field, quoting it so a comma stays in the cell."""
    return '"' + value.replace('"', '""') + '"'


def _tampered(tmp_path, filename, template, payload):
    """Write ``template`` with ``payload`` as the interesting cell."""
    path = tmp_path / filename
    path.write_text(template.format(cell=_csv_cell(payload)), encoding="utf-8")
    return path


def _clean_domains_clean(path, name="absbook", domain="absbook.com"):
    path.write_text(f"name,domain,count\n{name},{domain},1\n", encoding="utf-8")
    return path


def _clean_pairs(path, name1="absbook", name2="casebook"):
    path.write_text(f"name1,name2,similarity\n{name1},{name2},0.9\n", encoding="utf-8")
    return path


def _clean_bases(path, base="absbook"):
    path.write_text(f"cluster_id,base_domain,members\n1,{base},absbook\n", encoding="utf-8")
    return path


def _clean_clusters(path, *members):
    path.write_text("Cluster 1: " + ", ".join(members) + "\n", encoding="utf-8")
    return path


@pytest.mark.parametrize("filename", sorted(CSV_READERS))
@pytest.mark.parametrize("payload", LABEL_PAYLOADS, ids=repr)
def test_every_csv_reader_rejects_a_tampered_name_cell(tmp_path, filename, payload):
    """A stage output is untrusted input; the reader must fail closed, not skip.

    Skipping is what makes this dangerous: a silently dropped member leaves a
    cluster that no longer matches what the file says, and that cluster becomes a
    base domain in the analyst's report.
    """
    reader, template = CSV_READERS[filename]
    with pytest.raises(PipelineError):
        reader(_tampered(tmp_path, filename, template, payload))


@pytest.mark.parametrize("payload", CLUSTER_MEMBER_PAYLOADS, ids=repr)
def test_parse_clusters_rejects_a_tampered_member(tmp_path, payload):
    """clusters.txt is a line format: the member is everything after the colon."""
    path = _clean_clusters(tmp_path / clustering.DEFAULT_OUTPUT, "absbook", payload)
    with pytest.raises(PipelineError, match="bad cluster member"):
        clustering.parse_clusters(path)


@pytest.mark.parametrize("payload", ONLY_MEMBER_PAYLOADS, ids=repr)
def test_parse_clusters_rejects_a_tampered_only_member(tmp_path, payload):
    """Not only in second position: a single hostile member is enough."""
    path = _clean_clusters(tmp_path / clustering.DEFAULT_OUTPUT, payload)
    with pytest.raises(PipelineError, match="bad cluster member"):
        clustering.parse_clusters(path)


def test_parse_clusters_skips_a_record_with_no_member_at_all(tmp_path):
    """An empty record does not match the grammar, so it is skipped, not fatal.

    Documented here because it is the one tampered shape that is *not* an error:
    ``parse_clusters`` skips what it does not understand, and
    ``base_domain.select_base_domain`` is the backstop for the empty cluster.
    """
    path = tmp_path / clustering.DEFAULT_OUTPUT
    path.write_text("Cluster 1: absbook\nCluster 2: \n", encoding="utf-8")
    assert clustering.parse_clusters(path) == [["absbook"]]


@pytest.mark.parametrize("payload", ["=cmd", "=cmd.com", "absbook\nCluster 999: x", "-x", "a b"])
def test_load_counts_rejects_a_tampered_domain_column(tmp_path, payload):
    """The name column is not a gate on the domain column; both are checked."""
    path = tmp_path / preprocess.DEFAULT_OUTPUT
    path.write_text(
        f"name,domain,count\nabsbook,{_csv_cell(payload)},1\n", encoding="utf-8"
    )
    with pytest.raises(PipelineError, match="bad domain"):
        preprocess.load_counts(path)


@pytest.mark.parametrize("payload", ["=cmd", "absbook\nCluster 999: x", "a b"])
def test_load_pairs_rejects_a_tampered_name2_column(tmp_path, payload):
    """Both name columns are validated; the first one is not a gate on the second."""
    path = tmp_path / similarity.DEFAULT_OUTPUT
    path.write_text(
        f"name1,name2,similarity\nabsbook,{_csv_cell(payload)},0.9\n", encoding="utf-8"
    )
    with pytest.raises(PipelineError, match="bad name"):
        similarity.load_pairs(path)


def test_a_reader_rejects_a_ragged_row_rather_than_guessing(tmp_path):
    """A short row leaves the cell as None, which validation then refuses."""
    path = tmp_path / similarity.DEFAULT_OUTPUT
    path.write_text("name1,name2,similarity\nabsbook\n", encoding="utf-8")
    with pytest.raises(PipelineError):
        similarity.load_pairs(path)


# --------------------------------------------------------------------------
# Newline forgery: the payload that adds a record rather than a formula.
# --------------------------------------------------------------------------

FORGED_RECORD = "Cluster 999: injected"


@pytest.mark.parametrize("filename", sorted(CSV_READERS))
@pytest.mark.parametrize("break_", ["\n", "\r\n", "\r"], ids=["lf", "crlf", "cr"])
def test_a_quoted_line_break_in_any_csv_reader_is_refused(tmp_path, filename, break_):
    """CRLF and a bare CR are the same forgery with different plumbing."""
    reader, template = CSV_READERS[filename]
    payload = f"absbook{break_}{FORGED_RECORD}"
    with pytest.raises(PipelineError):
        reader(_tampered(tmp_path, filename, template, payload))


def test_the_newline_forgery_poc_reaches_no_writer(tmp_path):
    """The forged record only exists if a newline survives to clusters.txt.

    Both defences are asserted at once, because either alone would be a single
    point of failure: the reader refuses the cell, and the writer strips the
    newline even when handed the hostile value with every reader bypassed.
    """
    hostile = f"casebook\n{FORGED_RECORD}"
    path = _tampered(
        tmp_path,
        similarity.DEFAULT_OUTPUT,
        "name1,name2,similarity\nabsbook,{cell},0.9\n",
        hostile,
    )
    with pytest.raises(PipelineError, match="bad name"):
        similarity.load_pairs(path)

    out = tmp_path / clustering.DEFAULT_OUTPUT
    clustering.write_clusters(out, [{"absbook", hostile}])
    lines = out.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1, "an injected newline must not add a record"
    assert not lines[0].startswith("Cluster 999")


@pytest.mark.parametrize("break_", ["\n", "\r"], ids=["lf", "cr"])
def test_a_line_break_cannot_forge_a_cluster_record(tmp_path, break_):
    """``parse_clusters`` cannot tell a forged record from a real one.

    A line break is a record separator once the file is read - a bare CR included,
    because every reader passes universal newlines - so nothing downstream can
    notice. The only thing standing between the two is ``safe_cell`` at the writer,
    which is asserted here directly rather than through a reader.
    """
    path = tmp_path / clustering.DEFAULT_OUTPUT
    clustering.write_clusters(path, [{f"absbook{break_}{FORGED_RECORD}"}])
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1, "the line break must not add a record"
    assert not lines[0].startswith("Cluster 999")
    # The stripped value is no longer a usable member, so the corrupted file is
    # refused outright rather than turned into a cluster an analyst would chase.
    with pytest.raises(PipelineError, match="bad cluster member"):
        clustering.parse_clusters(path)


# --------------------------------------------------------------------------
# NUL bytes.
#
# A NUL inside a CSV field is rejected by the stdlib reader itself with csv.Error,
# which cli.run_step turns into one log line. The contract is the same either way:
# the reader refuses the data. For clusters.txt there is no stdlib reader in the
# way, so the module's own validator has to catch it.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("filename", sorted(CSV_READERS))
def test_every_csv_reader_refuses_a_nul_byte(tmp_path, filename):
    reader, template = CSV_READERS[filename]
    path = _tampered(tmp_path, filename, template, "goo\x00gle")
    with pytest.raises((PipelineError, csv.Error)):
        reader(path)


def test_parse_clusters_refuses_a_nul_byte_in_a_member(tmp_path):
    path = tmp_path / clustering.DEFAULT_OUTPUT
    path.write_bytes(b"Cluster 1: goo\x00gle\n")
    with pytest.raises(PipelineError, match="bad cluster member"):
        clustering.parse_clusters(path)


def test_a_nul_byte_becomes_one_readable_line_through_the_cli(tmp_path, capsys):
    """csv.Error is turned into an exit code, not a stack trace."""
    (tmp_path / similarity.DEFAULT_OUTPUT).write_bytes(
        b"name1,name2,similarity\ngoo\x00gle,absbook,0.9\n"
    )
    assert clustering.main(["--data-dir", str(tmp_path)]) == 1
    err = capsys.readouterr().err
    assert "Malformed CSV" in err
    assert "Traceback" not in err


# --------------------------------------------------------------------------
# Writers: defence in depth.
#
# Readers validate and writers sanitize, and these tests call the writers with a
# hand-built hostile value so that the second defence is exercised on its own,
# with every reader bypassed.
# --------------------------------------------------------------------------

HOSTILE_VALUES = [
    "=cmd|'/c calc'!A1",
    "+SUM(1+1)",
    "-legit-name",
    "@handle",
    "absbook\nCluster 999: injected",
    "absbook\rCluster 999: injected",
    "goo\x00gle",
    "\x1b[31mabsbook",
    "\x1b[2J\x1b[H",
    "absbook\x7f",
]


@pytest.mark.parametrize("value", HOSTILE_VALUES, ids=repr)
def test_save_counts_neutralizes_a_hostile_name(tmp_path, value):
    path = tmp_path / preprocess.DEFAULT_OUTPUT
    preprocess.save_counts(path, {value: preprocess.DomainCount(domain=value, count=1)})
    assert_output_invariant(path)


@pytest.mark.parametrize("value", HOSTILE_VALUES, ids=repr)
def test_save_pairs_neutralizes_a_hostile_name(tmp_path, value):
    path = tmp_path / similarity.DEFAULT_OUTPUT
    similarity.save_pairs(path, [(value, value, 0.9)])
    assert_output_invariant(path)


@pytest.mark.parametrize("value", HOSTILE_VALUES, ids=repr)
def test_write_clusters_neutralizes_a_hostile_member(tmp_path, value):
    path = tmp_path / clustering.DEFAULT_OUTPUT
    clustering.write_clusters(path, [{value, "absbook"}])
    assert_output_invariant(path)
    assert len(path.read_text(encoding="utf-8").splitlines()) == 1


@pytest.mark.parametrize("value", HOSTILE_VALUES, ids=repr)
def test_save_base_domains_neutralizes_a_hostile_name(tmp_path, value):
    path = tmp_path / base_domain.DEFAULT_OUTPUT
    base_domain.save_base_domains(path, [(value, [value, "absbook"])])
    assert_output_invariant(path)


@pytest.mark.parametrize("value", HOSTILE_VALUES, ids=repr)
def test_save_suspects_neutralizes_a_hostile_domain(tmp_path, value):
    path = tmp_path / detect_new.DEFAULT_OUTPUT
    detect_new.save_suspects(path, [(value, value, 0.9)])
    assert_output_invariant(path)


@pytest.mark.parametrize("value", HOSTILE_VALUES, ids=repr)
def test_save_domains_neutralises_hostile_values(tmp_path, value):
    """Step 1's writer sanitizes too, so domains_raw.txt is inert as a file.

    This one used to be a pass-through, which made ``domains_raw.txt`` the only
    output a hostile value could reach unquoted. It is also a committed artefact
    under ``data/``, so the file - not just the run that produced it - has to be
    safe to open.

    ``read_bytes`` rather than ``read_text``: universal newlines would translate a
    CR and hide the very case under test.
    """
    path = tmp_path / extract_domains.DEFAULT_OUTPUT
    extract_domains.save_domains(path, {value})

    assert path.read_bytes().decode("utf-8") == f"{safe_cell(value)}\n"
    assert len(path.read_text(encoding="utf-8").splitlines()) == 1, (
        "a newline must not survive to open a second line"
    )
    assert_output_invariant(path)


@pytest.mark.parametrize("prefix", FORMULA_PREFIXES)
def test_save_domains_quotes_a_dangerous_prefix(tmp_path, prefix):
    """Quoting is the whole defence: it is inside the cell, not around it."""
    path = tmp_path / extract_domains.DEFAULT_OUTPUT
    extract_domains.save_domains(path, {f"{prefix}cmd|'/c calc'!A1"})

    line = path.read_text(encoding="utf-8").rstrip("\n")
    assert line == f"'{prefix}cmd|'/c calc'!A1"
    assert not line.startswith(prefix)


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("goo\x00gle", "google"),
        ("\x1b[31mabsbook", "[31mabsbook"),
        ("\x1b[2J\x1b[H", "[2J[H"),
        ("absbook\x7f", "absbook"),
        ("absbook\rCluster 999: x", "absbookCluster 999: x"),
    ],
    ids=repr,
)
def test_save_domains_strips_control_characters(tmp_path, raw, expected):
    """A stripped byte must leave the text behind, not the whole domain."""
    path = tmp_path / extract_domains.DEFAULT_OUTPUT
    extract_domains.save_domains(path, {raw})

    assert path.read_text(encoding="utf-8") == f"{expected}\n"
    assert_output_invariant(path)


@pytest.mark.parametrize(
    "domain", ["absbook.com", "shop.com.au", "a-b.example.org", "xn--80ak6aa92e.com"]
)
def test_save_domains_writes_a_valid_domain_verbatim(tmp_path, domain):
    """Sanitizing must not touch ordinary input: no quoting, no case change."""
    path = tmp_path / extract_domains.DEFAULT_OUTPUT
    extract_domains.save_domains(path, {domain})

    assert path.read_text(encoding="utf-8") == f"{domain}\n"
    assert_bare_hostnames(path)


def test_save_domains_sorts_and_dedupes_without_reordering_the_set(tmp_path):
    """The writer's other job, unchanged by sanitizing."""
    path = tmp_path / extract_domains.DEFAULT_OUTPUT
    extract_domains.save_domains(path, {"shop.com.au", "absbook.com", "casebook.com"})

    assert path.read_text(encoding="utf-8") == (
        "absbook.com\ncasebook.com\nshop.com.au\n"
    )


def test_the_pipeline_never_reaches_save_domains_with_a_hostile_domain():
    """The reader in front of it is validated, so the real pipeline is unaffected."""
    records = [
        {"name_value": "=1+1.com"},
        {"name_value": "@sum(1+1).x"},
        {"name_value": "-2+3.com"},
        {"name_value": "absbook.com"},
    ]
    assert extract_domains.extract_domains(records) == {"absbook.com"}


# --------------------------------------------------------------------------
# The pair ceiling.
# --------------------------------------------------------------------------

# Eight mutually-similar names: 8 * 7 / 2 = 28 unordered pairs, every one of them
# above the threshold. Small enough to stay fast, large enough to sit on both
# sides of a small ceiling.
CROWDED_NAMES = [f"aaaa{i:03d}" for i in range(8)]
ALL_PAIRS = len(CROWDED_NAMES) * (len(CROWDED_NAMES) - 1) // 2


def _crowded_csv(path):
    path.write_text(
        "name,domain,count\n" + "".join(f"{name},{name}.com,1\n" for name in CROWDED_NAMES),
        encoding="utf-8",
    )
    return path


def test_the_fixture_really_produces_every_pair():
    """Guards the ceiling tests against a ceiling that is never approached."""
    assert len(similarity.find_similar_pairs(CROWDED_NAMES, 0.5)) == ALL_PAIRS


def test_exceeding_the_ceiling_is_loud():
    with pytest.raises(PipelineError, match="more than 3 similar pairs"):
        similarity.find_similar_pairs(CROWDED_NAMES, 0.5, 3)


def test_the_ceiling_names_the_flag_and_the_way_out():
    with pytest.raises(PipelineError) as excinfo:
        similarity.find_similar_pairs(CROWDED_NAMES, 0.5, 3)
    assert "--max-pairs" in str(excinfo.value)


def test_exactly_the_ceiling_is_allowed():
    """The ceiling is a maximum, not an off-by-one that rejects a legal run."""
    assert len(similarity.find_similar_pairs(CROWDED_NAMES, 0.5, ALL_PAIRS)) == ALL_PAIRS


def test_the_default_ceiling_is_the_documented_one():
    assert similarity.MAX_PAIRS == 1_000_000


def test_the_default_ceiling_leaves_a_normal_dataset_alone():
    """A realistic dataset is nowhere near the ceiling, so nothing changes for it."""
    names = ["absbook", "casebook", "tiffany", "bank", "shop"]
    assert similarity.find_similar_pairs(names) == similarity.find_similar_pairs(
        names, 0.8, similarity.MAX_PAIRS
    )


def test_raising_the_ceiling_returns_the_same_pairs():
    """Raising the ceiling must change only whether the run is allowed, not the result."""
    raised = similarity.find_similar_pairs(CROWDED_NAMES, 0.5, ALL_PAIRS)
    with pytest.raises(PipelineError):
        similarity.find_similar_pairs(CROWDED_NAMES, 0.5, 3)
    assert len(raised) == ALL_PAIRS


def test_the_run_fails_instead_of_writing_a_truncated_file(tmp_path, capsys):
    """The dangerous outcome is a partial report an analyst trusts."""
    _crowded_csv(tmp_path / preprocess.DEFAULT_OUTPUT)
    assert similarity.main(["--data-dir", str(tmp_path), "--max-pairs", "3"]) == 1
    err = capsys.readouterr().err
    assert "more than 3 similar pairs" in err
    assert not (tmp_path / similarity.DEFAULT_OUTPUT).exists()


def test_the_max_pairs_flag_raises_the_ceiling(tmp_path):
    _crowded_csv(tmp_path / preprocess.DEFAULT_OUTPUT)
    assert similarity.main(["--data-dir", str(tmp_path), "--max-pairs", str(ALL_PAIRS)]) == 0
    assert len(similarity.load_pairs(tmp_path / similarity.DEFAULT_OUTPUT)) == ALL_PAIRS


def test_the_max_pairs_flag_defaults_to_the_module_ceiling(tmp_path):
    _crowded_csv(tmp_path / preprocess.DEFAULT_OUTPUT)
    assert similarity.main(["--data-dir", str(tmp_path)]) == 0
    assert len(similarity.load_pairs(tmp_path / similarity.DEFAULT_OUTPUT)) == ALL_PAIRS


def test_a_single_name_never_compares_anything_so_the_ceiling_is_irrelevant():
    assert similarity.find_similar_pairs(["absbook"], 0.5, 0) == []


# --------------------------------------------------------------------------
# The empty cluster.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "members",
    [
        [],
        [""],
        ["", ""],
        # Whitespace-only used to slip through the `if member` filter, because a
        # blank string is falsy but `"  "` is not - and `min` then happily
        # returned it, writing a whitespace-only base_domain cell.
        ["   "],
        ["\t"],
        ["\n"],
        ["", "   "],
        ["  ", "  "],
    ],
)
def test_an_empty_cluster_cannot_produce_a_base_domain(members):
    """An empty base_domain cell would be an unmatchable, unauditable report row.

    A whitespace-only member counts as empty: it is truthy, so filtering on
    truthiness alone is not enough, and a report row keyed on `"  "` can never be
    matched by a domain coming out of ``normalize``.
    """
    with pytest.raises(PipelineError, match="empty cluster"):
        base_domain.select_base_domain(members, {})


def test_an_empty_cluster_fails_the_selection_not_the_run():
    """Every cluster is selected before any row is written, so none is written."""
    with pytest.raises(PipelineError, match="empty cluster"):
        base_domain.select_base_domains([["absbook"], []], {})


@pytest.mark.parametrize("blank", ["", "  ", "\t", "\n", "   "])
def test_a_blank_member_is_never_selected_over_a_usable_one(blank):
    """The blank is skipped, not merely outvoted by a longer name."""
    assert base_domain.select_base_domain(["absbook", blank], {}) == "absbook"


def test_an_empty_cluster_writes_no_file(tmp_path):
    clustering.write_clusters(tmp_path / clustering.DEFAULT_OUTPUT, [{"absbook"}, set()])
    _clean_domains_clean(tmp_path / preprocess.DEFAULT_OUTPUT)
    assert base_domain.main(["--data-dir", str(tmp_path)]) == 0
    assert_output_invariant(tmp_path / base_domain.DEFAULT_OUTPUT)


# --------------------------------------------------------------------------
# Log hygiene.
#
# The rejected lines are attacker-controlled text printed to the operator's
# terminal. Raw, they could forge or wipe out log lines.
# --------------------------------------------------------------------------


def _seed_list_run(tmp_path, lines):
    """Run step 6 over a seed list of ``lines``; return its exit code."""
    _clean_bases(tmp_path / base_domain.DEFAULT_OUTPUT)
    (tmp_path / detect_new.DEFAULT_NEW).write_text("".join(f"{line}\n" for line in lines))
    return detect_new.main(["--data-dir", str(tmp_path)])


def _log_lines(captured):
    return captured.splitlines()


def test_a_rejected_line_cannot_repaint_the_terminal(tmp_path, capsys):
    """ANSI escapes are how a log line clears the screen or hides what it said."""
    assert _seed_list_run(tmp_path, ["\x1b[2J\x1b[1;31mabsbook\x1b[0m", "junk"]) == 0
    err = capsys.readouterr().err
    assert "\x1b" not in err, "a raw escape byte reached the terminal"
    assert "\\x1b" in err, "the rejected line must still be shown, escaped"


def test_a_rejected_line_cannot_forge_a_second_log_record(tmp_path, capsys):
    """Every captured line must still be a log record the logger wrote.

    A rejected input line that broke out of its own record would show up here as a
    line with no timestamp, which is exactly what ``12:00:00 | INFO | all clear``
    is trying to become.
    """
    assert _seed_list_run(tmp_path, ["12:00:00 | INFO | all clear", "junk"]) == 0
    lines = _log_lines(capsys.readouterr().err)
    forged = [line for line in lines if not LOG_LINE.match(line)]
    assert forged == [], f"input text reached the log as its own record: {forged}"


def test_a_carriage_return_cannot_overwrite_a_log_line(tmp_path, capsys):
    """CR is neutralised twice over: newline translation and ``repr`` escaping."""
    assert _seed_list_run(tmp_path, ["junk\r00:00:00 | INFO | all clear"]) == 0
    err = capsys.readouterr().err
    assert "\r" not in err, "a raw carriage return can overwrite the line before it"
    assert all(LOG_LINE.match(line) for line in _log_lines(err))


@pytest.mark.parametrize("char", ["\n", "\r", "\x00", "\x0b", "\x0c", "\x1b", "\x7f"])
def test_no_unprintable_byte_reaches_the_log(tmp_path, capsys, char):
    assert _seed_list_run(tmp_path, [f"absbook{char}injected", "junk"]) == 0
    captured = capsys.readouterr().err
    for raw in UNPRINTABLE:
        assert raw not in captured
    assert all(LOG_LINE.match(line) for line in _log_lines(captured))


def test_an_extremely_long_rejected_line_is_truncated(tmp_path, capsys):
    """Half a megabyte of junk must not become half a megabyte of scrollback."""
    assert _seed_list_run(tmp_path, ["x" * 500_000, "junk"]) == 0
    err = capsys.readouterr().err
    assert "xxxx" in err
    assert len(err) < 2000
    assert "xxxxx..." in err, "the truncated rendering must be marked as such"


def test_only_the_first_few_rejected_lines_are_shown(tmp_path, capsys):
    """Five shown, the rest counted: a long bad list stays one readable line."""
    assert _seed_list_run(tmp_path, [f"bad{i:04d}" for i in range(50)]) == 0
    err = capsys.readouterr().err
    assert "Ignored 50 line(s)" in err
    assert "bad0004" in err
    assert "bad0005" not in err


def test_the_rejected_line_is_shown_quoted(tmp_path, capsys):
    assert _seed_list_run(tmp_path, ["=cmd|'/c calc'!A1"]) == 0
    assert repr("=cmd|'/c calc'!A1") in capsys.readouterr().err


def test_short_repr_caps_its_output():
    assert len(detect_new._short_repr("x" * 100_000)) == detect_new._REJECT_REPR_WIDTH
    assert detect_new._short_repr("x" * 100_000).endswith("...")


def test_short_repr_leaves_a_short_line_alone():
    assert detect_new._short_repr("junk") == "'junk'"


def test_a_healthy_run_warns_about_nothing(tmp_path, capsys):
    """The guard against a warning that fires on every ordinary run."""
    assert _seed_list_run(tmp_path, ["absbok.com"]) == 0
    assert "Ignored" not in capsys.readouterr().err


# --------------------------------------------------------------------------
# Robustness: a byte that is not UTF-8.
#
# Every reader passes errors="replace", so the outcome differs by stage: the stages
# that validate report one readable error line, the ones that scan bulk text skip
# the line and carry on. Neither may raise, and neither may traceback.
# --------------------------------------------------------------------------

BAD_BYTE = b"\xff\xfe"

STAGE_INPUTS = [
    pytest.param(
        extract_domains,
        extract_domains.DEFAULT_INPUT,
        b'[{"name_value": "absbook.com"' + BAD_BYTE + b'}]',
        id="extract_domains",
    ),
    pytest.param(
        preprocess,
        preprocess.DEFAULT_INPUT,
        b"absbook.com\n" + BAD_BYTE + b"\n",
        id="preprocess",
    ),
    pytest.param(
        similarity,
        preprocess.DEFAULT_OUTPUT,
        b"name,domain,count\n" + BAD_BYTE + b",absbook.com,1\n",
        id="similarity",
    ),
    pytest.param(
        clustering,
        similarity.DEFAULT_OUTPUT,
        b"name1,name2,similarity\n" + BAD_BYTE + b",absbook,0.9\n",
        id="clustering",
    ),
    pytest.param(
        base_domain,
        clustering.DEFAULT_OUTPUT,
        b"Cluster 1: " + BAD_BYTE + b"\n",
        id="base_domain",
    ),
    pytest.param(
        detect_new,
        detect_new.DEFAULT_NEW,
        b"absbok.com\n" + BAD_BYTE + b"\n",
        id="detect_new",
    ),
]

#: The stages that validate every cell, so a bad byte fails the run.
FAILING_STAGES = [
    row for row in STAGE_INPUTS if row.values[0] in (similarity, clustering, base_domain)
]
#: The stages that scan bulk text, so a bad byte is one skipped line.
SKIPPING_STAGES = [
    row for row in STAGE_INPUTS if row.values[0] in (preprocess, detect_new)
]


def _run_stage(tmp_path, module, filename, payload):
    """Stage ``module`` over an input containing a bad byte; return its exit code."""
    (tmp_path / filename).write_bytes(payload)
    if module is base_domain:
        _clean_domains_clean(tmp_path / preprocess.DEFAULT_OUTPUT)
    if module is detect_new:
        _clean_bases(tmp_path / base_domain.DEFAULT_OUTPUT)
    return module.main(["--data-dir", str(tmp_path)])


@pytest.mark.parametrize(("module", "filename", "payload"), STAGE_INPUTS)
def test_a_bad_byte_never_becomes_a_traceback(tmp_path, capsys, module, filename, payload):
    """The property every stage shares, whichever way it reports the problem."""
    assert _run_stage(tmp_path, module, filename, payload) in (0, 1)
    err = capsys.readouterr().err
    assert "Traceback" not in err
    assert all(LOG_LINE.match(line) for line in _log_lines(err))


@pytest.mark.parametrize(("module", "filename", "payload"), FAILING_STAGES)
def test_a_bad_byte_is_one_readable_error_line(tmp_path, capsys, module, filename, payload):
    """The validating stages fail closed, naming the cell in a single line."""
    assert _run_stage(tmp_path, module, filename, payload) == 1
    err = capsys.readouterr().err
    assert "bad " in err
    errors = [line for line in _log_lines(err) if " | ERROR" in line]
    assert len(errors) == 1, errors


@pytest.mark.parametrize(("module", "filename", "payload"), SKIPPING_STAGES)
def test_a_bad_byte_is_one_skipped_line_in_the_scanning_stage(
    tmp_path, capsys, module, filename, payload
):
    """The scanning stages drop the line and finish the run."""
    assert _run_stage(tmp_path, module, filename, payload) == 0
    captured = capsys.readouterr()
    assert "Traceback" not in captured.err
    assert "Skipped 1 line(s)" in captured.err or "Ignored 1 line(s)" in captured.err


def test_a_bad_byte_never_reaches_an_output_cell(tmp_path, capsys):
    """The replacement character is a U+FFFD; it must not end up in a report."""
    assert _seed_list_run(tmp_path, ["absbok.com"]) == 0
    report = (tmp_path / detect_new.DEFAULT_OUTPUT).read_text(encoding="utf-8")
    assert "�" not in report
    assert_output_invariant(tmp_path / detect_new.DEFAULT_OUTPUT)


def test_a_bad_byte_in_the_ct_dump_is_a_readable_error(tmp_path, capsys):
    """JSON has no room for a replacement character; the stage says so in one line."""
    assert _run_stage(
        tmp_path,
        extract_domains,
        extract_domains.DEFAULT_INPUT,
        b'[{"name_value": "absbook.com"' + BAD_BYTE + b'}]',
    ) == 1
    err = capsys.readouterr().err
    assert "invalid JSON" in err
    assert "Traceback" not in err
    errors = [line for line in _log_lines(err) if " | ERROR" in line]
    assert len(errors) == 1, errors


# --------------------------------------------------------------------------
# cli.raise_csv_field_limit.
# --------------------------------------------------------------------------


def test_raise_csv_field_limit_lifts_the_stdlib_default():
    """128 KiB is reachable by one long scraped line, and would abort a whole run."""
    original = csv.field_size_limit()
    try:
        csv.field_size_limit(131_072)
        raise_csv_field_limit()
        assert csv.field_size_limit() > 131_072
        assert csv.field_size_limit() >= sys.maxsize // 10
    finally:
        csv.field_size_limit(original)


def test_raise_csv_field_limit_backs_off_when_the_limit_overflows(monkeypatch):
    """csv.field_size_limit rejects an int above C long; the helper must retry."""
    real = csv.field_size_limit
    attempts = []

    def limited(value):
        attempts.append(value)
        if value > sys.maxsize // 1000:
            raise OverflowError("Python int too large to convert to C long")
        return real(value)

    monkeypatch.setattr(csv, "field_size_limit", limited)
    raise_csv_field_limit()
    assert attempts[0] == sys.maxsize
    assert len(attempts) > 1, "the helper gave up instead of backing off"
    assert real() > 131_072


def test_a_field_larger_than_the_stdlib_default_can_be_read(tmp_path):
    """The behaviour the helper exists for: one long cell, not a failed run."""
    original = csv.field_size_limit()
    long_label = "a" * 200_000
    path = tmp_path / preprocess.DEFAULT_OUTPUT
    path.write_text(f"name,domain,count\n{long_label},absbook.com,1\n", encoding="utf-8")
    try:
        csv.field_size_limit(131_072)
        with pytest.raises(csv.Error, match="field larger than field limit"):
            preprocess.load_counts(path)
        raise_csv_field_limit()
        counts = preprocess.load_counts(path)
    finally:
        csv.field_size_limit(original)
    assert long_label in counts
