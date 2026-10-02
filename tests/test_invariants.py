"""End-to-end checks that a run never ships a formula or a forged record.

Two things live here. First, self-tests for the invariant helpers in
``conftest``: a check that cannot fail is worse than no check, because it looks
like coverage. Second, the end-to-end runs that feed hostile data into the real
stages and then assert the output invariant over every generated file.
"""

import json

import pytest
from conftest import OUTPUT_FILES, assert_bare_hostnames, assert_output_invariant

from phishing_domain_detection import (
    base_domain,
    clustering,
    detect_new,
    pipeline,
    preprocess,
    similarity,
)

# Records that produce a handful of real clusters, so a run has something to
# detect rather than an empty report.
RECORDS = [
    {"name_value": "absbook.com\nabsbook.net\ncasebook.com"},
    {"name_value": "bank.com.au\nshop.com.au"},
    {"name_value": "www.tiffany.com"},
]


def _outputs(data_dir):
    """Return the subset of the declared outputs that the run actually wrote."""
    return [name for name in OUTPUT_FILES if (data_dir / name).exists()]


# --------------------------------------------------------------------------
# Self-tests for the invariant helper itself.
# --------------------------------------------------------------------------


def test_the_invariant_accepts_a_clean_csv(tmp_path):
    path = tmp_path / "domains_clean.csv"
    path.write_text("name,domain,count\nabsbook,absbook.com,2\n", encoding="utf-8")
    assert_output_invariant(path)


@pytest.mark.parametrize("prefix", ["=", "+", "-", "@"])
def test_the_invariant_catches_a_formula_cell(tmp_path, prefix):
    path = tmp_path / "suspect_domains.csv"
    path.write_text(
        f"new_domain,matched_base,similarity\n{prefix}cmd,absbook,0.9\n", encoding="utf-8"
    )
    with pytest.raises(AssertionError, match="starts a spreadsheet formula"):
        assert_output_invariant(path)


def test_the_invariant_catches_a_quoted_cell_that_forges_a_record(tmp_path):
    """The quoted newline is the mechanism; the row count exposes the result."""
    path = tmp_path / "similar_pairs.csv"
    path.write_text(
        'name1,name2,similarity\nabsbook,"casebook\nabsbook,forged",0.9\n',
        encoding="utf-8",
    )
    with pytest.raises(AssertionError, match="spans lines"):
        assert_output_invariant(path)


def test_the_invariant_catches_a_ragged_csv(tmp_path):
    path = tmp_path / "similar_pairs.csv"
    path.write_text("name1,name2,similarity\nabsbook\n", encoding="utf-8")
    with pytest.raises(AssertionError, match="expected 3"):
        assert_output_invariant(path)


def test_the_invariant_catches_a_control_character(tmp_path):
    path = tmp_path / "suspect_domains.csv"
    path.write_text("new_domain,matched_base,similarity\na\x00b,absbook,0.9\n", encoding="utf-8")
    with pytest.raises(AssertionError, match="control character"):
        assert_output_invariant(path)


def test_the_invariant_catches_a_forged_cluster_record(tmp_path):
    """This is the newline-forgery PoC, laid out by hand.

    ``Cluster 999`` after ``Cluster 1`` is exactly what one injected newline
    produces, and the non-contiguous index is what gives it away: a real run
    numbers its clusters 1..N.
    """
    path = tmp_path / "clusters.txt"
    path.write_text("Cluster 1: a\nCluster 999: injected\n", encoding="utf-8")
    with pytest.raises(AssertionError, match="not contiguous"):
        assert_output_invariant(path)


def test_the_invariant_catches_a_line_that_is_not_a_cluster_record(tmp_path):
    path = tmp_path / "clusters.txt"
    path.write_text("Cluster 1: a\nabsbook, casebook\n", encoding="utf-8")
    with pytest.raises(AssertionError, match="is not a cluster record"):
        assert_output_invariant(path)


def test_the_invariant_catches_a_forged_line_in_the_raw_domain_list(tmp_path):
    path = tmp_path / "domains_raw.txt"
    path.write_text("absbook.com\n=1+1.com\n", encoding="utf-8")
    with pytest.raises(AssertionError, match="starts a spreadsheet formula"):
        assert_output_invariant(path)


def test_the_invariant_catches_a_control_character_in_the_raw_domain_list(tmp_path):
    """domains_raw.txt gets the same sweep as the other five outputs.

    The sweep is deliberately weaker than ``assert_bare_hostnames``: it asserts
    what a *writer* owes, which is only that the file cannot act on whoever opens
    it. Whether a line is a hostname is the reader's job, and
    ``safe_cell`` leaves the space in ``'=cmd|'/c calc'!A1`` alone, so screening
    for it here would fail the writer for the reader's mistake.
    """
    path = tmp_path / "domains_raw.txt"
    path.write_text("absbook.com\nescape\x1b[31m.com\n", encoding="utf-8")
    with pytest.raises(AssertionError, match="control character"):
        assert_output_invariant(path)


def test_the_invariant_accepts_a_sanitized_value_that_is_not_a_hostname(tmp_path):
    """The boundary, pinned: inert is enough, valid is not the writer's promise."""
    path = tmp_path / "domains_raw.txt"
    path.write_text("'=cmd|'/c calc'!A1\n", encoding="utf-8")
    assert_output_invariant(path)

    with pytest.raises(AssertionError, match="more than one token"):
        assert_bare_hostnames(path)


def test_the_invariant_rejects_a_file_it_has_no_rule_for(tmp_path):
    """Silently skipping an unknown file would let a new output escape the check."""
    path = tmp_path / "notes.md"
    path.write_text("=1+1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="no invariant defined"):
        assert_output_invariant(path)


def test_the_data_dir_check_visits_every_declared_output(tmp_path, check_outputs):
    """Every name in OUTPUT_FILES must be reachable by the data-dir check."""
    clean = {
        "domains_raw.txt": "absbook.com\n",
        "domains_clean.csv": "name,domain,count\nabsbook,absbook.com,2\n",
        "similar_pairs.csv": "name1,name2,similarity\nabsbook,casebook,0.9\n",
        "clusters.txt": "Cluster 1: absbook, casebook\n",
        "base_domains.csv": "cluster_id,base_domain,members\n1,absbook,absbook|casebook\n",
        "suspect_domains.csv": "new_domain,matched_base,similarity\nabsbok.com,absbook,0.92\n",
    }
    for name in OUTPUT_FILES:
        (tmp_path / name).write_text(clean[name], encoding="utf-8")
    check_outputs(tmp_path)

    for name in OUTPUT_FILES:
        (tmp_path / name).write_text(f"{clean[name]}=cmd\n", encoding="utf-8")
        with pytest.raises(AssertionError):
            check_outputs(tmp_path)


def test_the_data_dir_check_passes_when_nothing_was_written(tmp_path, check_outputs):
    """An aborted run leaves nothing behind, and nothing to complain about."""
    check_outputs(tmp_path)
    assert _outputs(tmp_path) == []


# --------------------------------------------------------------------------
# End-to-end: a clean run satisfies the invariant.
# --------------------------------------------------------------------------


def test_a_clean_run_satisfies_the_output_invariant(tmp_path, check_outputs):
    (tmp_path / "crtsh_raw.json").write_text(json.dumps(RECORDS), encoding="utf-8")
    (tmp_path / detect_new.DEFAULT_NEW).write_text("absbok.com\n=1+1.com\n", encoding="utf-8")

    assert pipeline.main(["--data-dir", str(tmp_path)]) == 0

    assert _outputs(tmp_path) == list(OUTPUT_FILES)
    check_outputs(tmp_path)


# --------------------------------------------------------------------------
# End-to-end: a tampered input stops the run before any report exists.
#
# The tampered file is planted in its own directory and passed with --input, so
# that the data directory holds only what the run generated. Otherwise the planted
# file would be scanned by the invariant and fail it for the very thing under test.
# --------------------------------------------------------------------------


def _split_dirs(tmp_path):
    """Return ``(data_dir, attacker_dir)``, both empty and created."""
    data = tmp_path / "run"
    attacker = tmp_path / "synced-from-elsewhere"
    data.mkdir()
    attacker.mkdir()
    return data, attacker


def _chain(data_dir, domains_csv):
    """Run steps 3-6 over ``domains_csv``, stopping at the first failure.

    ``domains_clean.csv`` is step 2's output, so the chain starts at step 3 and
    takes the file with ``--input``/``--domains``: the tampered file has to be fed
    in as a plain input rather than regenerated. Step 5 reads it a second time for
    the label frequencies, so it gets ``--domains`` too. Returns the exit code of
    each step, so a test can assert that every later step also refused.
    """
    return [
        similarity.main(["--data-dir", str(data_dir), "--input", str(domains_csv)]),
        clustering.main(["--data-dir", str(data_dir)]),
        base_domain.main(["--data-dir", str(data_dir), "--domains", str(domains_csv)]),
        detect_new.main(["--data-dir", str(data_dir)]),
    ]


def test_a_tampered_domains_clean_csv_stops_the_run_before_a_report(tmp_path, check_outputs):
    """A stage output is an ordinary input, so step 3 must not trust it."""
    data, attacker = _split_dirs(tmp_path)
    (attacker / preprocess.DEFAULT_OUTPUT).write_text(
        "name,domain,count\n=cmd|'/c calc'!A1,evil.com,1\nabsbook,absbook.com,2\n",
        encoding="utf-8",
    )
    (data / detect_new.DEFAULT_NEW).write_text("absbok.com\n", encoding="utf-8")

    codes = _chain(data, attacker / preprocess.DEFAULT_OUTPUT)

    assert codes[0] == 1
    assert codes[1:] == [1, 1, 1], "every later step must refuse the missing input too"
    assert _outputs(data) == [], "the run must not write a single output file"
    check_outputs(data)


def test_the_tampered_run_names_the_offending_cell(tmp_path, capsys):
    data, attacker = _split_dirs(tmp_path)
    synced = attacker / preprocess.DEFAULT_OUTPUT
    synced.write_text("name,domain,count\n=cmd,evil.com,1\n", encoding="utf-8")
    code = similarity.main(["--data-dir", str(data), "--input", str(synced)])
    assert code == 1
    err = capsys.readouterr().err
    assert "bad name" in err
    assert "=cmd" in err
    assert "Traceback" not in err


def test_a_clean_domains_clean_csv_reaches_the_report(tmp_path, check_outputs):
    """The positive control: the same chain succeeds and the invariant holds."""
    data, attacker = _split_dirs(tmp_path)
    (attacker / preprocess.DEFAULT_OUTPUT).write_text(
        "name,domain,count\nabsbook,absbook.com,2\ncasebook,casebook.com,1\n", encoding="utf-8"
    )
    (data / detect_new.DEFAULT_NEW).write_text("absbok.com\n", encoding="utf-8")

    assert _chain(data, attacker / preprocess.DEFAULT_OUTPUT) == [0, 0, 0, 0]

    assert _outputs(data) == [
        "similar_pairs.csv",
        "clusters.txt",
        "base_domains.csv",
        "suspect_domains.csv",
    ]
    check_outputs(data)
    assert "absbok.com" in (data / detect_new.DEFAULT_OUTPUT).read_text(encoding="utf-8")


def test_a_tampered_base_domains_csv_stops_the_final_step(tmp_path, capsys, check_outputs):
    """Step 6 compares new registrations against this file; it must validate it."""
    data, attacker = _split_dirs(tmp_path)
    synced = attacker / base_domain.DEFAULT_OUTPUT
    synced.write_text(
        "cluster_id,base_domain,members\n1,absbook,absbook\n2,=cmd|'/c calc'!A1\n",
        encoding="utf-8",
    )
    (data / detect_new.DEFAULT_NEW).write_text("absbok.com\n", encoding="utf-8")

    code = detect_new.main(["--data-dir", str(data), "--bases", str(synced)])

    assert code == 1
    assert "bad base_domain" in capsys.readouterr().err
    assert _outputs(data) == [], "no report may be produced"
    check_outputs(data)


def test_a_tampered_clusters_txt_stops_the_base_domain_step(tmp_path, capsys, check_outputs):
    """Step 5 turns every cluster into a base domain, so it must validate members."""
    data, attacker = _split_dirs(tmp_path)
    synced = attacker / clustering.DEFAULT_OUTPUT
    synced.write_text(
        "Cluster 1: absbook\nCluster 2: =cmd|'/c calc'!A1\n", encoding="utf-8"
    )
    (data / preprocess.DEFAULT_OUTPUT).write_text(
        "name,domain,count\nabsbook,absbook.com,2\n", encoding="utf-8"
    )

    code = base_domain.main(["--data-dir", str(data), "--clusters", str(synced)])

    assert code == 1
    assert "bad cluster member" in capsys.readouterr().err
    assert not (data / base_domain.DEFAULT_OUTPUT).exists()
    check_outputs(data)


def test_a_forged_cluster_record_is_rejected_by_the_invariant(tmp_path):
    """The invariant, not the writer, is the backstop: forge one by hand.

    ``write_clusters`` is not called here. This is the file an attacker would
    produce if the sanitizer were ever removed, so the check has to notice it. The
    reader side of the same attack is in ``test_security.py``.
    """
    path = tmp_path / clustering.DEFAULT_OUTPUT
    path.write_text("Cluster 1: absbook\nCluster 999: injected\n", encoding="utf-8")
    with pytest.raises(AssertionError, match="not contiguous"):
        assert_output_invariant(path)
