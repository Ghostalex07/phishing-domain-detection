import json

import pytest
from conftest import OUTPUT_FILES, assert_bare_hostnames

from phishing_domain_detection import (
    base_domain,
    clustering,
    detect_new,
    extract_domains,
    pipeline,
    preprocess,
    similarity,
)
from phishing_domain_detection.cli import PipelineError

RECORDS = [
    {"name_value": "www.tiffany.com"},
    {"name_value": "*.bank.com.au"},
    {"name_value": "go to https://evil.test/path\nshop.com.au"},
    {"name_value": "absbook.com\nabsbook.net\ncasebook.com"},
    {"name_value": "=1+1.com\nnoise, prose and URLs"},
    {"name_value": ""},
    {},
    "not even a dict",
]


@pytest.fixture
def data_dir(tmp_path):
    (tmp_path / "crtsh_raw.json").write_text(json.dumps(RECORDS), encoding="utf-8")
    return tmp_path


def test_run_pipeline_writes_every_output_file(data_dir):
    pipeline.run_pipeline(data_dir)
    for module in (extract_domains, preprocess, similarity, clustering, base_domain, detect_new):
        assert (data_dir / module.DEFAULT_OUTPUT).is_file()


def test_run_pipeline_keeps_only_real_registrable_domains(data_dir):
    pipeline.run_pipeline(data_dir)
    domains = (data_dir / extract_domains.DEFAULT_OUTPUT).read_text(encoding="utf-8").split()
    assert domains == [
        "absbook.com",
        "absbook.net",
        "bank.com.au",
        "casebook.com",
        "shop.com.au",
        "tiffany.com",
    ]


def test_run_pipeline_discards_spurious_registrable_domains(data_dir):
    """Wildcards and country suffixes used to be destroyed or invented."""
    pipeline.run_pipeline(data_dir)
    raw = (data_dir / extract_domains.DEFAULT_OUTPUT).read_text(encoding="utf-8")
    assert "com.au" not in raw.split()
    assert "evil.test" not in raw.split()


def test_run_pipeline_produces_clusters_and_bases(data_dir):
    pipeline.run_pipeline(data_dir)
    clusters = clustering.parse_clusters(data_dir / clustering.DEFAULT_OUTPUT)
    assert ["absbook", "casebook"] in clusters
    # absbook is the shorter member, so it becomes the base the seed list is checked against.
    assert base_domain.load_base_domains(data_dir / base_domain.DEFAULT_OUTPUT) == ["absbook"]


def test_run_pipeline_flags_the_typosquat(data_dir):
    (data_dir / detect_new.DEFAULT_NEW).write_text("absbok.com\n", encoding="utf-8")
    pipeline.run_pipeline(data_dir)
    report = (data_dir / detect_new.DEFAULT_OUTPUT).read_text(encoding="utf-8")
    assert report == "new_domain,matched_base,similarity\nabsbok.com,absbook,0.92\n"


def test_missing_seed_list_writes_an_empty_report_instead_of_failing(data_dir):
    """new_domains.txt is a hand-curated input; its absence is not an error."""
    assert not (data_dir / detect_new.DEFAULT_NEW).exists()
    pipeline.run_pipeline(data_dir)
    assert (data_dir / detect_new.DEFAULT_OUTPUT).read_text(encoding="utf-8") == (
        "new_domain,matched_base,similarity\n"
    )


def test_missing_seed_list_is_reported_as_a_warning(data_dir, caplog):
    pipeline.run_pipeline(data_dir)
    assert "writing an empty suspect report" in caplog.text


def test_missing_ct_dump_is_a_readable_failure(tmp_path):
    with pytest.raises(PipelineError, match="input file not found"):
        pipeline.run_pipeline(tmp_path)


def test_main_turns_a_missing_input_into_exit_code_one(tmp_path):
    assert pipeline.main(["--data-dir", str(tmp_path)]) == 1


def test_main_succeeds(data_dir):
    assert pipeline.main(["--data-dir", str(data_dir)]) == 0


@pytest.mark.parametrize("flag", ["--pair-threshold", "--detect-threshold"])
def test_main_rejects_out_of_range_thresholds(data_dir, flag, capsys):
    assert pipeline.main(["--data-dir", str(data_dir), flag, "1.5"]) == 1
    assert f"{flag} must be" in capsys.readouterr().err


def test_a_stricter_threshold_produces_no_pairs(data_dir):
    pipeline.run_pipeline(data_dir, pair_threshold=1.0)
    assert similarity.load_pairs(data_dir / similarity.DEFAULT_OUTPUT) == []


def test_the_pipeline_is_deterministic(data_dir, tmp_path):
    pipeline.run_pipeline(data_dir)
    second = tmp_path / "second"
    second.mkdir()
    (second / "crtsh_raw.json").write_text(json.dumps(RECORDS), encoding="utf-8")
    pipeline.run_pipeline(second)
    for name in ("similar_pairs.csv", "clusters.txt", "base_domains.csv"):
        assert (data_dir / name).read_bytes() == (second / name).read_bytes()


def test_the_report_never_contains_a_formula(data_dir, check_outputs):
    """The whole point: nothing an analyst opens may start with = + - @.

    Uses the shared invariant from ``conftest`` rather than a hand-rolled scan, so
    this test and the writer tests in ``test_security.py`` cannot drift apart.
    """
    (data_dir / detect_new.DEFAULT_NEW).write_text("=1+1.com\nabsbok.com\n")
    pipeline.run_pipeline(data_dir)
    check_outputs(data_dir)
    for name in OUTPUT_FILES:
        path = data_dir / name
        assert path.is_file()
        for line in path.read_text(encoding="utf-8").splitlines():
            for cell in line.split(","):
                assert not cell.startswith(("=", "+", "@"))


def test_a_clean_run_writes_only_bare_hostnames_to_the_raw_list(data_dir):
    """domains_raw.txt gets the stronger promise a real run can keep.

    ``save_domains`` sanitizes but does not validate, so only the fact that step 1
    derives every line with ``registrable_domain`` is what keeps this true. That is
    worth a test of its own: if it stopped holding, step 2 would silently skip the
    lines rather than fail, and the loss would not show up anywhere else.
    """
    pipeline.run_pipeline(data_dir)

    assert_bare_hostnames(data_dir / extract_domains.DEFAULT_OUTPUT)
    lines = (data_dir / extract_domains.DEFAULT_OUTPUT).read_text(encoding="utf-8")
    assert lines.endswith("\n") and "\n\n" not in lines
    for domain in lines.splitlines():
        assert preprocess.normalize(domain) is not None
