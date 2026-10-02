import json

import pytest

from phishing_domain_detection import extract_domains
from phishing_domain_detection.cli import PipelineError

RECORDS = [
    {"name_value": "www.tiffany.com"},
    {"name_value": "a.wazizu.com\nSee www.rapidssl.com/resources/cps (c)12"},
    {"name_value": "Go to https://www.thawte.com/repository/index.html\nWWW.PATH2USA.COM"},
    {},
]


def test_reduces_names_to_registrable_domain():
    domains = extract_domains.extract_domains(RECORDS)
    assert "tiffany.com" in domains
    assert "wazizu.com" in domains


def test_skips_noise_lines():
    domains = extract_domains.extract_domains(RECORDS)
    assert "rapidssl.com" not in domains
    assert "thawte.com" not in domains


def test_lowercases_input():
    domains = extract_domains.extract_domains(RECORDS)
    assert "path2usa.com" in domains
    assert "WWW.PATH2USA.COM" not in domains


def test_handles_empty_input():
    assert extract_domains.extract_domains([]) == set()
    assert "wazizu.com" in extract_domains.extract_domains(RECORDS)


def test_recovers_wildcard_certificates():
    """crt.sh reports wildcards as *.example.com; the apex is what matters."""
    domains = extract_domains.extract_domains([{"name_value": "*.bank.com"}])
    assert domains == {"bank.com"}


def test_recovers_wildcard_names_hidden_in_a_multiline_field():
    records = [{"name_value": "noise here\n*.wildcard.test\nother"}]
    assert extract_domains.extract_domains(records) == {"wildcard.test"}


def test_keeps_the_registrable_domain_of_multi_part_suffixes():
    """The last-two-labels rule used to turn these into bare suffixes."""
    domains = extract_domains.extract_domains(
        [{"name_value": "www.seat.com.au\nshop.com.au\nmascus.com.cn"}]
    )
    assert domains == {"seat.com.au", "shop.com.au", "mascus.com.cn"}


def test_never_emits_a_bare_public_suffix():
    records = [{"name_value": "x.com.au\ny.com.br\nz.co.uk"}]
    domains = extract_domains.extract_domains(records)
    assert "com.au" not in domains
    assert "com.br" not in domains
    assert "co.uk" not in domains


def test_never_emits_a_formula_shaped_domain():
    records = [{"name_value": "=1+1.com\n@sum(1+1).x\n-2+3.com"}]
    assert extract_domains.extract_domains(records) == set()


def test_skips_records_that_are_not_objects():
    assert extract_domains.extract_domains(["a string", 42, None]) == set()


def test_skips_records_without_a_usable_name_value():
    assert extract_domains.extract_domains([{"name_value": None}, {"other": 1}]) == set()


def test_load_records_reads_a_json_array(tmp_path):
    path = tmp_path / "crtsh_raw.json"
    path.write_text(json.dumps(RECORDS), encoding="utf-8")
    assert extract_domains.load_records(path) == RECORDS


def test_load_records_rejects_invalid_json(tmp_path):
    path = tmp_path / "crtsh_raw.json"
    path.write_text("not json", encoding="utf-8")
    with pytest.raises(PipelineError, match="invalid JSON"):
        extract_domains.load_records(path)


def test_load_records_rejects_a_non_array_payload(tmp_path):
    """crt.sh returns an error object when rate limiting; iterating it would yield keys."""
    path = tmp_path / "crtsh_raw.json"
    path.write_text(json.dumps({"error": "rate limited"}), encoding="utf-8")
    with pytest.raises(PipelineError, match="expected a JSON array"):
        extract_domains.load_records(path)


def test_save_domains_is_sorted_and_round_trips(tmp_path):
    path = tmp_path / "domains_raw.txt"
    extract_domains.save_domains(path, {"b.com", "a.com", "c.com"})
    assert path.read_text(encoding="utf-8") == "a.com\nb.com\nc.com\n"


def test_main_succeeds(tmp_path):
    (tmp_path / "crtsh_raw.json").write_text(json.dumps(RECORDS), encoding="utf-8")
    assert extract_domains.main(["--data-dir", str(tmp_path)]) == 0
    assert "tiffany.com" in (tmp_path / "domains_raw.txt").read_text(encoding="utf-8")


def test_main_reports_a_missing_input(tmp_path):
    assert extract_domains.main(["--data-dir", str(tmp_path)]) == 1


def test_main_reports_a_bad_payload_without_a_traceback(tmp_path, capsys):
    """A user error must be one log line, not a stack trace.

    Asserted on stderr rather than caplog: config_logging(force=True) replaces the
    root handlers, which is exactly what would swallow caplog's own handler.
    """
    (tmp_path / "crtsh_raw.json").write_text("{}", encoding="utf-8")
    assert extract_domains.main(["--data-dir", str(tmp_path)]) == 1
    captured = capsys.readouterr()
    assert "expected a JSON array" in captured.err
    assert "Traceback" not in captured.err
