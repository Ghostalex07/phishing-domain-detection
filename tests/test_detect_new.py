import pytest

from phishing_domain_detection import base_domain, detect_new

FORMULA_LINES = [
    "=1+1.com",
    "+SUM(1+1).com",
    "@sum(1+1).x",
    "-2+3.com",
    "=cmd|'/c calc'!A1",
    '=HYPERLINK("http://evil.example","click").com',
]


def test_flags_lookalike_domains():
    suspects = detect_new.find_suspects([("absbok.com", "absbok")], ["absbook"], threshold=0.75)
    assert suspects == [("absbok.com", "absbook", 0.92)]


def test_flags_substring_match():
    suspects = detect_new.find_suspects(
        [("login.example-secure.org", "example-secure")], ["example"], threshold=1.0
    )
    assert any(base == "example" for _, base, _ in suspects)


def test_low_threshold_keeps_clear_matches_only():
    suspects = detect_new.find_suspects(
        [("totallyunrelated.com", "totallyunrelated")], ["anchor"], threshold=0.9
    )
    assert suspects == []


def test_does_not_report_a_domain_against_itself():
    assert detect_new.find_suspects([("absbook.com", "absbook")], ["absbook"]) == []


def test_reports_each_domain_once_against_its_best_base():
    suspects = detect_new.find_suspects([("boook.com", "boook")], ["book", "boook2"])
    assert len(suspects) == 1
    assert suspects[0][0] == "boook.com"


def test_keeps_the_duplicate_free_order_of_the_input():
    new_domains = [("zzz-absbook.com", "zzz-absbook"), ("absbok.com", "absbok")]
    suspects = detect_new.find_suspects(new_domains, ["absbook"])
    assert [domain for domain, _, _ in suspects] == ["zzz-absbook.com", "absbok.com"]


@pytest.mark.parametrize("base", ["a", "ab", "abc"])
def test_a_short_base_cannot_match_by_substring(base):
    """len(base) >= MIN_SUBSTRING_BASE, else a 1-char base would flag everything."""
    name = f"xyz{base}"
    assert detect_new.find_suspects([(f"{name}.com", name)], [base], threshold=1.0) == []


def test_a_base_of_the_minimum_length_can_still_match_by_substring():
    assert detect_new.MIN_SUBSTRING_BASE == 4
    suspects = detect_new.find_suspects(
        [("login.example-secure.org", "example-secure")], ["exam"], threshold=1.0
    )
    assert len(suspects) == 1


def test_reports_the_real_score_even_for_a_substring_match():
    """Filtering the CSV on similarity alone will miss these; the docstring says so."""
    suspects = detect_new.find_suspects(
        [("login.example-secure.org", "example-secure")], ["example"], threshold=1.0
    )
    assert suspects[0][2] < 1.0


def test_no_suspects_gives_an_empty_list():
    assert detect_new.find_suspects([], ["absbook"]) == []


def test_load_new_domains_strips_only_the_tld(tmp_path):
    path = tmp_path / "new_domains.txt"
    path.write_text("login.bank.co.uk\nabsbok.com\n", encoding="utf-8")
    assert detect_new.load_new_domains(path) == [
        ("login.bank.co.uk", "login.bank.co"),
        ("absbok.com", "absbok"),
    ]


def test_load_new_domains_skips_blank_lines(tmp_path):
    path = tmp_path / "new_domains.txt"
    path.write_text("\n   \nabsbok.com\n\n")
    assert detect_new.load_new_domains(path) == [("absbok.com", "absbok")]


def test_load_new_domains_normalizes_case_and_trailing_dots(tmp_path):
    path = tmp_path / "new_domains.txt"
    path.write_text("  ABSBOK.COM.  \n")
    assert detect_new.load_new_domains(path) == [("absbok.com", "absbok")]


@pytest.mark.parametrize("line", FORMULA_LINES)
def test_load_new_domains_rejects_formula_shaped_lines(tmp_path, line):
    path = tmp_path / "new_domains.txt"
    path.write_text(f"{line}\n", encoding="utf-8")
    assert detect_new.load_new_domains(path) == []


def test_formula_injection_cannot_reach_the_report(tmp_path):
    """The whole point: no cell in the analyst-facing CSV may start with =+-@."""
    base_domain.save_base_domains(
        tmp_path / "base_domains.csv", [("absbook", ["absbook", "absbok"])]
    )
    (tmp_path / "new_domains.txt").write_text("\n".join([*FORMULA_LINES, "absbok.com"]) + "\n")

    assert detect_new.main(["--data-dir", str(tmp_path)]) == 0

    report = (tmp_path / "suspect_domains.csv").read_text(encoding="utf-8")
    assert report == "new_domain,matched_base,similarity\nabsbok.com,absbook,0.92\n"
    for line in report.splitlines()[1:]:
        assert not line.startswith(("=", "+", "-", "@"))


def test_load_new_domains_warns_about_what_it_dropped(tmp_path, caplog):
    # caplog works here because no config_logging() call is involved; a test that
    # goes through main() has to read stderr instead, since force=True replaces
    # the root handlers caplog relies on.
    path = tmp_path / "new_domains.txt"
    path.write_text("absbok.com\n=1+1.com\nnot a domain\n")
    assert len(detect_new.load_new_domains(path)) == 1
    assert "Ignored 2 line(s)" in caplog.text


def test_save_suspects_round_trips_through_load_free_writing(tmp_path):
    path = tmp_path / "suspect_domains.csv"
    detect_new.save_suspects(path, [("absbok.com", "absbook", 0.92)])
    assert path.read_text(encoding="utf-8") == (
        "new_domain,matched_base,similarity\nabsbok.com,absbook,0.92\n"
    )


def test_main_reports_a_missing_input(tmp_path):
    assert detect_new.main(["--data-dir", str(tmp_path)]) == 1


def test_main_rejects_an_out_of_range_threshold(tmp_path, capsys):
    base_domain.save_base_domains(tmp_path / "base_domains.csv", [("absbook", ["absbook"])])
    (tmp_path / "new_domains.txt").write_text("absbok.com\n")
    assert detect_new.main(["--data-dir", str(tmp_path), "--threshold", "0"]) == 1
    assert "--threshold must be" in capsys.readouterr().err
