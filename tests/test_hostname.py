import pytest

from phishing_domain_detection.hostname import (
    MULTI_LABEL_SUFFIXES,
    normalize,
    normalize_label,
    registrable_domain,
    safe_cell,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "example.com"),
        ("EXAMPLE.COM", "example.com"),
        ("  example.com  ", "example.com"),
        ("www.example.com", "www.example.com"),
        ("*.example.com", "example.com"),
        ("*.*.example.com", "example.com"),
        (".example.com", "example.com"),
        ("example.com.", "example.com"),
        ("my-site.co.uk", "my-site.co.uk"),
    ],
)
def test_normalize_accepts_hostnames(raw, expected):
    assert normalize(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "nodots",
        "=1+1.com",
        "+SUM(1+1).com",
        "@sum(1+1).x",
        "-2+3.com",
        "=cmd|'/c calc'!A1",
        '=HYPERLINK("http://evil","x").com',
        "See www.example.com for details",
        "go to https://example.com/path",
        "user@example.com",
        "-leading-hyphen.com",
        "trailing-hyphen-.com",
        "double..dot.com",
        ".com",
    ],
)
def test_normalize_rejects_non_hostnames(raw):
    assert normalize(raw) is None


def test_normalize_rejects_every_formula_prefix():
    """The CSV written downstream must never start with a spreadsheet formula."""
    for prefix in ("=", "+", "-", "@"):
        assert normalize(f"{prefix}cmd.com") is None


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("tiffany.com", "tiffany.com"),
        ("www.tiffany.com", "tiffany.com"),
        ("a.b.c.tiffany.com", "tiffany.com"),
        ("xn--80ak6aa92e.com", "xn--80ak6aa92e.com"),
    ],
)
def test_registrable_domain_uses_last_two_labels(raw, expected):
    assert registrable_domain(raw) == expected


@pytest.mark.parametrize("suffix", sorted(MULTI_LABEL_SUFFIXES))
def test_registrable_domain_honours_every_known_multi_label_suffix(suffix):
    """The naive last-two-labels rule would return the suffix itself."""
    assert registrable_domain(f"shop.{suffix}") == f"shop.{suffix}"
    assert registrable_domain(f"www.shop.{suffix}") == f"shop.{suffix}"


@pytest.mark.parametrize(
    "raw",
    ["nodots", "com", "a..com", ".com"],
)
def test_registrable_domain_rejects_unusable_input(raw):
    assert registrable_domain(raw) is None


def test_registrable_domain_returns_none_for_single_label():
    assert registrable_domain("com") is None


# --------------------------------------------------------------------------
# normalize_label: the validator for a single DNS label.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("ad-digital", "ad-digital"),
        ("absbook", "absbook"),
        ("a", "a"),
        ("ABSBOK", "absbok"),
        ("  absbook  ", "absbook"),
        ("xn--80ak6aa92e", "xn--80ak6aa92e"),
        ("a1", "a1"),
    ],
)
def test_normalize_label_accepts_labels(raw, expected):
    assert normalize_label(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "   \t  ",
        "a.b",
        "a b",
        "a\tb",
        "a\nb",
        "a\rb",
        "a\x0bb",
        "a\x00b",
        "a\x1bb",
        "a\x7fb",
        "a,b",
        "a'b",
        'a"b',
        "a(b",
        "a)b",
        "a[b",
        "a]b",
        "a{b",
        "a}b",
        "a;b",
        "a|b",
        "a\\b",
        "-leading",
        "trailing-",
        "[a]",
        "a.b.c",
    ],
)
def test_normalize_label_rejects_anything_that_is_not_one_label(raw):
    assert normalize_label(raw) is None


@pytest.mark.parametrize("prefix", ["=", "+", "-", "@"])
def test_normalize_label_rejects_every_formula_prefix(prefix):
    """A label is written straight into a CSV cell, so a formula prefix must fail."""
    assert normalize_label(f"{prefix}cmd") is None
    assert normalize_label(f"{prefix}") is None


@pytest.mark.parametrize("char", ["\n", "\r", "\x00", "\x0b", "\x0c", "\x1b", "\x7f"])
def test_normalize_label_rejects_control_characters(char):
    """These either end a line early or repaint the operator's terminal."""
    assert normalize_label(f"abs{char}book") is None


def test_normalize_label_cannot_tell_a_tld_from_a_name():
    """A label is just a label; registrable_domain() is what needs two of them."""
    assert normalize_label("com") == "com"
    assert normalize_label("nodots") == "nodots"
    assert registrable_domain("com") is None


def test_normalize_label_never_returns_a_dotted_hostname():
    """It is a *label* validator; normalize() is the hostname one."""
    assert normalize_label("ad-digital.com") is None
    assert normalize("ad-digital.com") == "ad-digital.com"


# --------------------------------------------------------------------------
# safe_cell: the second layer, applied by every writer.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "absbook",
        "ad-digital",
        "absbook.com",
        "login.absbook.co",
        "0",
        "1.5",
        "",
        "   ",
        "a,b",
        "'already-prefixed",
    ],
)
def test_safe_cell_leaves_valid_data_alone(raw):
    """For validated input it is the identity function, so no row changes shape."""
    assert safe_cell(raw) == raw


@pytest.mark.parametrize("prefix", ["=", "+", "-", "@"])
def test_safe_cell_prefixes_every_formula_prefix(prefix):
    assert safe_cell(f"{prefix}cmd") == f"'{prefix}cmd"


@pytest.mark.parametrize("prefix", ["=", "+", "-", "@"])
def test_safe_cell_leaves_a_prefix_that_is_not_leading_alone(prefix):
    """A spreadsheet trims leading whitespace before evaluating, but only a cell
    whose *first* character is a formula prefix is treated as a formula, so the
    space here is not a bypass and must not be rewritten."""
    assert safe_cell(f" {prefix}cmd") == f" {prefix}cmd"


def test_safe_cell_prefixes_rather_than_strips_a_legitimate_leading_hyphen():
    """``-`` is legal inside a real label, so dropping it would corrupt the data."""
    assert safe_cell("-legit-name") == "'-legit-name"
    assert safe_cell("-legit-name").lstrip("'") == "-legit-name"


@pytest.mark.parametrize(
    "raw",
    [
        "=HYPERLINK(\"http://evil.example\",\"click\").com",
        "+SUM(1+1).com",
        "-2+3.com",
        "@sum(1+1).x",
        "=cmd|'/c calc'!A1",
    ],
)
def test_safe_cell_neutralizes_the_classic_injection_payloads(raw):
    assert not safe_cell(raw).startswith(("=", "+", "-", "@"))
    assert safe_cell(raw).startswith("'")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("a\nb", "ab"),
        ("a\rb", "ab"),
        ("a\r\nb", "ab"),
        ("a\x0bb", "ab"),
        ("a\x0cb", "ab"),
        ("a\x00b", "ab"),
        ("a\x7fb", "ab"),
        ("a\x1b[31mred", "a[31mred"),
        ("\x1b[2J", "[2J"),
    ],
)
def test_safe_cell_strips_control_characters(raw, expected):
    """Stripping, not escaping: a control byte must not survive into any format."""
    assert safe_cell(raw) == expected


def test_safe_cell_removes_the_newline_that_would_forge_a_record():
    """The record-forgery mechanism, removed rather than quoted."""
    hostile = "absbook\nCluster 999: injected"
    cleaned = safe_cell(hostile)
    assert "\n" not in cleaned
    assert cleaned.splitlines() == ["absbookCluster 999: injected"]


@pytest.mark.parametrize("raw", ["=x", "+x", "-x", "@x", "a\nb", "\x00", "a\x1b[31m"])
def test_safe_cell_is_idempotent(raw):
    """Double-sanitising must not stack quotes, which would corrupt the data."""
    once = safe_cell(raw)
    assert safe_cell(once) == once


def test_safe_cell_output_is_always_inert():
    """The property every writer depends on, asserted over the whole payload set."""
    payload = ["=x", "+x", "-x", "@x", "a\nb", "\x00", "\x1b[31m", "\x7f", "a,b"]
    for raw in payload:
        cleaned = safe_cell(raw)
        assert not cleaned.startswith(("=", "+", "-", "@"))
        assert not any(character in cleaned for character in "\r\n\x00\x1b\x7f")
