import logging
from pathlib import Path

import pytest

from phishing_domain_detection.cli import (
    DEFAULT_DATA_DIR,
    PipelineError,
    config_logging,
    require_fields,
    resolve_input,
    resolve_path,
    resolve_threshold,
    run_step,
)


def test_default_data_dir_is_relative_to_the_working_directory():
    """Deriving it from __file__ breaks once the package is installed elsewhere."""
    expected = Path("data")
    assert expected == DEFAULT_DATA_DIR
    assert not DEFAULT_DATA_DIR.is_absolute()


def test_resolve_path_prefers_the_override():
    override = Path("/tmp/elsewhere.csv")
    assert resolve_path(Path("data"), "x.csv", override) == override


def test_resolve_path_falls_back_to_the_data_dir():
    assert resolve_path(Path("data"), "x.csv", None) == Path("data") / "x.csv"


def test_resolve_input_returns_an_existing_file(tmp_path):
    target = tmp_path / "x.csv"
    target.write_text("a\n", encoding="utf-8")
    assert resolve_input(tmp_path, "x.csv", None) == target


def test_resolve_input_accepts_an_existing_override(tmp_path):
    target = tmp_path / "elsewhere.csv"
    target.write_text("", encoding="utf-8")
    assert resolve_input(tmp_path, "missing.csv", target) == target


def test_resolve_input_reports_a_missing_file_readably(tmp_path):
    with pytest.raises(PipelineError, match="input file not found"):
        resolve_input(tmp_path, "missing.csv", None)


def test_require_fields_accepts_a_complete_header():
    require_fields(["name1", "name2", "similarity"], ("name1", "name2"), Path("p"))


def test_require_fields_lists_every_missing_column():
    with pytest.raises(PipelineError) as excinfo:
        require_fields(["name1"], ("name1", "name2", "similarity"), Path("p"))
    message = str(excinfo.value)
    assert "name2" in message
    assert "similarity" in message


def test_require_fields_treats_a_missing_header_as_all_missing():
    with pytest.raises(PipelineError, match="name1"):
        require_fields(None, ("name1",), Path("p"))


@pytest.mark.parametrize("value", [1.0, 0.8, 0.75, 0.01, 1e-9])
def test_resolve_threshold_accepts_the_open_unit_interval(value):
    assert resolve_threshold(value, "--threshold") == value


@pytest.mark.parametrize("value", [0.0, -0.1, 1.5, 100.0])
def test_resolve_threshold_rejects_values_outside_the_range(value):
    with pytest.raises(PipelineError, match=r"\(0\.0, 1\.0\]"):
        resolve_threshold(value, "--threshold")


def test_resolve_threshold_names_the_flag():
    with pytest.raises(PipelineError, match="--pair-threshold"):
        resolve_threshold(0.0, "--pair-threshold")


def test_run_step_returns_zero_on_success():
    assert run_step(lambda: None) == 0


def test_run_step_turns_pipeline_errors_into_a_failure_code():
    def boom():
        raise PipelineError("bad input")

    assert run_step(boom) == 1


def test_run_step_turns_io_errors_into_a_failure_code():
    def boom():
        raise OSError("disk gone")

    assert run_step(boom) == 1


def test_run_step_does_not_swallow_unexpected_bugs():
    def boom():
        raise ValueError("a real bug")

    with pytest.raises(ValueError, match="a real bug"):
        run_step(boom)


def test_run_step_does_not_swallow_keyboard_interrupt():
    def boom():
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        run_step(boom)


def test_config_logging_forces_our_format_even_if_already_configured():
    """Without force=True, -v is silently ignored when something logged first."""
    root = logging.getLogger()
    previous = root.handlers[:]
    previous_level = root.level
    root.handlers.clear()
    root.addHandler(logging.NullHandler())
    try:
        config_logging(verbose=True)
        assert root.level == logging.DEBUG
        config_logging(verbose=False)
        assert root.level == logging.INFO
    finally:
        root.handlers[:] = previous
        root.setLevel(previous_level)
