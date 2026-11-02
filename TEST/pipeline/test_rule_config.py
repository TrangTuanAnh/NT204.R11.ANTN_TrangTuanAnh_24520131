"""Kiểm thử các tùy chọn cấu hình dùng cho phần nạp rule."""

from __future__ import annotations

import pytest

from src.config import DEFAULT_RULE_VARIABLES, Config, load_config


def test_rule_options_are_empty_by_default():
    config = Config()
    assert config.rule_files == [] and config.disabled_rule_files == [] and config.disabled_sids == []
    assert config.rule_variables == DEFAULT_RULE_VARIABLES


def test_config_file_only_needs_the_variables_it_changes(tmp_path):
    path = tmp_path / "config.json"
    path.write_text('{"rule_variables": {"HOME_NET": "10.0.0.0/8"}}', encoding="utf-8")
    variables = load_config(path).rule_variables
    assert variables["HOME_NET"] == "10.0.0.0/8"
    assert variables["HTTP_PORTS"] == DEFAULT_RULE_VARIABLES["HTTP_PORTS"]


@pytest.mark.parametrize("change", [
    {"rule_files": "a.rules"}, {"rule_files": [1]}, {"rule_files": [""]},
    {"disabled_rule_files": "a.rules"}, {"disabled_sids": ["1"]}, {"disabled_sids": [True]}, {"disabled_sids": 1},
    {"rule_variables": []}, {"rule_variables": {"HOME_NET": 1}},
])
def test_wrong_rule_options_are_rejected(change):
    with pytest.raises(ValueError):
        Config(**change)
