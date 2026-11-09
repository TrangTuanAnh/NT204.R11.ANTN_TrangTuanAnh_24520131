"""Kiểm thử việc nối Loader → Parser → Repository, báo cáo nạp rule và việc tắt rule bằng cấu hình."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.config import Config
from src.rules import rule_set as rule_set_module
from src.rules.rule_set import load_rule_set, load_warnings
from TEST.support.paths import REPO_ROOT

COMMUNITY_RULES = REPO_ROOT / "rules" / "community.rules"


def write_rules(path: Path, *lines: str) -> str:
    """Ghi file rule rồi trả đường dẫn dạng chuỗi."""
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


def good(sid: int) -> str:
    """Một rule hợp lệ với sid cho trước."""
    return f'alert tcp any any -> any 80 (msg:"x"; sid:{sid};)'


def test_one_bad_rule_does_not_stop_the_others(tmp_path):
    path = write_rules(tmp_path / "a.rules", "# comment", "", good(1), "alert sai", good(2),
                       'alert tcp any any -> any 80 (msg:"x"; pcre:"/x/"; sid:3;)')
    rule_set = load_rule_set(Config(rule_files=[path]))
    assert len(rule_set.repository) == 2
    summary = rule_set.report["summary"]
    assert (summary["rule_lines"], summary["valid"], summary["invalid"], summary["unsupported"]) == (4, 2, 1, 1)
    assert (summary["comment_lines"], summary["blank_lines"]) == (1, 1)
    assert [entry["status"] for entry in rule_set.report["rules"]] == ["valid", "invalid", "valid", "unsupported"]
    assert rule_set.report["unsupported_keywords"] == {"pcre": 1}
    assert "rule" in rule_set.report["rules"][0] and "rule" not in rule_set.report["rules"][1]


def test_duplicate_sid_is_invalid(tmp_path):
    first = write_rules(tmp_path / "a.rules", good(1))
    second = write_rules(tmp_path / "b.rules", good(1))
    rule_set = load_rule_set(Config(rule_files=[first, second]))
    assert len(rule_set.repository) == 1
    entry = rule_set.report["rules"][1]
    assert entry["status"] == "invalid" and entry["reasons"] == ["sid 1 đã được dùng cho rule khác"]


def test_rule_and_file_can_be_disabled_by_config(tmp_path):
    first = write_rules(tmp_path / "a.rules", good(1), good(2))
    second = write_rules(tmp_path / "b.rules", good(3))
    rule_set = load_rule_set(Config(rule_files=[first, second], disabled_sids=[2], disabled_rule_files=["b.rules"]))
    assert rule_set.repository.get(1) and rule_set.repository.get(2) is None and rule_set.repository.get(3) is None
    assert rule_set.report["summary"]["disabled"] == 1 and rule_set.report["summary"]["disabled_files"] == 1
    assert [item["enabled"] for item in rule_set.report["files"]] == [True, False]


def test_disabled_rule_can_be_enabled_again_by_config(tmp_path):
    path = write_rules(tmp_path / "a.rules", good(1))
    assert len(load_rule_set(Config(rule_files=[path], disabled_sids=[1])).repository) == 0
    assert len(load_rule_set(Config(rule_files=[path])).repository) == 1


def test_missing_rule_file_is_reported_to_the_caller(tmp_path):
    with pytest.raises(OSError):
        load_rule_set(Config(rule_files=[str(tmp_path / "khong_co.rules")]))


def test_unexpected_error_in_one_rule_does_not_stop_loading(tmp_path, monkeypatch):
    path = write_rules(tmp_path / "a.rules", good(1), good(2))
    original = rule_set_module.parse_rule

    def broken_for_first_line(text, variables, file, line):
        """Giả lập lỗi không lường trước khi phân tích dòng đầu tiên."""
        if line == 1:
            raise RuntimeError("boom")
        return original(text, variables, file, line)

    monkeypatch.setattr(rule_set_module, "parse_rule", broken_for_first_line)
    rule_set = load_rule_set(Config(rule_files=[path]))
    assert rule_set.repository.get(2) is not None
    assert rule_set.report["rules"][0]["reasons"] == ["Lỗi khi phân tích rule: boom"]


def test_report_can_be_written_as_json(tmp_path):
    path = write_rules(tmp_path / "a.rules", 'alert tcp 10.0.0.1 any <> any 80 (msg:"x"; content:"a"; sid:1;)')
    json.dumps(load_rule_set(Config(rule_files=[path])).report)


def test_warnings_are_limited_for_large_rule_sets(tmp_path):
    path = write_rules(tmp_path / "a.rules", *[f"sai {index}" for index in range(5)])
    lines = load_warnings(load_rule_set(Config(rule_files=[path])).report, limit=2)
    assert lines[0].startswith("Nap rule: 0 hop le, 5 sai cu phap")
    assert len(lines) == 4 and lines[3].startswith("Con 3 rule khac")


def test_snort_community_rules_load_without_stopping():
    rule_set = load_rule_set(Config(rule_files=[str(COMMUNITY_RULES)]))
    summary = rule_set.report["summary"]
    assert summary["rule_lines"] == summary["valid"] + summary["invalid"] + summary["unsupported"] > 0
    assert summary["invalid"] == 0  # mọi rule của Snort đều đúng cú pháp, chỉ có thể ngoài phạm vi
    assert "metadata" in rule_set.report["unsupported_keywords"]
