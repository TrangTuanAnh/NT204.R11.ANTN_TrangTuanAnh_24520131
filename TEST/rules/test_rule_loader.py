"""Kiểm thử Rule Loader: đọc file rule, bỏ comment và dòng trống, bật/tắt file."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.rules.loader import load_rule_lines, read_rule_file


def write_rules(path: Path, content: str) -> str:
    """Ghi file rule rồi trả đường dẫn dạng chuỗi."""
    path.write_text(content, encoding="utf-8")
    return str(path)


def test_comments_and_blank_lines_are_not_passed_on(tmp_path):
    path = write_rules(tmp_path / "a.rules",
                       "# comment\n\n   # comment thut dau dong\nalert tcp any any -> any 80 (sid:1;)\n   \n"
                       "# alert tcp any any -> any 80 (sid:2;)\nalert udp any any -> any 53 (sid:3;)\n")
    lines, summary = read_rule_file(path)
    assert [(item.line, item.text) for item in lines] == [(4, "alert tcp any any -> any 80 (sid:1;)"),
                                                          (7, "alert udp any any -> any 53 (sid:3;)")]
    assert (summary.rule_lines, summary.comment_lines, summary.blank_lines) == (2, 3, 2)


def test_rule_written_on_several_lines_is_joined(tmp_path):
    path = write_rules(tmp_path / "a.rules", 'alert tcp any any -> any 80 \\\n  (msg:"x"; \\\n  sid:1;)\nalert x\n')
    lines, summary = read_rule_file(path)
    assert [item.text for item in lines] == ['alert tcp any any -> any 80 (msg:"x"; sid:1;)', "alert x"]
    assert [item.line for item in lines] == [1, 4]
    assert summary.rule_lines == 2


def test_file_ending_in_the_middle_of_a_rule_is_still_passed_on(tmp_path):
    path = write_rules(tmp_path / "a.rules", "alert tcp any any -> any 80 \\\n")
    assert [item.text for item in read_rule_file(path)[0]] == ["alert tcp any any -> any 80"]


def test_several_files_are_read_in_order_and_disabled_files_are_skipped(tmp_path):
    first = write_rules(tmp_path / "first.rules", "rule1\n")
    second = write_rules(tmp_path / "second.rules", "rule2\n")
    third = write_rules(tmp_path / "third.rules", "rule3\n")
    lines, files = load_rule_lines([first, second, third], ["second.rules", third])
    assert [item.text for item in lines] == ["rule1"]
    assert [summary.enabled for summary in files] == [True, False, False]


def test_bytes_that_are_not_utf8_do_not_stop_reading(tmp_path):
    path = tmp_path / "a.rules"
    path.write_bytes(b'\xef\xbb\xbfalert \xff x\nalert y\n')
    assert [item.text for item in read_rule_file(str(path))[0]] == ["alert � x", "alert y"]


def test_missing_file_is_reported_to_the_caller(tmp_path):
    with pytest.raises(OSError):
        load_rule_lines([str(tmp_path / "khong_co.rules")], [])
