"""Rule Loader: đọc các file .rules, bỏ dòng trống và comment, ghép rule viết trên nhiều dòng."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RuleLine:
    """Một rule đọc được từ file, chưa phân tích; line là số dòng bắt đầu của rule."""

    file: str
    line: int
    text: str


@dataclass
class FileSummary:
    """Kết quả đọc một file rule; file bị tắt bằng cấu hình thì không được đọc nội dung."""

    path: str
    enabled: bool = True
    rule_lines: int = 0
    comment_lines: int = 0
    blank_lines: int = 0


def load_rule_lines(paths: list[str], disabled_files: list[str]) -> tuple[list[RuleLine], list[FileSummary]]:
    """Đọc lần lượt các file rule và trả các rule cần phân tích cùng thống kê từng file.

    File không tồn tại hoặc không đọc được làm phát sinh OSError, vì đó là lỗi
    tham số của người chạy chứ không phải lỗi của một rule.
    """
    rules: list[RuleLine] = []
    summaries: list[FileSummary] = []
    for path in paths:
        if _is_disabled(path, disabled_files):
            summaries.append(FileSummary(path, enabled=False))
            continue
        lines, summary = read_rule_file(path)
        rules.extend(lines)
        summaries.append(summary)
    return rules, summaries


def read_rule_file(path: str) -> tuple[list[RuleLine], FileSummary]:
    """Đọc một file rule: bỏ dòng trống và dòng comment, chỉ giữ các rule cho bước phân tích.

    Dòng kết thúc bằng dấu "\\" được nối với dòng sau, vì Snort cho phép viết
    một rule trên nhiều dòng. Byte không phải UTF-8 được thay bằng ký tự "�" để
    một dòng lỗi không làm hỏng cả file; rule đó sẽ được bước phân tích đánh giá.
    """
    text = Path(path).read_bytes().decode("utf-8-sig", errors="replace")
    summary = FileSummary(path)
    rules: list[RuleLine] = []
    pending: list[str] = []
    start_line = 0
    for number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not pending:
            if not line:
                summary.blank_lines += 1
                continue
            if line.startswith("#"):
                summary.comment_lines += 1
                continue
            start_line = number
        if line.endswith("\\"):
            pending.append(line[:-1].strip())
            continue
        pending.append(line)
        rules.append(RuleLine(path, start_line, " ".join(pending)))
        pending = []
    if pending:  # file hết khi rule còn dở: vẫn chuyển đi để bước phân tích báo sai cú pháp
        rules.append(RuleLine(path, start_line, " ".join(pending)))
    summary.rule_lines = len(rules)
    return rules, summary


def _is_disabled(path: str, disabled_files: list[str]) -> bool:
    """File có bị tắt trong cấu hình không; được ghi bằng tên file hoặc bằng đường dẫn."""
    resolved = Path(path).resolve()
    return any(item == resolved.name or Path(item).resolve() == resolved for item in disabled_files)
