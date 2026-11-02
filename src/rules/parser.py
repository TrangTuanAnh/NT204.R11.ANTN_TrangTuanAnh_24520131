"""Rule Parser & Validator: đổi một dòng rule thành Rule và phân loại valid / invalid / unsupported."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .header import parse_header
from .model import INVALID, UNSUPPORTED, VALID, Rule, RuleProblems
from .options import parse_options

__all__ = ["INVALID", "UNSUPPORTED", "VALID", "ParsedRule", "parse_rule"]


@dataclass
class ParsedRule:
    """Kết quả phân tích một rule; chỉ rule có status là valid mới có đối tượng Rule."""

    status: str
    rule: Rule | None = None
    sid: int | None = None
    reasons: list[str] = field(default_factory=list)
    unsupported_keywords: list[str] = field(default_factory=list)


def parse_rule(text: str, variables: dict[str, str], file: str = "", line: int = 0) -> ParsedRule:
    """Tách rule thành header và phần tùy chọn, kiểm tra từng phần rồi kết luận.

    Rule sai không làm phát sinh lỗi ra ngoài: kết quả cho biết trạng thái và lý
    do, để việc nạp các rule còn lại vẫn tiếp tục.
    """
    problems = RuleProblems()
    text = text.strip()
    opening = text.find("(")
    if opening == -1:
        problems.invalid.append('Rule thiếu dấu "(" mở phần tùy chọn')
        return _result(problems)
    if not text.endswith(")"):
        problems.invalid.append('Rule phải kết thúc bằng dấu ")"')
        return _result(problems)
    header = parse_header(text[:opening], variables, problems)
    options = parse_options(text[opening + 1:-1], problems)
    if options is None:
        return _result(problems)
    sid = options.get("sid")
    for name in ("msg", "sid"):
        if name not in options:
            problems.invalid.append(f"Rule thiếu keyword bắt buộc {name}")
    if problems.status() != VALID or header is None:
        return _result(problems, sid)
    return _result(problems, sid, Rule(**header, **options, file=file, line=line))


def _result(problems: RuleProblems, sid: Any = None, rule: Rule | None = None) -> ParsedRule:
    """Đóng gói kết luận từ sổ ghi vấn đề."""
    return ParsedRule(problems.status(), rule, sid, problems.reasons(), problems.unsupported_keywords)
