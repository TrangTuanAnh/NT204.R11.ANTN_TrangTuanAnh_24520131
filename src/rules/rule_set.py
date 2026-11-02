"""Nối ba bước Loader → Parser → Repository và tạo báo cáo nạp rule."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from typing import Any

from src.config import Config

from .loader import load_rule_lines
from .parser import INVALID, UNSUPPORTED, VALID, ParsedRule, parse_rule
from .repository import RuleRepository

DISABLED = "disabled"  # rule đúng hay sai đều không dùng vì đã bị tắt bằng cấu hình


@dataclass
class RuleSet:
    """Kho rule sẵn sàng để so khớp, kèm báo cáo về việc nạp."""

    repository: RuleRepository
    report: dict[str, Any]


def load_rule_set(config: Config) -> RuleSet:
    """Nạp mọi file rule trong cấu hình; một rule sai chỉ được ghi vào báo cáo, không làm dừng việc nạp."""
    lines, files = load_rule_lines(config.rule_files, config.disabled_rule_files)
    repository = RuleRepository()
    disabled_sids = set(config.disabled_sids)
    entries: list[dict[str, Any]] = []
    dropped_keywords: Counter[str] = Counter()
    for item in lines:
        try:
            parsed = parse_rule(item.text, config.rule_variables, item.file, item.line)
        except Exception as exc:
            # Lưới an toàn: lỗi không lường trước chỉ đánh dấu rule này, các rule sau vẫn được nạp.
            parsed = ParsedRule(INVALID, reasons=[f"Lỗi khi phân tích rule: {exc}"])
        status, reasons = parsed.status, parsed.reasons
        if parsed.sid in disabled_sids:
            status, reasons = DISABLED, ["Rule bị tắt bằng disabled_sids"]
        elif status == VALID and not repository.add(parsed.rule):
            status, reasons = INVALID, [f"sid {parsed.sid} đã được dùng cho rule khác"]
        if status == UNSUPPORTED:
            dropped_keywords.update(set(parsed.unsupported_keywords))
        entry = {"file": item.file, "line": item.line, "sid": parsed.sid, "status": status, "reasons": reasons}
        if status == VALID:
            entry["rule"] = parsed.rule.describe()
        entries.append(entry)
    statuses = Counter(entry["status"] for entry in entries)
    report = {
        "summary": {
            "files": len(files),
            "disabled_files": sum(not summary.enabled for summary in files),
            "comment_lines": sum(summary.comment_lines for summary in files),
            "blank_lines": sum(summary.blank_lines for summary in files),
            "rule_lines": len(entries),
            "valid": statuses[VALID],
            "invalid": statuses[INVALID],
            "unsupported": statuses[UNSUPPORTED],
            "disabled": statuses[DISABLED],
        },
        "unsupported_keywords": dict(dropped_keywords.most_common()),
        "files": [asdict(summary) for summary in files],
        "rules": entries,
    }
    return RuleSet(repository, report)


def load_warnings(report: dict[str, Any], limit: int = 20) -> list[str]:
    """Các dòng cảnh báo in ra khi nạp rule; bộ rule lớn chỉ in phần đầu để không làm ngập màn hình."""
    summary = report["summary"]
    lines = [f"Nap rule: {summary['valid']} hop le, {summary['invalid']} sai cu phap, "
             f"{summary['unsupported']} ngoai pham vi (da bo), {summary['disabled']} bi tat"]
    problems = [entry for entry in report["rules"] if entry["status"] in (INVALID, UNSUPPORTED)]
    for entry in problems[:limit]:
        lines.append(f"Canh bao: {entry['file']}:{entry['line']} sid={entry['sid']} {entry['status']}: "
                     + "; ".join(entry["reasons"]))
    if len(problems) > limit:
        lines.append(f"Con {len(problems) - limit} rule khac, xem file bao cao --rule-report")
    return lines
