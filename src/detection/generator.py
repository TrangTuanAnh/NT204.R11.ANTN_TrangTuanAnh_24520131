"""Detection Event Generator: tạo bản ghi thống nhất khi một rule khớp với một gói."""

from __future__ import annotations

from typing import Any

from src.rules.model import Rule

from .matcher import MatchResult


def build_detection_event(rule: Rule, result: MatchResult, event: dict[str, Any],
                          flow: dict[str, Any] | None = None) -> dict[str, Any]:
    """Ghép thông tin của rule và của gói thành một Detection Event.

    Hàm chỉ tạo dữ liệu, không in cảnh báo; việc ghi ra đâu do bước Alert/Logging quyết định.
    """
    network = event.get("network") or {}
    transport = event.get("transport") or {}
    application = event.get("application") or {}
    application_protocol = application.get("protocol") or (flow or {}).get("application_protocol")
    return {
        "timestamp": event.get("timestamp"),
        "packet_id": event.get("packet_id"),
        "sid": rule.sid,
        "rev": rule.rev,
        "msg": rule.msg,
        "priority": rule.priority,
        "classtype": rule.classtype,
        "src_ip": network.get("src_ip"),
        "src_port": transport.get("src_port"),
        "dst_ip": network.get("dst_ip"),
        "dst_port": transport.get("dst_port"),
        "protocol": transport.get("protocol") or "IP",
        "application_protocol": application_protocol,
        "flow_id": event.get("flow_id"),
        "match": result.matched,
        "rule_file": rule.file,
        "rule_line": rule.line,
    }
