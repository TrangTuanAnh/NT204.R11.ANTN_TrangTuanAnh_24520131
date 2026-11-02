"""Rule Evaluation Engine: lấy các rule cần xét cho một gói rồi gọi so khớp từng rule."""

from __future__ import annotations

from typing import Any

from src.rules.model import Rule
from src.rules.repository import RuleRepository

from .matcher import MATCH, CONTENT, FLOW, HEADER, PACKET, MatchResult, PacketView, match_rule


class RuleEvaluator:
    """Đánh giá từng event theo kho rule và giữ các số liệu để kiểm tra hiệu năng."""

    def __init__(self, repository: RuleRepository) -> None:
        """Bắt đầu với các bộ đếm bằng 0."""
        self.repository = repository
        self.stats: dict[str, Any] = {
            "rules_in_repository": len(repository),
            "events_seen": 0,          # mọi event được đưa vào
            "events_evaluated": 0,     # event đủ điều kiện để đánh giá
            "events_skipped": 0,       # event sai, bị bỏ theo cấu hình hoặc không có địa chỉ IP
            "candidate_rules": 0,      # tổng số rule phải xét, so với events_evaluated × rules_in_repository
            "content_checks": 0,       # số lần một rule đi tới bước tìm content
            "matches": 0,              # số lần rule khớp
            "rejected": {HEADER: 0, FLOW: 0, PACKET: 0, CONTENT: 0},  # số lần rule bị loại ở từng bước
            "errors": 0,               # số lần có lỗi không lường trước khi so khớp
        }

    def evaluate(self, event: dict[str, Any], flow: dict[str, Any] | None = None,
                 payload: bytes | None = None) -> list[tuple[Rule, MatchResult]]:
        """Trả mọi rule khớp với event; không dừng ở rule khớp đầu tiên.

        Lỗi khi xét một rule chỉ được đếm lại, các rule còn lại vẫn được xét.
        """
        self.stats["events_seen"] += 1
        if not _can_evaluate(event):
            self.stats["events_skipped"] += 1
            return []
        self.stats["events_evaluated"] += 1
        try:
            packet = PacketView(event, flow, payload)
            candidates = self.repository.candidates(packet.protocol, packet.source_port, packet.destination_port)
        except Exception:
            self.stats["errors"] += 1
            return []
        self.stats["candidate_rules"] += len(candidates)
        matches = []
        for rule in candidates:
            try:
                result = match_rule(rule, packet)
            except Exception:
                self.stats["errors"] += 1
                continue
            self.stats["content_checks"] += result.reached_content
            if result.verdict == MATCH:
                self.stats["matches"] += 1
                matches.append((rule, result))
            else:
                self.stats["rejected"][result.failed_at] += 1
        return matches


def _can_evaluate(event: dict[str, Any]) -> bool:
    """Chỉ đánh giá event có địa chỉ IP đọc được, không bị đánh dấu sai và không bị bỏ theo cấu hình.

    Event ICMP hay gói phân mảnh không được theo dõi flow nhưng vẫn là gói IP thật,
    nên vẫn được đánh giá; rule có keyword flow sẽ không khớp với chúng.
    """
    network = event.get("network")
    if not isinstance(network, dict) or network.get("src_ip") is None or network.get("dst_ip") is None:
        return False
    return event.get("preprocess_status") != "invalid" and event.get("processing_action") != "drop"
