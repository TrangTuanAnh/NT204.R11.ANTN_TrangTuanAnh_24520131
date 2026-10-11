"""Nối các bước xử lý: Parser → Decoder → Preprocessor → Flow Tracker."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from src.config import Config
from src.decoder import decode_event
from src.flow import FlowTracker
from src.parser import extract_payload, parse_packet
from src.preprocessor import preprocess_event

# Kết quả xử lý một gói: event để ghi ra file (None nếu bị bỏ) và các flow vừa kết thúc.
Result = tuple[dict[str, Any] | None, list[dict[str, Any]]]


class Pipeline:
    """Chạy lần lượt các bước xử lý cho từng gói tin hoặc từng event.

    Lỗi ở một bước chỉ được ghi vào event đang xử lý; chương trình vẫn chạy
    tiếp với gói sau.
    """

    def __init__(self, config: Config, clock: Callable[[], float] = time.time) -> None:
        """Tạo pipeline với một bảng flow riêng; clock là đồng hồ dùng khi bắt live."""
        self.config = config
        self.tracker = FlowTracker(config)
        self._clock = clock

    def process_packet(self, packet: Any, packet_id: int, timestamp: float, source: str) -> Result:
        """Phân tích một gói bắt được (Bài tập 1) rồi đưa qua các bước còn lại."""
        event = parse_packet(packet, packet_id, timestamp, source)
        return self.process_event(event, extract_payload(packet))

    def process_event(self, event: dict[str, Any], payload: bytes | None = None) -> Result:
        """Giải mã, kiểm tra/chuẩn hóa và gắn flow cho một event.

        payload là byte gốc của gói; event đọc từ file không có byte gốc thì để None.
        """
        decode_event(event, payload, self.config)  # hàm này tự bắt mọi lỗi bên trong
        try:
            preprocess_event(event, self.config)
        except Exception as exc:
            event.update(preprocess_status="invalid", processing_action="skip",
                         reason=[f"Lỗi khi kiểm tra event: {exc}"])
        event.update(flow_id=None, direction=None, flow_state=None)
        finished: list[dict[str, Any]] = []
        if event["processing_action"] == "process":
            try:
                finished = self.tracker.track(event)
            except Exception as exc:
                event.update(flow_id=None, direction=None, flow_state=None, processing_action="skip")
                event["reason"].append(f"Lỗi khi theo dõi flow: {exc}")
        else:
            # Event không theo dõi flow vẫn cho biết thời gian đã trôi tới đâu,
            # để các flow khác hết hạn đúng lúc.
            finished = self.tracker.observe_time(event.get("timestamp"))
        if event["processing_action"] == "drop":
            return None, finished
        return event, finished

    def expire_idle(self) -> list[dict[str, Any]]:
        """Đóng các flow quá hạn theo giờ hiện tại; dùng khi bắt live mà mạng đang im lặng."""
        return self.tracker.observe_time(self._clock())

    def finish(self, reason: str) -> list[dict[str, Any]]:
        """Đóng mọi flow còn lại khi nguồn dữ liệu kết thúc, kèm lý do kết thúc."""
        return self.tracker.finish(reason)
