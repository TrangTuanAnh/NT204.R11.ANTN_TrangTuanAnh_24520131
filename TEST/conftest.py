"""Dữ liệu mẫu dùng chung cho các bài kiểm thử từng module."""

from __future__ import annotations

from typing import Any, Callable

import pytest


@pytest.fixture
def make_event() -> Callable[..., dict[str, Any]]:
    """Trả hàm tạo event giống kết quả parser cho một gói TCP/UDP.

    Mặc định là gói TCP cờ ACK từ 192.0.2.1:40000 tới 192.0.2.2:80. Có thể đổi
    thời điểm, giao thức, chiều gói, cờ, phần ứng dụng hoặc bất kỳ trường nào.
    """
    def make(timestamp: float = 1.0, protocol: str = "TCP", flags: str = "A", reverse: bool = False,
             application: dict[str, Any] | None = None, **changes: Any) -> dict[str, Any]:
        """Tạo một event mới; reverse=True đảo nguồn và đích."""
        source, destination = ("192.0.2.1", 40000), ("192.0.2.2", 80)
        if reverse:
            source, destination = destination, source
        transport: dict[str, Any] = {"protocol": protocol, "src_port": source[1], "dst_port": destination[1]}
        if protocol == "TCP":
            transport.update(sequence=0, acknowledgment=0, flags=flags, window=8192, payload_length=0)
        else:
            transport.update(length=8, payload_length=0)
        event = {
            "packet_id": 1, "timestamp": timestamp, "source": "pcap", "captured_length": 60,
            "network": {"version": 4, "src_ip": source[0], "dst_ip": destination[0], "ttl": 64,
                        "protocol": 6 if protocol == "TCP" else 17, "total_length": 46,
                        "fragment_offset": 0, "more_fragments": False},
            "transport": transport,
            "application": application if application is not None else {"protocol": None},
            "status": "unknown", "errors": [],
        }
        event.update(changes)
        return event
    return make
