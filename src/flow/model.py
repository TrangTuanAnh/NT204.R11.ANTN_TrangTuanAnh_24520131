"""Thông tin và các bộ đếm của một flow (một phiên giao tiếp hai chiều)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, NamedTuple

from .tcp_state import TcpConnection

# Tên cờ TCP được đếm và chữ cái tương ứng trong chuỗi cờ của parser.
COUNTED_FLAGS = (("SYN", "S"), ("ACK", "A"), ("FIN", "F"), ("RST", "R"))


class Endpoint(NamedTuple):
    """Một đầu của kết nối: địa chỉ IP và port."""

    ip: str
    port: int


@dataclass
class Flow:
    """Một flow đang được theo dõi cùng các bộ đếm của nó.

    endpoint_a là bên gửi gói đầu tiên (thường là bên mở kết nối). Gói đi từ
    A sang B thuộc chiều "forward", gói đi từ B về A thuộc chiều "backward".
    """

    flow_id: str
    protocol: str
    endpoint_a: Endpoint
    endpoint_b: Endpoint
    start_time: float
    last_seen: float
    tcp: TcpConnection | None = None  # None với UDP vì UDP không có trạng thái kết nối
    application_protocol: str | None = None
    packet_count: int = 0
    byte_count: int = 0
    forward_packet_count: int = 0
    forward_byte_count: int = 0
    backward_packet_count: int = 0
    backward_byte_count: int = 0
    flag_counts: dict[str, int] = field(default_factory=lambda: {name: 0 for name, _ in COUNTED_FLAGS})

    @property
    def state(self) -> str | None:
        """Trạng thái TCP hiện tại; UDP không có trạng thái nên trả None."""
        return self.tcp.state if self.tcp is not None else None

    def add_packet(self, direction: str, timestamp: float, size: int, flags: str,
                   application_protocol: str | None) -> None:
        """Cộng một gói vào các bộ đếm của flow và cập nhật trạng thái TCP."""
        # Dùng min/max vì gói trong file có thể không theo đúng thứ tự thời gian.
        self.start_time = min(self.start_time, timestamp)
        self.last_seen = max(self.last_seen, timestamp)
        self.packet_count += 1
        self.byte_count += size
        if direction == "forward":
            self.forward_packet_count += 1
            self.forward_byte_count += size
        else:
            self.backward_packet_count += 1
            self.backward_byte_count += size
        if self.application_protocol is None:
            self.application_protocol = application_protocol
        if self.tcp is not None:
            for name, letter in COUNTED_FLAGS:
                if letter in flags:
                    self.flag_counts[name] += 1
            self.tcp.update(flags, direction)

    def summary(self, end_reason: str) -> dict[str, Any]:
        """Tạo bản tổng kết của flow để ghi ra file khi flow kết thúc.

        Các trường riêng của TCP (đếm cờ, state, handshake_observed) để null với UDP.
        """
        is_tcp = self.tcp is not None
        flags = self.flag_counts if is_tcp else dict.fromkeys(self.flag_counts)
        return {
            "flow_id": self.flow_id,
            "protocol": self.protocol,
            "application_protocol": self.application_protocol,
            "endpoint_a": {"ip": self.endpoint_a.ip, "port": self.endpoint_a.port},
            "endpoint_b": {"ip": self.endpoint_b.ip, "port": self.endpoint_b.port},
            "start_time": self.start_time,
            "last_seen": self.last_seen,
            # Làm tròn tới micro giây (độ chính xác của PCAP) để bỏ sai số khi trừ số thực.
            "duration": round(self.last_seen - self.start_time, 6),
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "forward_packet_count": self.forward_packet_count,
            "forward_byte_count": self.forward_byte_count,
            "backward_packet_count": self.backward_packet_count,
            "backward_byte_count": self.backward_byte_count,
            "SYN_count": flags["SYN"],
            "ACK_count": flags["ACK"],
            "FIN_count": flags["FIN"],
            "RST_count": flags["RST"],
            "state": self.state,
            "handshake_observed": self.tcp.handshake_observed if is_tcp else None,
            "end_reason": end_reason,
        }
