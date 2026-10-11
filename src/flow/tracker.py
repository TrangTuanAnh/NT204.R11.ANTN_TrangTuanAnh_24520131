"""Gom các gói cùng phiên thành flow hai chiều; đóng flow khi kết nối kết thúc hoặc hết hạn."""

from __future__ import annotations

import hashlib
from collections import OrderedDict
from typing import Any

from src.config import Config

from .model import Endpoint, Flow
from .tcp_state import CLOSED, FINISHED_STATES, TcpConnection

# Khóa tra flow: giao thức cùng hai đầu kết nối đã sắp xếp.
FlowKey = tuple[str, Endpoint, Endpoint]


def flow_key(protocol: str, source: Endpoint, destination: Endpoint) -> FlowKey:
    """Tạo khóa của 5-tuple sao cho hai chiều A→B và B→A cho cùng một khóa.

    Hai đầu kết nối được sắp xếp trước khi ghép vào khóa, nên đổi chỗ nguồn
    và đích vẫn ra cùng kết quả.
    """
    first, second = sorted((source, destination))
    return protocol, first, second


class FlowTracker:
    """Bảng các flow đang hoạt động cùng các quy tắc mở và đóng flow.

    Flow kết thúc khi: TCP đóng bằng FIN (tcp_closed) hoặc RST (tcp_reset),
    quá thời gian không có gói mới (idle_timeout), gặp gói SYN mở kết nối mới
    trên cùng 5-tuple (new_connection), bảng đầy (table_full), hoặc khi hết dữ
    liệu vào. Flow kết thúc được trả về dưới dạng bản tổng kết và xóa khỏi bảng.
    """

    def __init__(self, config: Config) -> None:
        """Tạo bảng flow rỗng."""
        self.config = config
        # Thứ tự trong bảng là thứ tự có gói gần nhất: flow lâu không có gói nằm ở đầu.
        self._active: OrderedDict[FlowKey, Flow] = OrderedDict()
        self._created = 0                         # số flow đã tạo, góp phần tạo flow_id
        self._now: float | None = None            # thời điểm mới nhất đã thấy
        self._next_deadline: float | None = None  # mốc sớm nhất mà một flow có thể hết hạn

    @property
    def active_count(self) -> int:
        """Số flow đang nằm trong bảng."""
        return len(self._active)

    def track(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        """Gắn flow_id, direction và flow_state vào event; trả các flow vừa kết thúc.

        Event phải đã qua Preprocessor với processing_action là "process", tức
        đã có đủ IP, port, giao thức TCP/UDP và timestamp hợp lệ.
        """
        network, transport = event["network"], event["transport"]
        protocol = transport["protocol"]
        source = Endpoint(network["src_ip"], transport["src_port"])
        destination = Endpoint(network["dst_ip"], transport["dst_port"])
        timestamp = event["timestamp"]
        flags = (transport.get("flags") or "") if protocol == "TCP" else ""
        # Đóng các flow đã hết hạn trước, kể cả flow cũ của chính 5-tuple này.
        finished = self.observe_time(timestamp)

        key = flow_key(protocol, source, destination)
        flow = self._active.get(key)
        if flow is not None and flow.tcp is not None and flow.tcp.starts_new_connection(flags):
            finished.append(self._close(key, "new_connection"))
            flow = None
        if flow is None:
            if len(self._active) >= self.config.max_active_flows:
                finished.append(self._close(next(iter(self._active)), "table_full"))
            flow = self._open(key, source, destination, flags, timestamp)
        else:
            self._active.move_to_end(key)

        direction = "forward" if source == flow.endpoint_a else "backward"
        application = event.get("application") or {}
        flow.add_packet(direction, timestamp, _packet_size(event), flags, application.get("protocol"))
        event["flow_id"], event["direction"], event["flow_state"] = flow.flow_id, direction, flow.state
        if flow.state in FINISHED_STATES:
            finished.append(self._close(key, "tcp_closed" if flow.state == CLOSED else "tcp_reset"))
        return finished

    def observe_time(self, timestamp: float | None) -> list[dict[str, Any]]:
        """Ghi nhận thời điểm vừa thấy và đóng các flow đã hết hạn tính tới lúc đó.

        Với PCAP hay file event, "thời gian hiện tại" là timestamp lớn nhất đã
        đọc; khi bắt live, hàm này còn được gọi định kỳ với giờ hiện tại của máy.
        Bảng chỉ được rà khi thời gian vượt qua mốc sớm nhất có flow có thể hết
        hạn, nên không tốn công rà lại sau mỗi gói.
        """
        if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)):
            return []  # event không có thời điểm hợp lệ thì không làm thời gian trôi
        if self._now is None or timestamp > self._now:
            self._now = timestamp
        if self._next_deadline is None or self._now < self._next_deadline:
            return []
        expired = [key for key, flow in self._active.items() if self._now >= self._deadline(flow)]
        finished = [self._close(key, "idle_timeout") for key in expired]
        self._next_deadline = min((self._deadline(flow) for flow in self._active.values()), default=None)
        return finished

    def finish(self, reason: str) -> list[dict[str, Any]]:
        """Đóng mọi flow còn lại khi hết dữ liệu vào hoặc chương trình dừng."""
        finished = [self._close(key, reason) for key in list(self._active)]
        self._next_deadline = None
        return finished

    def _open(self, key: FlowKey, source: Endpoint, destination: Endpoint, flags: str,
              timestamp: float) -> Flow:
        """Tạo flow mới cho gói đầu tiên của một phiên."""
        self._created += 1
        protocol, first, second = key
        # flow_id là mã băm của 5-tuple, thời điểm bắt đầu và số thứ tự flow: chạy lại cùng
        # dữ liệu cho cùng ID, còn phiên mới trên cùng 5-tuple luôn có ID khác.
        identity = f"{protocol}|{first.ip}|{first.port}|{second.ip}|{second.port}|{timestamp:.6f}|{self._created}"
        flow_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
        # Gói đầu là SYN/ACK nghĩa là đã lỡ gói SYN: bên nhận gói này mới là bên mở kết nối.
        if "S" in flags and "A" in flags:
            source, destination = destination, source
        flow = Flow(flow_id, protocol, source, destination, timestamp, timestamp,
                    tcp=TcpConnection() if protocol == "TCP" else None)
        self._active[key] = flow
        deadline = self._deadline(flow)
        if self._next_deadline is None or deadline < self._next_deadline:
            self._next_deadline = deadline
        return flow

    def _close(self, key: FlowKey, reason: str) -> dict[str, Any]:
        """Xóa flow khỏi bảng và trả bản tổng kết kèm lý do kết thúc."""
        return self._active.pop(key).summary(reason)

    def _deadline(self, flow: Flow) -> float:
        """Thời điểm flow hết hạn nếu từ giờ không có thêm gói nào."""
        timeout = self.config.tcp_idle_timeout if flow.protocol == "TCP" else self.config.udp_idle_timeout
        return flow.last_seen + timeout


def _packet_size(event: dict[str, Any]) -> int:
    """Số byte của gói: độ dài gói bắt được; thiếu thì dùng tổng độ dài IP; không có thì 0."""
    for value in (event.get("captured_length"), (event.get("network") or {}).get("total_length")):
        if isinstance(value, int):
            return value
    return 0
