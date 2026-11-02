"""Rule Matching Engine: trả lời một rule có khớp với một gói hay không."""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import cached_property
from typing import Any

from src.rules.model import BIDIRECTIONAL, ContentOption, DsizeOption, FlagsOption, FlowOption, Rule

MATCH = "MATCH"
NO_MATCH = "NO_MATCH"

# Thứ tự kiểm tra: phần rẻ trước, tìm chuỗi trong dữ liệu (tốn công nhất) sau cùng.
HEADER, FLOW, PACKET, CONTENT = "header", "flow", "packet", "content"

# Hai nơi có thể tìm content: byte gốc của gói và dữ liệu ứng dụng đã giải mã.
PAYLOAD_BUFFER, APPLICATION_BUFFER = "payload", "application"

# Số lần thử tối đa khi tìm các content cho một rule trên một vùng dữ liệu,
# để dữ liệu lặp lại có chủ đích không làm chương trình chạy quá lâu.
_MAX_SEARCH_STEPS = 10000


@dataclass
class MatchResult:
    """Kết quả so khớp một rule với một gói."""

    verdict: str                    # MATCH hoặc NO_MATCH
    sid: int
    failed_at: str | None = None    # bước làm rule không khớp: header, flow, packet hoặc content
    reached_content: bool = False   # rule đã đi tới bước tìm content hay chưa
    matched: dict[str, Any] = field(default_factory=dict)  # thông tin khớp, dùng cho Detection Event


@dataclass(frozen=True)
class _Buffer:
    """Một vùng dữ liệu để tìm content, kèm bản chữ thường dùng cho nocase."""

    name: str
    data: bytes
    lowered: bytes


class PacketView:
    """Dữ liệu của một gói đã chuẩn hóa, dùng chung khi so khớp nhiều rule với gói đó."""

    def __init__(self, event: dict[str, Any], flow: dict[str, Any] | None = None,
                 payload: bytes | None = None) -> None:
        """Lấy sẵn các trường hay dùng; event đọc từ file không có byte gốc thì payload là None."""
        self.event = event
        self.flow = flow
        self.payload = payload
        network = event.get("network") or {}
        transport = event.get("transport") or {}
        self.source_ip = network.get("src_ip")
        self.destination_ip = network.get("dst_ip")
        self.protocol = transport.get("protocol")
        has_ports = self.protocol in ("TCP", "UDP")
        self.source_port = transport.get("src_port") if has_ports else None
        self.destination_port = transport.get("dst_port") if has_ports else None
        self.flags = transport.get("flags") if self.protocol == "TCP" else None
        size = transport.get("payload_length")
        self.payload_size = len(payload) if size is None and payload is not None else size

    @cached_property
    def buffers(self) -> list[_Buffer]:
        """Các vùng dữ liệu cần tìm content; chỉ dựng khi có rule đi tới bước này."""
        result = []
        if self.payload:
            result.append(_Buffer(PAYLOAD_BUFFER, self.payload, self.payload.lower()))
        application = _application_data(self.event)
        if application and application != self.payload:
            result.append(_Buffer(APPLICATION_BUFFER, application, application.lower()))
        return result


def match_rule(rule: Rule, packet: PacketView) -> MatchResult:
    """So khớp một rule với một gói theo thứ tự header → flow → cờ và kích thước → content."""
    reversed_side = _match_header(rule, packet)
    if reversed_side is None:
        return MatchResult(NO_MATCH, rule.sid, HEADER)
    if rule.flow is not None and not flow_fits(rule.flow, packet.flow):
        return MatchResult(NO_MATCH, rule.sid, FLOW)
    if rule.flags is not None and not flags_fit(rule.flags, packet.flags):
        return MatchResult(NO_MATCH, rule.sid, PACKET)
    if rule.dsize is not None and not dsize_fits(rule.dsize, packet.payload_size):
        return MatchResult(NO_MATCH, rule.sid, PACKET)
    matched: dict[str, Any] = {"reversed_direction": reversed_side}
    if rule.flow is not None:
        matched["flow"] = {name: packet.flow[name] for name in ("direction", "state", "established")}
    if rule.flags is not None:
        matched["flags"] = packet.flags
    if rule.dsize is not None:
        matched["dsize"] = packet.payload_size
    if not rule.contents:
        return MatchResult(MATCH, rule.sid, matched=matched)
    for buffer in packet.buffers:
        found = find_contents(rule.contents, buffer.data, buffer.lowered)
        if found is not None:
            matched.update(buffer=buffer.name, contents=found)
            return MatchResult(MATCH, rule.sid, reached_content=True, matched=matched)
    return MatchResult(NO_MATCH, rule.sid, CONTENT, reached_content=True)


def flow_fits(option: FlowOption, flow: dict[str, Any] | None) -> bool:
    """Kiểm tra chiều gói và trạng thái kết nối theo thông tin của Flow Tracker.

    Gói không được theo dõi flow (flow là None) không khớp rule có keyword flow.
    """
    if flow is None:
        return False
    if option.direction is not None and flow["to_server"] != (option.direction == "to_server"):
        return False
    if option.state is not None and flow["established"] != (option.state == "established"):
        return False
    return True


def flags_fit(option: FlagsOption, flags: str | None) -> bool:
    """So cờ của gói với điều kiện trong rule; gói không phải TCP thì không khớp.

    Chữ N (cờ NS) không có trong cú pháp của Snort nên được bỏ qua.
    """
    if flags is None:
        return False
    present = set(flags) - {"N"} - set(option.ignored)
    wanted = set(option.flags)
    if option.modifier == "+":
        return wanted <= present
    if option.modifier == "*":
        return bool(wanted & present)
    if option.modifier == "!":
        return not wanted & present
    return wanted == present


def dsize_fits(option: DsizeOption, size: int | None) -> bool:
    """So số byte dữ liệu của gói với điều kiện trong rule; không biết kích thước thì không khớp."""
    if size is None:
        return False
    if option.operator == ">":
        return size > option.low
    if option.operator == "<":
        return size < option.low
    if option.operator == "<>":
        return option.low <= size <= option.high
    return size == option.low


def find_contents(contents: tuple[ContentOption, ...], data: bytes, lowered: bytes) -> list[dict[str, Any]] | None:
    """Tìm lần lượt các content trên một vùng dữ liệu; trả vị trí tìm thấy, không khớp thì None.

    Nếu content sau không thỏa điều kiện tính từ vị trí của content trước thì quay
    lại thử chỗ xuất hiện tiếp theo của content trước.
    """
    steps = 0

    def search(index: int, cursor: int) -> list[dict[str, Any]] | None:
        """Tìm content thứ index; cursor là vị trí ngay sau chuỗi vừa tìm thấy trước đó."""
        nonlocal steps
        if index == len(contents):
            return []
        content = contents[index]
        text = lowered if content.nocase else data
        pattern = content.pattern.lower() if content.nocase else content.pattern
        start, end = _search_window(content, cursor, len(data))
        position = text.find(pattern, start, end)
        if content.negated:
            if position != -1:
                return None
            rest = search(index + 1, cursor)
            return None if rest is None else [_found(content, None)] + rest
        while position != -1 and steps < _MAX_SEARCH_STEPS:
            steps += 1
            rest = search(index + 1, position + len(pattern))
            if rest is not None:
                return [_found(content, position)] + rest
            position = text.find(pattern, position + 1, end)
        return None

    return search(0, 0)


def _search_window(content: ContentOption, cursor: int, size: int) -> tuple[int, int]:
    """Tính vùng [đầu, cuối) được phép chứa chuỗi cần tìm."""
    if content.is_relative:
        start = max(cursor + (content.distance or 0), 0)
        limit = content.within
    else:
        start = max(content.offset or 0, 0)
        limit = content.depth
    return start, size if limit is None else min(start + limit, size)


def _found(content: ContentOption, position: int | None) -> dict[str, Any]:
    """Thông tin một content đã thỏa; content phủ định không có vị trí."""
    return {"content": content.text, "position": position, "nocase": content.nocase, "negated": content.negated}


def _match_header(rule: Rule, packet: PacketView) -> bool | None:
    """Kiểm tra giao thức, IP, port và chiều.

    Trả False nếu khớp đúng chiều viết trong rule, True nếu khớp theo chiều ngược
    của rule "<>", None nếu không khớp.
    """
    if rule.protocol != "ip" and rule.protocol != str(packet.protocol).lower():
        return None
    if (rule.source.contains(packet.source_ip) and rule.destination.contains(packet.destination_ip)
            and rule.source_ports.contains(packet.source_port)
            and rule.destination_ports.contains(packet.destination_port)):
        return False
    if (rule.direction == BIDIRECTIONAL and rule.source.contains(packet.destination_ip)
            and rule.destination.contains(packet.source_ip)
            and rule.source_ports.contains(packet.destination_port)
            and rule.destination_ports.contains(packet.source_port)):
        return True
    return None


def _application_data(event: dict[str, Any]) -> bytes:
    """Dựng lại dữ liệu ứng dụng từ các trường đã phân tích và giải mã.

    Vùng này giúp tìm được chuỗi bị che bằng mã hóa (ví dụ "..%2f" giải mã thành
    "../", thư Base64) và tìm được khi event đọc từ file không có byte gốc.
    """
    application = event.get("application")
    decoded = event.get("decoded")
    application = application if isinstance(application, dict) else {}
    decoded = decoded if isinstance(decoded, dict) else {}
    protocol = application.get("protocol")
    if protocol == "HTTP":
        text = _http_text(application, decoded)
    elif protocol == "SMTP":
        text = _smtp_text(application, decoded)
    elif protocol == "DNS":
        text = _dns_text(application)
    else:
        text = _text(decoded.get("text"))
    return text.encode("utf-8", errors="replace")


def _text(value: Any) -> str:
    """Đổi một trường về chữ; trường thiếu hoặc sai kiểu thành chuỗi rỗng."""
    return value if isinstance(value, str) else "" if value is None else str(value)


def _header_lines(headers: Any) -> list[str]:
    """Viết lại các header thành từng dòng "tên: giá trị"."""
    return [f"{name}: {value}" for name, value in headers.items()] if isinstance(headers, dict) else []


def _http_text(application: dict[str, Any], decoded: dict[str, Any]) -> str:
    """Thông điệp HTTP với URI và body đã giải mã; event thiếu bản giải mã thì dùng bản gốc."""
    if application.get("message_type") == "response":
        first = f"{_text(application.get('version'))} {_text(application.get('status_code'))} " \
                f"{_text(application.get('reason'))}"
    else:
        uri = decoded.get("uri") or application.get("uri")
        first = f"{_text(application.get('method'))} {_text(uri)} {_text(application.get('version'))}"
    body = decoded.get("body") if decoded.get("body") is not None else application.get("body")
    return "\r\n".join([first, *_header_lines(application.get("headers")), "", _text(body)])


def _smtp_text(application: dict[str, Any], decoded: dict[str, Any]) -> str:
    """Lệnh, phản hồi hoặc nội dung thư SMTP đã giải mã."""
    message_type = application.get("message_type")
    if message_type == "response":
        return f"{_text(application.get('status_code'))} {_text(application.get('message'))}"
    if message_type == "data":
        body = decoded.get("body") if decoded.get("body") is not None else application.get("body")
        return "\r\n".join([*_header_lines(decoded.get("headers") or application.get("headers")), "", _text(body)])
    return f"{_text(application.get('command'))} {_text(application.get('argument'))}".strip()


def _dns_text(application: dict[str, Any]) -> str:
    """Các tên miền và dữ liệu trong câu hỏi, câu trả lời DNS, mỗi giá trị một dòng."""
    values: list[str] = []
    for section in ("questions", "answers"):
        records = application.get(section)
        for record in records if isinstance(records, list) else []:
            if isinstance(record, dict):
                values.extend(_text(record.get(name)) for name in ("name", "data") if record.get(name) is not None)
    return "\n".join(values)
