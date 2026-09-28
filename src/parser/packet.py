from __future__ import annotations

import re
import struct
from typing import Any

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet

from .utils import decode_payload, text_value


class IncompleteDNS(ValueError):
    """Thông báo DNS thiếu byte để đọc đủ các phần đã khai báo."""


def parse_packet(packet: Any, packet_id: int, timestamp: float | None, source: str) -> dict[str, Any]:
    """Tạo một event IDS từ packet với thông tin mạng, vận chuyển và ứng dụng.

    Giữ packet_id, timestamp và source do bên gọi cấp; trả status/errors để
    gói không hỗ trợ hoặc lỗi phân tích vẫn có kết quả ghi ra file.
    """
    event: dict[str, Any] = {
        "packet_id": packet_id,
        "timestamp": timestamp,
        "source": source,
        "captured_length": _captured_length(packet),
        "network": None,
        "transport": None,
        "application": {"protocol": None},
        "status": "unknown",
        "errors": [],
    }
    if not isinstance(packet, Packet):
        event["status"] = "malformed"
        event["errors"].append("packet không phải đối tượng Scapy")
        return event

    try:
        _parse_network(event, packet)
        _parse_transport(event, packet)
        network = event['network']
        if not network:
            return event
        if network and (network['fragment_offset'] or network['more_fragments']):
            event['status'] = 'partial'
            event['errors'].append('Chua tai lap cac manh IPv4')
            return event
        transport_layer = packet.getlayer(TCP) or packet.getlayer(UDP)
        payload = bytes(transport_layer.payload) if transport_layer else b''
        _parse_application(event, packet, payload)
        if network and network['total_length'] and len(bytes(packet[IP])) < network['total_length']:
            event['status'] = 'partial'
            event['errors'].append('Packet ngan hon do dai IPv4 khai bao')
    except Exception as exc:
        # Cô lập lỗi dữ liệu ở ranh giới từng packet; lỗi ghi file vẫn truyền ra ngoài.
        event["status"] = "malformed"
        event["errors"].append(f"không thể phân tích packet: {exc}")
    return event


def _captured_length(packet: Any) -> int | None:
    """Đo độ dài packet; trả None nếu len() gây TypeError hoặc ValueError."""
    try:
        return len(packet)
    except (TypeError, ValueError):
        return None


def _parse_network(event: dict[str, Any], packet: Packet) -> None:
    """Đọc các trường IPv4 và thêm chúng vào sự kiện."""
    if not packet.haslayer(IP):
        return
    ip = packet[IP]
    if ip.version != 4 or (ip.ihl is not None and ip.ihl < 5):
        raise ValueError('Header IPv4 khong hop le')
    if ip.len is not None and ip.len < (ip.ihl or 5) * 4:
        raise ValueError('Do dai IPv4 nho hon header')
    event["network"] = {
        "version": 4,
        "src_ip": ip.src,
        "dst_ip": ip.dst,
        "ttl": ip.ttl,
        "protocol": ip.proto,
        "total_length": ip.len,
        "fragment_offset": ip.frag,
        "more_fragments": bool(ip.flags.MF),
    }


def _parse_transport(event: dict[str, Any], packet: Packet) -> None:
    """Đọc các trường TCP hoặc UDP và thêm chúng vào sự kiện."""
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        event["transport"] = {
            "protocol": "TCP",
            "src_port": tcp.sport,
            "dst_port": tcp.dport,
            "sequence": tcp.seq,
            "acknowledgment": tcp.ack,
            "flags": str(tcp.flags),
            "window": tcp.window,
            "payload_length": len(bytes(tcp.payload)),
        }
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        event["transport"] = {
            "protocol": "UDP",
            "src_port": udp.sport,
            "dst_port": udp.dport,
            "length": udp.len,
            "payload_length": len(bytes(udp.payload)),
        }


def _parse_application(event: dict[str, Any], packet: Packet, payload: bytes) -> None:
    """Nhận diện và đọc HTTP/SMTP theo payload TCP, rồi xét DNS trên port 53.

    Cập nhật application, status và errors trực tiếp trong event.
    """
    transport = event["transport"] or {}
    ports = {transport.get("src_port"), transport.get("dst_port")}
    is_tcp = transport.get('protocol') == 'TCP'
    text = decode_payload(payload) if is_tcp else ''
    if is_tcp and _looks_like_http(text):
        event["application"] = _parse_http(text)
        event["status"] = "ok"
        headers = {k.lower(): v for k, v in event['application']['headers'].items()}
        separator = b'\r\n\r\n' if b'\r\n\r\n' in payload else b'\n\n'
        body = payload.partition(separator)[2]
        incomplete = separator not in payload
        if 'content-length' in headers:
            length = int(headers['content-length'])
            if length < 0:
                raise ValueError('Content-Length am')
            incomplete |= len(body) < length
        if 'transfer-encoding' in headers:
            incomplete = True
        if incomplete:
            event['status'] = 'partial'
            event['errors'].append('HTTP chua day du hoac chua ho tro transfer encoding')
    elif is_tcp and _looks_like_smtp(text, ports):
        event["application"] = _parse_smtp(text)
        event["status"] = "ok"
        if not payload.endswith(b'\r\n'):
            event['status'] = 'partial'
            event['errors'].append('Dong SMTP chua ket thuc')
    elif 53 in ports and payload:
        event['application'] = {'protocol': 'DNS'}
        wire = payload
        if is_tcp:
            size = int.from_bytes(wire[:2], 'big')
            if len(wire) < 2 or len(wire) - 2 < size:
                event['status'] = 'partial'
                event['errors'].append('Thieu du lieu DNS TCP')
                return
            wire = wire[2:2+size]
        if len(wire) < 12:
            event['status'] = 'partial'
            event['errors'].append('Thieu header DNS')
            return
        try:
            event['application'] = _parse_dns(wire)
        except IncompleteDNS as exc:
            event['status'] = 'partial'
            event['errors'].append(str(exc))
            return
        event['status'] = 'ok'
    elif event["network"] or event["transport"]:
        event["status"] = "unknown"


def _looks_like_http(text: str) -> bool:
    """Kiểm tra dòng đầu có đúng dạng request hoặc response HTTP/1.x không."""
    return bool(re.match(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+\S+\s+HTTP/1\.[01]\r?\n", text)) or bool(
        re.match(r"^HTTP/1\.[01]\s+\d{3}\b", text)
    )


def _parse_http(text: str) -> dict[str, Any]:
    """Tách dòng đầu, header và body của một thông điệp HTTP."""
    head, _, body = text.partition("\r\n\r\n")
    if not _:
        head, _, body = text.partition("\n\n")
    lines = head.splitlines()
    first = lines[0] if lines else ""
    headers = _parse_headers(lines[1:])
    if first.startswith("HTTP/"):
        parts = first.split(" ", 2)
        return {
            "protocol": "HTTP",
            "message_type": "response",
            "version": parts[0],
            "status_code": int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None,
            "reason": parts[2] if len(parts) > 2 else "",
            "headers": headers,
            "body": body,
        }
    parts = first.split(" ", 2)
    return {
        "protocol": "HTTP",
        "message_type": "request",
        "method": parts[0] if parts else None,
        "uri": parts[1] if len(parts) > 1 else None,
        "version": parts[2] if len(parts) > 2 else None,
        "headers": headers,
        "body": body,
    }


def _parse_headers(lines: list[str]) -> dict[str, str]:
    """Chuyển các dòng header thành các cặp tên và giá trị."""
    headers: dict[str, str] = {}
    for line in lines:
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip()] = value.strip()
    return headers


def _looks_like_smtp(text: str, ports: set[int | None]) -> bool:
    """Kiểm tra payload có dạng lệnh hoặc phản hồi SMTP được hỗ trợ không."""
    return bool(re.match(r'^(?:EHLO |HELO |MAIL FROM:|RCPT TO:)', text, re.IGNORECASE)) or (
        bool(ports & {25, 587}) and bool(re.match(r'^[2-5]\d{2}[ -][\x20-\x7e]*\r?\n', text))
    )


def _parse_smtp(text: str) -> dict[str, Any]:
    """Tách dòng SMTP thành lệnh hoặc mã phản hồi và nội dung."""
    line = text.splitlines()[0].strip() if text.splitlines() else ""
    match = re.match(r"^(\d{3})(?:[ -])(.*)$", line)
    if match:
        return {
            "protocol": "SMTP",
            "message_type": "response",
            "status_code": int(match.group(1)),
            "message": match.group(2),
        }
    command, _, argument = line.partition(" ")
    return {
        "protocol": "SMTP",
        "message_type": "command",
        "command": command.upper(),
        "argument": argument or None,
    }


def _dns_name_end(wire: bytes, offset: int) -> int:
    """Trả vị trí ngay sau tên DNS trên wire, kiểm tra nhãn và con trỏ nén."""
    end = None
    visited = set()
    expanded_length = 0
    while True:
        if offset >= len(wire):
            raise IncompleteDNS('DNS thieu du lieu ten mien')
        if offset in visited:
            raise ValueError('Con tro ten DNS lap vong')
        visited.add(offset)
        length = wire[offset]
        if length & 0xc0 == 0xc0:
            if offset + 2 > len(wire):
                raise IncompleteDNS('DNS thieu byte con tro ten mien')
            target = ((length & 0x3f) << 8) | wire[offset + 1]
            if target < 12 or target >= offset:
                raise ValueError('Con tro ten DNS khong hop le')
            if end is None:
                end = offset + 2
            offset = target
            continue
        if length & 0xc0:
            raise ValueError('Do dai nhan DNS khong hop le')
        offset += 1
        expanded_length += length + 1
        if expanded_length > 255:
            raise ValueError('Ten DNS vuot qua 255 byte')
        if offset + length > len(wire):
            raise IncompleteDNS('DNS thieu byte trong ten mien')
        if length == 0:
            return end if end is not None else offset
        offset += length


def _validate_dns_wire(wire: bytes) -> None:
    """Kiểm tra đủ câu hỏi và bản ghi ở cả bốn phần DNS từ byte gốc."""
    if len(wire) < 12:
        raise IncompleteDNS('Thieu header DNS')
    counts = struct.unpack('!4H', wire[4:12])
    offset = 12
    for section, count in enumerate(counts):
        for _ in range(count):
            offset = _dns_name_end(wire, offset)
            header_length = 4 if section == 0 else 10
            if offset + header_length > len(wire):
                raise IncompleteDNS('DNS thieu truong cua cau hoi hoac ban ghi')
            if section == 0:
                offset += header_length
                continue
            record_type = int.from_bytes(wire[offset:offset + 2], 'big')
            data_length = int.from_bytes(wire[offset + 8:offset + 10], 'big')
            offset += header_length
            end = offset + data_length
            if end > len(wire):
                raise IncompleteDNS('DNS thieu du lieu ban ghi')
            if record_type in (1, 28) and data_length != {1: 4, 28: 16}[record_type]:
                raise ValueError('Do dai dia chi DNS khong hop le')
            if record_type in (2, 5, 12):
                if _dns_name_end(wire, offset) != end:
                    raise ValueError('Do dai ten trong ban ghi DNS khong hop le')
            offset = end


def _dns_records(section: Any, expected: int) -> list[Packet]:
    """Lấy đúng số bản ghi Scapy; báo thiếu nếu ít hơn số header khai báo."""
    if isinstance(section, list):
        records = list(section)
    else:
        records = []
        current = section
        for _ in range(expected):
            if not isinstance(current, (DNSQR, DNSRR)):
                break
            records.append(current)
            current = current.payload
    if len(records) != expected:
        raise IncompleteDNS('So ban ghi DNS doc duoc khong khop header')
    return records


def _parse_dns(wire: bytes) -> dict[str, Any]:
    """Kiểm tra thông điệp DNS rồi trả ID, cờ phản hồi, câu hỏi và answer."""
    _validate_dns_wire(wire)
    dns = DNS(wire)
    questions = []
    for current in _dns_records(dns.qd, int(dns.qdcount or 0)):
        questions.append({"name": text_value(current.qname), "type": current.qtype})

    answers = []
    for current in _dns_records(dns.an, int(dns.ancount or 0)):
        answers.append(
            {
                "name": text_value(current.rrname),
                "type": current.type,
                "data": text_value(current.rdata),
            }
        )
    return {
        "protocol": "DNS",
        "transaction_id": dns.id,
        "is_response": bool(dns.qr),
        "response_code": dns.rcode,
        "questions": questions,
        "answers": answers,
    }
