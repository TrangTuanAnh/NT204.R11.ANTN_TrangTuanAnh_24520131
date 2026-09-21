from __future__ import annotations

import re
from typing import Any

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet

from .utils import decode_payload, text_value


def parse_packet(packet: Any, packet_id: int, timestamp: float | None, source: str) -> dict[str, Any]:
    """Chuyển một packet Scapy thành sự kiện JSON-compatible."""
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
    try:
        return len(packet)
    except (TypeError, ValueError):
        return None


def _parse_network(event: dict[str, Any], packet: Packet) -> None:
    if not packet.haslayer(IP):
        return
    ip = packet[IP]
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
    transport = event["transport"] or {}
    ports = {transport.get("src_port"), transport.get("dst_port")}
    if 53 in ports and payload:
        wire = payload
        if transport.get('protocol') == 'TCP':
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
        event['application'] = _parse_dns(DNS(wire))
        event['status'] = 'ok'
        return
    text = decode_payload(payload)
    if transport.get('protocol') != 'TCP':
        return
    if _looks_like_http(text):
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
    elif _looks_like_smtp(text, ports):
        event["application"] = _parse_smtp(text)
        event["status"] = "ok"
        if not payload.endswith(b'\r\n'):
            event['status'] = 'partial'
            event['errors'].append('Dong SMTP chua ket thuc')
    elif event["network"] or event["transport"]:
        event["status"] = "unknown"


def _looks_like_http(text: str) -> bool:
    return bool(re.match(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+\S+\s+HTTP/1\.[01]\r?\n", text)) or bool(
        re.match(r"^HTTP/1\.[01]\s+\d{3}\b", text)
    )


def _parse_http(text: str) -> dict[str, Any]:
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
    headers: dict[str, str] = {}
    for line in lines:
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip()] = value.strip()
    return headers


def _looks_like_smtp(text: str, ports: set[int | None]) -> bool:
    return bool(re.match(r'^(?:EHLO |HELO |MAIL FROM:|RCPT TO:)', text, re.IGNORECASE)) or (
        bool(ports & {25, 587}) and bool(re.match(r'^[2-5]\d{2}[ -][\x20-\x7e]*\r?\n', text))
    )


def _parse_smtp(text: str) -> dict[str, Any]:
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


def _parse_dns(dns: DNS) -> dict[str, Any]:
    questions = []
    current = dns.qd
    for _ in range(int(dns.qdcount or 0)):
        if not isinstance(current, DNSQR):
            break
        questions.append({"name": text_value(current.qname), "type": current.qtype})
        current = current.payload

    answers = []
    current = dns.an
    for _ in range(int(dns.ancount or 0)):
        if not isinstance(current, DNSRR):
            break
        answers.append(
            {
                "name": text_value(current.rrname),
                "type": current.type,
                "data": text_value(current.rdata),
            }
        )
        current = current.payload
    return {
        "protocol": "DNS",
        "transaction_id": dns.id,
        "is_response": bool(dns.qr),
        "response_code": dns.rcode,
        "questions": questions,
        "answers": answers,
    }
