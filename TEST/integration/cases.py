"""Đầu vào và kết quả mong đợi của 14 ca kiểm thử bắt buộc T01–T14 (Decoder, Preprocessor, Flow Tracker).

Gói tin được dựng bằng Scapy rồi lưu ra PCAP (dữ liệu tổng hợp, không gửi ra
mạng). Ca nào cần event thiếu hoặc sai trường thì dùng file JSON Lines.

Đường dẫn trong checks:
- "events.<i>.<trường>": event thứ i (tính từ 0) trong file event đầu ra.
- "flows.<i>.<trường>": bản tổng kết flow thứ i theo thứ tự được ghi ra.
- "flow_of_event.<i>.<trường>": bản tổng kết của flow chứa event thứ i.
- "exit_code", "event_count", "flow_count": mã thoát và số dòng đầu ra.
- "active_flows_trace": số flow còn trong bảng sau từng gói/event đầu vào.
"""

from __future__ import annotations

import base64
import json
import quopri
from dataclasses import dataclass, field
from typing import Any

from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, Raw, TCP, UDP

BASE_TIME = 1_700_000_000.0
CLIENT = "192.0.2.10"
SERVER = "192.0.2.20"
DNS_SERVER = "192.0.2.53"


@dataclass
class Case:
    """Một ca kiểm thử: đầu vào, cấu hình và các giá trị phải quan sát được."""

    case_id: str                      # mã ca trong đề, ví dụ "T07"
    name: str                         # tên thư mục lưu kết quả
    title: str                        # tên ngắn của ca
    requirement: str                  # kết quả mong đợi ghi trong đề
    scenario: str                     # mô tả dữ liệu đầu vào
    explanation: str                  # giải thích vì sao kết quả mong đợi như vậy
    checks: dict[str, Any]            # đường dẫn trường → giá trị mong đợi
    packets: list[Any] = field(default_factory=list)       # đầu vào dạng PCAP
    event_lines: list[str] = field(default_factory=list)   # đầu vào dạng JSON Lines
    config: dict[str, Any] = field(default_factory=dict)   # tùy chọn cấu hình khác mặc định
    same_flow: list[list[int]] = field(default_factory=list)       # các nhóm event phải cùng flow
    different_flow: list[list[int]] = field(default_factory=list)  # các nhóm event phải khác flow

    @property
    def input_name(self) -> str:
        """Tên file đầu vào trong thư mục của ca."""
        return "input.pcap" if self.packets else "input.jsonl"


# ---------------------------------------------------------------- dựng gói tin

def _frame(layers: Any, at: float) -> Any:
    """Thêm lớp Ethernet để lưu được vào PCAP và gán thời điểm BASE_TIME + at giây."""
    packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / layers
    packet.time = BASE_TIME + at
    return packet


def tcp(at: float, src: str, sport: int, dst: str, dport: int, flags: str,
        payload: bytes = b"", seq: int = 0, ack: int = 0) -> Any:
    """Tạo một gói IPv4/TCP với cờ và dữ liệu cho trước."""
    layers = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
    return _frame(layers / Raw(payload) if payload else layers, at)


def udp(at: float, src: str, sport: int, dst: str, dport: int, payload: Any) -> Any:
    """Tạo một gói IPv4/UDP; payload là byte hoặc một lớp Scapy như DNS."""
    return _frame(IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / payload, at)


def http_message(first_line: str, headers: dict[str, str], body: bytes = b"") -> bytes:
    """Ghép một thông điệp HTTP; có body thì tự thêm Content-Length đúng độ dài."""
    if body:
        headers = {**headers, "Content-Length": str(len(body))}
    head = "\r\n".join([first_line] + [f"{name}: {value}" for name, value in headers.items()])
    return head.encode("ascii") + b"\r\n\r\n" + body


def mail_data(headers: list[str], body: str) -> bytes:
    """Ghép nội dung một thư gửi sau lệnh DATA, kết thúc bằng dòng "." như SMTP."""
    return ("\r\n".join(headers) + "\r\n\r\n" + body + "\r\n.\r\n").encode("utf-8")


def size(*packets: Any) -> int:
    """Tổng số byte của các gói (độ dài khung Ethernet, giống captured_length)."""
    return sum(len(bytes(packet)) for packet in packets)


# ---------------------------------------------------------------- dựng event JSON

def parsed_event(packet_id: int, at: float, protocol: str = "TCP", src: str = CLIENT, sport: int = 40000,
                 dst: str = SERVER, dport: int = 80, flags: str = "A") -> dict[str, Any]:
    """Event giống hệt kết quả parser tạo cho một gói TCP/UDP không có dữ liệu ứng dụng."""
    transport: dict[str, Any] = {"protocol": protocol, "src_port": sport, "dst_port": dport}
    if protocol == "TCP":
        transport.update(sequence=0, acknowledgment=0, flags=flags, window=8192, payload_length=0)
    else:
        transport.update(length=8, payload_length=0)
    return {
        "packet_id": packet_id, "timestamp": BASE_TIME + at, "source": "pcap", "captured_length": 54,
        "network": {"version": 4, "src_ip": src, "dst_ip": dst, "ttl": 64,
                    "protocol": 6 if protocol == "TCP" else 17, "total_length": 40,
                    "fragment_offset": 0, "more_fragments": False},
        "transport": transport,
        "application": {"protocol": None},
        "status": "unknown",
        "errors": [],
    }


def json_lines(*events: Any) -> list[str]:
    """Đổi mỗi event thành một dòng JSON."""
    return [json.dumps(event, ensure_ascii=False) for event in events]


# ---------------------------------------------------------------- 14 ca kiểm thử

def required_cases() -> list[Case]:
    """Danh sách đủ 14 ca theo bảng test bắt buộc của đề."""
    return [
        _t01_http_url_decode(), _t02_html_entity(), _t03_smtp_mime(), _t04_invalid_bytes(),
        _t05_normalization(), _t06_missing_fields(), _t07_tcp_handshake(), _t08_bidirectional(),
        _t09_tcp_close(), _t10_udp_dns(), _t11_concurrent_flows(), _t12_idle_timeout(),
        _t13_statistics(), _t14_malformed_events(),
    ]


def _t01_http_url_decode() -> Case:
    """T01: URI và form có percent-encoding."""
    raw_uri = "/search?q=%27%20OR%201%3D1&lang=vi%2Ben&next=%2527"
    get = tcp(0.0, CLIENT, 40000, SERVER, 80, "PA",
              http_message(f"GET {raw_uri} HTTP/1.1", {"Host": "shop.example.test"}))
    form_body = b"user=admin%27--&pass=a+b%26c&note="
    post = tcp(1.0, CLIENT, 40000, SERVER, 80, "PA", http_message(
        "POST /login HTTP/1.1",
        {"Host": "shop.example.test", "Content-Type": "application/x-www-form-urlencoded"}, form_body))
    return Case(
        "T01", "t01_http_url_decode", "HTTP URL decode",
        "decoded URI đúng; raw URI còn nguyên",
        "Hai gói HTTP: GET có tham số mã hóa %XX (gồm cả %2527 là dấu % bị mã hóa hai lần) và "
        "POST có body dạng application/x-www-form-urlencoded.",
        "URI gốc ở application.uri giữ nguyên; decoded.uri giải mã một lượt nên %2527 chỉ thành %27. "
        "Trong tham số và form, dấu + là khoảng trắng còn %2B là dấu cộng thật.",
        {
            "exit_code": 0, "event_count": 2,
            "events.0.application.uri": raw_uri,
            "events.0.decoded.uri": "/search?q=' OR 1=1&lang=vi+en&next=%27",
            "events.0.decoded.query": [["q", "' OR 1=1"], ["lang", "vi+en"], ["next", "%27"]],
            "events.0.decode_status": "ok",
            "events.1.decoded.body": form_body.decode(),
            "events.1.decoded.form": [["user", "admin'--"], ["pass", "a b&c"], ["note", ""]],
            "events.1.decode_status": "ok",
        },
        packets=[get, post],
    )


def _t02_html_entity() -> Case:
    """T02: thực thể HTML trong nội dung chữ của HTTP."""
    html_body = ("<p>Xin chào &lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt; "
                 "&amp; &#39;ok&#39; &#x3C;b&#x3E;</p>").encode("utf-8")
    response = tcp(0.0, SERVER, 80, CLIENT, 40000, "PA", http_message(
        "HTTP/1.1 200 OK", {"Content-Type": "text/html; charset=utf-8"}, html_body))
    comment = tcp(1.0, CLIENT, 40001, SERVER, 80, "PA", http_message(
        "POST /comment HTTP/1.1", {"Host": "blog.example.test", "Content-Type": "text/plain; charset=utf-8"},
        "Bình luận: &lt;img src=x onerror=alert(1)&gt;".encode("utf-8")))
    json_body = b'{"note": "&lt;b&gt;"}'
    api = tcp(2.0, CLIENT, 40002, SERVER, 80, "PA", http_message(
        "POST /api HTTP/1.1", {"Host": "blog.example.test", "Content-Type": "application/json"}, json_body))
    return Case(
        "T02", "t02_html_entity_decode", "HTML entity",
        "decoded text đúng, không crash",
        "Ba gói HTTP: response text/html chứa &lt;script&gt;, &quot;, &#39;, &#x3C;...; request text/plain "
        "chứa &lt;img ...&gt;; request application/json chứa &lt;b&gt;.",
        "Nội dung dạng chữ (text/html, text/plain) được đổi thực thể HTML; body gốc ở application.body giữ "
        "nguyên. JSON không phải văn bản HTML nên giữ nguyên chuỗi &lt;b&gt;.",
        {
            "exit_code": 0, "event_count": 3,
            "events.0.application.body": html_body.decode("utf-8"),
            "events.0.decoded.body": "<p>Xin chào <script>alert(\"XSS\")</script> & 'ok' <b></p>",
            "events.0.decode_status": "ok",
            "events.1.decoded.body": "Bình luận: <img src=x onerror=alert(1)>",
            "events.1.decode_status": "ok",
            "events.2.decoded.body": json_body.decode(),
            "events.2.decode_status": "ok",
        },
        packets=[response, comment, api],
    )


def _t03_smtp_mime() -> Case:
    """T03: thư MIME mã hóa Base64 và Quoted-Printable."""
    plain_text = "Xin chào Bob,\r\nĐây là báo cáo IDS.\r\n"
    subject = "Báo cáo IDS"
    base64_mail = mail_data([
        "From: alice@example.test", "To: bob@example.test",
        "Subject: =?utf-8?b?" + base64.b64encode(subject.encode()).decode() + "?=",
        "MIME-Version: 1.0", "Content-Type: text/plain; charset=utf-8",
        "Content-Transfer-Encoding: base64",
    ], base64.encodebytes(plain_text.encode()).decode().strip())
    qp_text = "Giới thiệu: 1 + 1 = 2, dòng này được nối từ hai dòng mã hóa."
    attachment = b"\x00\x01\x02\x03\x04"
    multipart_mail = mail_data([
        "From: alice@example.test", "To: bob@example.test", "Subject: Quoted-Printable",
        "MIME-Version: 1.0", 'Content-Type: multipart/mixed; boundary="ranh-gioi"',
    ], "\r\n".join([
        "--ranh-gioi",
        "Content-Type: text/plain; charset=utf-8",
        "Content-Transfer-Encoding: quoted-printable",
        "",
        quopri.encodestring(qp_text.encode()).decode().replace("\n", "\r\n"),
        "--ranh-gioi",
        "Content-Type: application/octet-stream",
        "Content-Transfer-Encoding: base64",
        'Content-Disposition: attachment; filename="data.bin"',
        "",
        base64.b64encode(attachment).decode(),
        "--ranh-gioi--",
    ]))
    broken_mail = mail_data([
        "From: alice@example.test", "Subject: Base64 hong", "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=utf-8", "Content-Transfer-Encoding: base64",
    ], "@@@ khong phai base64 @@@")
    return Case(
        "T03", "t03_smtp_mime_decode", "SMTP Base64/QP",
        "decoded body đúng + decode_status",
        "Ba gói nội dung thư gửi tới port 25 sau lệnh DATA: thư Base64 (Subject dạng =?utf-8?b?...?=), "
        "thư nhiều phần gồm một phần Quoted-Printable và một file đính kèm Base64, và một thư Base64 hỏng.",
        "Cách giải mã lấy theo header Content-Transfer-Encoding của từng phần. Thư hỏng không giải mã được "
        "phần nào nên decode_status là error, nhưng chương trình vẫn chạy và ghi đủ ba event.",
        {
            "exit_code": 0, "event_count": 3,
            "events.0.application.message_type": "data",
            "events.0.decoded.headers.subject": subject,
            "events.0.decoded.body": plain_text,
            "events.0.decoded.mime_parts.0.transfer_encoding": "base64",
            "events.0.decoded.mime_parts.0.status": "ok",
            "events.0.decode_status": "ok",
            "events.1.decoded.body": qp_text,
            "events.1.decoded.mime_parts.0.transfer_encoding": "quoted-printable",
            "events.1.decoded.mime_parts.1.filename": "data.bin",
            "events.1.decoded.mime_parts.1.size": len(attachment),
            "events.1.decode_status": "ok",
            "events.2.decoded.mime_parts.0.status": "error",
            "events.2.decode_status": "error",
        },
        packets=[
            tcp(0.0, CLIENT, 40001, SERVER, 25, "PA", base64_mail),
            tcp(1.0, CLIENT, 40002, SERVER, 25, "PA", multipart_mail),
            tcp(2.0, CLIENT, 40003, SERVER, 25, "PA", broken_mail),
        ],
    )


def _t04_invalid_bytes() -> Case:
    """T04: dữ liệu không phải UTF-8 hợp lệ."""
    bad_body = tcp(0.0, CLIENT, 40000, SERVER, 80, "PA", http_message(
        "POST /upload HTTP/1.1", {"Host": "example.test", "Content-Type": "text/plain; charset=utf-8"},
        b"ten=\xff\xfeabc"))
    bad_uri = tcp(1.0, CLIENT, 40000, SERVER, 80, "PA",
                  http_message("GET /file%FFname HTTP/1.1", {"Host": "example.test"}))
    raw_payload = tcp(2.0, CLIENT, 40001, SERVER, 9000, "PA", payload=b"\xc3\x28 hello \x80")
    ascii_body = tcp(3.0, SERVER, 80, CLIENT, 40000, "PA", http_message(
        "HTTP/1.1 200 OK", {"Content-Type": "text/plain; charset=us-ascii"}, "café".encode("utf-8")))
    good = tcp(4.0, CLIENT, 40000, SERVER, 80, "PA", http_message("GET /ok HTTP/1.1", {"Host": "example.test"}))
    return Case(
        "T04", "t04_invalid_character_bytes", "Invalid bytes",
        "đánh dấu lỗi/partial; chương trình tiếp tục",
        "Năm gói: body khai báo UTF-8 nhưng có byte \\xff\\xfe; URI có %FF; payload TCP thô (port 9000) chứa "
        "\\xc3\\x28 và \\x80; body khai báo us-ascii nhưng chứa chữ \"é\"; cuối cùng là một GET hợp lệ.",
        "Byte sai được thay bằng ký tự �, decode_status là partial và decode_errors ghi vị trí byte lỗi. "
        "Gói hợp lệ cuối vẫn được xử lý bình thường, chứng tỏ chương trình không dừng.",
        {
            "exit_code": 0, "event_count": 5,
            "events.0.decoded.body": "ten=��abc",
            "events.0.decode_status": "partial",
            "events.0.decode_errors": ["Body HTTP: có byte không hợp lệ với bảng mã utf-8 (vị trí 4)"],
            "events.1.decoded.uri": "/file�name",
            "events.1.decode_status": "partial",
            "events.2.application.protocol": None,
            "events.2.decoded.text": "�( hello �",
            "events.2.decode_status": "partial",
            "events.3.decoded.body": "caf��",
            "events.3.decode_errors": ["Body HTTP: có byte không hợp lệ với bảng mã us-ascii (vị trí 3)"],
            "events.4.decoded.uri": "/ok",
            "events.4.decode_status": "ok",
        },
        packets=[bad_body, bad_uri, raw_payload, ascii_body, good],
    )


def _t05_normalization() -> Case:
    """T05: cùng một thông tin nhưng viết khác kiểu chữ hoặc định dạng."""
    first = parsed_event(1, 0.0, flags="pa")
    first["timestamp"] = "2026-10-02T07:00:00+07:00"
    first["transport"]["protocol"] = " tcp "
    first["application"] = {
        "protocol": "http", "message_type": "request", "method": "GET",
        "uri": "/Shop/./Products/../Index.HTML?ID=%7e5&q=%2f", "version": "HTTP/1.1",
        "headers": {"HOST": "WWW.Example.TEST.", "User-AGENT": "  curl/8.0  ",
                    "X-Forwarded-For": "198.51.100.7", "x-forwarded-for": "203.0.113.9"},
        "body": "",
    }
    second = parsed_event(2, 1.0)
    second["timestamp"] = "2026-10-02T00:00:01Z"
    second["transport"]["protocol"] = "Tcp"
    second["application"] = {"protocol": "Http", "message_type": "request", "method": "GET", "uri": "/",
                             "version": "HTTP/1.1", "headers": {"host": "www.example.test"}, "body": ""}
    dns = parsed_event(3, 2.0, protocol="udp", sport=53000, dport=53)
    dns["timestamp"] = "1790899202.5"
    dns["network"].update(version=6, src_ip="2001:DB8:0:0::A", dst_ip="2001:db8::0:35")
    dns["application"] = {
        "protocol": "Dns", "transaction_id": 4660, "is_response": True, "response_code": 0,
        "questions": [{"name": "WWW.Example.TEST.", "type": 28}],
        "answers": [{"name": "www.EXAMPLE.test", "type": 28, "data": "2001:0DB8:0000::0001"},
                    {"name": "Example.TEST", "type": 5, "data": "ALIAS.Example.TEST."}],
    }
    return Case(
        "T05", "t05_event_normalization", "Normalization",
        "representation sau preprocess nhất quán",
        "Ba event JSON viết khác kiểu: tên giao thức \" tcp \", \"Tcp\", \"http\", \"Dns\"; header HOST/User-AGENT; "
        "tên miền chữ hoa có dấu chấm cuối; IPv6 viết dài; timestamp dạng ISO có múi giờ, dạng Z và chuỗi số; "
        "URI có \"./\", \"../\" và %7e.",
        "Sau Preprocessor: tên giao thức viết hoa, tên header viết thường (header trùng tên được gộp), tên miền "
        "viết thường không có dấu chấm cuối, IP theo cách viết chuẩn, timestamp là số giây Unix. URI gốc giữ "
        "nguyên, uri_normalized bỏ \"./\", \"../\" và giải mã %7e thành ~ nhưng giữ %2F.",
        {
            "exit_code": 0, "event_count": 3,
            "events.0.timestamp": 1790899200.0,
            "events.0.transport.protocol": "TCP",
            "events.0.transport.flags": "PA",
            "events.0.application.protocol": "HTTP",
            "events.0.application.headers": {"host": "www.example.test", "user-agent": "curl/8.0",
                                             "x-forwarded-for": "198.51.100.7, 203.0.113.9"},
            "events.0.application.uri": "/Shop/./Products/../Index.HTML?ID=%7e5&q=%2f",
            "events.0.application.uri_normalized": "/Shop/Index.HTML?ID=~5&q=%2F",
            "events.0.preprocess_status": "valid",
            "events.1.timestamp": 1790899201.0,
            "events.1.transport.protocol": "TCP",
            "events.1.application.protocol": "HTTP",
            "events.1.application.headers.host": "www.example.test",
            "events.2.timestamp": 1790899202.5,
            "events.2.network.src_ip": "2001:db8::a",
            "events.2.network.dst_ip": "2001:db8::35",
            "events.2.transport.protocol": "UDP",
            "events.2.application.protocol": "DNS",
            "events.2.application.questions": [{"name": "www.example.test", "type": 28}],
            "events.2.application.answers": [{"name": "www.example.test", "type": 28, "data": "2001:db8::1"},
                                             {"name": "example.test", "type": 5, "data": "alias.example.test"}],
            "events.2.preprocess_status": "valid",
        },
        event_lines=json_lines(first, second, dns),
    )


def _t06_missing_fields() -> Case:
    """T06: event thiếu các trường không bắt buộc."""
    tcp_event = parsed_event(1, 0.0, flags="S")
    for name in ("captured_length", "errors", "status", "application"):
        del tcp_event[name]
    for name in ("ttl", "fragment_offset", "more_fragments"):
        del tcp_event["network"][name]
    for name in ("sequence", "acknowledgment", "window"):
        del tcp_event["transport"][name]
    dns_event = parsed_event(2, 1.0, protocol="UDP", sport=53000, dport=53)
    dns_event["application"] = {"protocol": "DNS", "questions": [{"name": "example.test", "type": 1}]}
    http_event = parsed_event(3, 2.0, sport=40001)
    http_event["application"] = {"protocol": "HTTP", "method": "GET", "uri": "/"}
    no_notes = parsed_event(4, 3.0, sport=40002)
    for name in ("packet_id", "source"):
        del no_notes[name]
    return Case(
        "T06", "t06_missing_optional_fields", "Missing field",
        "xử lý null/[] nhất quán, không exception",
        "Bốn event JSON: TCP thiếu captured_length, errors, status, application, ttl, sequence, window...; "
        "DNS thiếu answers và transaction_id; HTTP thiếu headers, body, version; event thiếu packet_id, source.",
        "Trường thiếu được điền null, danh sách thiếu thành [], header thiếu thành {}. Event thiếu trường thông "
        "tin gói có trạng thái partial (reason liệt kê trường thiếu) nhưng vẫn được theo dõi flow; byte_count "
        "dùng network.total_length khi thiếu captured_length.",
        {
            "exit_code": 0, "event_count": 4, "flow_count": 4,
            "events.0.captured_length": None,
            "events.0.errors": [],
            "events.0.status": None,
            "events.0.application": {"protocol": None},
            "events.0.network.ttl": None,
            "events.0.transport.window": None,
            "events.0.preprocess_status": "partial",
            "events.0.processing_action": "process",
            "events.0.reason": ["Thiếu trường không bắt buộc, đã điền null: captured_length, network.ttl, "
                                "network.fragment_offset, network.more_fragments, transport.sequence, "
                                "transport.acknowledgment, transport.window"],
            "flow_of_event.0.byte_count": 40,
            "events.1.application.answers": [],
            "events.1.application.transaction_id": None,
            "events.1.preprocess_status": "valid",
            "events.2.application.headers": {},
            "events.2.application.body": None,
            "events.2.application.version": None,
            "events.2.decoded.uri": "/",
            "events.3.packet_id": None,
            "events.3.source": None,
            "events.3.preprocess_status": "valid",
        },
        event_lines=json_lines(tcp_event, dns_event, http_event, no_notes),
        same_flow=[[0], [1], [2], [3]],
    )


def _t07_tcp_handshake() -> Case:
    """T07: bắt tay ba bước SYN → SYN/ACK → ACK."""
    return Case(
        "T07", "t07_tcp_connection_handshake", "TCP handshake",
        "1 flow; trạng thái ESTABLISHED",
        "Ba gói: client 192.0.2.10:40000 gửi SYN, server 192.0.2.20:80 trả SYN/ACK, client gửi ACK.",
        "Sau từng gói, trạng thái lần lượt là NEW → HANDSHAKE → ESTABLISHED; cả ba gói thuộc một flow và "
        "handshake_observed là true.",
        {
            "exit_code": 0, "event_count": 3, "flow_count": 1,
            "events.0.flow_state": "NEW",
            "events.1.flow_state": "HANDSHAKE",
            "events.2.flow_state": "ESTABLISHED",
            "flows.0.state": "ESTABLISHED",
            "flows.0.handshake_observed": True,
            "flows.0.packet_count": 3,
            "flows.0.SYN_count": 2,
            "flows.0.ACK_count": 2,
            "flows.0.end_reason": "end_of_input",
        },
        packets=[
            tcp(0.00, CLIENT, 40000, SERVER, 80, "S", seq=1000),
            tcp(0.01, SERVER, 80, CLIENT, 40000, "SA", seq=5000, ack=1001),
            tcp(0.02, CLIENT, 40000, SERVER, 80, "A", seq=1001, ack=5001),
        ],
        same_flow=[[0, 1, 2]],
    )


def _t08_bidirectional() -> Case:
    """T08: gói hai chiều của cùng một phiên."""
    client = "198.51.100.200"  # IP của client lớn hơn IP server, để thấy chiều không phụ thuộc thứ tự IP
    request = http_message("GET / HTTP/1.1", {"Host": "example.test"})
    response = http_message("HTTP/1.1 200 OK", {"Content-Type": "text/plain"}, b"OK")
    packets = [
        tcp(0.00, client, 51000, SERVER, 80, "S", seq=10),
        tcp(0.01, SERVER, 80, client, 51000, "SA", seq=20, ack=11),
        tcp(0.02, client, 51000, SERVER, 80, "A", seq=11, ack=21),
        tcp(0.03, client, 51000, SERVER, 80, "PA", request, seq=11, ack=21),
        tcp(0.04, SERVER, 80, client, 51000, "PA", response, seq=21, ack=11 + len(request)),
        tcp(0.05, client, 51000, SERVER, 80, "A", seq=11 + len(request), ack=21 + len(response)),
    ]
    return Case(
        "T08", "t08_bidirectional_flow", "Bidirectional flow",
        "cùng flow_id; đúng direction",
        "Sáu gói qua lại giữa client 198.51.100.200:51000 và server 192.0.2.20:80 (bắt tay, request, response, "
        "ACK). IP của client lớn hơn IP server.",
        "Cả sáu gói cùng flow_id. endpoint_a là bên gửi gói đầu tiên (client), nên gói client → server là "
        "forward, gói server → client là backward, dù khóa tra flow sắp xếp IP server lên trước.",
        {
            "exit_code": 0, "event_count": 6, "flow_count": 1,
            "events.0.direction": "forward", "events.1.direction": "backward", "events.2.direction": "forward",
            "events.3.direction": "forward", "events.4.direction": "backward", "events.5.direction": "forward",
            "flows.0.endpoint_a": {"ip": client, "port": 51000},
            "flows.0.endpoint_b": {"ip": SERVER, "port": 80},
            "flows.0.forward_packet_count": 4,
            "flows.0.backward_packet_count": 2,
            "flows.0.forward_byte_count": size(packets[0], packets[2], packets[3], packets[5]),
            "flows.0.backward_byte_count": size(packets[1], packets[4]),
            "flows.0.application_protocol": "HTTP",
        },
        packets=packets,
        same_flow=[[0, 1, 2, 3, 4, 5]],
    )


def _t09_tcp_close() -> Case:
    """T09: đóng kết nối bằng FIN/ACK và ngắt bằng RST."""
    return Case(
        "T09", "t09_tcp_connection_close", "TCP close",
        "flow chuyển CLOSED/RESET phù hợp",
        "Hai kết nối. Kết nối 1 (port 40001): bắt tay, client FIN/ACK, server ACK, server FIN/ACK, client ACK. "
        "Kết nối 2 (port 40002): bắt tay rồi server gửi RST/ACK.",
        "Kết nối 1 ở CLOSING từ gói FIN đầu tiên và chuyển CLOSED khi FIN thứ hai được ACK. Kết nối 2 chuyển "
        "RESET ngay khi có RST. Cả hai flow được ghi ra (tcp_closed, tcp_reset) và xóa khỏi bảng, nên sau gói "
        "cuối bảng flow rỗng.",
        {
            "exit_code": 0, "event_count": 11, "flow_count": 2,
            "events.2.flow_state": "ESTABLISHED",
            "events.3.flow_state": "CLOSING",
            "events.4.flow_state": "CLOSING",
            "events.5.flow_state": "CLOSING",
            "events.6.flow_state": "CLOSED",
            "events.10.flow_state": "RESET",
            "flows.0.state": "CLOSED", "flows.0.end_reason": "tcp_closed", "flows.0.FIN_count": 2,
            "flows.1.state": "RESET", "flows.1.end_reason": "tcp_reset", "flows.1.RST_count": 1,
            "active_flows_trace": [1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0],
        },
        packets=[
            tcp(0.00, CLIENT, 40001, SERVER, 80, "S", seq=100),
            tcp(0.01, SERVER, 80, CLIENT, 40001, "SA", seq=300, ack=101),
            tcp(0.02, CLIENT, 40001, SERVER, 80, "A", seq=101, ack=301),
            tcp(0.10, CLIENT, 40001, SERVER, 80, "FA", seq=101, ack=301),
            tcp(0.11, SERVER, 80, CLIENT, 40001, "A", seq=301, ack=102),
            tcp(0.12, SERVER, 80, CLIENT, 40001, "FA", seq=301, ack=102),
            tcp(0.13, CLIENT, 40001, SERVER, 80, "A", seq=102, ack=302),
            tcp(1.00, CLIENT, 40002, SERVER, 80, "S", seq=500),
            tcp(1.01, SERVER, 80, CLIENT, 40002, "SA", seq=700, ack=501),
            tcp(1.02, CLIENT, 40002, SERVER, 80, "A", seq=501, ack=701),
            tcp(1.10, SERVER, 80, CLIENT, 40002, "RA", seq=701, ack=501),
        ],
        same_flow=[[0, 1, 2, 3, 4, 5, 6], [7, 8, 9, 10]],
        different_flow=[[0, 7]],
    )


def _t10_udp_dns() -> Case:
    """T10: DNS query/response qua UDP."""
    query = udp(0.0, CLIENT, 53000, DNS_SERVER, 53, DNS(id=0x1A2B, rd=1, qd=DNSQR(qname="www.example.test")))
    answer = udp(0.05, DNS_SERVER, 53, CLIENT, 53000, DNS(
        id=0x1A2B, qr=1, rd=1, ra=1, qd=DNSQR(qname="www.example.test"),
        an=DNSRR(rrname="www.example.test", type="A", rdata="192.0.2.80", ttl=300)))
    return Case(
        "T10", "t10_udp_dns_flow", "UDP query/response",
        "1 UDP flow, packet/byte count đúng",
        "Một truy vấn DNS từ 192.0.2.10:53000 tới 192.0.2.53:53 và câu trả lời ngược lại (bản ghi A 192.0.2.80).",
        "Hai gói ngược chiều cùng 5-tuple tạo một flow UDP. byte_count là tổng độ dài hai khung Ethernet "
        f"({size(query)} + {size(answer)} byte). UDP không có trạng thái kết nối nên state và các bộ đếm "
        "cờ TCP là null.",
        {
            "exit_code": 0, "event_count": 2, "flow_count": 1,
            "events.0.direction": "forward", "events.1.direction": "backward",
            "events.1.application.answers": [{"name": "www.example.test", "type": 1, "data": "192.0.2.80"}],
            "flows.0.protocol": "UDP",
            "flows.0.application_protocol": "DNS",
            "flows.0.packet_count": 2,
            "flows.0.byte_count": size(query, answer),
            "flows.0.forward_packet_count": 1, "flows.0.forward_byte_count": size(query),
            "flows.0.backward_packet_count": 1, "flows.0.backward_byte_count": size(answer),
            "flows.0.duration": 0.05,
            "flows.0.state": None,
            "flows.0.SYN_count": None,
        },
        packets=[query, answer],
        same_flow=[[0, 1]],
    )


def _t11_concurrent_flows() -> Case:
    """T11: nhiều flow xen kẽ nhau."""
    other_client = "192.0.2.11"
    packets = [
        tcp(0.00, CLIENT, 40001, SERVER, 80, "S"),              # flow 1
        tcp(0.01, CLIENT, 40002, SERVER, 80, "S"),              # flow 2: khác port client
        tcp(0.02, other_client, 40001, SERVER, 80, "S"),        # flow 3: khác IP client
        udp(0.03, CLIENT, 40001, SERVER, 80, b"ping"),          # flow 4: cùng IP/port với flow 1 nhưng là UDP
        tcp(0.04, SERVER, 80, CLIENT, 40001, "SA"),
        tcp(0.05, SERVER, 80, CLIENT, 40002, "SA"),
        udp(0.06, SERVER, 80, CLIENT, 40001, b"pong"),
        tcp(0.07, SERVER, 80, other_client, 40001, "SA"),
        tcp(0.08, CLIENT, 40001, SERVER, 80, "A"),
        tcp(0.09, CLIENT, 40002, SERVER, 80, "A"),
        tcp(0.10, other_client, 40001, SERVER, 80, "A"),
    ]
    return Case(
        "T11", "t11_concurrent_flows", "Concurrent flows",
        "không gộp nhầm flow",
        "Mười một gói xen kẽ của bốn phiên tới 192.0.2.20:80: TCP từ 192.0.2.10:40001, TCP từ 192.0.2.10:40002 "
        "(khác port), TCP từ 192.0.2.11:40001 (khác IP) và UDP từ 192.0.2.10:40001 (cùng IP/port với phiên đầu "
        "nhưng khác giao thức).",
        "Mỗi phiên có flow riêng: bốn flow_id khác nhau, ba flow TCP mỗi flow 3 gói ở trạng thái ESTABLISHED, "
        "flow UDP 2 gói.",
        {
            "exit_code": 0, "event_count": 11, "flow_count": 4,
            "flow_of_event.0.packet_count": 3, "flow_of_event.0.state": "ESTABLISHED",
            "flow_of_event.1.packet_count": 3, "flow_of_event.1.state": "ESTABLISHED",
            "flow_of_event.2.packet_count": 3, "flow_of_event.2.state": "ESTABLISHED",
            "flow_of_event.3.packet_count": 2, "flow_of_event.3.protocol": "UDP",
            "active_flows_trace": [1, 2, 3, 4, 4, 4, 4, 4, 4, 4, 4],
        },
        packets=packets,
        same_flow=[[0, 4, 8], [1, 5, 9], [2, 7, 10], [3, 6]],
        different_flow=[[0, 1, 2, 3]],
    )


def _t12_idle_timeout() -> Case:
    """T12: flow không có gói mới quá thời gian chờ."""
    def dns_query(at: float, port: int) -> Any:
        """Truy vấn DNS từ port cho trước."""
        return udp(at, CLIENT, port, DNS_SERVER, 53, DNS(id=port, rd=1, qd=DNSQR(qname="example.test")))

    def dns_answer(at: float, port: int) -> Any:
        """Câu trả lời DNS gửi về port cho trước."""
        return udp(at, DNS_SERVER, 53, CLIENT, port, DNS(id=port, qr=1, qd=DNSQR(qname="example.test")))

    return Case(
        "T12", "t12_flow_idle_timeout", "Idle timeout",
        "flow hết hạn và bị loại khỏi active table",
        "Cấu hình udp_idle_timeout = 5 giây, tcp_idle_timeout = 10 giây. Flow UDP A (port 50000) có gói ở giây "
        "0 và 0,1; flow TCP bắt tay ở giây 1–1,2; flow UDP B (port 50001) có gói ở giây 3 và 4; giây 8 có truy "
        "vấn mới từ port 50000; giây 12 có câu trả lời cho truy vấn đó.",
        "Giây 8: flow A đã im lặng 7,9 giây (≥ 5) nên được ghi ra với lý do idle_timeout và xóa khỏi bảng; gói "
        "mới từ port 50000 tạo flow mới với flow_id khác. Flow B mới im lặng 4 giây nên chưa hết hạn. Giây 12: "
        "flow B (im lặng 8 giây) và flow TCP (10,8 giây) hết hạn. active_flows_trace cho thấy số flow trong "
        "bảng giảm đúng lúc.",
        {
            "exit_code": 0, "event_count": 9, "flow_count": 4,
            "flows.0.end_reason": "idle_timeout",
            "flows.0.endpoint_a": {"ip": CLIENT, "port": 50000},
            "flows.0.packet_count": 2,
            "flow_of_event.2.end_reason": "idle_timeout",
            "flow_of_event.2.state": "ESTABLISHED",
            "flow_of_event.5.end_reason": "idle_timeout",
            "flow_of_event.7.end_reason": "end_of_input",
            "flow_of_event.7.packet_count": 2,
            "active_flows_trace": [1, 1, 2, 2, 2, 3, 3, 3, 1],
        },
        packets=[
            dns_query(0.0, 50000), dns_answer(0.1, 50000),
            tcp(1.0, CLIENT, 40000, SERVER, 80, "S"), tcp(1.1, SERVER, 80, CLIENT, 40000, "SA"),
            tcp(1.2, CLIENT, 40000, SERVER, 80, "A"),
            dns_query(3.0, 50001), dns_answer(4.0, 50001),
            dns_query(8.0, 50000), dns_answer(12.0, 50000),
        ],
        config={"udp_idle_timeout": 5, "tcp_idle_timeout": 10},
        same_flow=[[0, 1], [5, 6], [7, 8]],
        different_flow=[[0, 7]],
    )


def _t13_statistics() -> Case:
    """T13: thống kê một phiên TCP đầy đủ."""
    request = http_message("POST /upload HTTP/1.1", {"Host": "example.test", "Content-Type": "text/plain"},
                           b"x" * 64)
    response = http_message("HTTP/1.1 200 OK", {"Content-Type": "text/plain"}, b"uploaded")
    forward = [
        tcp(0.000, CLIENT, 40000, SERVER, 80, "S", seq=100),
        tcp(0.020, CLIENT, 40000, SERVER, 80, "A", seq=101, ack=301),
        tcp(0.100, CLIENT, 40000, SERVER, 80, "PA", request, seq=101, ack=301),
        tcp(0.250, CLIENT, 40000, SERVER, 80, "A", seq=101 + len(request), ack=301 + len(response)),
        tcp(0.300, CLIENT, 40000, SERVER, 80, "FA", seq=101 + len(request), ack=301 + len(response)),
        tcp(0.320, CLIENT, 40000, SERVER, 80, "A", seq=102 + len(request), ack=302 + len(response)),
    ]
    backward = [
        tcp(0.010, SERVER, 80, CLIENT, 40000, "SA", seq=300, ack=101),
        tcp(0.150, SERVER, 80, CLIENT, 40000, "A", seq=301, ack=101 + len(request)),
        tcp(0.200, SERVER, 80, CLIENT, 40000, "PA", response, seq=301, ack=101 + len(request)),
        tcp(0.310, SERVER, 80, CLIENT, 40000, "FA", seq=301 + len(response), ack=102 + len(request)),
    ]
    packets = sorted(forward + backward, key=lambda packet: packet.time)
    return Case(
        "T13", "t13_flow_statistics", "Statistics",
        "packet/byte/flag counters và duration đúng",
        "Một phiên TCP đầy đủ gồm 10 gói trong 0,32 giây: bắt tay, client gửi POST 64 byte dữ liệu, server ACK "
        "rồi trả response, client ACK, hai bên trao đổi FIN/ACK và ACK cuối.",
        f"Chiều forward (client → server) có 6 gói, {size(*forward)} byte; chiều backward có 4 gói, "
        f"{size(*backward)} byte. Cờ: 2 SYN (SYN, SYN/ACK), 9 ACK (mọi gói trừ SYN đầu), 2 FIN, 0 RST. "
        "Duration = 0,32 giây; flow kết thúc ở trạng thái CLOSED.",
        {
            "exit_code": 0, "event_count": 10, "flow_count": 1,
            "flows.0.packet_count": 10,
            "flows.0.byte_count": size(*packets),
            "flows.0.forward_packet_count": 6, "flows.0.forward_byte_count": size(*forward),
            "flows.0.backward_packet_count": 4, "flows.0.backward_byte_count": size(*backward),
            "flows.0.SYN_count": 2, "flows.0.ACK_count": 9, "flows.0.FIN_count": 2, "flows.0.RST_count": 0,
            "flows.0.start_time": BASE_TIME, "flows.0.last_seen": BASE_TIME + 0.32, "flows.0.duration": 0.32,
            "flows.0.state": "CLOSED", "flows.0.handshake_observed": True,
            "flows.0.application_protocol": "HTTP", "flows.0.end_reason": "tcp_closed",
        },
        packets=packets,
        same_flow=[list(range(10))],
    )


def _t14_malformed_events() -> Case:
    """T14: event hỏng hoặc chưa được hỗ trợ."""
    bad_port = parsed_event(4, 3.0)
    bad_port["transport"]["src_port"] = -1
    bad_time = parsed_event(5, 4.0)
    bad_time["timestamp"] = "hôm qua"
    bad_ip = parsed_event(6, 5.0)
    bad_ip["network"]["src_ip"] = "999.0.0.1"
    mismatch = parsed_event(7, 6.0, protocol="UDP")
    mismatch["network"]["protocol"] = 6
    icmp = parsed_event(8, 7.0)
    icmp["network"]["protocol"] = 1
    icmp["transport"] = None
    sctp = parsed_event(9, 8.0)
    sctp["transport"] = {"protocol": "SCTP", "src_port": 1000, "dst_port": 2000}
    broken_dns = parsed_event(11, 10.0, protocol="UDP", sport=53000, dport=53)
    broken_dns.update(status="malformed", errors=["không thể phân tích packet: Con tro ten DNS lap vong"],
                      application={"protocol": "DNS"})
    lines = json_lines(parsed_event(1, 0.0)) + ["{broken json", "[1, 2, 3]"]
    lines += json_lines(bad_port, bad_time, bad_ip, mismatch, icmp, sctp)
    lines += [json.dumps(parsed_event(10, 9.0)).replace("1700000009.0", "NaN")]
    lines += json_lines(broken_dns, parsed_event(12, 11.0))
    return Case(
        "T14", "t14_malformed_event", "Malformed event",
        "không crash; status/reason phù hợp",
        "Mười hai dòng JSON Lines: event hợp lệ; dòng không phải JSON; mảng JSON; port -1; timestamp \"hôm qua\"; "
        "IP 999.0.0.1; IP protocol 6 nhưng transport UDP; gói ICMP; giao thức SCTP; timestamp NaN; event DNS bị "
        "parser đánh dấu malformed; event hợp lệ cùng phiên với dòng đầu.",
        "Dữ liệu sai được đánh dấu invalid và skip, giao thức chưa hỗ trợ được đánh dấu partial và skip, mỗi "
        "event có reason giải thích. Event DNS malformed vẫn có IP/UDP hợp lệ nên được đếm vào flow. Chương "
        "trình đọc hết 12 dòng, mã thoát 0, và dòng cuối vẫn được gắn đúng vào flow của dòng đầu.",
        {
            "exit_code": 0, "event_count": 12, "flow_count": 2,
            "events.0.processing_action": "process",
            "events.1.preprocess_status": "invalid", "events.1.processing_action": "skip",
            "events.1.errors": ["Dòng 2 không phải JSON hợp lệ (Expecting property name enclosed in double quotes)"],
            "events.2.preprocess_status": "invalid",
            "events.2.errors": ["Dòng 3 không phải JSON object"],
            "events.3.preprocess_status": "invalid",
            "events.3.reason": ["transport.src_port không hợp lệ: -1"],
            "events.4.preprocess_status": "invalid",
            "events.4.reason": ["timestamp không hợp lệ (không đọc được dạng thời gian): 'hôm qua'"],
            "events.5.reason": ["network.src_ip không phải địa chỉ IP hợp lệ: '999.0.0.1'"],
            "events.6.reason": ["network.protocol (6) không khớp với UDP"],
            "events.7.preprocess_status": "partial", "events.7.processing_action": "skip",
            "events.7.reason": ["Giao thức IP số 1 chưa được hỗ trợ (chỉ theo dõi TCP/UDP)"],
            "events.8.preprocess_status": "partial", "events.8.processing_action": "skip",
            "events.8.reason": ["Giao thức vận chuyển SCTP chưa được hỗ trợ (chỉ theo dõi TCP/UDP)"],
            "events.9.preprocess_status": "invalid",
            "events.9.timestamp": None,
            "events.10.preprocess_status": "partial", "events.10.processing_action": "process",
            "events.11.processing_action": "process",
            "flow_of_event.0.packet_count": 2,
        },
        event_lines=lines,
        same_flow=[[0, 11], [10]],
    )
