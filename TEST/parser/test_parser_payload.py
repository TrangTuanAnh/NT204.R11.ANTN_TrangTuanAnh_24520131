"""Kiểm thử phần parser bổ sung cho Bài tập 2: lấy payload, byte đệm Ethernet, nội dung thư SMTP."""

from __future__ import annotations

from scapy.all import ARP, Ether, IP, TCP, UDP, Raw

from src.parser import extract_payload, parse_packet

# Ghi rõ địa chỉ MAC để Scapy không phải gửi ARP ra mạng thật khi dựng gói.
ETHERNET = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")


def smtp_packet(payload: bytes, port: int = 25):
    """Gói TCP gửi tới port SMTP với dữ liệu cho trước."""
    return ETHERNET / IP(src="192.0.2.1", dst="192.0.2.2") / TCP(sport=40000, dport=port, flags="PA") / Raw(payload)


def test_ethernet_padding_is_not_payload():
    # Khung Ethernet ngắn được đệm thêm byte 0 cho đủ 60 byte; các byte này không phải dữ liệu TCP.
    syn = Ether(bytes(ETHERNET / IP(src="192.0.2.1", dst="192.0.2.2") / TCP(flags="S")) + b"\x00" * 6)
    data = Ether(bytes(ETHERNET / IP(src="192.0.2.1", dst="192.0.2.2") / TCP(flags="PA") / Raw(b"hi")) + b"\x00" * 4)
    assert parse_packet(syn, 1, 1.0, "pcap")["transport"]["payload_length"] == 0
    assert parse_packet(data, 2, 1.0, "pcap")["transport"]["payload_length"] == 2
    assert extract_payload(syn) == b"" and extract_payload(data) == b"hi"


def test_extract_payload_for_udp_and_other_packets():
    assert extract_payload(IP() / UDP() / Raw(b"abc")) == b"abc"
    assert extract_payload(ETHERNET / ARP()) == b""
    assert extract_payload("not a packet") == b""


def test_smtp_mail_data_is_recognized():
    payload = (b"From: a@example.test\r\nSubject: hi\r\nContent-Type: multipart/mixed;\r\n\tboundary=x\r\n\r\n"
               b"body\r\n.\r\n")
    event = parse_packet(smtp_packet(payload), 1, 1.0, "pcap")
    application = event["application"]
    assert (application["protocol"], application["message_type"]) == ("SMTP", "data")
    assert application["headers"]["Content-Type"] == "multipart/mixed; boundary=x"
    assert application["body"] == "body\r\n"
    assert event["status"] == "ok"


def test_mail_data_sent_together_with_data_command():
    event = parse_packet(smtp_packet(b"DATA\r\nSubject: hi\r\n\r\nbody\r\n.\r\n"), 1, 1.0, "pcap")
    assert event["application"]["headers"] == {"Subject": "hi"}


def test_mail_data_without_end_marker_is_partial():
    event = parse_packet(smtp_packet(b"Subject: hi\r\n\r\nbody continues"), 1, 1.0, "pcap")
    assert event["application"]["message_type"] == "data"
    assert event["status"] == "partial"
    assert event["errors"] == ["Noi dung thu SMTP chua ket thuc trong goi nay"]


def test_header_like_text_on_other_ports_is_not_mail():
    event = parse_packet(smtp_packet(b"Subject: hi\r\n\r\nbody\r\n.\r\n", port=9000), 1, 1.0, "pcap")
    assert event["application"] == {"protocol": None}


def test_length_error_does_not_stop_parser():
    class BrokenLength:
        """Đối tượng giả: đo độ dài thì báo lỗi."""

        def __len__(self):
            """Luôn báo lỗi khi bị đo độ dài."""
            raise RuntimeError("broken")

    event = parse_packet(BrokenLength(), 1, 1.0, "pcap")
    assert event["captured_length"] is None and event["status"] == "malformed"
