import json

from scapy.all import DNS, DNSQR, DNSRR, IP, Raw, TCP, UDP

from src.parser import parse_packet


def test_tcp_flags_and_payload_are_normalized():
    packet = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
        sport=1234, dport=80, flags="PA", seq=10, ack=20, window=4096
    ) / Raw(b"hello")

    event = parse_packet(packet, packet_id=1, timestamp=123.5, source="pcap")

    assert event["packet_id"] == 1
    assert event["timestamp"] == 123.5
    assert event["source"] == "pcap"
    assert event["network"] == {
        "version": 4,
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "ttl": 64,
        "protocol": 6,
        "total_length": None,
        "fragment_offset": 0,
        "more_fragments": False,
    }
    assert event["transport"]["flags"] == "PA"
    assert event["transport"]["payload_length"] == 5
    assert event["application"]["protocol"] is None


def test_http_get_on_non_standard_port_is_detected():
    packet = IP() / TCP(sport=50000, dport=8088) / Raw(
        b"GET /index.html HTTP/1.1\r\nHost: example.test\r\n\r\n"
    )

    event = parse_packet(packet, packet_id=2, timestamp=1.0, source="live")

    assert event["application"]["protocol"] == "HTTP"
    assert event["application"]["message_type"] == "request"
    assert event["application"]["method"] == "GET"
    assert event["application"]["uri"] == "/index.html"
    assert event["application"]["headers"]["Host"] == "example.test"


def test_http_response_and_body_are_parsed():
    packet = IP() / TCP(sport=80, dport=50000) / Raw(
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
    )

    application = parse_packet(packet, 3, 1.0, "pcap")["application"]

    assert application["message_type"] == "response"
    assert application["status_code"] == 200
    assert application["headers"]["Content-Length"] == "5"
    assert application["body"] == "hello"


def test_dns_query_and_response_are_parsed():
    query = IP() / UDP(sport=53000, dport=53) / DNS(
        id=7, rd=1, qd=DNSQR(qname="example.com", qtype="A")
    )
    response = IP() / UDP(sport=53, dport=53000) / DNS(
        id=7,
        qr=1,
        an=DNSRR(rrname="example.com", type="A", rdata="192.0.2.1"),
        qd=DNSQR(qname="example.com", qtype="A"),
    )

    query_event = parse_packet(query, 4, 1.0, "pcap")["application"]
    response_event = parse_packet(response, 5, 1.0, "pcap")["application"]

    assert query_event["protocol"] == "DNS"
    assert query_event["is_response"] is False
    assert query_event["questions"][0]["name"] == "example.com"
    assert response_event["is_response"] is True
    assert response_event["answers"][0]["data"] == "192.0.2.1"


def test_smtp_command_and_response_are_parsed():
    command = IP() / TCP(sport=50000, dport=25) / Raw(b"EHLO mail.example\r\n")
    response = IP() / TCP(sport=25, dport=50000) / Raw(b"250-mail.example\r\n")

    command_event = parse_packet(command, 6, 1.0, "pcap")["application"]
    response_event = parse_packet(response, 7, 1.0, "pcap")["application"]

    assert command_event["protocol"] == "SMTP"
    assert command_event["command"] == "EHLO"
    assert command_event["argument"] == "mail.example"
    assert response_event["status_code"] == 250


def test_unknown_and_malformed_packets_do_not_raise():
    unknown = IP() / UDP(sport=12345, dport=9999) / Raw(b"binary\xff")
    malformed = object()

    unknown_event = parse_packet(unknown, 8, 1.0, "pcap")
    malformed_event = parse_packet(malformed, 9, 1.0, "pcap")

    assert unknown_event["status"] == "unknown"
    assert malformed_event["status"] == "malformed"
    assert json.dumps(malformed_event)
