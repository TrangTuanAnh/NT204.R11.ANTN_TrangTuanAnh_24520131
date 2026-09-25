from scapy.all import IP, TCP

from src.parser import parse_packet


def test_invalid_ipv4_header_is_malformed():
    packet = IP(ihl=4) / TCP()

    event = parse_packet(packet, packet_id=1, timestamp=1.0, source="pcap")

    assert event["status"] == "malformed"
    assert event["errors"]
