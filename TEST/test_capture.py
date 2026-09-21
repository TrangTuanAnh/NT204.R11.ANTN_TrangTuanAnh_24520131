from pathlib import Path

from scapy.all import IP, TCP, Raw, wrpcap

from src.capture import iter_pcap


def test_iter_pcap_streams_packets_with_timestamps(tmp_path: Path):
    path = tmp_path / "sample.pcap"
    wrpcap(
        str(path),
        [IP(src="192.0.2.1") / TCP(dport=80) / Raw(b"GET / HTTP/1.1\r\n\r\n")],
    )

    packets = list(iter_pcap(path))

    assert len(packets) == 1
    assert packets[0][0].haslayer(IP)
    assert isinstance(packets[0][1], float)
