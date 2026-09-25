import json

import pytest
from scapy.all import IP, TCP, wrpcap

from main import main
from src.capture import iter_pcap


@pytest.mark.parametrize("cut", [1, 8])
def test_incomplete_record_reports_error_preserves_prior(tmp_path, cut):
    pcap_path = tmp_path / "cut.pcap"
    output_path = tmp_path / "events.jsonl"
    wrpcap(str(pcap_path), [IP() / TCP(flags="S"), IP() / TCP(flags="A")])
    pcap_path.write_bytes(pcap_path.read_bytes()[:-cut])

    assert main(["--pcap", str(pcap_path), "--output", str(output_path)]) == 1

    events = [json.loads(line) for line in output_path.read_text().splitlines()]
    assert len(events) == 1
    assert events[0]["transport"]["flags"] == "S"


def test_partial_record_header_is_not_clean_eof(tmp_path):
    pcap_path = tmp_path / "cut_header.pcap"
    wrpcap(str(pcap_path), [IP() / TCP()])
    with pcap_path.open("ab") as stream:
        stream.write(b"123")

    with pytest.raises(ValueError):
        list(iter_pcap(pcap_path))
