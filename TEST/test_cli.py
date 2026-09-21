import json

from scapy.all import IP, TCP, Raw, wrpcap

from main import main


def test_cli_requires_a_source(capsys):
    assert main([]) == 2
    assert "--interface" in capsys.readouterr().err


def test_cli_lists_interfaces(capsys, monkeypatch):
    monkeypatch.setattr("main.list_interfaces", lambda: ["Ethernet", "Loopback"])

    assert main(["--list-interfaces"]) == 0
    assert capsys.readouterr().out.splitlines() == ["Ethernet", "Loopback"]


def test_cli_processes_pcap_into_json_lines(tmp_path):
    pcap_path = tmp_path / "input.pcap"
    output_path = tmp_path / "events.jsonl"
    wrpcap(str(pcap_path), [IP() / TCP(dport=8080) / Raw(b"GET / HTTP/1.1\r\n\r\n")])

    assert main(["--pcap", str(pcap_path), "--output", str(output_path)]) == 0

    event = json.loads(output_path.read_text(encoding="utf-8"))
    assert event["packet_id"] == 1
    assert event["source"] == "pcap"
    assert event["application"]["protocol"] == "HTTP"


def test_cli_reports_invalid_pcap(tmp_path, capsys):
    pcap_path = tmp_path / "broken.pcap"
    pcap_path.write_bytes(b"not a pcap")

    assert main(["--pcap", str(pcap_path)]) == 1
    assert "Khong the xu ly" in capsys.readouterr().err
