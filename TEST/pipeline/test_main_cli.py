"""Kiểm thử chương trình chính main.py: các nguồn vào, chế độ chạy, xử lý lỗi và ghi kết quả."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from scapy.all import IP, TCP, UDP, Raw, wrpcap

import main
from src.config import Config
from src.pipeline import Pipeline


def rows(path: Path) -> list[dict]:
    """Đọc file JSON Lines thành danh sách."""
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def write_pcap(path: Path, *packets) -> Path:
    """Ghi các gói ra file PCAP, gán thời điểm 1, 2, 3... giây."""
    for second, packet in enumerate(packets, start=1):
        packet.time = float(second)
    wrpcap(str(path), list(packets))
    return path


def tcp(flags: str, reverse: bool = False, payload: bytes = b""):
    """Gói IPv4/TCP giữa 192.0.2.1:40000 và 192.0.2.2:80."""
    ends = (("192.0.2.2", 80), ("192.0.2.1", 40000)) if reverse else (("192.0.2.1", 40000), ("192.0.2.2", 80))
    packet = IP(src=ends[0][0], dst=ends[1][0]) / TCP(sport=ends[0][1], dport=ends[1][1], flags=flags)
    return packet / Raw(payload) if payload else packet


def test_pcap_run_writes_events_and_flows(tmp_path):
    pcap = write_pcap(tmp_path / "in.pcap", tcp("S"), tcp("SA", reverse=True), tcp("A"))
    events, flows = tmp_path / "events.jsonl", tmp_path / "flows.jsonl"
    assert main.main(["--pcap", str(pcap), "--output", str(events), "--flow-output", str(flows)]) == 0
    assert [event["flow_state"] for event in rows(events)] == ["NEW", "HANDSHAKE", "ESTABLISHED"]
    assert [(flow["packet_count"], flow["end_reason"]) for flow in rows(flows)] == [(3, "end_of_input")]


def test_parse_only_keeps_exercise_one_output(tmp_path):
    pcap = write_pcap(tmp_path / "in.pcap", tcp("PA", payload=b"GET / HTTP/1.1\r\nHost: A\r\n\r\n"))
    events, flows = tmp_path / "events.jsonl", tmp_path / "flows.jsonl"
    assert main.main(["--pcap", str(pcap), "--output", str(events), "--flow-output", str(flows),
                      "--parse-only"]) == 0
    event = rows(events)[0]
    assert set(event) == {"packet_id", "timestamp", "source", "captured_length", "network", "transport",
                          "application", "status", "errors"}
    assert event["application"]["headers"] == {"Host": "A"}
    assert not flows.exists()


def test_events_input_continues_after_bad_lines(tmp_path, make_event):
    source = tmp_path / "in.jsonl"
    source.write_text(json.dumps(make_event(1.0)) + "\n{broken\n" + json.dumps(make_event(2.0)) + "\n",
                      encoding="utf-8")
    events, flows = tmp_path / "events.jsonl", tmp_path / "flows.jsonl"
    assert main.main(["--events", str(source), "--output", str(events), "--flow-output", str(flows)]) == 0
    written = rows(events)
    assert [event["processing_action"] for event in written] == ["process", "skip", "process"]
    assert written[0]["flow_id"] == written[2]["flow_id"]
    assert rows(flows)[0]["packet_count"] == 2


def test_drop_policy_removes_events_from_output(tmp_path, make_event):
    source, config = tmp_path / "in.jsonl", tmp_path / "config.json"
    source.write_text(json.dumps(make_event(timestamp="sai")) + "\n" + json.dumps(make_event()) + "\n",
                      encoding="utf-8")
    config.write_text('{"drop_invalid_events": true}', encoding="utf-8")
    events = tmp_path / "events.jsonl"
    assert main.main(["--events", str(source), "--config", str(config), "--output", str(events),
                      "--flow-output", str(tmp_path / "flows.jsonl")]) == 0
    assert [event["processing_action"] for event in rows(events)] == ["process"]


@pytest.mark.parametrize("content", ['{"tcp_idle_timeout": -1}', '{"udp_idle_timeout": true}',
                                     '{"max_mime_parts": 0}', '{"max_active_flows": 1.5}',
                                     '{"drop_invalid_events": 1}', '{"unknown_option": 1}', "[]", "{bad"])
def test_bad_config_stops_before_creating_output(tmp_path, content):
    config = tmp_path / "config.json"
    config.write_text(content, encoding="utf-8")
    events = tmp_path / "events.jsonl"
    pcap = write_pcap(tmp_path / "in.pcap", tcp("S"))
    assert main.main(["--pcap", str(pcap), "--config", str(config), "--output", str(events)]) == 2
    assert not events.exists()


def test_output_must_not_overwrite_input_or_other_output(tmp_path):
    pcap = write_pcap(tmp_path / "in.pcap", tcp("S"))
    same = tmp_path / "same.jsonl"
    assert main.main(["--pcap", str(pcap), "--output", str(pcap)]) == 2
    assert main.main(["--pcap", str(pcap), "--output", str(same), "--flow-output", str(same)]) == 2
    assert main.main(["--events", str(pcap), "--parse-only", "--output", str(same)]) == 2
    assert not same.exists()


def test_live_run_closes_idle_flows_and_keeps_output_after_ctrl_c(tmp_path, monkeypatch):
    now = [100.0]
    monkeypatch.setattr(main, "Pipeline", lambda config: Pipeline(config, clock=lambda: now[0]))

    def fake_capture(interface, process_packet, count, timeout, *, on_idle, idle_interval):
        """Giả lập card mạng: một gói UDP, im lặng quá hạn, một gói TCP rồi người dùng nhấn Ctrl+C."""
        process_packet(IP(src="192.0.2.1", dst="192.0.2.2") / UDP(sport=5000, dport=53), 100.0)
        now[0] = 131.0
        on_idle()
        process_packet(tcp("S"), 131.5)
        raise KeyboardInterrupt

    monkeypatch.setattr(main, "capture_live", fake_capture)
    events, flows = tmp_path / "events.jsonl", tmp_path / "flows.jsonl"
    assert main.main(["--interface", "fake", "--output", str(events), "--flow-output", str(flows)]) == 130
    assert [event["source"] for event in rows(events)] == ["live", "live"]
    assert [(flow["protocol"], flow["end_reason"]) for flow in rows(flows)] == \
        [("UDP", "idle_timeout"), ("TCP", "interrupted")]


def test_write_error_returns_failure(tmp_path, monkeypatch):
    pcap = write_pcap(tmp_path / "in.pcap", tcp("S"))

    def fail(self, event):
        """Giả lập ổ đĩa đầy khi ghi kết quả."""
        raise OSError("disk full")

    monkeypatch.setattr(main.JsonLinesWriter, "write", fail)
    assert main.main(["--pcap", str(pcap), "--output", str(tmp_path / "e.jsonl"),
                      "--flow-output", str(tmp_path / "f.jsonl")]) == 1


def test_broken_pcap_still_writes_open_flows(tmp_path):
    pcap = write_pcap(tmp_path / "in.pcap", tcp("S"), tcp("SA", reverse=True))
    pcap.write_bytes(pcap.read_bytes()[:-10])  # cắt mất phần cuối của gói thứ hai
    events, flows = tmp_path / "events.jsonl", tmp_path / "flows.jsonl"
    assert main.main(["--pcap", str(pcap), "--output", str(events), "--flow-output", str(flows)]) == 1
    assert len(rows(events)) == 1
    assert [flow["end_reason"] for flow in rows(flows)] == ["source_error"]


def test_default_config_file_matches_built_in_values():
    path = Path(__file__).resolve().parents[2] / "config" / "default.json"
    assert main.load_config(path) == Config()


def test_config_file_may_change_only_some_options(tmp_path):
    path = tmp_path / "config.json"
    path.write_text('{"udp_idle_timeout": 5}', encoding="utf-8")
    assert main.load_config(path) == Config(udp_idle_timeout=5)
