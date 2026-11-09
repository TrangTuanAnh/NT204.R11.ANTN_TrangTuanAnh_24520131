"""Kiểm thử việc nối phần so khớp rule vào Pipeline và chương trình chính main.py."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from scapy.all import IP, TCP, Raw, wrpcap

import main
from src.config import Config
from src.pipeline import Pipeline
from src.rules.rule_set import load_rule_set

RULE = 'alert tcp any any -> any 80 (msg:"Directory traversal"; flow:to_server,established; content:"../"; sid:1;)'


def rows(path: Path) -> list[dict]:
    """Đọc file JSON Lines thành danh sách."""
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def tcp(flags: str, reverse: bool = False, payload: bytes = b""):
    """Gói IPv4/TCP giữa 192.0.2.1:40000 và 192.0.2.2:80."""
    ends = (("192.0.2.2", 80), ("192.0.2.1", 40000)) if reverse else (("192.0.2.1", 40000), ("192.0.2.2", 80))
    packet = IP(src=ends[0][0], dst=ends[1][0]) / TCP(sport=ends[0][1], dport=ends[1][1], flags=flags)
    return packet / Raw(payload) if payload else packet


def session_pcap(path: Path) -> Path:
    """Ghi một phiên TCP có request chứa dấu hiệu tấn công."""
    packets = [tcp("S"), tcp("SA", reverse=True), tcp("A"), tcp("PA", payload=b"GET /../x HTTP/1.1\r\n\r\n")]
    for second, packet in enumerate(packets, start=1):
        packet.time = float(second)
    wrpcap(str(path), packets)
    return path


@pytest.fixture
def run_files(tmp_path) -> dict[str, Path]:
    """Các đường dẫn dùng cho một lần chạy main.py."""
    rules = tmp_path / "a.rules"
    rules.write_text(RULE + "\n", encoding="utf-8")
    return {"pcap": session_pcap(tmp_path / "in.pcap"), "rules": rules, "events": tmp_path / "events.jsonl",
            "flows": tmp_path / "flows.jsonl", "detections": tmp_path / "detections.jsonl",
            "report": tmp_path / "report.json"}


def arguments(files: dict[str, Path]) -> list[str]:
    """Tham số dòng lệnh chạy đủ các bước với rule."""
    return ["--pcap", str(files["pcap"]), "--rules", str(files["rules"]), "--output", str(files["events"]),
            "--flow-output", str(files["flows"]), "--detection-output", str(files["detections"]),
            "--rule-report", str(files["report"])]


def test_detection_events_and_report_are_written(run_files):
    assert main.main(arguments(run_files)) == 0
    detections = rows(run_files["detections"])
    assert [detection["sid"] for detection in detections] == [1]
    events = rows(run_files["events"])
    assert detections[0]["flow_id"] == events[3]["flow_id"] and detections[0]["packet_id"] == 4
    report = json.loads(run_files["report"].read_text(encoding="utf-8"))
    assert report["summary"]["valid"] == 1 and report["engine"]["events_evaluated"] == 4
    assert report["engine"]["matches"] == 1


def test_event_file_keeps_the_same_form_with_or_without_rules(run_files, tmp_path):
    assert main.main(arguments(run_files)) == 0
    without_rules = tmp_path / "plain.jsonl"
    assert main.main(["--pcap", str(run_files["pcap"]), "--output", str(without_rules),
                      "--flow-output", str(tmp_path / "plain_flows.jsonl")]) == 0
    assert rows(run_files["events"]) == rows(without_rules)


def test_no_detection_file_without_rules(run_files):
    assert main.main(["--pcap", str(run_files["pcap"]), "--output", str(run_files["events"]),
                      "--flow-output", str(run_files["flows"]), "--detection-output", str(run_files["detections"]),
                      "--rule-report", str(run_files["report"])]) == 0
    assert not run_files["detections"].exists() and not run_files["report"].exists()


def test_rule_files_can_come_from_config(run_files, tmp_path):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"rule_files": [str(run_files["rules"])]}), encoding="utf-8")
    assert main.main(["--pcap", str(run_files["pcap"]), "--config", str(config), "--output", str(run_files["events"]),
                      "--flow-output", str(run_files["flows"]), "--detection-output", str(run_files["detections"]),
                      "--rule-report", str(run_files["report"])]) == 0
    assert len(rows(run_files["detections"])) == 1


def test_several_rule_files_can_be_given(run_files, tmp_path):
    other = tmp_path / "b.rules"
    other.write_text('alert tcp any any -> any 80 (msg:"b"; content:"GET"; sid:2;)\n', encoding="utf-8")
    assert main.main(arguments(run_files) + ["--rules", str(other)]) == 0
    assert sorted(detection["sid"] for detection in rows(run_files["detections"])) == [1, 2]


def test_bad_rules_do_not_stop_the_run(run_files):
    run_files["rules"].write_text("alert sai\n" + RULE + '\nalert tcp any any -> any 80 (msg:"a"; pcre:"/x/"; sid:9;)\n',
                                  encoding="utf-8")
    assert main.main(arguments(run_files)) == 0
    assert [detection["sid"] for detection in rows(run_files["detections"])] == [1]
    report = json.loads(run_files["report"].read_text(encoding="utf-8"))
    assert (report["summary"]["invalid"], report["summary"]["unsupported"]) == (1, 1)


def test_warning_is_printed_while_loading(run_files, capsys):
    run_files["rules"].write_text("alert sai\n", encoding="utf-8")
    assert main.main(arguments(run_files)) == 0
    assert "Canh bao" in capsys.readouterr().err


def test_missing_rule_file_stops_before_creating_output(run_files):
    run_files["rules"].unlink()
    assert main.main(arguments(run_files)) == 2
    assert not run_files["events"].exists() and not run_files["detections"].exists()


def test_rules_cannot_be_used_with_parse_only(run_files):
    assert main.main(arguments(run_files) + ["--parse-only"]) == 2


def test_output_must_not_overwrite_rule_file_or_other_outputs(run_files):
    same_as_rules = arguments(run_files) + ["--detection-output", str(run_files["rules"])]
    assert main.main(same_as_rules) == 2
    same_as_events = arguments(run_files) + ["--rule-report", str(run_files["events"])]
    assert main.main(same_as_events) == 2


def test_report_is_written_even_when_the_source_breaks(run_files):
    run_files["pcap"].write_bytes(run_files["pcap"].read_bytes()[:-10])
    assert main.main(arguments(run_files)) == 1
    assert json.loads(run_files["report"].read_text(encoding="utf-8"))["engine"]["events_seen"] == 3


def test_events_from_file_are_matched_on_application_data(run_files, tmp_path, make_event):
    source = tmp_path / "in.jsonl"
    event = make_event(application={"protocol": "HTTP", "message_type": "request", "method": "GET", "uri": "/../x"})
    source.write_text(json.dumps(event) + "\n", encoding="utf-8")
    run_files["rules"].write_text('alert tcp any any -> any 80 (msg:"a"; content:"../"; sid:1;)\n', encoding="utf-8")
    assert main.main(["--events", str(source), "--rules", str(run_files["rules"]), "--output", str(run_files["events"]),
                      "--flow-output", str(run_files["flows"]), "--detection-output", str(run_files["detections"]),
                      "--rule-report", str(run_files["report"])]) == 0
    assert rows(run_files["detections"])[0]["match"]["buffer"] == "application"


def test_live_capture_writes_detections_and_report_after_ctrl_c(run_files, monkeypatch):
    def fake_capture(interface, process_packet, count, timeout, *, on_idle, idle_interval):
        """Giả lập card mạng: một phiên có gói tấn công rồi người dùng nhấn Ctrl+C."""
        for second, packet in enumerate([tcp("A"), tcp("PA", payload=b"GET /../x HTTP/1.1\r\n\r\n")], start=1):
            process_packet(packet, float(second))
        on_idle()
        raise KeyboardInterrupt

    monkeypatch.setattr(main, "capture_live", fake_capture)
    assert main.main(["--interface", "fake", "--rules", str(run_files["rules"]), "--output", str(run_files["events"]),
                      "--flow-output", str(run_files["flows"]), "--detection-output", str(run_files["detections"]),
                      "--rule-report", str(run_files["report"])]) == 130
    assert [detection["packet_id"] for detection in rows(run_files["detections"])] == [2]
    assert json.loads(run_files["report"].read_text(encoding="utf-8"))["engine"]["matches"] == 1


def test_flow_context_is_kept_for_the_packet_that_closes_the_flow(run_files):
    pipeline = Pipeline(Config())
    rule_file = run_files["rules"]
    rule_file.write_text('alert tcp any any -> any 80 (msg:"a"; flow:established; flags:R; sid:1;)\n', encoding="utf-8")
    pipeline.use_rules(load_rule_set(Config(rule_files=[str(rule_file)])).repository)
    pipeline.process_packet(tcp("A"), 1, 1.0, "pcap")
    _, finished = pipeline.process_packet(tcp("R"), 2, 2.0, "pcap")
    assert [flow["end_reason"] for flow in finished] == ["tcp_reset"]
    assert [detection["sid"] for detection in pipeline.take_detections()] == [1]
    assert pipeline.take_detections() == []


def test_pipeline_without_rules_produces_no_detection():
    pipeline = Pipeline(Config())
    pipeline.process_packet(tcp("S"), 1, 1.0, "pcap")
    assert pipeline.take_detections() == []


@pytest.mark.parametrize("limit,expected", [(4, []), (5, [1])])
def test_payload_limit_from_config_also_applies_to_rules(run_files, limit, expected):
    pipeline = Pipeline(Config(max_payload_bytes=limit))
    rule_file = run_files["rules"]
    rule_file.write_text('alert tcp any any -> any 80 (msg:"a"; content:"GET /"; sid:1;)\n', encoding="utf-8")
    pipeline.use_rules(load_rule_set(Config(rule_files=[str(rule_file)])).repository)
    pipeline.process_packet(tcp("PA", payload=b"GET /"), 1, 1.0, "pcap")
    assert [detection["sid"] for detection in pipeline.take_detections()] == expected
