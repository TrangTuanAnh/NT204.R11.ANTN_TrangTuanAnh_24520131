"""Kiểm thử Pipeline: nối đủ các bước, cô lập lỗi từng bước, chính sách bỏ event và đóng flow."""

from __future__ import annotations

from scapy.all import IP, TCP, UDP, Raw

from src import pipeline as pipeline_module
from src.config import Config
from src.pipeline import Pipeline


def http_packet():
    """Gói HTTP GET có tham số mã hóa %XX (không có lớp Ethernet nên không cần dò địa chỉ MAC)."""
    return IP(src="192.0.2.1", dst="192.0.2.2") / TCP(sport=40000, dport=80, flags="PA") / Raw(
        b"GET /?q=%27x HTTP/1.1\r\nHOST: Example.TEST\r\n\r\n")


def test_packet_goes_through_every_step():
    pipeline = Pipeline(Config())
    event, finished = pipeline.process_packet(http_packet(), 1, 10.0, "pcap")
    assert finished == []
    assert event["decoded"]["query"] == [["q", "'x"]] and event["decode_status"] == "ok"
    assert event["application"]["headers"] == {"host": "example.test"}
    assert (event["preprocess_status"], event["processing_action"]) == ("valid", "process")
    assert event["flow_id"] and event["direction"] == "forward" and event["flow_state"] == "ESTABLISHED"
    flows = pipeline.finish("end_of_input")
    assert [(flow["application_protocol"], flow["end_reason"]) for flow in flows] == [("HTTP", "end_of_input")]


def test_skipped_event_has_empty_flow_fields(make_event):
    event, _ = Pipeline(Config()).process_event(make_event(timestamp=None))
    assert event["processing_action"] == "skip"
    assert (event["flow_id"], event["direction"], event["flow_state"]) == (None, None, None)


def test_error_in_preprocessor_is_isolated(make_event, monkeypatch):
    def broken(event, config):
        """Giả lập lỗi không lường trước trong Preprocessor."""
        raise RuntimeError("boom")

    monkeypatch.setattr(pipeline_module, "preprocess_event", broken)
    event, finished = Pipeline(Config()).process_event(make_event())
    assert (event["preprocess_status"], event["processing_action"]) == ("invalid", "skip")
    assert event["reason"] == ["Lỗi khi kiểm tra event: boom"] and finished == []


def test_error_in_flow_tracker_is_isolated_and_next_event_still_works(make_event, monkeypatch):
    pipeline = Pipeline(Config())
    original = pipeline.tracker.track

    def broken_once(event):
        """Lần đầu báo lỗi, các lần sau chạy bình thường."""
        monkeypatch.setattr(pipeline.tracker, "track", original)
        raise ValueError("bad state")

    monkeypatch.setattr(pipeline.tracker, "track", broken_once)
    first, _ = pipeline.process_event(make_event(1.0))
    second, _ = pipeline.process_event(make_event(2.0))
    assert first["processing_action"] == "skip" and first["flow_id"] is None
    assert first["reason"] == ["Lỗi khi theo dõi flow: bad state"]
    assert second["flow_id"] is not None


def test_dropped_event_is_not_returned_but_time_still_moves(make_event):
    pipeline = Pipeline(Config(udp_idle_timeout=5, drop_unsupported_events=True))
    pipeline.process_event(make_event(0.0, protocol="UDP"))
    event, finished = pipeline.process_event(make_event(10.0, transport=None))
    assert event is None
    assert [(flow["protocol"], flow["end_reason"]) for flow in finished] == [("UDP", "idle_timeout")]


def test_live_idle_check_uses_clock():
    now = [100.0]
    pipeline = Pipeline(Config(udp_idle_timeout=5), clock=lambda: now[0])
    pipeline.process_packet(IP(src="192.0.2.1", dst="192.0.2.2") / UDP(sport=1, dport=2), 1, 100.0, "live")
    assert pipeline.expire_idle() == []
    now[0] = 105.0
    assert [flow["end_reason"] for flow in pipeline.expire_idle()] == ["idle_timeout"]
