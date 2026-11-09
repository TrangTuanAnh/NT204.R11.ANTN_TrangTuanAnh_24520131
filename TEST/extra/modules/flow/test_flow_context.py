"""Kiểm thử thông tin flow mà Flow Tracker cung cấp cho phần so khớp rule."""

from __future__ import annotations

from src.config import Config
from src.flow import FlowTracker


def contexts(tracker: FlowTracker, events: list[dict]) -> list[dict]:
    """Đưa lần lượt các event vào tracker; trả thông tin flow ngay sau từng gói."""
    result = []
    for event in events:
        tracker.track(event)
        result.append(tracker.last_context)
    return result


def test_established_after_handshake_and_during_close(make_event):
    events = [make_event(1, flags="S"), make_event(2, flags="SA", reverse=True), make_event(3, flags="A"),
              make_event(4, flags="PA"), make_event(5, flags="FPA"), make_event(6, flags="FA", reverse=True),
              make_event(7, flags="A")]
    result = contexts(FlowTracker(Config()), events)
    assert [item["established"] for item in result] == [False, False, True, True, True, True, True]
    assert [item["state"] for item in result] == ["NEW", "HANDSHAKE", "ESTABLISHED", "ESTABLISHED", "CLOSING",
                                                  "CLOSING", "CLOSED"]


def test_context_survives_after_flow_is_removed(make_event):
    tracker = FlowTracker(Config())
    result = contexts(tracker, [make_event(1, flags="A"), make_event(2, flags="R", reverse=True)])
    assert tracker.active_count == 0
    assert (result[1]["state"], result[1]["established"]) == ("RESET", True)


def test_reset_before_connection_is_not_established(make_event):
    result = contexts(FlowTracker(Config()), [make_event(1, flags="S"), make_event(2, flags="RA", reverse=True)])
    assert result[1]["established"] is False


def test_direction_is_seen_from_the_side_that_opened_the_connection(make_event):
    result = contexts(FlowTracker(Config()), [make_event(1, flags="S"), make_event(2, flags="SA", reverse=True)])
    assert [(item["direction"], item["to_server"]) for item in result] == [("forward", True), ("backward", False)]


def test_syn_ack_seen_first_still_points_to_the_real_server(make_event):
    result = contexts(FlowTracker(Config()), [make_event(1, flags="SA", reverse=True), make_event(2, flags="A")])
    assert [item["to_server"] for item in result] == [False, True]


def test_udp_is_never_established(make_event):
    result = contexts(FlowTracker(Config()), [make_event(1, protocol="UDP"), make_event(2, protocol="UDP", reverse=True)])
    assert [item["established"] for item in result] == [False, False]
    assert result[1]["state"] is None and result[1]["handshake_observed"] is None


def test_context_carries_identity_and_counters(make_event):
    event = make_event(1, application={"protocol": "HTTP"})
    result = contexts(FlowTracker(Config()), [event])[0]
    assert result["flow_id"] == event["flow_id"]
    assert (result["protocol"], result["application_protocol"]) == ("TCP", "HTTP")
    assert (result["packet_count"], result["byte_count"]) == (1, 60)
