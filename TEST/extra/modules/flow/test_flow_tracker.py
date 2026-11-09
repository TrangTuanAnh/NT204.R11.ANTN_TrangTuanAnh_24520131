"""Kiểm thử module Flow Tracker: gom flow hai chiều, trạng thái TCP, thời gian chờ và thống kê."""

from __future__ import annotations

import pytest

from src.config import Config
from src.flow import FlowTracker


def run(tracker: FlowTracker, events: list[dict]) -> list[dict]:
    """Đưa lần lượt các event vào tracker; trả các flow đã kết thúc trong lúc đó."""
    finished = []
    for event in events:
        finished += tracker.track(event)
    return finished


def test_handshake_with_zero_sequence_numbers(make_event):
    tracker = FlowTracker(Config())
    events = [make_event(1, flags="S"), make_event(2, flags="SA", reverse=True), make_event(3, flags="A")]
    run(tracker, events)
    assert [event["flow_state"] for event in events] == ["NEW", "HANDSHAKE", "ESTABLISHED"]
    assert [event["direction"] for event in events] == ["forward", "backward", "forward"]
    assert len({event["flow_id"] for event in events}) == 1
    flow = tracker.finish("end_of_input")[0]
    assert (flow["state"], flow["handshake_observed"], flow["SYN_count"], flow["ACK_count"]) == \
        ("ESTABLISHED", True, 2, 2)


def test_direction_follows_first_sender_not_ip_order(make_event):
    tracker = FlowTracker(Config())
    first = make_event(1, reverse=True)  # gói đầu đi từ 192.0.2.2:80 (IP lớn hơn)
    second = make_event(2)
    run(tracker, [first, second])
    assert (first["direction"], second["direction"]) == ("forward", "backward")
    flow = tracker.finish("end_of_input")[0]
    assert flow["endpoint_a"] == {"ip": "192.0.2.2", "port": 80}


def test_syn_ack_first_marks_receiver_as_initiator(make_event):
    tracker = FlowTracker(Config())
    synack = make_event(1, flags="SA", reverse=True)
    ack = make_event(2, flags="A")
    run(tracker, [synack, ack])
    assert (synack["direction"], ack["direction"]) == ("backward", "forward")
    flow = tracker.finish("end_of_input")[0]
    assert flow["endpoint_a"] == {"ip": "192.0.2.1", "port": 40000}
    assert (flow["state"], flow["handshake_observed"]) == ("ESTABLISHED", False)


def test_midstream_traffic_is_established_without_handshake(make_event):
    tracker = FlowTracker(Config())
    event = make_event(1, flags="PA")
    run(tracker, [event])
    assert event["flow_state"] == "ESTABLISHED"
    assert tracker.finish("end_of_input")[0]["handshake_observed"] is False


@pytest.mark.parametrize("closing", [
    [("FA", False), ("A", True), ("FA", True), ("A", False)],   # đóng 4 bước
    [("FA", False), ("FA", True), ("A", False)],                # đóng 3 bước
    [("FA", False), ("FA", True), ("A", True), ("A", False)],   # hai bên gửi FIN gần như cùng lúc
])
def test_fin_exchange_closes_and_removes_flow(make_event, closing):
    tracker = FlowTracker(Config())
    events = [make_event(1, flags="S"), make_event(2, flags="SA", reverse=True), make_event(3, flags="A")]
    events += [make_event(4 + index, flags=flags, reverse=reverse) for index, (flags, reverse) in enumerate(closing)]
    finished = run(tracker, events)
    assert [event["flow_state"] for event in events[3:-1]] == ["CLOSING"] * (len(closing) - 1)
    assert events[-1]["flow_state"] == "CLOSED"
    assert len(finished) == 1 and finished[0]["end_reason"] == "tcp_closed"
    assert tracker.active_count == 0


def test_half_close_stays_closing(make_event):
    tracker = FlowTracker(Config())
    events = [make_event(1, flags="A"), make_event(2, flags="FA"), make_event(3, flags="A", reverse=True),
              make_event(4, flags="PA", reverse=True)]
    assert run(tracker, events) == []
    assert events[-1]["flow_state"] == "CLOSING"
    assert tracker.active_count == 1


def test_rst_resets_and_removes_flow(make_event):
    tracker = FlowTracker(Config())
    finished = run(tracker, [make_event(1, flags="S"), make_event(2, flags="R", reverse=True)])
    assert [(flow["state"], flow["end_reason"], flow["RST_count"]) for flow in finished] == [("RESET", "tcp_reset", 1)]
    assert tracker.active_count == 0


def test_syn_on_established_flow_starts_new_connection(make_event):
    tracker = FlowTracker(Config())
    old = [make_event(1, flags="S"), make_event(2, flags="SA", reverse=True), make_event(3, flags="A")]
    run(tracker, old)
    new_syn = make_event(4, flags="S")
    finished = tracker.track(new_syn)
    assert finished[0]["end_reason"] == "new_connection" and finished[0]["packet_count"] == 3
    assert new_syn["flow_id"] != old[0]["flow_id"] and new_syn["flow_state"] == "NEW"


def test_repeated_syn_stays_in_same_flow(make_event):
    tracker = FlowTracker(Config())
    first, again = make_event(1, flags="S"), make_event(2, flags="S")
    run(tracker, [first, again])
    assert first["flow_id"] == again["flow_id"] and again["flow_state"] == "NEW"


def test_udp_flow_has_no_tcp_fields(make_event):
    tracker = FlowTracker(Config())
    events = [make_event(1, protocol="UDP"), make_event(2, protocol="UDP", reverse=True)]
    run(tracker, events)
    assert events[0]["flow_id"] == events[1]["flow_id"]
    assert events[0]["flow_state"] is None
    flow = tracker.finish("end_of_input")[0]
    assert (flow["protocol"], flow["packet_count"], flow["state"], flow["SYN_count"], flow["handshake_observed"]) == \
        ("UDP", 2, None, None, None)


def test_tcp_and_udp_with_same_ports_are_different_flows(make_event):
    tracker = FlowTracker(Config())
    tcp_event, udp_event = make_event(1), make_event(1, protocol="UDP")
    run(tracker, [tcp_event, udp_event])
    assert tcp_event["flow_id"] != udp_event["flow_id"] and tracker.active_count == 2


def test_tcp_and_udp_use_their_own_idle_timeout(make_event):
    tracker = FlowTracker(Config(tcp_idle_timeout=10, udp_idle_timeout=5))
    run(tracker, [make_event(0), make_event(0, protocol="UDP")])
    assert tracker.observe_time(4.9) == []
    expired = tracker.observe_time(5.0)
    assert [flow["protocol"] for flow in expired] == ["UDP"]
    assert [flow["protocol"] for flow in tracker.observe_time(10.0)] == ["TCP"]
    assert tracker.active_count == 0


def test_same_tuple_after_timeout_starts_new_flow(make_event):
    tracker = FlowTracker(Config(udp_idle_timeout=5))
    first, later = make_event(0, protocol="UDP"), make_event(6, protocol="UDP")
    finished = run(tracker, [first, later])
    assert [flow["end_reason"] for flow in finished] == ["idle_timeout"]
    assert first["flow_id"] != later["flow_id"] and tracker.active_count == 1


def test_flow_expires_exactly_when_timeout_is_reached(make_event):
    tracker = FlowTracker(Config(udp_idle_timeout=5))
    run(tracker, [make_event(0, protocol="UDP"), make_event(3, protocol="UDP")])
    assert tracker.observe_time(7.999) == []       # mới im lặng 4,999 giây
    expired = tracker.observe_time(8.0)
    assert [(flow["packet_count"], flow["end_reason"]) for flow in expired] == [(2, "idle_timeout")]
    assert tracker.active_count == 0


def test_full_table_closes_least_recent_flow(make_event):
    tracker = FlowTracker(Config(max_active_flows=2))
    first = make_event(1)
    second = make_event(2, transport={"protocol": "TCP", "src_port": 40001, "dst_port": 80, "flags": "A"})
    third = make_event(3, transport={"protocol": "TCP", "src_port": 40002, "dst_port": 80, "flags": "A"})
    run(tracker, [first, second])
    run(tracker, [make_event(4)])  # flow đầu vừa có gói mới nên flow thứ hai thành flow lâu nhất
    finished = tracker.track(third)
    assert [(flow["endpoint_a"]["port"], flow["end_reason"]) for flow in finished] == [(40001, "table_full")]
    assert tracker.active_count == 2


def test_finish_closes_everything_once(make_event):
    tracker = FlowTracker(Config(udp_idle_timeout=5))
    expired = run(tracker, [make_event(0, protocol="UDP"), make_event(9)])
    assert [(flow["protocol"], flow["end_reason"]) for flow in expired] == [("UDP", "idle_timeout")]
    finished = tracker.finish("end_of_input")
    assert [(flow["protocol"], flow["end_reason"]) for flow in finished] == [("TCP", "end_of_input")]
    assert tracker.finish("end_of_input") == [] and tracker.active_count == 0


def test_statistics_and_out_of_order_timestamps(make_event):
    tracker = FlowTracker(Config())
    run(tracker, [make_event(10.0), make_event(8.5, reverse=True, captured_length=100), make_event(12.25)])
    flow = tracker.finish("end_of_input")[0]
    assert (flow["start_time"], flow["last_seen"], flow["duration"]) == (8.5, 12.25, 3.75)
    assert (flow["packet_count"], flow["byte_count"]) == (3, 220)
    assert (flow["forward_packet_count"], flow["forward_byte_count"]) == (2, 120)
    assert (flow["backward_packet_count"], flow["backward_byte_count"]) == (1, 100)


def test_byte_count_falls_back_to_ip_length(make_event):
    tracker = FlowTracker(Config())
    run(tracker, [make_event(1, captured_length=None)])
    assert tracker.finish("end_of_input")[0]["byte_count"] == 46


def test_flow_id_is_repeatable_and_new_per_session(make_event):
    first_run = [make_event(1, flags="S"), make_event(2, flags="R", reverse=True), make_event(3, flags="S")]
    second_run = [make_event(1, flags="S"), make_event(2, flags="R", reverse=True), make_event(3, flags="S")]
    run(FlowTracker(Config()), first_run)
    run(FlowTracker(Config()), second_run)
    assert [event["flow_id"] for event in first_run] == [event["flow_id"] for event in second_run]
    assert first_run[0]["flow_id"] == first_run[1]["flow_id"] != first_run[2]["flow_id"]


def test_observe_time_ignores_missing_time():
    tracker = FlowTracker(Config())
    assert tracker.observe_time(None) == [] and tracker.observe_time("1") == []
