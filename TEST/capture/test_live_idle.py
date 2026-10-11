"""Kiểm thử bắt gói live có gọi kiểm tra flow hết hạn định kỳ, dùng bộ bắt gói giả (không cần card mạng)."""

from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import pytest

from src.capture import live


class FakeSniffer:
    """Thay cho AsyncSniffer của Scapy: phát lần lượt các gói giả ở một luồng riêng."""

    packets: list = []
    delay = 0.0
    thread_error: BaseException | None = None

    def __init__(self, prn, stop_filter, **options):
        """Giữ lại hàm xử lý gói và điều kiện dừng giống AsyncSniffer."""
        self.prn, self.stop_filter, self.options = prn, stop_filter, options
        self.running = False
        self.stopped = False
        self.error = None
        self.thread = threading.Thread(target=self._run)

    def start(self):
        """Bắt đầu phát gói ở luồng riêng."""
        self.running = True
        self.thread.start()

    def _run(self):
        """Phát từng gói cách nhau một khoảng delay; dừng khi được yêu cầu."""
        try:
            if self.thread_error is not None:
                self.error = self.thread_error
                return
            for packet in self.packets:
                time.sleep(self.delay)
                if self.stopped:
                    return
                self.prn(packet)
                if self.stop_filter(packet):
                    return
        finally:
            self.running = False

    def stop(self):
        """Yêu cầu dừng và chờ luồng kết thúc."""
        self.stopped = True
        self.thread.join()


@pytest.fixture
def fake_sniffer(monkeypatch):
    """Cài bộ bắt gói giả vào module live và trả lớp đó để từng test chỉnh."""
    monkeypatch.setattr(live, "_ReportingSniffer", FakeSniffer)
    monkeypatch.setattr(FakeSniffer, "packets", [SimpleNamespace(time=float(n)) for n in (1, 2, 3)])
    monkeypatch.setattr(FakeSniffer, "delay", 0.05)
    monkeypatch.setattr(FakeSniffer, "thread_error", None)
    return FakeSniffer


def test_packets_are_processed_and_idle_check_runs_regularly(fake_sniffer):
    received, idle_calls = [], []
    live._capture_with_idle_checks({}, lambda packet, timestamp: received.append(timestamp),
                                   lambda: idle_calls.append(1), interval=0.01)
    assert received == [1.0, 2.0, 3.0]
    assert len(idle_calls) >= 3


def test_error_while_handling_packet_stops_capture(fake_sniffer):
    received = []

    def handle(packet, timestamp):
        """Giả lập ghi file thất bại ở gói thứ hai."""
        received.append(timestamp)
        if timestamp == 2.0:
            raise OSError("disk full")

    with pytest.raises(OSError, match="disk full"):
        live._capture_with_idle_checks({}, handle, lambda: None, interval=0.01)
    assert received == [1.0, 2.0]


def test_error_inside_capture_thread_is_reported(fake_sniffer, monkeypatch):
    monkeypatch.setattr(fake_sniffer, "thread_error", RuntimeError("khong mo duoc card"))
    with pytest.raises(RuntimeError, match="khong mo duoc card"):
        live._capture_with_idle_checks({}, lambda packet, timestamp: None, lambda: None, interval=0.01)


def test_error_in_idle_check_stops_capture_thread(fake_sniffer, monkeypatch):
    monkeypatch.setattr(fake_sniffer, "delay", 0.5)
    created = []
    monkeypatch.setattr(live, "_ReportingSniffer", lambda **options: created.append(FakeSniffer(**options))
                        or created[-1])

    def broken_idle():
        """Giả lập lỗi khi ghi flow hết hạn."""
        raise ValueError("idle failed")

    with pytest.raises(ValueError, match="idle failed"):
        live._capture_with_idle_checks({}, lambda packet, timestamp: None, broken_idle, interval=0.01)
    assert created[0].stopped and not created[0].thread.is_alive()


def test_capture_live_chooses_plain_sniff_without_idle_check(monkeypatch):
    calls = []
    monkeypatch.setattr(live, "_capture_name", lambda interface: "eth0")
    monkeypatch.setattr(live, "sniff", lambda **options: calls.append(("sniff", options["iface"])))
    monkeypatch.setattr(live, "_capture_with_idle_checks",
                        lambda options, process, on_idle, interval: calls.append(("idle", interval)))
    live.capture_live("eth0", lambda packet, timestamp: None)
    live.capture_live("eth0", lambda packet, timestamp: None, on_idle=lambda: None, idle_interval=2.5)
    assert calls == [("sniff", "eth0"), ("idle", 2.5)]
