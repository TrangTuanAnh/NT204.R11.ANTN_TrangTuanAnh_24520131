"""Sổ ghi kết quả kiểm tra và các hàm kiểm tra từng trường của event."""

from __future__ import annotations

from typing import Any

from src.config import Config

from .normalize import normalize_ip

# Thứ tự chuẩn của các cờ TCP khi viết thành chuỗi (giống cách Scapy viết):
# F=FIN, S=SYN, R=RST, P=PSH, A=ACK, U=URG, E=ECE, C=CWR, N=NS.
TCP_FLAG_ORDER = "FSRPAUECN"


class CheckReport:
    """Sổ ghi các vấn đề tìm thấy khi kiểm tra một event, chia thành bốn nhóm.

    - invalid: trường bắt buộc bị thiếu, hoặc trường của lớp IP/TCP/UDP có
      giá trị sai. Event không được đưa vào Flow Tracker.
    - unsupported: dữ liệu đúng nhưng hệ thống chưa hỗ trợ (ví dụ ICMP).
      Event không được đưa vào Flow Tracker.
    - partial: dữ liệu dùng được nhưng chưa đầy đủ.
    - missing: tên các trường không bắt buộc bị thiếu (đã điền null).
    """

    def __init__(self) -> None:
        """Bắt đầu với sổ trống."""
        self.invalid: list[str] = []
        self.unsupported: list[str] = []
        self.partial: list[str] = []
        self.missing: list[str] = []

    def status(self) -> str:
        """Trạng thái sau kiểm tra: invalid, partial hoặc valid."""
        if self.invalid:
            return "invalid"
        if self.unsupported or self.partial or self.missing:
            return "partial"
        return "valid"

    def action(self, config: Config) -> str:
        """Việc làm tiếp với event.

        - process: đưa vào Flow Tracker.
        - skip: vẫn ghi event ra file nhưng không theo dõi flow.
        - drop: bỏ hẳn event (khi cấu hình bật drop_invalid_events / drop_unsupported_events).
        """
        if self.invalid:
            return "drop" if config.drop_invalid_events else "skip"
        if self.unsupported:
            return "drop" if config.drop_unsupported_events else "skip"
        return "process"

    def reasons(self) -> list[str]:
        """Danh sách lý do theo thứ tự nặng đến nhẹ; event hợp lệ thì danh sách rỗng."""
        reasons = self.invalid + self.unsupported + self.partial
        if self.missing:
            reasons.append("Thiếu trường không bắt buộc, đã điền null: " + ", ".join(self.missing))
        return list(dict.fromkeys(reasons))


def check_integer(section: dict[str, Any], name: str, low: int, high: int | None,
                  report: CheckReport, path: str, required: bool = False) -> None:
    """Kiểm tra một trường số nguyên phải nằm trong khoảng từ low đến high.

    Thiếu trường: trường bắt buộc thì ghi invalid, trường phụ thì điền null.
    Có giá trị nhưng sai kiểu hoặc ngoài khoảng: ghi invalid và đổi về null.
    """
    value = section.get(name)
    if value is None:
        _mark_missing(section, name, report, path, required)
        return
    # Dùng type(...) is int để loại true/false, vì trong Python bool cũng được tính là số nguyên.
    if type(value) is not int or value < low or (high is not None and value > high):
        report.invalid.append(f"{path} không hợp lệ: {value!r}")
        section[name] = None


def check_choice(section: dict[str, Any], name: str, choices: tuple[int, ...],
                 report: CheckReport, path: str) -> None:
    """Kiểm tra một trường số nguyên không bắt buộc chỉ được nhận một trong các giá trị cho phép."""
    value = section.get(name)
    if value is None:
        _mark_missing(section, name, report, path, required=False)
    elif type(value) is not int or value not in choices:
        report.invalid.append(f"{path} không hợp lệ: {value!r}")
        section[name] = None


def check_boolean(section: dict[str, Any], name: str, report: CheckReport, path: str) -> None:
    """Kiểm tra một trường không bắt buộc chỉ nhận true hoặc false."""
    value = section.get(name)
    if value is None:
        _mark_missing(section, name, report, path, required=False)
    elif not isinstance(value, bool):
        report.invalid.append(f"{path} phải là true/false: {value!r}")
        section[name] = None


def check_ip(section: dict[str, Any], name: str, report: CheckReport, path: str) -> None:
    """Kiểm tra địa chỉ IP (bắt buộc) và đổi về cách viết chuẩn, ví dụ "2001:DB8::1" → "2001:db8::1"."""
    value = section.get(name)
    if value is None:
        _mark_missing(section, name, report, path, required=True)
        return
    try:
        section[name] = normalize_ip(value)
    except ValueError:
        report.invalid.append(f"{path} không phải địa chỉ IP hợp lệ: {value!r}")
        section[name] = None


def check_tcp_flags(transport: dict[str, Any], report: CheckReport) -> None:
    """Kiểm tra chuỗi cờ TCP và viết lại theo một thứ tự cố định, ví dụ "af" → "FA"."""
    value = transport.get("flags")
    if value is None:
        _mark_missing(transport, "flags", report, "transport.flags", required=False)
        return
    letters = set(value.upper()) if isinstance(value, str) else None
    if letters is None or not letters <= set(TCP_FLAG_ORDER):
        report.invalid.append(f"transport.flags không hợp lệ: {value!r}")
        transport["flags"] = None
        return
    transport["flags"] = "".join(letter for letter in TCP_FLAG_ORDER if letter in letters)


def _mark_missing(section: dict[str, Any], name: str, report: CheckReport, path: str,
                  required: bool) -> None:
    """Điền null cho trường không có giá trị và ghi vào sổ.

    Trường bắt buộc thiếu thì event invalid. Trường phụ chỉ bị ghi là thiếu khi
    hẳn không có trong event; trường đã ghi rõ null được coi là "không có giá trị".
    """
    absent = name not in section
    section[name] = None
    if required:
        report.invalid.append(f"Thiếu {path}")
    elif absent:
        report.missing.append(path)
