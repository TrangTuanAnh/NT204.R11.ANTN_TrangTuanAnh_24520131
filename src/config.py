"""Cấu hình cho các bước xử lý sau parser: thời gian chờ, giới hạn kích thước, chính sách bỏ qua."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, fields
from pathlib import Path

# Nhóm các tùy chọn theo loại giá trị để kiểm tra cho gọn.
_SECOND_OPTIONS = ("tcp_idle_timeout", "udp_idle_timeout", "live_check_interval")
_COUNT_OPTIONS = ("max_active_flows", "max_payload_bytes", "max_mime_parts", "max_event_bytes")
_SWITCH_OPTIONS = ("drop_invalid_events", "drop_unsupported_events")


@dataclass(frozen=True)
class Config:
    """Các giá trị chỉnh được của Decoder, Preprocessor và Flow Tracker.

    Giá trị mặc định ở đây trùng với file config/default.json.
    """

    # Flow TCP/UDP không có gói mới sau bấy nhiêu giây thì coi là hết hạn.
    tcp_idle_timeout: float = 120.0
    udp_idle_timeout: float = 30.0
    # Khi bắt live: cứ bấy nhiêu giây kiểm tra flow hết hạn một lần, kể cả lúc mạng im lặng.
    live_check_interval: float = 1.0
    # Số flow giữ cùng lúc tối đa; đầy thì đóng flow lâu nhất không có gói mới.
    max_active_flows: int = 100000
    # Decoder chỉ đọc tối đa bấy nhiêu byte dữ liệu của mỗi gói.
    max_payload_bytes: int = 65536
    # Số phần tối đa được giải mã trong một thư MIME.
    max_mime_parts: int = 50
    # Độ dài tối đa (byte) của một dòng khi đọc event từ file JSON Lines.
    max_event_bytes: int = 1048576
    # true: bỏ hẳn event sai hoặc chưa hỗ trợ (không ghi ra file);
    # false: vẫn ghi event ra file kèm trạng thái và lý do.
    drop_invalid_events: bool = False
    drop_unsupported_events: bool = False

    def __post_init__(self) -> None:
        """Báo lỗi ngay khi tạo cấu hình nếu có giá trị sai kiểu hoặc không dương."""
        for name in _SECOND_OPTIONS:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{name} phai la so giay")
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} phai lon hon 0")
        for name in _COUNT_OPTIONS:
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} phai la so nguyen lon hon 0")
        for name in _SWITCH_OPTIONS:
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"{name} phai la true hoac false")


def load_config(path: Path | None) -> Config:
    """Đọc file cấu hình JSON; không truyền file thì dùng giá trị mặc định.

    File chỉ cần ghi các tùy chọn muốn đổi. Tên tùy chọn lạ bị báo lỗi để
    tránh gõ sai tên mà không biết.
    """
    if path is None:
        return Config()
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("File cau hinh phai la mot JSON object")
    known = {item.name for item in fields(Config)}
    unknown = sorted(set(data) - known)
    if unknown:
        raise ValueError("Tuy chon cau hinh khong ho tro: " + ", ".join(unknown))
    return Config(**data)
