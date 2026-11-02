"""Cấu hình cho các bước xử lý sau parser: thời gian chờ, giới hạn kích thước, chính sách bỏ qua, rule."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field, fields
from pathlib import Path

# Nhóm các tùy chọn theo loại giá trị để kiểm tra cho gọn.
_SECOND_OPTIONS = ("tcp_idle_timeout", "udp_idle_timeout", "live_check_interval")
_COUNT_OPTIONS = ("max_active_flows", "max_payload_bytes", "max_mime_parts", "max_event_bytes")
_SWITCH_OPTIONS = ("drop_invalid_events", "drop_unsupported_events")

# Giá trị của các biến như $HOME_NET mà rule Snort dùng, lấy đúng từ file snort.conf đi kèm bộ rule cộng đồng.
DEFAULT_RULE_VARIABLES = {
    "HOME_NET": "any",
    "EXTERNAL_NET": "any",
    "DNS_SERVERS": "$HOME_NET",
    "SMTP_SERVERS": "$HOME_NET",
    "HTTP_SERVERS": "$HOME_NET",
    "SQL_SERVERS": "$HOME_NET",
    "TELNET_SERVERS": "$HOME_NET",
    "SSH_SERVERS": "$HOME_NET",
    "FTP_SERVERS": "$HOME_NET",
    "SIP_SERVERS": "$HOME_NET",
    "HTTP_PORTS": (
        "[36,80,81,82,83,84,85,86,87,88,89,90,311,323,383,443,444,555,591,593,623,631,664,801,808,818,901,972,"
        "1158,1220,1270,1414,1533,1581,1719,1720,1741,1801,1812,1830,1942,2231,2301,2375,2381,2578,2809,2869,"
        "2980,3000,3029,3037,3057,3128,3323,3443,3702,4000,4343,4444,4592,4848,5000,5054,5060,5061,5117,5222,"
        "5250,5416,5443,5450,5480,5555,5600,5814,5894,5984,5985,5986,6060,6080,6173,6988,7000,7001,7005,7070,"
        "7071,7080,7144,7145,7180,7181,7510,7770,7777,7778,7779,8000,8001,8008,8014,8015,8020,8028,8040,8080,"
        "8081,8082,8085,8088,8090,8095,8118,8123,8161,8180,8181,8182,8222,8243,8280,8300,8333,8344,8393,8400,"
        "8443,8484,8500,8509,8511,8694,8787,8800,8848,8852,8880,8888,8899,8983,9000,9001,9002,9050,9060,9080,"
        "9090,9091,9111,9200,9201,9290,9443,9447,9502,9700,9710,9788,9830,9850,9990,9999,10000,10080,10100,"
        "10250,10255,10297,10443,11371,12601,13014,14592,15489,16000,16992,16993,16994,16995,17000,18081,19980,"
        "20000,29991,30007,30018,30888,33300,34412,34443,34444,36099,37215,40007,41080,44449,49152,49153,50000,"
        "50002,50452,51423,53331,54444,55252,55555,56712]"
    ),
    "SHELLCODE_PORTS": "!80",
    "ORACLE_PORTS": "1024:",
    "SSH_PORTS": "22",
    "FTP_PORTS": "[21,2100,3535]",
    "SIP_PORTS": "[5060,5061,5600]",
    "FILE_DATA_PORTS": "[$HTTP_PORTS,110,143]",
    "GTP_PORTS": "[2123,2152,3386]",
    "AIM_SERVERS": (
        "[64.12.24.0/23,64.12.28.0/23,64.12.161.0/24,64.12.163.0/24,64.12.200.0/24,205.188.3.0/24,"
        "205.188.5.0/24,205.188.7.0/24,205.188.9.0/24,205.188.153.0/24,205.188.179.0/24,205.188.248.0/24]"
    ),
}


@dataclass(frozen=True)
class Config:
    """Các giá trị chỉnh được của Decoder, Preprocessor, Flow Tracker và phần nạp rule.

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
    # Các file .rules cần nạp; để rỗng và không truyền --rules thì không chạy bước so khớp rule.
    rule_files: list[str] = field(default_factory=list)
    # Tắt cả một file rule (ghi tên file hoặc đường dẫn) hoặc tắt từng rule theo sid.
    disabled_rule_files: list[str] = field(default_factory=list)
    disabled_sids: list[int] = field(default_factory=list)
    # Giá trị của các biến trong rule; file cấu hình chỉ cần ghi biến muốn đổi, ví dụ {"HOME_NET": "10.0.0.0/8"}.
    rule_variables: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_RULE_VARIABLES))

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
        for name in ("rule_files", "disabled_rule_files"):
            value = getattr(self, name)
            if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
                raise ValueError(f"{name} phai la danh sach duong dan")
        if not isinstance(self.disabled_sids, list) or not all(type(sid) is int for sid in self.disabled_sids):
            raise ValueError("disabled_sids phai la danh sach so nguyen")
        variables = self.rule_variables
        if not isinstance(variables, dict) or not all(isinstance(value, str) for value in variables.values()):
            raise ValueError("rule_variables phai la object voi gia tri la chuoi")
        # Dataclass này không cho sửa sau khi tạo nên phải ghi trực tiếp; biến không ghi thì giữ giá trị mặc định.
        object.__setattr__(self, "rule_variables", {**DEFAULT_RULE_VARIABLES, **variables})


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
