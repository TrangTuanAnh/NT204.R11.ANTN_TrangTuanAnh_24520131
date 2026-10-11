"""Đổi byte thành chữ và ghi lại các lỗi gặp phải trong lúc giải mã một event."""

from __future__ import annotations


class DecodeReport:
    """Sổ ghi kết quả giải mã của một event.

    Mỗi phần dữ liệu (URI, body, một phần của thư...) giải mã xong thì ghi
    "có kết quả"; gặp lỗi thì ghi lỗi. Từ hai thông tin này suy ra trạng
    thái chung của cả event.
    """

    def __init__(self) -> None:
        """Bắt đầu với sổ trống: chưa có phần nào được giải mã, chưa có lỗi."""
        self.errors: list[str] = []
        self.decoded = 0

    def add_result(self) -> None:
        """Ghi nhận một phần dữ liệu đã giải mã ra kết quả."""
        self.decoded += 1

    def add_error(self, message: str) -> None:
        """Ghi một lỗi; cùng một nội dung lỗi chỉ ghi một lần."""
        if message not in self.errors:
            self.errors.append(message)

    def status(self) -> str:
        """Suy ra trạng thái giải mã của event.

        - not_applicable: không có gì cần giải mã.
        - ok: giải mã được và không gặp lỗi.
        - partial: có kết quả nhưng gặp lỗi ở một số chỗ.
        - error: có lỗi và không giải mã được phần nào.
        """
        if not self.errors:
            return "ok" if self.decoded else "not_applicable"
        return "partial" if self.decoded else "error"


def decode_text(data: bytes, charset: str | None, report: DecodeReport, label: str) -> str:
    """Đổi byte thành chữ theo bảng mã (charset); không ghi bảng mã thì dùng UTF-8.

    UTF-8 bao gồm cả ASCII nên chữ ASCII thuần luôn đọc đúng. Byte không hợp lệ
    được thay bằng ký tự "�" và ghi lại lỗi, nên dữ liệu hỏng không làm dừng
    chương trình. Bảng mã lạ thì tạm đọc theo UTF-8.
    """
    name = (charset or "").strip().strip("\"'").lower() or "utf-8"
    if not _is_text_charset(name):
        report.add_error(f"{label}: chưa hỗ trợ bảng mã '{name}', tạm đọc theo UTF-8")
        name = "utf-8"
    try:
        return data.decode(name)
    except UnicodeDecodeError as exc:
        report.add_error(f"{label}: có byte không hợp lệ với bảng mã {name} (vị trí {exc.start})")
        return data.decode(name, errors="replace")


def _is_text_charset(name: str) -> bool:
    """Python có bảng mã chữ mang tên này không.

    Thử mã hóa một chữ cái: tên lạ hoặc bộ mã không dành cho chữ (như "base64")
    đều báo lỗi. Không thử với chuỗi rỗng vì Python bỏ qua việc kiểm tra tên khi đó.
    """
    try:
        "a".encode(name)
        return True
    except (LookupError, UnicodeError):
        return False


def limit_bytes(data: bytes, limit: int, report: DecodeReport, label: str) -> bytes:
    """Cắt dữ liệu dài hơn giới hạn cấu hình và ghi lại việc chỉ giải mã phần đầu."""
    if len(data) <= limit:
        return data
    report.add_error(f"{label} dài {len(data)} byte, vượt giới hạn {limit} byte; chỉ giải mã phần đầu")
    return data[:limit]
