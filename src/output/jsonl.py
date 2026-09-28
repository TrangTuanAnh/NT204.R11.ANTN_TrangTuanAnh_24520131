from __future__ import annotations

import json
from pathlib import Path
from typing import Any, TextIO


class JsonLinesWriter:
    """Quản lý file JSON Lines để ghi và flush từng event ngay khi nhận được."""

    def __init__(self, path: str | Path) -> None:
        """Lưu đường dẫn file sẽ nhận các dòng JSON."""
        self.path = Path(path)
        self._stream: TextIO | None = None

    def __enter__(self) -> "JsonLinesWriter":
        """Tạo thư mục cha và mở file ở chế độ nối tiếp, giữ kết quả cũ."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._stream = self.path.open("a", encoding="utf-8")
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        """Đóng file khi rời khối with, kể cả nếu quá trình ghi gặp lỗi."""
        if self._stream is not None:
            self._stream.close()

    def write(self, event: dict[str, Any]) -> None:
        """Chuyển event thành một dòng JSON UTF-8 rồi flush xuống file."""
        if self._stream is None:
            raise RuntimeError("JsonLinesWriter phải được dùng trong with")
        self._stream.write(json.dumps(event, ensure_ascii=False) + "\n")
        self._stream.flush()
