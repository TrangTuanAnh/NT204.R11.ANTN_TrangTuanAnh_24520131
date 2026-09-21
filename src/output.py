from __future__ import annotations

import json
from pathlib import Path
from typing import Any, TextIO


class JsonLinesWriter:
    """Ghi mỗi sự kiện thành một dòng JSON và flush ngay sau khi ghi."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._stream: TextIO | None = None

    def __enter__(self) -> "JsonLinesWriter":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._stream = self.path.open("a", encoding="utf-8")
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        if self._stream is not None:
            self._stream.close()

    def write(self, event: dict[str, Any]) -> None:
        if self._stream is None:
            raise RuntimeError("JsonLinesWriter phải được dùng trong with")
        self._stream.write(json.dumps(event, ensure_ascii=False) + "\n")
        self._stream.flush()
