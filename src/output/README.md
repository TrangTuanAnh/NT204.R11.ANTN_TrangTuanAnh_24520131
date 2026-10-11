# Output - Ghi event thành JSON Lines

Module nhận dictionary từ `main.py` và ghi vào file. Nó không phân tích packet, không nhận diện giao thức và không quyết định event có phải dấu hiệu xâm nhập hay không.

Ở chế độ đầy đủ, `main.py` mở hai writer: một ghi event (`--output`, mặc định `output/ids.jsonl`), một ghi bản tổng kết flow (`--flow-output`, mặc định `output/flows.jsonl`). Chế độ `--parse-only` chỉ mở writer cho event.

## Các file và cách dùng

- `jsonl.py`: cài đặt lớp `JsonLinesWriter`.
- `__init__.py`: xuất lại lớp để có thể import qua package.

```python
from src.output.jsonl import JsonLinesWriter

event = {"packet_id": 1, "status": "unknown", "errors": []}
with JsonLinesWriter("output/ids.jsonl") as writer:
    writer.write(event)
```

Ví dụ trên minh họa cách ghi dictionary; các trường của event được mô tả trong [README chung](../../README.md#3-đọc-kết-quả-đầu-ra), các trường của bản tổng kết flow trong [README Flow Tracker](../flow/README.md#thống-kê-của-mỗi-flow).

## Vòng đời file

| Phương thức | Công việc |
| --- | --- |
| `__init__(path)` | Lưu đường dẫn, chưa mở file |
| `__enter__()` | Tạo thư mục cha nếu thiếu, mở file UTF-8 ở chế độ nối tiếp |
| `write(event)` | Chuyển event thành JSON, thêm xuống dòng và flush |
| `__exit__(...)` | Đóng file khi ra khỏi khối `with`, kể cả khi có lỗi |

Mỗi event nằm trên một dòng; file không phải một JSON array. Đọc từng dòng rồi dùng JSON parser cho từng dòng.

Flush đẩy dữ liệu khỏi bộ đệm Python; không tương đương cam kết dữ liệu đã được ghi bền vững xuống thiết bị khi mất điện. File được nối thêm nên chạy lại sẽ giữ các dòng cũ. Lớp này không đánh số packet, không chống trùng ID và không xoay vòng file log.

Gọi `write` trước khi mở file bằng `with` sẽ báo lỗi. Lỗi mở/ghi file được truyền về bên gọi; module không tự thử lại. Các lỗi I/O thông thường được `main.py` báo ra stderr.

[Quay lại kiến trúc chung](../../README.md)
