# Output - Ghi event thành JSON Lines

Module nhận dictionary event từ `main.py` và ghi vào file. Nó không phân tích packet, không nhận diện giao thức và không quyết định event có phải dấu hiệu xâm nhập hay không.

## Các file và cách dùng

- `jsonl.py`: cài đặt lớp `JsonLinesWriter`.
- `__init__.py`: xuất lại lớp để có thể import qua package.

```python
from src.output.jsonl import JsonLinesWriter

event = {"packet_id": 1, "status": "unknown", "errors": []}
with JsonLinesWriter("output/ids.jsonl") as writer:
    writer.write(event)
```

Ví dụ trên minh họa cách ghi dictionary; các trường còn lại của event được mô tả trong [README parser](../parser/README.md).

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
