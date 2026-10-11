# T05 - Normalization

**Kết quả mong đợi theo đề:** representation sau preprocess nhất quán.

## Dữ liệu đầu vào

Ba event JSON viết khác kiểu: tên giao thức " tcp ", "Tcp", "http", "Dns"; header HOST/User-AGENT; tên miền chữ hoa có dấu chấm cuối; IPv6 viết dài; timestamp dạng ISO có múi giờ, dạng Z và chuỗi số; URI có "./", "../" và %7e. File `input.jsonl` chứa event JSON, mỗi dòng một event, được đọc offline.

Cấu hình mặc định (ghi đầy đủ trong `config.json`).

## Cách chạy lại

Từ thư mục gốc repo; dùng tên file output mới vì chương trình ghi nối tiếp:

```powershell
python main.py --events TEST/integration/required_cases/t05_event_normalization/input.jsonl --config TEST/integration/required_cases/t05_event_normalization/config.json --output output/t05_events.jsonl --flow-output output/t05_flows.jsonl
```

Tạo lại toàn bộ đầu vào, chạy và đối chiếu ca này bằng script:

```powershell
python TEST/integration/run_required_cases.py --case T05 --overwrite
```

## Kết quả đã chạy

- Kết luận: **ĐẠT** (22/22 phép đối chiếu).
- Mã thoát CLI: `0`; số event: `3`; số flow ghi ra: `2`.
- Ý nghĩa: Sau Preprocessor: tên giao thức viết hoa, tên header viết thường (header trùng tên được gộp), tên miền viết thường không có dấu chấm cuối, IP theo cách viết chuẩn, timestamp là số giây Unix. URI gốc giữ nguyên, uri_normalized bỏ "./", "../" và giải mã %7e thành ~ nhưng giữ %2F.

| Trường kiểm tra | Mong đợi | Thực tế | Kết quả |
| --- | --- | --- | --- |
| `exit_code` | `0` | `0` | ĐẠT |
| `event_count` | `3` | `3` | ĐẠT |
| `events.0.timestamp` | `1790899200.0` | `1790899200.0` | ĐẠT |
| `events.0.transport.protocol` | `"TCP"` | `"TCP"` | ĐẠT |
| `events.0.transport.flags` | `"PA"` | `"PA"` | ĐẠT |
| `events.0.application.protocol` | `"HTTP"` | `"HTTP"` | ĐẠT |
| `events.0.application.headers` | `{"host": "www.example.test", "user-agent": "curl/8.0", "x-forwarded-for": "198.51.100.7, 203.0.113.9"}` | `{"host": "www.example.test", "user-agent": "curl/8.0", "x-forwarded-for": "198.51.100.7, 203.0.113.9"}` | ĐẠT |
| `events.0.application.uri` | `"/Shop/./Products/../Index.HTML?ID=%7e5&q=%2f"` | `"/Shop/./Products/../Index.HTML?ID=%7e5&q=%2f"` | ĐẠT |
| `events.0.application.uri_normalized` | `"/Shop/Index.HTML?ID=~5&q=%2F"` | `"/Shop/Index.HTML?ID=~5&q=%2F"` | ĐẠT |
| `events.0.preprocess_status` | `"valid"` | `"valid"` | ĐẠT |
| `events.1.timestamp` | `1790899201.0` | `1790899201.0` | ĐẠT |
| `events.1.transport.protocol` | `"TCP"` | `"TCP"` | ĐẠT |
| `events.1.application.protocol` | `"HTTP"` | `"HTTP"` | ĐẠT |
| `events.1.application.headers.host` | `"www.example.test"` | `"www.example.test"` | ĐẠT |
| `events.2.timestamp` | `1790899202.5` | `1790899202.5` | ĐẠT |
| `events.2.network.src_ip` | `"2001:db8::a"` | `"2001:db8::a"` | ĐẠT |
| `events.2.network.dst_ip` | `"2001:db8::35"` | `"2001:db8::35"` | ĐẠT |
| `events.2.transport.protocol` | `"UDP"` | `"UDP"` | ĐẠT |
| `events.2.application.protocol` | `"DNS"` | `"DNS"` | ĐẠT |
| `events.2.application.questions` | `[{"name": "www.example.test", "type": 28}]` | `[{"name": "www.example.test", "type": 28}]` | ĐẠT |
| `events.2.application.answers` | `[{"name": "www.example.test", "type": 28, "data": "2001:db8::1"}, {"name": "example.test", "type": 5, "data": "alias.example.test"}]` | `[{"name": "www.example.test", "type": 28, "data": "2001:db8::1"}, {"name": "example.test", "type": 5, "data": "alias.example.test"}]` | ĐẠT |
| `events.2.preprocess_status` | `"valid"` | `"valid"` | ĐẠT |

## Artifact

- `input.jsonl`: dữ liệu đầu vào.
- `config.json`: cấu hình đã dùng.
- `expected.json`: các giá trị phải quan sát được.
- `events.jsonl`: event sau toàn bộ pipeline, mỗi dòng ứng với một gói/event đầu vào.
- `flows.jsonl`: tổng kết flow theo thứ tự được ghi ra.
- `result.json`: mã thoát, từng giá trị thực tế và kết luận đối chiếu.

[Về bảng tổng hợp](../README.md)
