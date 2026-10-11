# T01 - HTTP URL decode

**Kết quả mong đợi theo đề:** decoded URI đúng; raw URI còn nguyên.

## Dữ liệu đầu vào

Hai gói HTTP: GET có tham số mã hóa %XX (gồm cả %2527 là dấu % bị mã hóa hai lần) và POST có body dạng application/x-www-form-urlencoded. File `input.pcap` chứa gói tin tổng hợp dựng bằng Scapy, được đọc offline.

Cấu hình mặc định (ghi đầy đủ trong `config.json`).

## Cách chạy lại

Từ thư mục gốc repo; dùng tên file output mới vì chương trình ghi nối tiếp:

```powershell
python main.py --pcap TEST/integration/required_cases/t01_http_url_decode/input.pcap --config TEST/integration/required_cases/t01_http_url_decode/config.json --output output/t01_events.jsonl --flow-output output/t01_flows.jsonl
```

Tạo lại toàn bộ đầu vào, chạy và đối chiếu ca này bằng script:

```powershell
python TEST/integration/run_required_cases.py --case T01 --overwrite
```

## Kết quả đã chạy

- Kết luận: **ĐẠT** (9/9 phép đối chiếu).
- Mã thoát CLI: `0`; số event: `2`; số flow ghi ra: `1`.
- Ý nghĩa: URI gốc ở application.uri giữ nguyên; decoded.uri giải mã một lượt nên %2527 chỉ thành %27. Trong tham số và form, dấu + là khoảng trắng còn %2B là dấu cộng thật.

| Trường kiểm tra | Mong đợi | Thực tế | Kết quả |
| --- | --- | --- | --- |
| `exit_code` | `0` | `0` | ĐẠT |
| `event_count` | `2` | `2` | ĐẠT |
| `events.0.application.uri` | `"/search?q=%27%20OR%201%3D1&lang=vi%2Ben&next=%2527"` | `"/search?q=%27%20OR%201%3D1&lang=vi%2Ben&next=%2527"` | ĐẠT |
| `events.0.decoded.uri` | `"/search?q=' OR 1=1&lang=vi+en&next=%27"` | `"/search?q=' OR 1=1&lang=vi+en&next=%27"` | ĐẠT |
| `events.0.decoded.query` | `[["q", "' OR 1=1"], ["lang", "vi+en"], ["next", "%27"]]` | `[["q", "' OR 1=1"], ["lang", "vi+en"], ["next", "%27"]]` | ĐẠT |
| `events.0.decode_status` | `"ok"` | `"ok"` | ĐẠT |
| `events.1.decoded.body` | `"user=admin%27--&pass=a+b%26c&note="` | `"user=admin%27--&pass=a+b%26c&note="` | ĐẠT |
| `events.1.decoded.form` | `[["user", "admin'--"], ["pass", "a b&c"], ["note", ""]]` | `[["user", "admin'--"], ["pass", "a b&c"], ["note", ""]]` | ĐẠT |
| `events.1.decode_status` | `"ok"` | `"ok"` | ĐẠT |

## Artifact

- `input.pcap`: dữ liệu đầu vào.
- `config.json`: cấu hình đã dùng.
- `expected.json`: các giá trị phải quan sát được.
- `events.jsonl`: event sau toàn bộ pipeline, mỗi dòng ứng với một gói/event đầu vào.
- `flows.jsonl`: tổng kết flow theo thứ tự được ghi ra.
- `result.json`: mã thoát, từng giá trị thực tế và kết luận đối chiếu.

[Về bảng tổng hợp](../README.md)
