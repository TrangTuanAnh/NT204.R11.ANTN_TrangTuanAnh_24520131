# T04 - Invalid bytes

**Kết quả mong đợi theo đề:** đánh dấu lỗi/partial; chương trình tiếp tục.

## Dữ liệu đầu vào

Năm gói: body khai báo UTF-8 nhưng có byte \xff\xfe; URI có %FF; payload TCP thô (port 9000) chứa \xc3\x28 và \x80; body khai báo us-ascii nhưng chứa chữ "é"; cuối cùng là một GET hợp lệ. File `input.pcap` chứa gói tin tổng hợp dựng bằng Scapy, được đọc offline.

Cấu hình mặc định (ghi đầy đủ trong `config.json`).

## Cách chạy lại

Từ thư mục gốc repo; dùng tên file output mới vì chương trình ghi nối tiếp:

```powershell
python main.py --pcap TEST/integration/required_cases/t04_invalid_character_bytes/input.pcap --config TEST/integration/required_cases/t04_invalid_character_bytes/config.json --output output/t04_events.jsonl --flow-output output/t04_flows.jsonl
```

Tạo lại toàn bộ đầu vào, chạy và đối chiếu ca này bằng script:

```powershell
python TEST/integration/run_required_cases.py --case T04 --overwrite
```

## Kết quả đã chạy

- Kết luận: **ĐẠT** (14/14 phép đối chiếu).
- Mã thoát CLI: `0`; số event: `5`; số flow ghi ra: `2`.
- Ý nghĩa: Byte sai được thay bằng ký tự �, decode_status là partial và decode_errors ghi vị trí byte lỗi. Gói hợp lệ cuối vẫn được xử lý bình thường, chứng tỏ chương trình không dừng.

| Trường kiểm tra | Mong đợi | Thực tế | Kết quả |
| --- | --- | --- | --- |
| `exit_code` | `0` | `0` | ĐẠT |
| `event_count` | `5` | `5` | ĐẠT |
| `events.0.decoded.body` | `"ten=��abc"` | `"ten=��abc"` | ĐẠT |
| `events.0.decode_status` | `"partial"` | `"partial"` | ĐẠT |
| `events.0.decode_errors` | `["Body HTTP: có byte không hợp lệ với bảng mã utf-8 (vị trí 4)"]` | `["Body HTTP: có byte không hợp lệ với bảng mã utf-8 (vị trí 4)"]` | ĐẠT |
| `events.1.decoded.uri` | `"/file�name"` | `"/file�name"` | ĐẠT |
| `events.1.decode_status` | `"partial"` | `"partial"` | ĐẠT |
| `events.2.application.protocol` | `null` | `null` | ĐẠT |
| `events.2.decoded.text` | `"�( hello �"` | `"�( hello �"` | ĐẠT |
| `events.2.decode_status` | `"partial"` | `"partial"` | ĐẠT |
| `events.3.decoded.body` | `"caf��"` | `"caf��"` | ĐẠT |
| `events.3.decode_errors` | `["Body HTTP: có byte không hợp lệ với bảng mã us-ascii (vị trí 3)"]` | `["Body HTTP: có byte không hợp lệ với bảng mã us-ascii (vị trí 3)"]` | ĐẠT |
| `events.4.decoded.uri` | `"/ok"` | `"/ok"` | ĐẠT |
| `events.4.decode_status` | `"ok"` | `"ok"` | ĐẠT |

## Artifact

- `input.pcap`: dữ liệu đầu vào.
- `config.json`: cấu hình đã dùng.
- `expected.json`: các giá trị phải quan sát được.
- `events.jsonl`: event sau toàn bộ pipeline, mỗi dòng ứng với một gói/event đầu vào.
- `flows.jsonl`: tổng kết flow theo thứ tự được ghi ra.
- `result.json`: mã thoát, từng giá trị thực tế và kết luận đối chiếu.

[Về bảng tổng hợp](../README.md)
