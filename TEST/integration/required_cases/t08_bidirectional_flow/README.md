# T08 - Bidirectional flow

**Kết quả mong đợi theo đề:** cùng flow_id; đúng direction.

## Dữ liệu đầu vào

Sáu gói qua lại giữa client 198.51.100.200:51000 và server 192.0.2.20:80 (bắt tay, request, response, ACK). IP của client lớn hơn IP server. File `input.pcap` chứa gói tin tổng hợp dựng bằng Scapy, được đọc offline.

Cấu hình mặc định (ghi đầy đủ trong `config.json`).

## Cách chạy lại

Từ thư mục gốc repo; dùng tên file output mới vì chương trình ghi nối tiếp:

```powershell
python main.py --pcap TEST/integration/required_cases/t08_bidirectional_flow/input.pcap --config TEST/integration/required_cases/t08_bidirectional_flow/config.json --output output/t08_events.jsonl --flow-output output/t08_flows.jsonl
```

Tạo lại toàn bộ đầu vào, chạy và đối chiếu ca này bằng script:

```powershell
python TEST/integration/run_required_cases.py --case T08 --overwrite
```

## Kết quả đã chạy

- Kết luận: **ĐẠT** (17/17 phép đối chiếu).
- Mã thoát CLI: `0`; số event: `6`; số flow ghi ra: `1`.
- Ý nghĩa: Cả sáu gói cùng flow_id. endpoint_a là bên gửi gói đầu tiên (client), nên gói client → server là forward, gói server → client là backward, dù khóa tra flow sắp xếp IP server lên trước.

| Trường kiểm tra | Mong đợi | Thực tế | Kết quả |
| --- | --- | --- | --- |
| `exit_code` | `0` | `0` | ĐẠT |
| `event_count` | `6` | `6` | ĐẠT |
| `flow_count` | `1` | `1` | ĐẠT |
| `events.0.direction` | `"forward"` | `"forward"` | ĐẠT |
| `events.1.direction` | `"backward"` | `"backward"` | ĐẠT |
| `events.2.direction` | `"forward"` | `"forward"` | ĐẠT |
| `events.3.direction` | `"forward"` | `"forward"` | ĐẠT |
| `events.4.direction` | `"backward"` | `"backward"` | ĐẠT |
| `events.5.direction` | `"forward"` | `"forward"` | ĐẠT |
| `flows.0.endpoint_a` | `{"ip": "198.51.100.200", "port": 51000}` | `{"ip": "198.51.100.200", "port": 51000}` | ĐẠT |
| `flows.0.endpoint_b` | `{"ip": "192.0.2.20", "port": 80}` | `{"ip": "192.0.2.20", "port": 80}` | ĐẠT |
| `flows.0.forward_packet_count` | `4` | `4` | ĐẠT |
| `flows.0.backward_packet_count` | `2` | `2` | ĐẠT |
| `flows.0.forward_byte_count` | `254` | `254` | ĐẠT |
| `flows.0.backward_byte_count` | `174` | `174` | ĐẠT |
| `flows.0.application_protocol` | `"HTTP"` | `"HTTP"` | ĐẠT |
| `same_flow [0, 1, 2, 3, 4, 5]` | `"cùng một flow_id"` | `["f73f1d3b205d6fb3", "f73f1d3b205d6fb3", "f73f1d3b205d6fb3", "f73f1d3b205d6fb3", "f73f1d3b205d6fb3", "f73f1d3b205d6fb3"]` | ĐẠT |

## Artifact

- `input.pcap`: dữ liệu đầu vào.
- `config.json`: cấu hình đã dùng.
- `expected.json`: các giá trị phải quan sát được.
- `events.jsonl`: event sau toàn bộ pipeline, mỗi dòng ứng với một gói/event đầu vào.
- `flows.jsonl`: tổng kết flow theo thứ tự được ghi ra.
- `result.json`: mã thoát, từng giá trị thực tế và kết luận đối chiếu.

[Về bảng tổng hợp](../README.md)
