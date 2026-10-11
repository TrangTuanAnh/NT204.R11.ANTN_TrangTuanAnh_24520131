# T12 - Idle timeout

**Kết quả mong đợi theo đề:** flow hết hạn và bị loại khỏi active table.

## Dữ liệu đầu vào

Cấu hình udp_idle_timeout = 5 giây, tcp_idle_timeout = 10 giây. Flow UDP A (port 50000) có gói ở giây 0 và 0,1; flow TCP bắt tay ở giây 1–1,2; flow UDP B (port 50001) có gói ở giây 3 và 4; giây 8 có truy vấn mới từ port 50000; giây 12 có câu trả lời cho truy vấn đó. File `input.pcap` chứa gói tin tổng hợp dựng bằng Scapy, được đọc offline.

Cấu hình khác mặc định: `udp_idle_timeout` = 5, `tcp_idle_timeout` = 10 (đầy đủ trong `config.json`).

## Cách chạy lại

Từ thư mục gốc repo; dùng tên file output mới vì chương trình ghi nối tiếp:

```powershell
python main.py --pcap TEST/integration/required_cases/t12_flow_idle_timeout/input.pcap --config TEST/integration/required_cases/t12_flow_idle_timeout/config.json --output output/t12_events.jsonl --flow-output output/t12_flows.jsonl
```

Tạo lại toàn bộ đầu vào, chạy và đối chiếu ca này bằng script:

```powershell
python TEST/integration/run_required_cases.py --case T12 --overwrite
```

## Kết quả đã chạy

- Kết luận: **ĐẠT** (16/16 phép đối chiếu).
- Mã thoát CLI: `0`; số event: `9`; số flow ghi ra: `4`.
- Ý nghĩa: Giây 8: flow A đã im lặng 7,9 giây (≥ 5) nên được ghi ra với lý do idle_timeout và xóa khỏi bảng; gói mới từ port 50000 tạo flow mới với flow_id khác. Flow B mới im lặng 4 giây nên chưa hết hạn. Giây 12: flow B (im lặng 8 giây) và flow TCP (10,8 giây) hết hạn. active_flows_trace cho thấy số flow trong bảng giảm đúng lúc.

| Trường kiểm tra | Mong đợi | Thực tế | Kết quả |
| --- | --- | --- | --- |
| `exit_code` | `0` | `0` | ĐẠT |
| `event_count` | `9` | `9` | ĐẠT |
| `flow_count` | `4` | `4` | ĐẠT |
| `flows.0.end_reason` | `"idle_timeout"` | `"idle_timeout"` | ĐẠT |
| `flows.0.endpoint_a` | `{"ip": "192.0.2.10", "port": 50000}` | `{"ip": "192.0.2.10", "port": 50000}` | ĐẠT |
| `flows.0.packet_count` | `2` | `2` | ĐẠT |
| `flow_of_event.2.end_reason` | `"idle_timeout"` | `"idle_timeout"` | ĐẠT |
| `flow_of_event.2.state` | `"ESTABLISHED"` | `"ESTABLISHED"` | ĐẠT |
| `flow_of_event.5.end_reason` | `"idle_timeout"` | `"idle_timeout"` | ĐẠT |
| `flow_of_event.7.end_reason` | `"end_of_input"` | `"end_of_input"` | ĐẠT |
| `flow_of_event.7.packet_count` | `2` | `2` | ĐẠT |
| `active_flows_trace` | `[1, 1, 2, 2, 2, 3, 3, 3, 1]` | `[1, 1, 2, 2, 2, 3, 3, 3, 1]` | ĐẠT |
| `same_flow [0, 1]` | `"cùng một flow_id"` | `["efed469b3a2e9007", "efed469b3a2e9007"]` | ĐẠT |
| `same_flow [5, 6]` | `"cùng một flow_id"` | `["3a250da563c261b8", "3a250da563c261b8"]` | ĐẠT |
| `same_flow [7, 8]` | `"cùng một flow_id"` | `["c7c58ddd6ef4ad6c", "c7c58ddd6ef4ad6c"]` | ĐẠT |
| `different_flow [0, 7]` | `"các flow_id khác nhau"` | `["efed469b3a2e9007", "c7c58ddd6ef4ad6c"]` | ĐẠT |

## Artifact

- `input.pcap`: dữ liệu đầu vào.
- `config.json`: cấu hình đã dùng.
- `expected.json`: các giá trị phải quan sát được.
- `events.jsonl`: event sau toàn bộ pipeline, mỗi dòng ứng với một gói/event đầu vào.
- `flows.jsonl`: tổng kết flow theo thứ tự được ghi ra.
- `result.json`: mã thoát, từng giá trị thực tế và kết luận đối chiếu.

[Về bảng tổng hợp](../README.md)
