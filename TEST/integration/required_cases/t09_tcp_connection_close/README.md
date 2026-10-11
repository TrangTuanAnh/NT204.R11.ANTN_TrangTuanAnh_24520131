# T09 - TCP close

**Kết quả mong đợi theo đề:** flow chuyển CLOSED/RESET phù hợp.

## Dữ liệu đầu vào

Hai kết nối. Kết nối 1 (port 40001): bắt tay, client FIN/ACK, server ACK, server FIN/ACK, client ACK. Kết nối 2 (port 40002): bắt tay rồi server gửi RST/ACK. File `input.pcap` chứa gói tin tổng hợp dựng bằng Scapy, được đọc offline.

Cấu hình mặc định (ghi đầy đủ trong `config.json`).

## Cách chạy lại

Từ thư mục gốc repo; dùng tên file output mới vì chương trình ghi nối tiếp:

```powershell
python main.py --pcap TEST/integration/required_cases/t09_tcp_connection_close/input.pcap --config TEST/integration/required_cases/t09_tcp_connection_close/config.json --output output/t09_events.jsonl --flow-output output/t09_flows.jsonl
```

Tạo lại toàn bộ đầu vào, chạy và đối chiếu ca này bằng script:

```powershell
python TEST/integration/run_required_cases.py --case T09 --overwrite
```

## Kết quả đã chạy

- Kết luận: **ĐẠT** (19/19 phép đối chiếu).
- Mã thoát CLI: `0`; số event: `11`; số flow ghi ra: `2`.
- Ý nghĩa: Kết nối 1 ở CLOSING từ gói FIN đầu tiên và chuyển CLOSED khi FIN thứ hai được ACK. Kết nối 2 chuyển RESET ngay khi có RST. Cả hai flow được ghi ra (tcp_closed, tcp_reset) và xóa khỏi bảng, nên sau gói cuối bảng flow rỗng.

| Trường kiểm tra | Mong đợi | Thực tế | Kết quả |
| --- | --- | --- | --- |
| `exit_code` | `0` | `0` | ĐẠT |
| `event_count` | `11` | `11` | ĐẠT |
| `flow_count` | `2` | `2` | ĐẠT |
| `events.2.flow_state` | `"ESTABLISHED"` | `"ESTABLISHED"` | ĐẠT |
| `events.3.flow_state` | `"CLOSING"` | `"CLOSING"` | ĐẠT |
| `events.4.flow_state` | `"CLOSING"` | `"CLOSING"` | ĐẠT |
| `events.5.flow_state` | `"CLOSING"` | `"CLOSING"` | ĐẠT |
| `events.6.flow_state` | `"CLOSED"` | `"CLOSED"` | ĐẠT |
| `events.10.flow_state` | `"RESET"` | `"RESET"` | ĐẠT |
| `flows.0.state` | `"CLOSED"` | `"CLOSED"` | ĐẠT |
| `flows.0.end_reason` | `"tcp_closed"` | `"tcp_closed"` | ĐẠT |
| `flows.0.FIN_count` | `2` | `2` | ĐẠT |
| `flows.1.state` | `"RESET"` | `"RESET"` | ĐẠT |
| `flows.1.end_reason` | `"tcp_reset"` | `"tcp_reset"` | ĐẠT |
| `flows.1.RST_count` | `1` | `1` | ĐẠT |
| `active_flows_trace` | `[1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0]` | `[1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0]` | ĐẠT |
| `same_flow [0, 1, 2, 3, 4, 5, 6]` | `"cùng một flow_id"` | `["0cd6317f54a73e2f", "0cd6317f54a73e2f", "0cd6317f54a73e2f", "0cd6317f54a73e2f", "0cd6317f54a73e2f", "0cd6317f54a73e2f", "0cd6317f54a73e2f"]` | ĐẠT |
| `same_flow [7, 8, 9, 10]` | `"cùng một flow_id"` | `["0a698ee36b19e023", "0a698ee36b19e023", "0a698ee36b19e023", "0a698ee36b19e023"]` | ĐẠT |
| `different_flow [0, 7]` | `"các flow_id khác nhau"` | `["0cd6317f54a73e2f", "0a698ee36b19e023"]` | ĐẠT |

## Artifact

- `input.pcap`: dữ liệu đầu vào.
- `config.json`: cấu hình đã dùng.
- `expected.json`: các giá trị phải quan sát được.
- `events.jsonl`: event sau toàn bộ pipeline, mỗi dòng ứng với một gói/event đầu vào.
- `flows.jsonl`: tổng kết flow theo thứ tự được ghi ra.
- `result.json`: mã thoát, từng giá trị thực tế và kết luận đối chiếu.

[Về bảng tổng hợp](../README.md)
