# T11 - Concurrent flows

**Kết quả mong đợi theo đề:** không gộp nhầm flow.

## Dữ liệu đầu vào

Mười một gói xen kẽ của bốn phiên tới 192.0.2.20:80: TCP từ 192.0.2.10:40001, TCP từ 192.0.2.10:40002 (khác port), TCP từ 192.0.2.11:40001 (khác IP) và UDP từ 192.0.2.10:40001 (cùng IP/port với phiên đầu nhưng khác giao thức). File `input.pcap` chứa gói tin tổng hợp dựng bằng Scapy, được đọc offline.

Cấu hình mặc định (ghi đầy đủ trong `config.json`).

## Cách chạy lại

Từ thư mục gốc repo; dùng tên file output mới vì chương trình ghi nối tiếp:

```powershell
python main.py --pcap TEST/integration/required_cases/t11_concurrent_flows/input.pcap --config TEST/integration/required_cases/t11_concurrent_flows/config.json --output output/t11_events.jsonl --flow-output output/t11_flows.jsonl
```

Tạo lại toàn bộ đầu vào, chạy và đối chiếu ca này bằng script:

```powershell
python TEST/integration/run_required_cases.py --case T11 --overwrite
```

## Kết quả đã chạy

- Kết luận: **ĐẠT** (17/17 phép đối chiếu).
- Mã thoát CLI: `0`; số event: `11`; số flow ghi ra: `4`.
- Ý nghĩa: Mỗi phiên có flow riêng: bốn flow_id khác nhau, ba flow TCP mỗi flow 3 gói ở trạng thái ESTABLISHED, flow UDP 2 gói.

| Trường kiểm tra | Mong đợi | Thực tế | Kết quả |
| --- | --- | --- | --- |
| `exit_code` | `0` | `0` | ĐẠT |
| `event_count` | `11` | `11` | ĐẠT |
| `flow_count` | `4` | `4` | ĐẠT |
| `flow_of_event.0.packet_count` | `3` | `3` | ĐẠT |
| `flow_of_event.0.state` | `"ESTABLISHED"` | `"ESTABLISHED"` | ĐẠT |
| `flow_of_event.1.packet_count` | `3` | `3` | ĐẠT |
| `flow_of_event.1.state` | `"ESTABLISHED"` | `"ESTABLISHED"` | ĐẠT |
| `flow_of_event.2.packet_count` | `3` | `3` | ĐẠT |
| `flow_of_event.2.state` | `"ESTABLISHED"` | `"ESTABLISHED"` | ĐẠT |
| `flow_of_event.3.packet_count` | `2` | `2` | ĐẠT |
| `flow_of_event.3.protocol` | `"UDP"` | `"UDP"` | ĐẠT |
| `active_flows_trace` | `[1, 2, 3, 4, 4, 4, 4, 4, 4, 4, 4]` | `[1, 2, 3, 4, 4, 4, 4, 4, 4, 4, 4]` | ĐẠT |
| `same_flow [0, 4, 8]` | `"cùng một flow_id"` | `["0cd6317f54a73e2f", "0cd6317f54a73e2f", "0cd6317f54a73e2f"]` | ĐẠT |
| `same_flow [1, 5, 9]` | `"cùng một flow_id"` | `["de16268f8dc00349", "de16268f8dc00349", "de16268f8dc00349"]` | ĐẠT |
| `same_flow [2, 7, 10]` | `"cùng một flow_id"` | `["b00df8dcaa863850", "b00df8dcaa863850", "b00df8dcaa863850"]` | ĐẠT |
| `same_flow [3, 6]` | `"cùng một flow_id"` | `["c973eda276550fc4", "c973eda276550fc4"]` | ĐẠT |
| `different_flow [0, 1, 2, 3]` | `"các flow_id khác nhau"` | `["0cd6317f54a73e2f", "de16268f8dc00349", "b00df8dcaa863850", "c973eda276550fc4"]` | ĐẠT |

## Artifact

- `input.pcap`: dữ liệu đầu vào.
- `config.json`: cấu hình đã dùng.
- `expected.json`: các giá trị phải quan sát được.
- `events.jsonl`: event sau toàn bộ pipeline, mỗi dòng ứng với một gói/event đầu vào.
- `flows.jsonl`: tổng kết flow theo thứ tự được ghi ra.
- `result.json`: mã thoát, từng giá trị thực tế và kết luận đối chiếu.

[Về bảng tổng hợp](../README.md)
