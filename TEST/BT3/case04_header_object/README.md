# Ca 04 - Parse header

**Kết quả mong đợi theo đề:** Internal Rule Object đúng.

## Dữ liệu đầu vào

Bốn rule TCP: any/any; IP đơn và port đơn; dải CIDR với khoảng port hai đầu và khoảng chỉ có đầu cuối; khoảng chỉ có đầu đầu. Một gói từ 10.0.0.5:52133 tới 192.168.1.20:80 để kiểm tra đối tượng đó hoạt động đúng. File `input.pcap` chứa gói tin tổng hợp dựng bằng Scapy, được đọc offline.

Cấu hình mặc định.

## Cách chạy lại

Từ thư mục gốc repo; dùng tên file output mới vì chương trình ghi nối tiếp:

```powershell
python main.py --pcap TEST/BT3/case04_header_object/input.pcap --rules TEST/BT3/case04_header_object/input.rules --config TEST/BT3/case04_header_object/config.json --output output/case04_events.jsonl --flow-output output/case04_flows.jsonl --detection-output output/case04_detections.jsonl --rule-report output/case04_rule_report.json
```

Tạo lại toàn bộ đầu vào, chạy và đối chiếu ca này bằng script:

```powershell
python TEST/BT3/run_cases.py --case 04 --overwrite
```

## Kết quả đã chạy

- Kết luận: **ĐẠT** (23/23 phép đối chiếu).
- Mã thoát CLI: `0`; số event: `1`; số Detection Event: `3`.
- Ý nghĩa: report.rules.<i>.rule là Internal Rule Object của từng rule. IP đơn được lưu dạng /32, :1023 là từ 0 tới 1023, 1024: là từ 1024 tới 65535. Gói có port đích 80 khớp ba rule đầu, không khớp rule cần port đích 8000-8080.

| Trường kiểm tra | Mong đợi | Thực tế | Kết quả |
| --- | --- | --- | --- |
| `exit_code` | `0` | `0` | ĐẠT |
| `report.summary.valid` | `4` | `4` | ĐẠT |
| `report.rules.0.rule.action` | `"alert"` | `"alert"` | ĐẠT |
| `report.rules.0.rule.protocol` | `"tcp"` | `"tcp"` | ĐẠT |
| `report.rules.0.rule.direction` | `"->"` | `"->"` | ĐẠT |
| `report.rules.0.rule.source` | `{"any": true, "include": [], "exclude": []}` | `{"any": true, "include": [], "exclude": []}` | ĐẠT |
| `report.rules.0.rule.source_ports` | `{"any": true, "include": [], "exclude": []}` | `{"any": true, "include": [], "exclude": []}` | ĐẠT |
| `report.rules.0.rule.destination` | `{"any": true, "include": [], "exclude": []}` | `{"any": true, "include": [], "exclude": []}` | ĐẠT |
| `report.rules.0.rule.destination_ports` | `{"any": true, "include": [], "exclude": []}` | `{"any": true, "include": [], "exclude": []}` | ĐẠT |
| `report.rules.1.rule.source` | `{"any": false, "include": ["10.0.0.5/32"], "exclude": []}` | `{"any": false, "include": ["10.0.0.5/32"], "exclude": []}` | ĐẠT |
| `report.rules.1.rule.source_ports` | `{"any": false, "include": [[52133, 52133]], "exclude": []}` | `{"any": false, "include": [[52133, 52133]], "exclude": []}` | ĐẠT |
| `report.rules.1.rule.destination` | `{"any": false, "include": ["192.168.1.20/32"], "exclude": []}` | `{"any": false, "include": ["192.168.1.20/32"], "exclude": []}` | ĐẠT |
| `report.rules.1.rule.destination_ports` | `{"any": false, "include": [[80, 80]], "exclude": []}` | `{"any": false, "include": [[80, 80]], "exclude": []}` | ĐẠT |
| `report.rules.2.rule.source` | `{"any": false, "include": ["10.0.0.0/8"], "exclude": []}` | `{"any": false, "include": ["10.0.0.0/8"], "exclude": []}` | ĐẠT |
| `report.rules.2.rule.source_ports` | `{"any": false, "include": [[1024, 65535]], "exclude": []}` | `{"any": false, "include": [[1024, 65535]], "exclude": []}` | ĐẠT |
| `report.rules.2.rule.destination` | `{"any": false, "include": ["192.168.1.0/24"], "exclude": []}` | `{"any": false, "include": ["192.168.1.0/24"], "exclude": []}` | ĐẠT |
| `report.rules.2.rule.destination_ports` | `{"any": false, "include": [[0, 1023]], "exclude": []}` | `{"any": false, "include": [[0, 1023]], "exclude": []}` | ĐẠT |
| `report.rules.3.rule.source_ports` | `{"any": false, "include": [[1024, 65535]], "exclude": []}` | `{"any": false, "include": [[1024, 65535]], "exclude": []}` | ĐẠT |
| `report.rules.3.rule.destination_ports` | `{"any": false, "include": [[8000, 8080]], "exclude": []}` | `{"any": false, "include": [[8000, 8080]], "exclude": []}` | ĐẠT |
| `report.rules.1.rule.sid` | `100402` | `100402` | ĐẠT |
| `report.rules.1.rule.rev` | `1` | `1` | ĐẠT |
| `report.rules.1.rule.msg` | `"IP don, port don"` | `"IP don, port don"` | ĐẠT |
| `by_packet.1` | `[100401, 100402, 100403]` | `[100401, 100402, 100403]` | ĐẠT |

## Artifact

- `input.pcap`: dữ liệu đầu vào.
- `input.rules`: file rule của ca.
- `config.json`: các tùy chọn cấu hình khác mặc định.
- `expected.json`: các giá trị phải quan sát được.
- `events.jsonl`, `flows.jsonl`: event và tổng kết flow của các bước trước.
- `detections.jsonl`: các Detection Event, mỗi dòng một lần rule khớp.
- `rule_report.json`: kết quả nạp từng rule và số liệu đánh giá của engine.
- `result.json`: mã thoát, từng giá trị thực tế và kết luận đối chiếu.

[Về bảng tổng hợp](../README.md)
