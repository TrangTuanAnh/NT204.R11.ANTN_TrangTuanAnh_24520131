# Ca 13 - Một event match ≥2 rule

**Kết quả mong đợi theo đề:** Sinh đầy đủ các kết quả match.

## Dữ liệu đầu vào

Phiên TCP có bắt tay rồi GET /etc/passwd. Năm rule: theo port đích 80; theo content passwd; theo dải IP và flow established; rule ip có dsize lớn hơn 0; và một rule có content không có trong gói. File `input.pcap` chứa gói tin tổng hợp dựng bằng Scapy, được đọc offline.

Cấu hình mặc định.

## Cách chạy lại

Từ thư mục gốc repo; dùng tên file output mới vì chương trình ghi nối tiếp:

```powershell
python main.py --pcap TEST/BT3/case13_several_rules/input.pcap --rules TEST/BT3/case13_several_rules/input.rules --config TEST/BT3/case13_several_rules/config.json --output output/case13_events.jsonl --flow-output output/case13_flows.jsonl --detection-output output/case13_detections.jsonl --rule-report output/case13_rule_report.json
```

Tạo lại toàn bộ đầu vào, chạy và đối chiếu ca này bằng script:

```powershell
python TEST/integration/run_detection_cases.py --case 13 --overwrite
```

## Kết quả đã chạy

- Kết luận: **ĐẠT** (12/12 phép đối chiếu).
- Mã thoát CLI: `0`; số event: `4`; số Detection Event: `7`.
- Ý nghĩa: Gói GET khớp đồng thời bốn rule và sinh đủ bốn Detection Event; engine không dừng ở rule đầu tiên. Rule có content không tồn tại không sinh kết quả. Các gói bắt tay chỉ khớp những rule phù hợp với chúng.

| Trường kiểm tra | Mong đợi | Thực tế | Kết quả |
| --- | --- | --- | --- |
| `exit_code` | `0` | `0` | ĐẠT |
| `detection_count` | `7` | `7` | ĐẠT |
| `by_packet.1` | `[101301]` | `[101301]` | ĐẠT |
| `by_packet.2` | `[]` | `[]` | ĐẠT |
| `by_packet.3` | `[101301, 101303]` | `[101301, 101303]` | ĐẠT |
| `by_packet.4` | `[101301, 101302, 101303, 101304]` | `[101301, 101302, 101303, 101304]` | ĐẠT |
| `report.engine.matches` | `7` | `7` | ĐẠT |
| `report.engine.rejected.content` | `6` | `6` | ĐẠT |
| `detections.3.packet_id` | `4` | `4` | ĐẠT |
| `detections.4.packet_id` | `4` | `4` | ĐẠT |
| `detections.5.packet_id` | `4` | `4` | ĐẠT |
| `detections.6.packet_id` | `4` | `4` | ĐẠT |

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
