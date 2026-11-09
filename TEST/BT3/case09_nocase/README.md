# Ca 09 - content có/không có nocase

**Kết quả mong đợi theo đề:** Phân biệt/không phân biệt hoa thường đúng.

## Dữ liệu đầu vào

Một gói GET /ADMIN/login. Bốn rule: content ADMIN đúng kiểu chữ; content admin không có nocase; content admin có nocase; content viết bằng byte hex của chữ ADMIN. File `input.pcap` chứa gói tin tổng hợp dựng bằng Scapy, được đọc offline.

Cấu hình mặc định.

## Cách chạy lại

Từ thư mục gốc repo; dùng tên file output mới vì chương trình ghi nối tiếp:

```powershell
python main.py --pcap TEST/BT3/case09_nocase/input.pcap --rules TEST/BT3/case09_nocase/input.rules --config TEST/BT3/case09_nocase/config.json --output output/case09_events.jsonl --flow-output output/case09_flows.jsonl --detection-output output/case09_detections.jsonl --rule-report output/case09_rule_report.json
```

Tạo lại toàn bộ đầu vào, chạy và đối chiếu ca này bằng script:

```powershell
python TEST/BT3/run_cases.py --case 09 --overwrite
```

## Kết quả đã chạy

- Kết luận: **ĐẠT** (8/8 phép đối chiếu).
- Mã thoát CLI: `0`; số event: `1`; số Detection Event: `3`.
- Ý nghĩa: Không có nocase thì phải đúng kiểu chữ nên rule admin thường không khớp. Có nocase thì khớp, vị trí tìm thấy là byte 5. Chuỗi viết bằng hex cho cùng kết quả với chuỗi chữ.

| Trường kiểm tra | Mong đợi | Thực tế | Kết quả |
| --- | --- | --- | --- |
| `exit_code` | `0` | `0` | ĐẠT |
| `detection_count` | `3` | `3` | ĐẠT |
| `by_packet.1` | `[100901, 100903, 100904]` | `[100901, 100903, 100904]` | ĐẠT |
| `report.engine.rejected.content` | `1` | `1` | ĐẠT |
| `detections.0.match.contents.0.nocase` | `false` | `false` | ĐẠT |
| `detections.1.match.contents.0.nocase` | `true` | `true` | ĐẠT |
| `detections.1.match.contents.0.position` | `5` | `5` | ĐẠT |
| `detections.2.match.contents.0.content` | `"\|41 44 4D 49 4E\|"` | `"\|41 44 4D 49 4E\|"` | ĐẠT |

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
