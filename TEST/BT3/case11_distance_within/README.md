# Ca 11 - Hai content với distance/within

**Kết quả mong đợi theo đề:** Relative matching đúng.

## Dữ liệu đầu vào

Một gói TCP tới port 9000 có dữ liệu ABC12345DEF..ABCDEF: ABC ở byte 0 và 13, DEF ở byte 8 và 16. Sáu rule gồm hai content với distance/within khác nhau, trong đó có distance âm. File `input.pcap` chứa gói tin tổng hợp dựng bằng Scapy, được đọc offline.

Cấu hình mặc định.

## Cách chạy lại

Từ thư mục gốc repo; dùng tên file output mới vì chương trình ghi nối tiếp:

```powershell
python main.py --pcap TEST/BT3/case11_distance_within/input.pcap --rules TEST/BT3/case11_distance_within/input.rules --config TEST/BT3/case11_distance_within/config.json --output output/case11_events.jsonl --flow-output output/case11_flows.jsonl --detection-output output/case11_detections.jsonl --rule-report output/case11_rule_report.json
```

Tạo lại toàn bộ đầu vào, chạy và đối chiếu ca này bằng script:

```powershell
python TEST/BT3/run_cases.py --case 11 --overwrite
```

## Kết quả đã chạy

- Kết luận: **ĐẠT** (12/12 phép đối chiếu).
- Mã thoát CLI: `0`; số event: `1`; số Detection Event: `4`.
- Ý nghĩa: 101101: DEF cách ABC đầu ít nhất 1 byte. 101102: DEF phải nằm ngay sau ABC, ABC đầu không thỏa nên phải thử ABC ở byte 13. 101103: distance quá lớn, không còn dữ liệu. 101104: ABC thứ hai chỉ nằm một phần trong vùng within. 101105: sau DEF bỏ 2 byte rồi có ABC. 101106: distance âm quay lại tìm 345 ngay trước DEF.

| Trường kiểm tra | Mong đợi | Thực tế | Kết quả |
| --- | --- | --- | --- |
| `exit_code` | `0` | `0` | ĐẠT |
| `detection_count` | `4` | `4` | ĐẠT |
| `by_packet.1` | `[101101, 101102, 101105, 101106]` | `[101101, 101102, 101105, 101106]` | ĐẠT |
| `report.engine.rejected.content` | `2` | `2` | ĐẠT |
| `detections.0.match.contents.0.position` | `0` | `0` | ĐẠT |
| `detections.0.match.contents.1.position` | `8` | `8` | ĐẠT |
| `detections.1.match.contents.0.position` | `13` | `13` | ĐẠT |
| `detections.1.match.contents.1.position` | `16` | `16` | ĐẠT |
| `detections.2.match.contents.0.position` | `8` | `8` | ĐẠT |
| `detections.2.match.contents.1.position` | `13` | `13` | ĐẠT |
| `detections.3.match.contents.0.position` | `8` | `8` | ĐẠT |
| `detections.3.match.contents.1.position` | `5` | `5` | ĐẠT |

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
