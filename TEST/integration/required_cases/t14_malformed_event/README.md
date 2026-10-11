# T14 - Malformed event

**Kết quả mong đợi theo đề:** không crash; status/reason phù hợp.

## Dữ liệu đầu vào

Mười hai dòng JSON Lines: event hợp lệ; dòng không phải JSON; mảng JSON; port -1; timestamp "hôm qua"; IP 999.0.0.1; IP protocol 6 nhưng transport UDP; gói ICMP; giao thức SCTP; timestamp NaN; event DNS bị parser đánh dấu malformed; event hợp lệ cùng phiên với dòng đầu. File `input.jsonl` chứa event JSON, mỗi dòng một event, được đọc offline.

Cấu hình mặc định (ghi đầy đủ trong `config.json`).

## Cách chạy lại

Từ thư mục gốc repo; dùng tên file output mới vì chương trình ghi nối tiếp:

```powershell
python main.py --events TEST/integration/required_cases/t14_malformed_event/input.jsonl --config TEST/integration/required_cases/t14_malformed_event/config.json --output output/t14_events.jsonl --flow-output output/t14_flows.jsonl
```

Tạo lại toàn bộ đầu vào, chạy và đối chiếu ca này bằng script:

```powershell
python TEST/integration/run_required_cases.py --case T14 --overwrite
```

## Kết quả đã chạy

- Kết luận: **ĐẠT** (29/29 phép đối chiếu).
- Mã thoát CLI: `0`; số event: `12`; số flow ghi ra: `2`.
- Ý nghĩa: Dữ liệu sai được đánh dấu invalid và skip, giao thức chưa hỗ trợ được đánh dấu partial và skip, mỗi event có reason giải thích. Event DNS malformed vẫn có IP/UDP hợp lệ nên được đếm vào flow. Chương trình đọc hết 12 dòng, mã thoát 0, và dòng cuối vẫn được gắn đúng vào flow của dòng đầu.

| Trường kiểm tra | Mong đợi | Thực tế | Kết quả |
| --- | --- | --- | --- |
| `exit_code` | `0` | `0` | ĐẠT |
| `event_count` | `12` | `12` | ĐẠT |
| `flow_count` | `2` | `2` | ĐẠT |
| `events.0.processing_action` | `"process"` | `"process"` | ĐẠT |
| `events.1.preprocess_status` | `"invalid"` | `"invalid"` | ĐẠT |
| `events.1.processing_action` | `"skip"` | `"skip"` | ĐẠT |
| `events.1.errors` | `["Dòng 2 không phải JSON hợp lệ (Expecting property name enclosed in double quotes)"]` | `["Dòng 2 không phải JSON hợp lệ (Expecting property name enclosed in double quotes)"]` | ĐẠT |
| `events.2.preprocess_status` | `"invalid"` | `"invalid"` | ĐẠT |
| `events.2.errors` | `["Dòng 3 không phải JSON object"]` | `["Dòng 3 không phải JSON object"]` | ĐẠT |
| `events.3.preprocess_status` | `"invalid"` | `"invalid"` | ĐẠT |
| `events.3.reason` | `["transport.src_port không hợp lệ: -1"]` | `["transport.src_port không hợp lệ: -1"]` | ĐẠT |
| `events.4.preprocess_status` | `"invalid"` | `"invalid"` | ĐẠT |
| `events.4.reason` | `["timestamp không hợp lệ (không đọc được dạng thời gian): 'hôm qua'"]` | `["timestamp không hợp lệ (không đọc được dạng thời gian): 'hôm qua'"]` | ĐẠT |
| `events.5.reason` | `["network.src_ip không phải địa chỉ IP hợp lệ: '999.0.0.1'"]` | `["network.src_ip không phải địa chỉ IP hợp lệ: '999.0.0.1'"]` | ĐẠT |
| `events.6.reason` | `["network.protocol (6) không khớp với UDP"]` | `["network.protocol (6) không khớp với UDP"]` | ĐẠT |
| `events.7.preprocess_status` | `"partial"` | `"partial"` | ĐẠT |
| `events.7.processing_action` | `"skip"` | `"skip"` | ĐẠT |
| `events.7.reason` | `["Giao thức IP số 1 chưa được hỗ trợ (chỉ theo dõi TCP/UDP)"]` | `["Giao thức IP số 1 chưa được hỗ trợ (chỉ theo dõi TCP/UDP)"]` | ĐẠT |
| `events.8.preprocess_status` | `"partial"` | `"partial"` | ĐẠT |
| `events.8.processing_action` | `"skip"` | `"skip"` | ĐẠT |
| `events.8.reason` | `["Giao thức vận chuyển SCTP chưa được hỗ trợ (chỉ theo dõi TCP/UDP)"]` | `["Giao thức vận chuyển SCTP chưa được hỗ trợ (chỉ theo dõi TCP/UDP)"]` | ĐẠT |
| `events.9.preprocess_status` | `"invalid"` | `"invalid"` | ĐẠT |
| `events.9.timestamp` | `null` | `null` | ĐẠT |
| `events.10.preprocess_status` | `"partial"` | `"partial"` | ĐẠT |
| `events.10.processing_action` | `"process"` | `"process"` | ĐẠT |
| `events.11.processing_action` | `"process"` | `"process"` | ĐẠT |
| `flow_of_event.0.packet_count` | `2` | `2` | ĐẠT |
| `same_flow [0, 11]` | `"cùng một flow_id"` | `["d708470a798cb5d1", "d708470a798cb5d1"]` | ĐẠT |
| `same_flow [10]` | `"cùng một flow_id"` | `["fc191b21b411b21b"]` | ĐẠT |

## Artifact

- `input.jsonl`: dữ liệu đầu vào.
- `config.json`: cấu hình đã dùng.
- `expected.json`: các giá trị phải quan sát được.
- `events.jsonl`: event sau toàn bộ pipeline, mỗi dòng ứng với một gói/event đầu vào.
- `flows.jsonl`: tổng kết flow theo thứ tự được ghi ra.
- `result.json`: mã thoát, từng giá trị thực tế và kết luận đối chiếu.

[Về bảng tổng hợp](../README.md)
