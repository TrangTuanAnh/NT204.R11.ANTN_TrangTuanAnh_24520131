# T06 - Missing field

**Kết quả mong đợi theo đề:** xử lý null/[] nhất quán, không exception.

## Dữ liệu đầu vào

Bốn event JSON: TCP thiếu captured_length, errors, status, application, ttl, sequence, window...; DNS thiếu answers và transaction_id; HTTP thiếu headers, body, version; event thiếu packet_id, source. File `input.jsonl` chứa event JSON, mỗi dòng một event, được đọc offline.

Cấu hình mặc định (ghi đầy đủ trong `config.json`).

## Cách chạy lại

Từ thư mục gốc repo; dùng tên file output mới vì chương trình ghi nối tiếp:

```powershell
python main.py --events TEST/integration/required_cases/t06_missing_optional_fields/input.jsonl --config TEST/integration/required_cases/t06_missing_optional_fields/config.json --output output/t06_events.jsonl --flow-output output/t06_flows.jsonl
```

Tạo lại toàn bộ đầu vào, chạy và đối chiếu ca này bằng script:

```powershell
python TEST/integration/run_required_cases.py --case T06 --overwrite
```

## Kết quả đã chạy

- Kết luận: **ĐẠT** (27/27 phép đối chiếu).
- Mã thoát CLI: `0`; số event: `4`; số flow ghi ra: `4`.
- Ý nghĩa: Trường thiếu được điền null, danh sách thiếu thành [], header thiếu thành {}. Event thiếu trường thông tin gói có trạng thái partial (reason liệt kê trường thiếu) nhưng vẫn được theo dõi flow; byte_count dùng network.total_length khi thiếu captured_length.

| Trường kiểm tra | Mong đợi | Thực tế | Kết quả |
| --- | --- | --- | --- |
| `exit_code` | `0` | `0` | ĐẠT |
| `event_count` | `4` | `4` | ĐẠT |
| `flow_count` | `4` | `4` | ĐẠT |
| `events.0.captured_length` | `null` | `null` | ĐẠT |
| `events.0.errors` | `[]` | `[]` | ĐẠT |
| `events.0.status` | `null` | `null` | ĐẠT |
| `events.0.application` | `{"protocol": null}` | `{"protocol": null}` | ĐẠT |
| `events.0.network.ttl` | `null` | `null` | ĐẠT |
| `events.0.transport.window` | `null` | `null` | ĐẠT |
| `events.0.preprocess_status` | `"partial"` | `"partial"` | ĐẠT |
| `events.0.processing_action` | `"process"` | `"process"` | ĐẠT |
| `events.0.reason` | `["Thiếu trường không bắt buộc, đã điền null: captured_length, network.ttl, network.fragment_offset, network.more_fragments, transport.sequence, transport.acknowledgment, transport.window"]` | `["Thiếu trường không bắt buộc, đã điền null: captured_length, network.ttl, network.fragment_offset, network.more_fragments, transport.sequence, transport.acknowledgment, transport.window"]` | ĐẠT |
| `flow_of_event.0.byte_count` | `40` | `40` | ĐẠT |
| `events.1.application.answers` | `[]` | `[]` | ĐẠT |
| `events.1.application.transaction_id` | `null` | `null` | ĐẠT |
| `events.1.preprocess_status` | `"valid"` | `"valid"` | ĐẠT |
| `events.2.application.headers` | `{}` | `{}` | ĐẠT |
| `events.2.application.body` | `null` | `null` | ĐẠT |
| `events.2.application.version` | `null` | `null` | ĐẠT |
| `events.2.decoded.uri` | `"/"` | `"/"` | ĐẠT |
| `events.3.packet_id` | `null` | `null` | ĐẠT |
| `events.3.source` | `null` | `null` | ĐẠT |
| `events.3.preprocess_status` | `"valid"` | `"valid"` | ĐẠT |
| `same_flow [0]` | `"cùng một flow_id"` | `["d708470a798cb5d1"]` | ĐẠT |
| `same_flow [1]` | `"cùng một flow_id"` | `["0858ea4107ded0d8"]` | ĐẠT |
| `same_flow [2]` | `"cùng một flow_id"` | `["4b4ec2b11a93bdec"]` | ĐẠT |
| `same_flow [3]` | `"cùng một flow_id"` | `["001c7dacb70887ac"]` | ĐẠT |

## Artifact

- `input.jsonl`: dữ liệu đầu vào.
- `config.json`: cấu hình đã dùng.
- `expected.json`: các giá trị phải quan sát được.
- `events.jsonl`: event sau toàn bộ pipeline, mỗi dòng ứng với một gói/event đầu vào.
- `flows.jsonl`: tổng kết flow theo thứ tự được ghi ra.
- `result.json`: mã thoát, từng giá trị thực tế và kết luận đối chiếu.

[Về bảng tổng hợp](../README.md)
