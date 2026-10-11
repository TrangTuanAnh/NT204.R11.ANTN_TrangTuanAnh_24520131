# T03 - SMTP Base64/QP

**Kết quả mong đợi theo đề:** decoded body đúng + decode_status.

## Dữ liệu đầu vào

Ba gói nội dung thư gửi tới port 25 sau lệnh DATA: thư Base64 (Subject dạng =?utf-8?b?...?=), thư nhiều phần gồm một phần Quoted-Printable và một file đính kèm Base64, và một thư Base64 hỏng. File `input.pcap` chứa gói tin tổng hợp dựng bằng Scapy, được đọc offline.

Cấu hình mặc định (ghi đầy đủ trong `config.json`).

## Cách chạy lại

Từ thư mục gốc repo; dùng tên file output mới vì chương trình ghi nối tiếp:

```powershell
python main.py --pcap TEST/integration/required_cases/t03_smtp_mime_decode/input.pcap --config TEST/integration/required_cases/t03_smtp_mime_decode/config.json --output output/t03_events.jsonl --flow-output output/t03_flows.jsonl
```

Tạo lại toàn bộ đầu vào, chạy và đối chiếu ca này bằng script:

```powershell
python TEST/integration/run_required_cases.py --case T03 --overwrite
```

## Kết quả đã chạy

- Kết luận: **ĐẠT** (15/15 phép đối chiếu).
- Mã thoát CLI: `0`; số event: `3`; số flow ghi ra: `3`.
- Ý nghĩa: Cách giải mã lấy theo header Content-Transfer-Encoding của từng phần. Thư hỏng không giải mã được phần nào nên decode_status là error, nhưng chương trình vẫn chạy và ghi đủ ba event.

| Trường kiểm tra | Mong đợi | Thực tế | Kết quả |
| --- | --- | --- | --- |
| `exit_code` | `0` | `0` | ĐẠT |
| `event_count` | `3` | `3` | ĐẠT |
| `events.0.application.message_type` | `"data"` | `"data"` | ĐẠT |
| `events.0.decoded.headers.subject` | `"Báo cáo IDS"` | `"Báo cáo IDS"` | ĐẠT |
| `events.0.decoded.body` | `"Xin chào Bob,\r\nĐây là báo cáo IDS.\r\n"` | `"Xin chào Bob,\r\nĐây là báo cáo IDS.\r\n"` | ĐẠT |
| `events.0.decoded.mime_parts.0.transfer_encoding` | `"base64"` | `"base64"` | ĐẠT |
| `events.0.decoded.mime_parts.0.status` | `"ok"` | `"ok"` | ĐẠT |
| `events.0.decode_status` | `"ok"` | `"ok"` | ĐẠT |
| `events.1.decoded.body` | `"Giới thiệu: 1 + 1 = 2, dòng này được nối từ hai dòng mã hóa."` | `"Giới thiệu: 1 + 1 = 2, dòng này được nối từ hai dòng mã hóa."` | ĐẠT |
| `events.1.decoded.mime_parts.0.transfer_encoding` | `"quoted-printable"` | `"quoted-printable"` | ĐẠT |
| `events.1.decoded.mime_parts.1.filename` | `"data.bin"` | `"data.bin"` | ĐẠT |
| `events.1.decoded.mime_parts.1.size` | `5` | `5` | ĐẠT |
| `events.1.decode_status` | `"ok"` | `"ok"` | ĐẠT |
| `events.2.decoded.mime_parts.0.status` | `"error"` | `"error"` | ĐẠT |
| `events.2.decode_status` | `"error"` | `"error"` | ĐẠT |

## Artifact

- `input.pcap`: dữ liệu đầu vào.
- `config.json`: cấu hình đã dùng.
- `expected.json`: các giá trị phải quan sát được.
- `events.jsonl`: event sau toàn bộ pipeline, mỗi dòng ứng với một gói/event đầu vào.
- `flows.jsonl`: tổng kết flow theo thứ tự được ghi ra.
- `result.json`: mã thoát, từng giá trị thực tế và kết luận đối chiếu.

[Về bảng tổng hợp](../README.md)
