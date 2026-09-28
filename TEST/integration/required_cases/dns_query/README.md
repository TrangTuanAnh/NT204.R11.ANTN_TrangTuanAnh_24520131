# DNS Query

**Yêu cầu:** Phân tích domain và query type.

## Dữ liệu đầu vào

Truy vấn DNS ID 123 cho example.test, loại A. Dữ liệu được tạo tổng hợp; lệnh kiểm thử đọc PCAP offline, không gửi packet ra mạng.

## Cách chạy lại

Từ thư mục gốc repo:

```powershell
python main.py --pcap TEST/integration/required_cases/dns_query/input.pcap --output TEST/integration/required_cases/dns_query/rerun.jsonl
```

File đầu ra được ghi nối tiếp. Dùng tên `rerun.jsonl` mới cho mỗi lần chạy lại để không trộn kết quả cũ.

## Kết quả đã chạy

- Kết luận: **ĐẠT**.
- Mã thoát CLI: `0`; số event: `1`; đối chiếu đạt: `11/11`.
- Ý nghĩa: Question name phải là example.test và query type A có giá trị số 1.

Quan sát trong `events.jsonl`:

- Packet 1: `application.protocol` = `"DNS"`, `application.transaction_id` = `123`, `application.is_response` = `false`, `application.questions.0.name` = `"example.test"`, `application.questions.0.type` = `1`, `status` = `"ok"`

Đối chiếu sai:

Không có trường nào sai so với giá trị mong đợi.

## Artifact

- `input.pcap`: packet đầu vào.
- `expected.json`: các trường phải có theo yêu cầu.
- `events.jsonl`: từng event do chương trình tạo ra.
- `result.json`: mã thoát, từng giá trị thực tế và kết luận đối chiếu.
