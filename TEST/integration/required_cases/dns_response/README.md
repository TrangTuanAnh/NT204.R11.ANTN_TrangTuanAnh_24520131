# DNS Response

**Yêu cầu:** Phân tích ít nhất một answer.

## Dữ liệu đầu vào

Phản hồi DNS ID 123 cho example.test, có một answer A 192.0.2.1. Dữ liệu được tạo tổng hợp; lệnh kiểm thử đọc PCAP offline, không gửi packet ra mạng.

## Cách chạy lại

Từ thư mục gốc repo:

```powershell
python main.py --pcap TEST/integration/required_cases/dns_response/input.pcap --output TEST/integration/required_cases/dns_response/rerun.jsonl
```

File đầu ra được ghi nối tiếp. Dùng tên `rerun.jsonl` mới cho mỗi lần chạy lại để không trộn kết quả cũ.

## Kết quả đã chạy

- Kết luận: **ĐẠT**.
- Mã thoát CLI: `0`; số event: `1`; đối chiếu đạt: `12/12`.
- Ý nghĩa: Phản hồi phải mang cùng ID, có ít nhất một answer và địa chỉ 192.0.2.1.

Quan sát trong `events.jsonl`:

- Packet 1: `application.protocol` = `"DNS"`, `application.transaction_id` = `123`, `application.is_response` = `true`, `application.answers.0.name` = `"example.test"`, `application.answers.0.type` = `1`, `application.answers.0.data` = `"192.0.2.1"`, `status` = `"ok"`

Đối chiếu sai:

Không có trường nào sai so với giá trị mong đợi.

## Artifact

- `input.pcap`: packet đầu vào.
- `expected.json`: các trường phải có theo yêu cầu.
- `events.jsonl`: từng event do chương trình tạo ra.
- `result.json`: mã thoát, từng giá trị thực tế và kết luận đối chiếu.
