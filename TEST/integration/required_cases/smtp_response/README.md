# SMTP response

**Yêu cầu:** Phân tích SMTP status code.

## Dữ liệu đầu vào

Một phản hồi SMTP '250 OK'. Dữ liệu được tạo tổng hợp; lệnh kiểm thử đọc PCAP offline, không gửi packet ra mạng.

## Cách chạy lại

Từ thư mục gốc repo:

```powershell
python main.py --pcap TEST/integration/required_cases/smtp_response/input.pcap --output TEST/integration/required_cases/smtp_response/rerun.jsonl
```

File đầu ra được ghi nối tiếp. Dùng tên `rerun.jsonl` mới cho mỗi lần chạy lại để không trộn kết quả cũ.

## Kết quả đã chạy

- Kết luận: **ĐẠT**.
- Mã thoát CLI: `0`; số event: `1`; đối chiếu đạt: `10/10`.
- Ý nghĩa: Event phải nhận diện phản hồi SMTP và trả status code 250.

Quan sát trong `events.jsonl`:

- Packet 1: `application.protocol` = `"SMTP"`, `application.message_type` = `"response"`, `application.status_code` = `250`, `application.message` = `"OK"`, `status` = `"ok"`

Đối chiếu sai:

Không có trường nào sai so với giá trị mong đợi.

## Artifact

- `input.pcap`: packet đầu vào.
- `expected.json`: các trường phải có theo yêu cầu.
- `events.jsonl`: từng event do chương trình tạo ra.
- `result.json`: mã thoát, từng giá trị thực tế và kết luận đối chiếu.
