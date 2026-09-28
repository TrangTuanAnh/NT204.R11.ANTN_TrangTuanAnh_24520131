# SMTP command

**Yêu cầu:** Phân tích HELO/EHLO, MAIL FROM hoặc RCPT TO.

## Dữ liệu đầu vào

Bốn packet chứa lần lượt HELO, EHLO, MAIL FROM và RCPT TO. Dữ liệu được tạo tổng hợp; lệnh kiểm thử đọc PCAP offline, không gửi packet ra mạng.

## Cách chạy lại

Từ thư mục gốc repo:

```powershell
python main.py --pcap TEST/integration/required_cases/smtp_command/input.pcap --output TEST/integration/required_cases/smtp_command/rerun.jsonl
```

File đầu ra được ghi nối tiếp. Dùng tên `rerun.jsonl` mới cho mỗi lần chạy lại để không trộn kết quả cũ.

## Kết quả đã chạy

- Kết luận: **ĐẠT**.
- Mã thoát CLI: `0`; số event: `4`; đối chiếu đạt: `34/34`.
- Ý nghĩa: Mỗi lệnh phải được đọc thành command và argument. Theo cách parser hiện tại, MAIL FROM và RCPT TO được tách thành MAIL/RCPT cùng phần còn lại trong argument.

Quan sát trong `events.jsonl`:

- Packet 1: `application.protocol` = `"SMTP"`, `application.message_type` = `"command"`, `application.command` = `"HELO"`, `application.argument` = `"example.test"`, `status` = `"ok"`
- Packet 2: `application.protocol` = `"SMTP"`, `application.message_type` = `"command"`, `application.command` = `"EHLO"`, `application.argument` = `"example.test"`, `status` = `"ok"`
- Packet 3: `application.protocol` = `"SMTP"`, `application.message_type` = `"command"`, `application.command` = `"MAIL"`, `application.argument` = `"FROM:<sender@example.test>"`, `status` = `"ok"`
- Packet 4: `application.protocol` = `"SMTP"`, `application.message_type` = `"command"`, `application.command` = `"RCPT"`, `application.argument` = `"TO:<recipient@example.test>"`, `status` = `"ok"`

Đối chiếu sai:

Không có trường nào sai so với giá trị mong đợi.

## Artifact

- `input.pcap`: packet đầu vào.
- `expected.json`: các trường phải có theo yêu cầu.
- `events.jsonl`: từng event do chương trình tạo ra.
- `result.json`: mã thoát, từng giá trị thực tế và kết luận đối chiếu.
