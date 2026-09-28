# HTTP POST

**Yêu cầu:** Phân tích HTTP request có body.

## Dữ liệu đầu vào

HTTP POST /submit có Content-Length 5 và body 'hello'. Dữ liệu được tạo tổng hợp; lệnh kiểm thử đọc PCAP offline, không gửi packet ra mạng.

## Cách chạy lại

Từ thư mục gốc repo:

```powershell
python main.py --pcap TEST/integration/required_cases/http_post/input.pcap --output TEST/integration/required_cases/http_post/rerun.jsonl
```

File đầu ra được ghi nối tiếp. Dùng tên `rerun.jsonl` mới cho mỗi lần chạy lại để không trộn kết quả cũ.

## Kết quả đã chạy

- Kết luận: **ĐẠT**.
- Mã thoát CLI: `0`; số event: `1`; đối chiếu đạt: `12/12`.
- Ý nghĩa: Event phải giữ method POST, URI, header Content-Length và body đủ 5 ký tự.

Quan sát trong `events.jsonl`:

- Packet 1: `application.protocol` = `"HTTP"`, `application.message_type` = `"request"`, `application.method` = `"POST"`, `application.uri` = `"/submit"`, `application.headers.Content-Length` = `"5"`, `application.body` = `"hello"`, `status` = `"ok"`

Đối chiếu sai:

Không có trường nào sai so với giá trị mong đợi.

## Artifact

- `input.pcap`: packet đầu vào.
- `expected.json`: các trường phải có theo yêu cầu.
- `events.jsonl`: từng event do chương trình tạo ra.
- `result.json`: mã thoát, từng giá trị thực tế và kết luận đối chiếu.
