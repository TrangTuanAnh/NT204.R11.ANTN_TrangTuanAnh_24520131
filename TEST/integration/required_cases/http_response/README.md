# HTTP response

**Yêu cầu:** Phân tích status code và header.

## Dữ liệu đầu vào

HTTP/1.1 200 OK có Content-Type, Content-Length và body 'OK'. Dữ liệu được tạo tổng hợp; lệnh kiểm thử đọc PCAP offline, không gửi packet ra mạng.

## Cách chạy lại

Từ thư mục gốc repo:

```powershell
python main.py --pcap TEST/integration/required_cases/http_response/input.pcap --output TEST/integration/required_cases/http_response/rerun.jsonl
```

File đầu ra được ghi nối tiếp. Dùng tên `rerun.jsonl` mới cho mỗi lần chạy lại để không trộn kết quả cũ.

## Kết quả đã chạy

- Kết luận: **ĐẠT**.
- Mã thoát CLI: `0`; số event: `1`; đối chiếu đạt: `12/12`.
- Ý nghĩa: Event phải có status code 200, hai header đúng giá trị và body 'OK'.

Quan sát trong `events.jsonl`:

- Packet 1: `application.protocol` = `"HTTP"`, `application.message_type` = `"response"`, `application.status_code` = `200`, `application.headers.Content-Type` = `"text/plain"`, `application.headers.Content-Length` = `"2"`, `application.body` = `"OK"`, `status` = `"ok"`

Đối chiếu sai:

Không có trường nào sai so với giá trị mong đợi.

## Artifact

- `input.pcap`: packet đầu vào.
- `expected.json`: các trường phải có theo yêu cầu.
- `events.jsonl`: từng event do chương trình tạo ra.
- `result.json`: mã thoát, từng giá trị thực tế và kết luận đối chiếu.
