# HTTP GET

**Yêu cầu:** Phân tích HTTP request.

## Dữ liệu đầu vào

HTTP GET /index.html với Host example.test trên port 8088. Dữ liệu được tạo tổng hợp; lệnh kiểm thử đọc PCAP offline, không gửi packet ra mạng.

## Cách chạy lại

Từ thư mục gốc repo:

```powershell
python main.py --pcap TEST/integration/required_cases/http_get/input.pcap --output TEST/integration/required_cases/http_get/rerun.jsonl
```

File đầu ra được ghi nối tiếp. Dùng tên `rerun.jsonl` mới cho mỗi lần chạy lại để không trộn kết quả cũ.

## Kết quả đã chạy

- Kết luận: **ĐẠT**.
- Mã thoát CLI: `0`; số event: `1`; đối chiếu đạt: `12/12`.
- Ý nghĩa: Method, URI, version và Host phải có trong event; port 8088 còn kiểm tra nhận diện theo payload.

Quan sát trong `events.jsonl`:

- Packet 1: `application.protocol` = `"HTTP"`, `application.message_type` = `"request"`, `application.method` = `"GET"`, `application.uri` = `"/index.html"`, `application.version` = `"HTTP/1.1"`, `application.headers.Host` = `"example.test"`, `status` = `"ok"`

Đối chiếu sai:

Không có trường nào sai so với giá trị mong đợi.

## Artifact

- `input.pcap`: packet đầu vào.
- `expected.json`: các trường phải có theo yêu cầu.
- `events.jsonl`: từng event do chương trình tạo ra.
- `result.json`: mã thoát, từng giá trị thực tế và kết luận đối chiếu.
