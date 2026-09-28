# Unknown protocol

**Yêu cầu:** Giao thức không hỗ trợ không làm chương trình crash.

## Dữ liệu đầu vào

IPv4 protocol 99 với payload nhị phân; không có lớp TCP hoặc UDP. Dữ liệu được tạo tổng hợp; lệnh kiểm thử đọc PCAP offline, không gửi packet ra mạng.

## Cách chạy lại

Từ thư mục gốc repo:

```powershell
python main.py --pcap TEST/integration/required_cases/unknown_protocol/input.pcap --output TEST/integration/required_cases/unknown_protocol/rerun.jsonl
```

File đầu ra được ghi nối tiếp. Dùng tên `rerun.jsonl` mới cho mỗi lần chạy lại để không trộn kết quả cũ.

## Kết quả đã chạy

- Kết luận: **ĐẠT**.
- Mã thoát CLI: `0`; số event: `1`; đối chiếu đạt: `10/10`.
- Ý nghĩa: Event được ghi với status unknown, trường transport rỗng và chương trình kết thúc bình thường.

Quan sát trong `events.jsonl`:

- Packet 1: `network.protocol` = `99`, `transport` = `null`, `application.protocol` = `null`, `status` = `"unknown"`, `errors` = `[]`

Đối chiếu sai:

Không có trường nào sai so với giá trị mong đợi.

## Artifact

- `input.pcap`: packet đầu vào.
- `expected.json`: các trường phải có theo yêu cầu.
- `events.jsonl`: từng event do chương trình tạo ra.
- `result.json`: mã thoát, từng giá trị thực tế và kết luận đối chiếu.
