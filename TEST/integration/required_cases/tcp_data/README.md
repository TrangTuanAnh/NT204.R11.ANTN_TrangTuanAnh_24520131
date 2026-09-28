# TCP data

**Yêu cầu:** Phân tích TCP packet có payload.

## Dữ liệu đầu vào

- Một packet TCP mang 5 byte dữ liệu 'hello'. Dữ liệu được tạo tổng hợp; lệnh kiểm thử đọc PCAP offline, không gửi packet ra mạng.

## Cách chạy lại

- Từ thư mục gốc repo:

```powershell
python main.py --pcap TEST/integration/required_cases/tcp_data/input.pcap --output TEST/integration/required_cases/tcp_data/rerun.jsonl
```

File đầu ra được ghi nối tiếp. Dùng tên `rerun.jsonl` mới cho mỗi lần chạy lại để không trộn kết quả cũ.

## Kết quả đã chạy

- Kết luận: **ĐẠT**.
- Mã thoát CLI: `0`; số event: `1`; đối chiếu đạt: `11/11`.
- Ý nghĩa: Payload dài 5 byte và các trường TCP vẫn được đọc; nội dung này không thuộc ứng dụng được hỗ trợ nên status là unknown.

Quan sát trong `events.jsonl`:

- Packet 1: `transport.protocol` = `"TCP"`, `transport.flags` = `"PA"`, `transport.sequence` = `42`, `transport.acknowledgment` = `7`, `transport.payload_length` = `5`, `status` = `"unknown"`

Đối chiếu sai:

> Không có trường nào sai so với giá trị mong đợi.

## Artifact

- `input.pcap`: packet đầu vào.
- `expected.json`: các trường phải có theo yêu cầu.
- `events.jsonl`: từng event do chương trình tạo ra.
- `result.json`: mã thoát, từng giá trị thực tế và kết luận đối chiếu.
