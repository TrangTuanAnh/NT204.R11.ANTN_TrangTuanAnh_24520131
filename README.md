# IDS Packet Capture & Parser

Module đầu tiên của hệ thống IDS: bắt packet từ network interface hoặc đọc lần lượt từ file PCAP, phân tích IPv4/TCP/UDP/HTTP/DNS/SMTP và ghi event chuẩn hóa theo JSON Lines.

## Cài đặt

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Trên Windows, live capture cần cài Npcap và chạy terminal với quyền phù hợp. Có thể xem interface bằng:

```powershell
python main.py --list-interfaces
```

## Chạy chương trình

Đọc PCAP:

```powershell
python main.py --pcap data/sample.pcap --output output/ids.jsonl
```

Bắt live traffic:

```powershell
python main.py --interface "<tên interface>" --count 100 --timeout 30 --output output/ids.jsonl
```

Mỗi dòng trong file output là một JSON object độc lập. Event chứa metadata packet, thông tin IPv4, TCP/UDP, application protocol, trạng thái và lỗi nếu có. Parser không phụ thuộc tuyệt đối vào port; payload HTTP hợp lệ được nhận diện cả trên port không chuẩn.

Phiên bản này xử lý theo từng packet, chưa tái lắp TCP stream hoặc IPv4 fragment và không giải mã HTTPS/TLS.

Live capture dùng callback xử lý ngay từng packet, không giữ danh sách packet trong RAM. Ctrl+C đóng file và giữ những dòng đã ghi. Hai nguồn dùng chung hàm xử lý và đánh số lại từ 1 mỗi lần chạy; file JSON Lines được nối thêm.

HTTP thiếu kết thúc header hoặc thiếu body theo Content-Length được đánh dấu `partial`. Transfer-Encoding chưa được giải mã nên cũng trả `partial`. IPv4 phân mảnh và DNS/TCP chưa đủ dữ liệu được đánh dấu `partial`; cần thêm các packet khác mới có thể phân tích đầy đủ. SMTP cần dấu hiệu nội dung hợp lệ, không suy ra chỉ từ port. DNS/TCP hiện đọc thông điệp đầu tiên hoàn chỉnh trong packet, chưa ghép stream hoặc tách nhiều thông điệp liên tiếp.

## Kiểm thử

```powershell
python -m pytest TEST -q
python -m pytest TEST --cov=src --cov-report=term-missing
```

Các test bao phủ TCP handshake/data, UDP, HTTP request/response, DNS query/response, SMTP command/response, packet unknown/malformed, đọc PCAP tuần tự và ghi JSON Lines.

Đo cả mã CLI và parser, không tính mã test vào coverage:

```powershell
coverage run --source=src,main -m pytest TEST -q
coverage report -m
```

Test live sử dụng nguồn giả lập để xác nhận event được ghi trước khi capture kết thúc, Ctrl+C giữ output và hai nguồn cho kết quả tương đương. Đây không phải bằng chứng đã chạy capture thật với Npcap.
