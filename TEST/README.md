# Kiểm thử

Thư mục `TEST` chứa kết quả các ca kiểm thử bắt buộc của từng bài tập và các bài kiểm thử tự động (pytest). Thư mục con được chia theo **module chức năng** giống `src/`, không chia theo bài tập.

```text
TEST/
  conftest.py                  Dữ liệu mẫu dùng chung (hàm tạo event giống kết quả parser)
  capture/                     Đọc file event JSON Lines; bắt live có kiểm tra flow hết hạn (bộ bắt gói giả)
  parser/                      Phần parser bổ sung: payload, byte đệm Ethernet, nội dung thư SMTP
  decoder/                     URI/form, thực thể HTML, MIME, bảng mã, giới hạn kích thước
  preprocessor/                Kiểm tra trường, chuẩn hóa, dữ liệu thiếu/chưa hỗ trợ, chính sách bỏ event
  flow/                        Flow hai chiều, trạng thái TCP, thời gian chờ, thống kê
  pipeline/                    Nối các bước, cô lập lỗi, chương trình chính main.py, cấu hình
  integration/
    cases.py                   Khai báo đầu vào và kết quả mong đợi của các ca T01–T14
    run_required_cases.py      Tạo đầu vào, chạy main.py và lưu kết quả từng ca vào required_cases/
    test_required_cases.py     Chạy lại các ca bằng pytest và so với kết quả đã lưu
    required_cases/            Kết quả các ca bắt buộc của Bài tập 1 và Bài tập 2 (xem README trong đó)
    live_capture/              Kết quả bắt gói trên card Wi-Fi thật (Bài tập 1)
```

## Chạy kiểm thử

Tại thư mục gốc repo (cần cài `requirements.txt`):

```powershell
python -m pytest
```

`pytest.ini` ở gốc repo chỉ định thư mục `TEST` và cho phép import `src`, `main`. Có thể chạy riêng một module, ví dụ `python -m pytest TEST/flow`. Các bài kiểm thử chỉ đọc PCAP/event tổng hợp và dùng bộ bắt gói giả, nên không cần card mạng và không gửi gói nào ra mạng.

Ngoài kiểm tra từng module, `test_required_cases.py` làm hai việc:

- Chạy 14 ca T01–T14 qua đúng hàm `main` của chương trình và đối chiếu mọi giá trị mong đợi trong `cases.py`.
- Chạy lại đầu vào đã lưu của **mọi** ca trong `required_cases/` (cả 12 ca Bài tập 1, với `--parse-only`) và so với `events.jsonl`/`flows.jsonl` đã lưu. Bài kiểm thử này báo lỗi nếu thay đổi code làm kết quả đã nộp không còn tái hiện được.

## Tạo lại kết quả các ca Bài tập 2

```powershell
python TEST/integration/run_required_cases.py --case T07 --overwrite   # một ca
python TEST/integration/run_required_cases.py --overwrite              # cả 14 ca
```

Script dựng lại `input.pcap`/`input.jsonl`, `config.json`, `expected.json`, chạy `main.py` bằng một tiến trình riêng, rồi ghi `events.jsonl`, `flows.jsonl`, `result.json` và `README.md` của từng ca. Không có `--overwrite` thì script từ chối ghi đè kết quả đã có. Các trường thay đổi giữa các lần chạy là `run_at` trong `result.json`; mã băm đầu vào và kết quả đối chiếu giữ nguyên.

[Về README chung](../README.md)
