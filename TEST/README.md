# Kiểm thử

Thư mục `TEST` tách làm hai phần:

- **Các ca bắt buộc của đề:** mỗi bài tập một thư mục riêng `BT1`, `BT2`, `BT3`, lưu kết quả từng ca (đầu vào, giá trị mong đợi, kết quả chương trình ghi ra, kết quả đối chiếu, README).
- **Phần mở rộng:** `extra`, gồm các kiểm thử thêm ngoài danh sách của đề: bắt gói thật, bộ rule Snort và kiểm thử từng module.

```text
TEST/
  README.md
  conftest.py                  Dữ liệu mẫu dùng chung cho pytest (hàm tạo event giống kết quả parser)
  support/                     Mã dùng chung của các script và bài kiểm thử
    paths.py                   Đường dẫn gốc repo và các thư mục BT1, BT2, BT3, extra
    builders.py                Dựng gói tin tổng hợp bằng Scapy
    checks.py                  Đọc/ghi JSON, tra giá trị theo đường dẫn, so sánh kết quả
  BT1/                         Bài tập 1 - 12 ca bắt buộc
    test_bt1_cases.py          Kiểm tra giá trị mong đợi và tính tái hiện của kết quả đã lưu
  BT2/                         Bài tập 2 - 14 ca bắt buộc T01-T14
    cases.py                   Khai báo đầu vào và kết quả mong đợi của từng ca
    run_cases.py               Tạo đầu vào, chạy main.py, lưu kết quả từng ca
    test_bt2_cases.py          Chạy lại các ca bằng pytest và so với kết quả đã lưu
  BT3/                         Bài tập 3 - 14 ca bắt buộc
    cases.py, run_cases.py, test_bt3_cases.py   Như BT2; thêm cả ca bổ sung B1
  extra/                       Phần mở rộng
    live_capture/              Bắt gói trên card Wi-Fi thật (Bài tập 1)
    snort_community_rules/     Ca bổ sung B1 của Bài tập 3: bộ rule cộng đồng của Snort
    modules/                   Kiểm thử pytest từng module, bố cục theo src/
```

Mỗi thư mục `BT*` và `extra` có README riêng với bảng kết quả:
[BT1](BT1/README.md) · [BT2](BT2/README.md) · [BT3](BT3/README.md) · [extra](extra/README.md).

## Chạy kiểm thử

Tại thư mục gốc repo (cần cài `requirements.txt`):

```powershell
python -m pytest                 # tất cả
python -m pytest TEST/BT2        # chỉ các ca bắt buộc của Bài tập 2
python -m pytest TEST/extra      # chỉ phần mở rộng
```

`pytest.ini` ở gốc repo chỉ định thư mục `TEST` và cho phép import `src`, `main`, `TEST`. Các bài kiểm thử chỉ đọc PCAP/event tổng hợp và dùng bộ bắt gói giả, nên không cần card mạng và không gửi gói nào ra mạng. Bài kiểm thử trong các thư mục `BT*` làm hai việc cho mỗi ca:

- Chạy ca qua đúng hàm `main` của chương trình và đối chiếu mọi giá trị mong đợi.
- Chạy lại đầu vào **đã lưu** và so với kết quả đã lưu. Thay đổi code làm kết quả đã nộp không còn tái hiện được sẽ bị báo lỗi.

Bài tập 1 chỉ có capture và parser nên các ca chạy với `--parse-only`; Bài tập 2 và 3 chạy đủ pipeline.

## Tạo lại kết quả các ca

Script chỉ tạo lại ca được chọn; không có `--overwrite` thì script từ chối ghi đè kết quả đã có.

```powershell
python TEST/BT2/run_cases.py --case T07 --overwrite     # một ca của Bài tập 2
python TEST/BT2/run_cases.py --overwrite                # cả 14 ca
python TEST/BT3/run_cases.py --case 07 --overwrite      # một ca của Bài tập 3
python TEST/BT3/run_cases.py --case B1 --overwrite      # ca bổ sung B1 (kết quả lưu trong extra)
```

Script dựng lại `input.pcap`/`input.jsonl`, `config.json`, `expected.json`, chạy `main.py` bằng một tiến trình riêng, rồi ghi `events.jsonl`, `flows.jsonl`, `result.json` và `README.md` của ca (bài 3 thêm `input.rules`, `detections.jsonl`, `rule_report.json`). Trường thay đổi giữa các lần chạy là `run_at` trong `result.json`; mã băm đầu vào và kết quả đối chiếu giữ nguyên. Kết quả của Bài tập 1 do script cũ tạo ra từ trước và được giữ nguyên, nên `BT1` chỉ có bài kiểm thử mà không có script tạo lại.

## Thêm kiểm thử cho bài tập mới

- Ca bắt buộc của đề: tạo thư mục `BTn` cùng bộ `cases.py`, `run_cases.py`, `test_btn_cases.py` như `BT2`/`BT3`, dùng lại hàm trong `support/`.
- Kiểm thử thêm: đặt trong `extra`; test của module nào thì vào `extra/modules/<tên module>`.
- Tên file test phải khác nhau giữa các thư mục (pytest không dùng `__init__.py` ở đây), nên đặt tên có mã bài hoặc tên module, ví dụ `test_bt2_cases.py`, `test_rule_parser.py`.

[Về README chung](../README.md)
