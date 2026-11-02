# Bộ rule Snort

Thư mục này chứa bộ rule cộng đồng (Community Rules) của Snort, dùng làm đầu vào cho Core Engine. Engine không viết cứng dấu hiệu tấn công nào trong mã nguồn; mọi rule đều đọc từ file `.rules`.

| File | Nội dung |
| --- | --- |
| `community.rules` | Bộ rule cộng đồng của Snort 2, giữ nguyên, không sửa nội dung |
| `LICENSE` | Giấy phép GNU GPL phiên bản 2 đi kèm bộ rule |
| `AUTHORS` | Danh sách tác giả đi kèm bộ rule |

## Nguồn

- Tải từ `https://www.snort.org/downloads/community/community-rules.tar.gz` ngày 02/11/2026.
- SHA-256 của file nén: `631d4251af4af8528a83fb43f9255ae6cbbce37b853dbe00dbfc9d86e1f6685f`.
- SHA-256 của `community.rules`: `21d3087b048c849f6484f91fff959f2b6ab343a454df8a766616c5f3e777f2f7`.

## Kết quả khi nạp vào engine

```powershell
python main.py --pcap TEST/BT3/case15_snort_community_rules/input.pcap --rules rules/community.rules --output output/snort_events.jsonl --flow-output output/snort_flows.jsonl --detection-output output/snort_detections.jsonl --rule-report output/snort_rule_report.json
```

File có 4.038 dòng: 568 rule đang bật, còn lại là comment (phần lớn là rule đã bị Snort tắt sẵn bằng dấu `#`).

| Kết quả | Số rule |
| --- | ---: |
| `valid` | 0 |
| `invalid` | 0 |
| `unsupported` | 568 |

Cả 568 rule đều đúng cú pháp. Chúng bị bỏ vì quy tắc của bài làm là rule có **bất kỳ** keyword nào ngoài phạm vi đề bài thì bị đánh dấu `unsupported` và không được dùng, mà cả 568 rule đều có `metadata`. Các keyword làm rule bị bỏ nhiều nhất:

| Keyword | Số rule có keyword này |
| --- | ---: |
| `metadata` | 568 |
| `fast_pattern` | 425 |
| `reference` | 423 |
| `http_uri` | 216 |
| `flowbits` | 199 |
| `pcre` | 185 |

Thống kê đầy đủ nằm trong trường `unsupported_keywords` của file báo cáo, xem [kết quả đã lưu](../TEST/BT3/case15_snort_community_rules/README.md).

Rule viết bằng cú pháp Snort trong phạm vi đề bài vẫn chạy bình thường qua `--rules`, ví dụ các file `input.rules` trong [TEST/BT3](../TEST/BT3/README.md).

[Về README chung](../README.md)
