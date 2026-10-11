# T02 - HTML entity

**Kết quả mong đợi theo đề:** decoded text đúng, không crash.

## Dữ liệu đầu vào

Ba gói HTTP: response text/html chứa &lt;script&gt;, &quot;, &#39;, &#x3C;...; request text/plain chứa &lt;img ...&gt;; request application/json chứa &lt;b&gt;. File `input.pcap` chứa gói tin tổng hợp dựng bằng Scapy, được đọc offline.

Cấu hình mặc định (ghi đầy đủ trong `config.json`).

## Cách chạy lại

Từ thư mục gốc repo; dùng tên file output mới vì chương trình ghi nối tiếp:

```powershell
python main.py --pcap TEST/integration/required_cases/t02_html_entity_decode/input.pcap --config TEST/integration/required_cases/t02_html_entity_decode/config.json --output output/t02_events.jsonl --flow-output output/t02_flows.jsonl
```

Tạo lại toàn bộ đầu vào, chạy và đối chiếu ca này bằng script:

```powershell
python TEST/integration/run_required_cases.py --case T02 --overwrite
```

## Kết quả đã chạy

- Kết luận: **ĐẠT** (9/9 phép đối chiếu).
- Mã thoát CLI: `0`; số event: `3`; số flow ghi ra: `3`.
- Ý nghĩa: Nội dung dạng chữ (text/html, text/plain) được đổi thực thể HTML; body gốc ở application.body giữ nguyên. JSON không phải văn bản HTML nên giữ nguyên chuỗi &lt;b&gt;.

| Trường kiểm tra | Mong đợi | Thực tế | Kết quả |
| --- | --- | --- | --- |
| `exit_code` | `0` | `0` | ĐẠT |
| `event_count` | `3` | `3` | ĐẠT |
| `events.0.application.body` | `"<p>Xin chào &lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt; &amp; &#39;ok&#39; &#x3C;b&#x3E;</p>"` | `"<p>Xin chào &lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt; &amp; &#39;ok&#39; &#x3C;b&#x3E;</p>"` | ĐẠT |
| `events.0.decoded.body` | `"<p>Xin chào <script>alert(\"XSS\")</script> & 'ok' <b></p>"` | `"<p>Xin chào <script>alert(\"XSS\")</script> & 'ok' <b></p>"` | ĐẠT |
| `events.0.decode_status` | `"ok"` | `"ok"` | ĐẠT |
| `events.1.decoded.body` | `"Bình luận: <img src=x onerror=alert(1)>"` | `"Bình luận: <img src=x onerror=alert(1)>"` | ĐẠT |
| `events.1.decode_status` | `"ok"` | `"ok"` | ĐẠT |
| `events.2.decoded.body` | `"{\"note\": \"&lt;b&gt;\"}"` | `"{\"note\": \"&lt;b&gt;\"}"` | ĐẠT |
| `events.2.decode_status` | `"ok"` | `"ok"` | ĐẠT |

## Artifact

- `input.pcap`: dữ liệu đầu vào.
- `config.json`: cấu hình đã dùng.
- `expected.json`: các giá trị phải quan sát được.
- `events.jsonl`: event sau toàn bộ pipeline, mỗi dòng ứng với một gói/event đầu vào.
- `flows.jsonl`: tổng kết flow theo thứ tự được ghi ra.
- `result.json`: mã thoát, từng giá trị thực tế và kết luận đối chiếu.

[Về bảng tổng hợp](../README.md)
