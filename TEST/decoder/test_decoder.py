"""Kiểm thử module Decoder: URI/form, thực thể HTML, MIME, bảng mã và các giới hạn."""

from __future__ import annotations

import base64

import pytest

from src.config import Config
from src.decoder import decode_event


def decode(event: dict, payload: bytes | None = None, config: Config | None = None) -> dict:
    """Giải mã event rồi trả lại chính event để kiểm tra cho gọn."""
    decode_event(event, payload, config or Config())
    return event


def http(make_event, **application) -> dict:
    """Event HTTP với các trường ứng dụng cho trước."""
    return make_event(application={"protocol": "HTTP", **application})


def mail(make_event, headers: dict, body: str) -> dict:
    """Event nội dung thư SMTP (không có byte gốc, như event đọc từ file)."""
    return make_event(application={"protocol": "SMTP", "message_type": "data", "headers": headers, "body": body})


# ------------------------------------------------------------------ HTTP

def test_uri_is_decoded_once_and_raw_uri_is_kept(make_event):
    event = decode(http(make_event, uri="/a%2527b%20c+d?x=%41+1&y=%2B"))
    assert event["application"]["uri"] == "/a%2527b%20c+d?x=%41+1&y=%2B"
    assert event["decoded"]["uri"] == "/a%27b c+d?x=A+1&y=+"
    assert event["decoded"]["query"] == [["x", "A 1"], ["y", "+"]]
    assert event["decode_status"] == "ok"


def test_form_keeps_order_duplicates_and_empty_values(make_event):
    body = "a=1&a=&b=x+y%2Bz&&c"
    event = decode(http(make_event, headers={"Content-Type": "application/x-www-form-urlencoded"}, body=body))
    assert event["decoded"]["form"] == [["a", "1"], ["a", ""], ["b", "x y+z"], ["c", ""]]
    assert event["decoded"]["body"] == body


def test_bad_percent_sequence_is_kept_and_reported(make_event):
    event = decode(http(make_event, uri="/%ZZ%4"))
    assert event["decoded"]["uri"] == "/%ZZ%4"
    assert event["decode_status"] == "partial"
    assert event["decode_errors"] == ["URI: có dấu % không đúng dạng %XX, giữ nguyên"]


def test_percent_bytes_that_are_not_utf8_are_replaced(make_event):
    event = decode(http(make_event, uri="/x%FF"))
    assert event["decoded"]["uri"] == "/x�"
    assert event["decode_status"] == "partial"


@pytest.mark.parametrize("content_type", [None, "text/html", "text/plain; charset=utf-8", "application/xhtml+xml"])
def test_html_entities_are_decoded_in_text_bodies(make_event, content_type):
    headers = {"Content-Type": content_type} if content_type else {}
    event = decode(http(make_event, headers=headers, body="&lt;b&gt; &#39;x&#39; &amp;"))
    assert event["decoded"]["body"] == "<b> 'x' &"


@pytest.mark.parametrize("content_type", ["application/json", "application/octet-stream"])
def test_html_entities_are_kept_in_non_html_bodies(make_event, content_type):
    event = decode(http(make_event, headers={"Content-Type": content_type}, body="&lt;b&gt;"))
    assert event["decoded"]["body"] == "&lt;b&gt;"


def test_html_entities_are_decoded_only_once(make_event):
    event = decode(http(make_event, headers={"Content-Type": "text/html"}, body="&amp;lt;script&amp;gt;"))
    assert event["decoded"]["body"] == "&lt;script&gt;"


def test_body_bytes_from_packet_are_preferred(make_event):
    payload = b"POST / HTTP/1.1\r\nContent-Type: text/plain\r\n\r\nab\xffcd"
    event = decode(http(make_event, headers={"Content-Type": "text/plain"}, body="ab�cd"), payload)
    assert event["decoded"]["body"] == "ab�cd"
    assert event["decode_errors"] == ["Body HTTP: có byte không hợp lệ với bảng mã utf-8 (vị trí 2)"]


def test_declared_charset_is_used(make_event):
    payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=ISO-8859-1\r\n\r\ncaf\xe9"
    event = decode(http(make_event, headers={"Content-Type": "text/plain; charset=ISO-8859-1"}), payload)
    assert event["decoded"]["body"] == "café"
    assert event["decode_status"] == "ok"


def test_unknown_charset_falls_back_to_utf8(make_event):
    event = decode(http(make_event, headers={"Content-Type": "text/plain; charset=x-unknown"}, body="xin chào"))
    assert event["decoded"]["body"] == "xin chào"
    assert event["decode_errors"] == ["Body HTTP: chưa hỗ trợ bảng mã 'x-unknown', tạm đọc theo UTF-8"]


def test_compressed_body_is_not_decoded(make_event):
    event = decode(http(make_event, message_type="response", headers={"Content-Encoding": "gzip"}, body="\x1f\x8b"))
    assert event["decoded"]["body"] is None
    assert event["decode_status"] == "error"


def test_chunked_body_is_marked_partial(make_event):
    event = decode(http(make_event, headers={"Transfer-Encoding": "chunked"}, body="5\r\nhello\r\n0\r\n\r\n"))
    assert event["decoded"]["body"] == "5\r\nhello\r\n0\r\n\r\n"
    assert event["decode_status"] == "partial"


def test_payload_longer_than_limit_is_cut(make_event):
    payload = b"GET / HTTP/1.1\r\n\r\n" + b"x" * 50
    event = decode(http(make_event, uri="/"), payload, Config(max_payload_bytes=30))
    assert event["decoded"]["body"] == "x" * 12
    assert event["decode_status"] == "partial"
    assert "vượt giới hạn 30 byte" in event["decode_errors"][0]


# ------------------------------------------------------------------ SMTP / MIME

def test_base64_body_and_encoded_subject(make_event):
    subject = "=?utf-8?b?" + base64.b64encode("Chào".encode()).decode() + "?="
    event = decode(mail(make_event, {"Subject": subject, "Content-Type": "text/plain; charset=utf-8",
                                     "Content-Transfer-Encoding": "base64"},
                        base64.b64encode("Xin chào".encode()).decode()))
    assert event["decoded"]["headers"]["subject"] == "Chào"
    assert event["decoded"]["body"] == "Xin chào"
    assert event["decoded"]["mime_parts"][0]["status"] == "ok"
    assert event["decode_status"] == "ok"


def test_quoted_printable_with_soft_line_break(make_event):
    event = decode(mail(make_event, {"Content-Type": "text/plain; charset=utf-8",
                                     "Content-Transfer-Encoding": "quoted-printable"},
                        "1 + 1 =3D 2, d=C3=B2ng =\r\nn=E1=BB=91i"))
    assert event["decoded"]["body"] == "1 + 1 = 2, dòng nối"
    assert event["decode_status"] == "ok"


def test_multipart_mail_from_packet_bytes(make_event):
    payload = (b"DATA\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n"
               b"--b\r\nContent-Type: text/html; charset=utf-8\r\n\r\n&lt;p&gt;hi\r\n"
               b"--b\r\nContent-Type: image/png\r\nContent-Transfer-Encoding: base64\r\n"
               b"Content-Disposition: attachment; filename=a.png\r\n\r\niVBORw==\r\n--b--\r\n.\r\n")
    event = decode(mail(make_event, {}, ""), payload)
    first, second = event["decoded"]["mime_parts"]
    assert first["body"] == "<p>hi"
    assert (second["filename"], second["size"], second["body"]) == ("a.png", 4, None)
    assert event["decoded"]["body"] == "<p>hi"
    assert event["decode_status"] == "ok"


def test_missing_base64_padding_is_accepted(make_event):
    event = decode(mail(make_event, {"Content-Transfer-Encoding": "base64"}, "aGVsbG8"))
    assert event["decoded"]["body"] == "hello"
    assert event["decode_status"] == "ok"


@pytest.mark.parametrize("encoding,body", [("base64", "***"), ("base64", "abcde"), ("x-uuencode", "hello")])
def test_body_that_cannot_be_decoded_is_an_error(make_event, encoding, body):
    event = decode(mail(make_event, {"Content-Transfer-Encoding": encoding}, body))
    assert event["decoded"]["mime_parts"][0]["status"] == "error"
    assert event["decoded"]["body"] is None
    assert event["decode_status"] == "error"


def test_bad_quoted_printable_escape_is_kept(make_event):
    event = decode(mail(make_event, {"Content-Transfer-Encoding": "quoted-printable"}, "a=ZZb"))
    assert event["decoded"]["body"] == "a=ZZb"
    assert event["decode_status"] == "partial"


def test_smtp_end_marker_and_added_dots_are_removed(make_event):
    payload = b"Subject: x\r\n\r\n..dong bat dau bang dau cham\r\nhet\r\n.\r\n"
    event = decode(mail(make_event, {}, ""), payload)
    assert event["decoded"]["body"] == ".dong bat dau bang dau cham\r\nhet\r\n"


def test_mime_part_limit(make_event):
    payload = (b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\r\none\r\n--b\r\n\r\ntwo\r\n--b--\r\n")
    event = decode(mail(make_event, {}, ""), payload, Config(max_mime_parts=1))
    assert len(event["decoded"]["mime_parts"]) == 1
    assert event["decode_status"] == "partial"


def test_cut_multipart_is_partial(make_event):
    payload = b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nhello"
    event = decode(mail(make_event, {}, ""), payload)
    assert event["decoded"]["body"] == "hello"
    assert event["decode_status"] == "partial"
    assert "CloseBoundaryNotFoundDefect" in event["decode_errors"][0]


# ------------------------------------------------------------------ dữ liệu khác

def test_unknown_payload_is_read_as_text(make_event):
    assert decode(make_event(), b"hello")["decoded"]["text"] == "hello"
    event = decode(make_event(), b"\xc3\x28")
    assert event["decoded"]["text"] == "�("
    assert event["decode_status"] == "partial"


def test_smtp_command_payload_is_read_as_text(make_event):
    event = decode(make_event(application={"protocol": "SMTP", "message_type": "command"}), b"EHLO a\r\n")
    assert event["decoded"]["text"] == "EHLO a\r\n"


def test_nothing_to_decode_is_not_applicable(make_event):
    assert decode(make_event())["decode_status"] == "not_applicable"
    assert decode(make_event(application={"protocol": "DNS"}), b"\x00\x01")["decode_status"] == "not_applicable"


@pytest.mark.parametrize("application", ["garbage", {"protocol": "HTTP", "uri": 5, "headers": [], "body": 7},
                                         {"protocol": 10}, {"protocol": "SMTP", "message_type": "data",
                                                            "headers": "x", "body": None}])
def test_strange_input_never_raises(make_event, application):
    event = decode(make_event(application=application))
    assert set(event["decoded"]) == {"uri", "query", "form", "body", "headers", "mime_parts", "text"}
    assert event["decode_status"] in {"ok", "partial", "error", "not_applicable"}
