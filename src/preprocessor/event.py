"""Kiểm tra và chuẩn hóa event để các module phía sau nhận cùng một cách biểu diễn."""

from __future__ import annotations

from typing import Any

from src.config import Config

from .checks import CheckReport, check_boolean, check_choice, check_integer, check_ip, check_tcp_flags
from .normalize import normalize_application, normalize_timestamp, put_in_order

# Thứ tự trường cố định sau Preprocessor: phần do parser tạo rồi tới phần do decoder thêm.
EVENT_FIELDS = ("packet_id", "timestamp", "source", "captured_length", "network", "transport", "application",
                "status", "errors", "decoded", "decode_status", "decode_errors")
NETWORK_FIELDS = ("version", "src_ip", "dst_ip", "ttl", "protocol", "total_length", "fragment_offset",
                  "more_fragments")
TRANSPORT_FIELDS = {
    "TCP": ("protocol", "src_port", "dst_port", "sequence", "acknowledgment", "flags", "window", "payload_length"),
    "UDP": ("protocol", "src_port", "dst_port", "length", "payload_length"),
}
# Số hiệu giao thức ghi trong header IP tương ứng với TCP và UDP.
_IP_PROTOCOL_NUMBERS = {"TCP": 6, "UDP": 17}
# Giao thức ứng dụng mà parser đọc được nội dung.
_SUPPORTED_APPLICATIONS = {"HTTP", "DNS", "SMTP"}
_LARGEST_TCP_NUMBER = 2**32 - 1  # sequence và acknowledgment là số 32 bit


def preprocess_event(event: dict[str, Any], config: Config) -> None:
    """Kiểm tra, chuẩn hóa event và ghi kết quả vào chính event đó.

    Thêm ba trường:
    - preprocess_status: valid / partial / invalid.
    - processing_action: process (đưa vào Flow Tracker), skip (vẫn ghi event
      nhưng không theo dõi flow) hoặc drop (bỏ hẳn event, theo cấu hình).
    - reason: danh sách lý do khi event chưa hoàn toàn hợp lệ.
    """
    report = CheckReport()
    _check_notes(event, report)
    _check_timestamp(event, report)
    network = _check_network(event, report)
    _check_transport(event, network, report)
    _check_application(event, report)
    _check_parser_status(event, network, report)
    put_in_order(event, EVENT_FIELDS)
    event["preprocess_status"] = report.status()
    event["processing_action"] = report.action(config)
    event["reason"] = report.reasons()


def _check_notes(event: dict[str, Any], report: CheckReport) -> None:
    """Kiểm tra các trường ghi chú chung: số thứ tự gói, nguồn, danh sách lỗi, độ dài gói.

    Trường ghi chú sai kiểu được đổi về giá trị mặc định (không làm event
    invalid), riêng captured_length sai thì event invalid vì dùng để đếm byte.
    """
    packet_id = event.get("packet_id")
    if packet_id is not None and (type(packet_id) is not int or packet_id < 0):
        report.partial.append(f"packet_id không hợp lệ, đã đổi thành null: {packet_id!r}")
        packet_id = None
    event["packet_id"] = packet_id
    source = event.get("source")
    if source is not None and not isinstance(source, str):
        report.partial.append(f"source không hợp lệ, đã đổi thành null: {source!r}")
        source = None
    event["source"] = source
    errors = event.get("errors")
    if errors is not None and not isinstance(errors, list):
        report.partial.append("errors không phải danh sách, đã thay bằng []")
        errors = None
    event["errors"] = errors if errors is not None else []
    check_integer(event, "captured_length", 0, None, report, "captured_length")


def _check_timestamp(event: dict[str, Any], report: CheckReport) -> None:
    """Timestamp là trường bắt buộc; đổi về số giây Unix để mọi nguồn có cùng đơn vị."""
    value = event.get("timestamp")
    if value is None:
        report.invalid.append("Thiếu timestamp")
        event["timestamp"] = None
        return
    try:
        event["timestamp"] = normalize_timestamp(value)
    except (ValueError, OverflowError) as exc:
        report.invalid.append(f"timestamp không hợp lệ ({exc}): {value!r}")
        event["timestamp"] = None


def _check_network(event: dict[str, Any], report: CheckReport) -> dict[str, Any] | None:
    """Kiểm tra lớp IP; trả network đã chuẩn hóa hoặc None nếu không dùng được."""
    network = event.get("network")
    if network is None:
        event["network"] = None
        if event.get("status") == "malformed":
            report.invalid.append("Event bị đánh dấu malformed và không có thông tin lớp IP")
        else:
            report.unsupported.append("Không có lớp IP được hỗ trợ (ví dụ gói ARP, IPv6 hoặc thiếu network)")
        return None
    if not isinstance(network, dict):
        report.invalid.append("network phải là object")
        event["network"] = None
        return None
    check_choice(network, "version", (4, 6), report, "network.version")
    check_ip(network, "src_ip", report, "network.src_ip")
    check_ip(network, "dst_ip", report, "network.dst_ip")
    check_integer(network, "ttl", 0, 255, report, "network.ttl")
    check_integer(network, "protocol", 0, 255, report, "network.protocol")
    check_integer(network, "total_length", 0, 65535, report, "network.total_length")
    check_integer(network, "fragment_offset", 0, 8191, report, "network.fragment_offset")
    check_boolean(network, "more_fragments", report, "network.more_fragments")
    put_in_order(network, NETWORK_FIELDS)
    _check_ip_versions(network, report)
    if network["more_fragments"] or network["fragment_offset"]:
        report.unsupported.append("Gói IPv4 bị phân mảnh, chưa ghép lại nên không theo dõi flow")
    return network


def _check_ip_versions(network: dict[str, Any], report: CheckReport) -> None:
    """Hai địa chỉ phải cùng là IPv4 hoặc cùng là IPv6, và khớp với trường version nếu có."""
    if network["src_ip"] is None or network["dst_ip"] is None:
        return
    versions = {4 if ":" not in network[name] else 6 for name in ("src_ip", "dst_ip")}
    declared = network["version"]
    if len(versions) > 1 or (declared is not None and declared not in versions):
        report.invalid.append("Phiên bản IP không khớp với địa chỉ nguồn/đích")


def _check_transport(event: dict[str, Any], network: dict[str, Any] | None, report: CheckReport) -> None:
    """Kiểm tra lớp TCP/UDP; giao thức khác vẫn được giữ nhưng đánh dấu chưa hỗ trợ."""
    transport = event.get("transport")
    if transport is None:
        event["transport"] = None
        if network is not None and network["protocol"] is not None:
            report.unsupported.append(
                f"Giao thức IP số {network['protocol']} chưa được hỗ trợ (chỉ theo dõi TCP/UDP)")
        elif network is not None:
            report.unsupported.append("Không có lớp TCP/UDP")
        return
    if not isinstance(transport, dict):
        report.invalid.append("transport phải là object")
        event["transport"] = None
        return
    protocol = transport.get("protocol")
    if not isinstance(protocol, str) or not protocol.strip():
        report.invalid.append(f"Thiếu hoặc sai transport.protocol: {protocol!r}")
        transport["protocol"] = None
        return
    protocol = protocol.strip().upper()
    transport["protocol"] = protocol
    if protocol not in TRANSPORT_FIELDS:
        report.unsupported.append(f"Giao thức vận chuyển {protocol} chưa được hỗ trợ (chỉ theo dõi TCP/UDP)")
        return
    check_integer(transport, "src_port", 0, 65535, report, "transport.src_port", required=True)
    check_integer(transport, "dst_port", 0, 65535, report, "transport.dst_port", required=True)
    if protocol == "TCP":
        check_integer(transport, "sequence", 0, _LARGEST_TCP_NUMBER, report, "transport.sequence")
        check_integer(transport, "acknowledgment", 0, _LARGEST_TCP_NUMBER, report, "transport.acknowledgment")
        check_tcp_flags(transport, report)
        check_integer(transport, "window", 0, 65535, report, "transport.window")
    else:
        check_integer(transport, "length", 0, 65535, report, "transport.length")
    check_integer(transport, "payload_length", 0, None, report, "transport.payload_length")
    put_in_order(transport, TRANSPORT_FIELDS[protocol])
    if network is not None and network["protocol"] not in (None, _IP_PROTOCOL_NUMBERS[protocol]):
        report.invalid.append(f"network.protocol ({network['protocol']}) không khớp với {protocol}")


def _check_application(event: dict[str, Any], report: CheckReport) -> None:
    """Chuẩn hóa phần ứng dụng; dữ liệu sai cấu trúc được thay bằng giá trị mặc định.

    Phần ứng dụng không dùng để ghép flow, nên lỗi ở đây chỉ làm event partial.
    """
    application = event.get("application")
    if application is None:
        event["application"] = {"protocol": None}
        return
    if not isinstance(application, dict):
        report.partial.append('application không phải object, đã thay bằng {"protocol": null}')
        event["application"] = {"protocol": None}
        return
    protocol = application.get("protocol")
    if isinstance(protocol, str):
        protocol = protocol.strip().upper() or None
    elif protocol is not None:
        report.partial.append(f"application.protocol không hợp lệ, đã đổi thành null: {protocol!r}")
        protocol = None
    application["protocol"] = protocol
    if protocol is not None and protocol not in _SUPPORTED_APPLICATIONS:
        report.partial.append(f"Giao thức ứng dụng {protocol} chưa được hỗ trợ phân tích")
    report.partial.extend(normalize_application(application))


def _check_parser_status(event: dict[str, Any], network: dict[str, Any] | None,
                         report: CheckReport) -> None:
    """Mang kết luận của parser sang: parser chưa đọc đủ hoặc gặp lỗi thì event là partial."""
    status = event.get("status")
    if status is not None and not isinstance(status, str):
        report.partial.append(f"status không hợp lệ, đã đổi thành null: {status!r}")
        event["status"] = None
    elif status == "partial":
        report.partial.append("Parser chưa đọc đủ dữ liệu của gói")
    elif status == "malformed" and network is not None:
        report.partial.append("Parser gặp lỗi khi đọc gói (status malformed)")
    elif "status" not in event:
        event["status"] = None
