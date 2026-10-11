from collections.abc import Callable
from typing import Any

from scapy.all import AsyncSniffer, conf, sniff

from .interfaces import list_interfaces


def _capture_name(interface: str) -> str | None:
    """Đổi tên thường, GUID hoặc tên Npcap thành tên card mà Scapy dùng."""
    prefix = "\\Device\\NPF_"
    for device in conf.ifaces.values():
        network_name = device.network_name or ""
        aliases = {device.name, network_name}
        if network_name.startswith(prefix):
            aliases.add(network_name[len(prefix):])
        if interface in aliases:
            return device.name
    return None


def capture_live(interface: str, process_packet: Callable[[Any, float], None],
                 count: int = 0, timeout: int | None = None, *,
                 on_idle: Callable[[], None] | None = None, idle_interval: float = 1.0) -> None:
    """Bắt live trên interface và gọi callback với packet cùng timestamp.

    Không lưu danh sách packet trong bộ nhớ; count và timeout giới hạn lần bắt.
    Nếu truyền on_idle, hàm này được gọi đều đặn mỗi idle_interval giây kể cả
    khi card mạng không nhận thêm gói nào (dùng để đóng các flow đã hết hạn).
    """
    capture_name = _capture_name(interface)
    if capture_name is None and interface not in list_interfaces():
        raise ValueError('Interface khong ton tai; dung --list-interfaces')
    options = {"iface": capture_name or interface, "count": count, "timeout": timeout, "store": False}
    if on_idle is None:
        sniff(**options, prn=lambda packet: process_packet(packet, float(packet.time)))
    else:
        _capture_with_idle_checks(options, process_packet, on_idle, idle_interval)


class _ReportingSniffer(AsyncSniffer):
    """AsyncSniffer có giữ lại lỗi xảy ra trong luồng bắt gói.

    Scapy chạy việc bắt gói ở một luồng riêng và không báo lỗi của luồng đó
    (ví dụ mở card thất bại) về luồng chính; lớp này ghi lại lỗi để báo tiếp.
    """

    error: BaseException | None = None

    def _run(self, *args: Any, **kwargs: Any) -> None:
        """Chạy vòng bắt gói của Scapy; có lỗi thì giữ lại và đánh dấu đã dừng."""
        try:
            super()._run(*args, **kwargs)
        except BaseException as exc:
            self.error = exc
        finally:
            self.running = False


def _capture_with_idle_checks(options: dict[str, Any], process_packet: Callable[[Any, float], None],
                              on_idle: Callable[[], None], interval: float) -> None:
    """Bắt gói ở luồng phụ; luồng chính cứ mỗi interval giây lại gọi on_idle.

    Lỗi khi xử lý một gói (ví dụ ghi file thất bại) làm dừng việc bắt gói và
    được báo lại ở luồng chính, giống như khi bắt gói bằng sniff thông thường.
    """
    callback_errors: list[BaseException] = []

    def handle(packet: Any) -> None:
        """Xử lý một gói ở luồng bắt gói; lỗi được giữ lại thay vì bị mất."""
        try:
            process_packet(packet, float(packet.time))
        except BaseException as exc:
            callback_errors.append(exc)

    sniffer = _ReportingSniffer(**options, prn=handle, stop_filter=lambda _packet: bool(callback_errors))
    sniffer.start()
    try:
        while sniffer.thread.is_alive():
            sniffer.thread.join(interval)
            if not callback_errors:
                on_idle()
    finally:
        # Dừng bằng Ctrl+C hoặc on_idle lỗi: phải tắt luồng bắt gói trước khi thoát.
        if sniffer.running:
            try:
                sniffer.stop()
            except Exception:
                pass  # luồng bắt gói vừa tự dừng hoặc chưa kịp mở card

    if sniffer.error is not None:
        raise sniffer.error
    if callback_errors:
        raise callback_errors[0]
