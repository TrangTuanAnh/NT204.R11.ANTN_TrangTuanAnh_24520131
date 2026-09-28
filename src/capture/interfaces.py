from scapy.all import get_if_list


def list_interfaces() -> list[str]:
    """Trả về tên các interface Scapy tìm thấy để người dùng chọn khi bắt live."""
    return list(get_if_list())
