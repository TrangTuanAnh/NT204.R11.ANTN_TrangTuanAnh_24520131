from scapy.all import get_if_list


def list_interfaces() -> list[str]:
    """Trả về danh sách interface Scapy nhìn thấy."""
    return list(get_if_list())
