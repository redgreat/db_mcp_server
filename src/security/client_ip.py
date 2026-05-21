"""
客户端真实 IP 提取工具
"""
from ipaddress import ip_address
from typing import Optional, List
from fastapi import Request


def _parse_ip_value(raw_value: Optional[str]) -> Optional[str]:
    """标准化单个 IP 字符串并过滤非法值"""
    if not raw_value:
        return None
    value = raw_value.strip()
    if not value:
        return None
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    if ":" in value and value.count(":") == 1 and "." in value:
        host_part, port_part = value.rsplit(":", 1)
        if port_part.isdigit():
            value = host_part
    try:
        return str(ip_address(value))
    except ValueError:
        return None


def _parse_forwarded_for(header_value: Optional[str]) -> List[str]:
    """解析 X-Forwarded-For 头中的候选 IP 列表"""
    if not header_value:
        return []
    items: List[str] = []
    for part in header_value.split(","):
        ip_value = _parse_ip_value(part)
        if ip_value:
            items.append(ip_value)
    return items


def _is_proxy_like_ip(ip_value: Optional[str]) -> bool:
    """判断当前连接地址是否更像代理或容器网络地址"""
    parsed = _parse_ip_value(ip_value)
    if not parsed:
        return False
    ip_obj = ip_address(parsed)
    return bool(
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_reserved
    )


def get_real_client_ip(request: Request) -> Optional[str]:
    """优先返回客户端真实 IP，在反向代理场景下兼容转发头"""
    peer_ip = _parse_ip_value(request.client.host if request.client else None)
    if peer_ip and not _is_proxy_like_ip(peer_ip):
        return peer_ip

    forwarded_for = _parse_forwarded_for(request.headers.get("x-forwarded-for"))
    for ip_value in forwarded_for:
        if not _is_proxy_like_ip(ip_value):
            return ip_value
    if forwarded_for:
        return forwarded_for[0]

    real_ip = _parse_ip_value(request.headers.get("x-real-ip"))
    if real_ip:
        return real_ip

    forwarded = request.headers.get("forwarded")
    if forwarded:
        for item in forwarded.split(";"):
            if "=" not in item:
                continue
            key, value = item.split("=", 1)
            if key.strip().lower() != "for":
                continue
            parsed = _parse_ip_value(value.strip().strip('"'))
            if parsed:
                return parsed

    return peer_ip
