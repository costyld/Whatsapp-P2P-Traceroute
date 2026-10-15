"""Reverse-DNS resolution with caching. Helps label endpoints
(e.g. *.whatsapp.net, *.fbcdn.net) and spot non-Meta peers."""
import logging
import socket
from functools import lru_cache

log = logging.getLogger("wit")


@lru_cache(maxsize=4096)
def reverse_dns(ip: str):
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except (socket.herror, socket.gaierror, OSError):
        return None


def is_meta_hostname(host) -> bool:
    if not host:
        return False
    host = host.lower().rstrip(".")
    domains = ("whatsapp.net", "whatsapp.com", "facebook.com", "facebook.net",
               "fbcdn.net", "fbsbx.com", "instagram.com")
    return any(host == d or host.endswith("." + d) for d in domains)
