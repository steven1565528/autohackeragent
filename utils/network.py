"""Network utility functions"""

import socket
import urllib.parse
from typing import Optional, Tuple
from utils.logger import get_logger

logger = get_logger(__name__)


class NetworkUtils:
    @staticmethod
    def is_port_open(host: str, port: int, timeout: float = 3.0) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except (socket.error, OSError):
            return False

    @staticmethod
    def parse_target(target: str) -> Tuple[str, Optional[int]]:
        if "://" in target:
            parsed = urllib.parse.urlparse(target)
            host = parsed.hostname or ""
            port = parsed.port
            if port is None:
                port = 443 if parsed.scheme == "https" else 80
            return host, port
        if ":" in target:
            parts = target.rsplit(":", 1)
            try:
                return parts[0], int(parts[1])
            except ValueError:
                return target, None
        return target, None

    @staticmethod
    def build_url(host: str, port: Optional[int] = None, scheme: str = "http", path: str = "/") -> str:
        if port:
            if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
                return f"{scheme}://{host}{path}"
            return f"{scheme}://{host}:{port}{path}"
        return f"{scheme}://{host}{path}"

    @staticmethod
    def get_common_ports() -> list:
        return [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
                1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9090, 27017]

    @staticmethod
    def get_web_ports() -> list:
        return [80, 443, 8000, 8080, 8443, 8888, 9090, 3000, 5000, 7001]
