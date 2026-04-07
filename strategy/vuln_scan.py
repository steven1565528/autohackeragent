"""Vulnerability scanning strategy"""
from typing import Any, Dict, List


class VulnScanStrategy:
    @staticmethod
    def get_scan_steps(service: str, target: str, port: int) -> List[Dict[str, Any]]:
        steps = []
        sl = service.lower()
        url = f"http://{target}:{port}"
        if any(k in sl for k in ["http", "web", "apache", "nginx", "iis", "tomcat"]):
            steps.append({"tool": "nikto", "description": "Web vuln scan", "params": {"target": url}})
            steps.append({"tool": "dirscan", "description": "Dir scan", "params": {"url": url, "extensions": "php,asp,txt,bak,sql,zip,conf"}})
        elif any(k in sl for k in ["mysql", "mariadb"]):
            steps.append({"tool": "nmap", "description": "MySQL scripts", "params": {"target": target, "args": f"--script=mysql-* -p {port}"}})
        elif "redis" in sl:
            steps.append({"tool": "shell", "description": "Redis unauth test", "params": {"command": f"redis-cli -h {target} -p {port} INFO 2>/dev/null | head -30"}})
        elif any(k in sl for k in ["smb", "microsoft-ds"]):
            steps.append({"tool": "nmap", "description": "SMB vuln scan", "params": {"target": target, "args": "--script=smb-vuln* -p 445"}})
        steps.append({"tool": "exploit", "description": f"Search {service} exploits", "params": {"action": "searchsploit", "query": service}})
        return steps
