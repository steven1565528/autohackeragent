"""Reconnaissance strategy"""
from typing import Any, Dict, List


class ReconStrategy:
    @staticmethod
    def get_initial_recon_steps(target: str, port: int = None) -> List[Dict[str, Any]]:
        steps = [{"tool": "nmap", "description": "Quick scan top 1000 ports", "params": {"target": target, "args": "-sV -sC -T4 --open"}}]
        if port and port in [80, 443, 8080, 8443, 8888, 3000, 5000]:
            steps.append({"tool": "curl", "description": "Probe web service", "params": {"url": f"http://{target}:{port}/", "args": "-L -v"}})
            steps.append({"tool": "curl", "description": "Check robots.txt", "params": {"url": f"http://{target}:{port}/robots.txt"}})
        return steps

    @staticmethod
    def get_deep_recon_steps(target: str) -> List[Dict[str, Any]]:
        return [
            {"tool": "nmap", "description": "Full port scan", "params": {"target": target, "args": "-sV -p- -T4 --open"}},
            {"tool": "nmap", "description": "UDP top 100", "params": {"target": target, "args": "-sU --top-ports 100 -T4"}},
            {"tool": "nmap", "description": "Vuln scripts", "params": {"target": target, "args": "--script=vuln -T4"}},
        ]

    @staticmethod
    def get_web_recon_steps(target_url: str) -> List[Dict[str, Any]]:
        return [
            {"tool": "dirscan", "description": "Directory scan", "params": {"url": target_url, "extensions": "php,html,txt,bak,sql,zip,conf"}},
            {"tool": "nikto", "description": "Web vuln scan", "params": {"target": target_url}},
            {"tool": "curl", "description": "Check .git", "params": {"url": f"{target_url.rstrip('/')}/.git/HEAD"}},
        ]
