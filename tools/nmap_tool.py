"""Nmap port scanner tool"""

from typing import Any, Dict
from tools.base import BaseTool, ToolResult
from tools.shell import ShellTool
from utils.logger import get_logger

logger = get_logger(__name__)


class NmapTool(BaseTool):
    def __init__(self, config: dict = None):
        super().__init__(config)
        self.shell = ShellTool(config=config)
        self.default_args = self.config.get("default_args", "-sV -sC")
        self.timeout = self.config.get("timeout", 300)

    @property
    def name(self) -> str:
        return "nmap"

    @property
    def description(self) -> str:
        return ("Run Nmap port scanner. Discover open ports, identify services/versions, "
                "run NSE scripts. Examples: -F (fast), -p- (all ports), --script=vuln")

    @property
    def parameters(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname."},
                "args": {"type": "string", "description": f"Nmap arguments. Default: '{self.default_args}'"},
                "ports": {"type": "string", "description": "Ports to scan. E.g. '80,443' or '1-1000'"},
            },
            "required": ["target"],
        }

    def execute(self, **kwargs) -> ToolResult:
        target = kwargs.get("target", "")
        args = kwargs.get("args", self.default_args)
        ports = kwargs.get("ports", "")
        if not target:
            return ToolResult(success=False, output="", error="Target required")
        cmd_parts = ["nmap"]
        if args:
            cmd_parts.append(args)
        if ports:
            cmd_parts.extend(["-p", ports])
        cmd_parts.append(target)
        command = " ".join(cmd_parts)
        logger.info(f"Nmap scan: {command}")
        return self.shell.execute(command=command, timeout=self.timeout)
