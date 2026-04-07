"""SQLMap SQL injection tool"""

from typing import Any, Dict
from tools.base import BaseTool, ToolResult
from tools.shell import ShellTool
from utils.logger import get_logger

logger = get_logger(__name__)


class SqlmapTool(BaseTool):
    def __init__(self, config: dict = None):
        super().__init__(config)
        self.shell = ShellTool(config=config)
        self.default_args = self.config.get("default_args", "--batch --random-agent")
        self.timeout = self.config.get("timeout", 600)

    @property
    def name(self) -> str:
        return "sqlmap"

    @property
    def description(self) -> str:
        return ("Run SQLMap for automatic SQL injection detection and exploitation. "
                "Test URLs, POST data. Use --dbs, --tables, --dump, --os-shell.")

    @property
    def parameters(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL with injectable param."},
                "data": {"type": "string", "description": "POST data string."},
                "args": {"type": "string", "description": "Additional sqlmap arguments."},
                "cookie": {"type": "string", "description": "Cookie header value."},
            },
            "required": ["url"],
        }

    def execute(self, **kwargs) -> ToolResult:
        url = kwargs.get("url", "")
        data = kwargs.get("data", "")
        args = kwargs.get("args", "")
        cookie = kwargs.get("cookie", "")
        if not url:
            return ToolResult(success=False, output="", error="URL required")
        cmd = ["sqlmap", "-u", f"'{url}'", self.default_args]
        if data:
            cmd.extend(["--data", f"'{data}'"])
        if cookie:
            cmd.extend(["--cookie", f"'{cookie}'"])
        if args:
            cmd.append(args)
        return self.shell.execute(command=" ".join(cmd), timeout=self.timeout)
