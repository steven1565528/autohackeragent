"""Web pentesting tools: curl, directory scan, nikto"""

from typing import Any, Dict
from tools.base import BaseTool, ToolResult
from tools.shell import ShellTool
from utils.logger import get_logger

logger = get_logger(__name__)


class CurlTool(BaseTool):
    def __init__(self, config: dict = None):
        super().__init__(config)
        self.shell = ShellTool(config=config)

    @property
    def name(self) -> str:
        return "curl"

    @property
    def description(self) -> str:
        return "Send HTTP requests via curl. GET, POST, custom headers, follow redirects."

    @property
    def parameters(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL."},
                "method": {"type": "string", "description": "HTTP method (default: GET)"},
                "data": {"type": "string", "description": "POST data."},
                "headers": {"type": "string", "description": "Headers separated by newline."},
                "args": {"type": "string", "description": "Additional curl args."},
            },
            "required": ["url"],
        }

    def execute(self, **kwargs) -> ToolResult:
        url = kwargs.get("url", "")
        method = kwargs.get("method", "GET").upper()
        data = kwargs.get("data", "")
        headers = kwargs.get("headers", "")
        args = kwargs.get("args", "")
        if not url:
            return ToolResult(success=False, output="", error="URL required")
        cmd = ["curl", "-s", "-i"]
        if method != "GET":
            cmd.extend(["-X", method])
        if data:
            cmd.extend(["-d", f"'{data}'"])
        if headers:
            for h in headers.split("\\n"):
                h = h.strip()
                if h:
                    cmd.extend(["-H", f"'{h}'"])
        if args:
            cmd.append(args)
        cmd.append(f"'{url}'")
        return self.shell.execute(command=" ".join(cmd), timeout=30)


class DirScanTool(BaseTool):
    def __init__(self, config: dict = None):
        super().__init__(config)
        self.shell = ShellTool(config=config)

    @property
    def name(self) -> str:
        return "dirscan"

    @property
    def description(self) -> str:
        return "Scan web directories using gobuster or dirb. Find hidden paths, admin panels, backups."

    @property
    def parameters(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target base URL."},
                "wordlist": {"type": "string", "description": "Wordlist path (default: /usr/share/wordlists/dirb/common.txt)"},
                "extensions": {"type": "string", "description": "File extensions: 'php,txt,bak'"},
                "tool": {"type": "string", "description": "'gobuster' or 'dirb' (default: gobuster)"},
                "args": {"type": "string", "description": "Additional arguments."},
            },
            "required": ["url"],
        }

    def execute(self, **kwargs) -> ToolResult:
        url = kwargs.get("url", "")
        wordlist = kwargs.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        extensions = kwargs.get("extensions", "")
        tool = kwargs.get("tool", "gobuster")
        args = kwargs.get("args", "")
        if not url:
            return ToolResult(success=False, output="", error="URL required")
        if tool == "gobuster":
            cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-q", "--no-error"]
            if extensions:
                cmd.extend(["-x", extensions])
        else:
            cmd = ["dirb", url, wordlist, "-S"]
        if args:
            cmd.append(args)
        return self.shell.execute(command=" ".join(cmd), timeout=300)


class NiktoTool(BaseTool):
    def __init__(self, config: dict = None):
        super().__init__(config)
        self.shell = ShellTool(config=config)

    @property
    def name(self) -> str:
        return "nikto"

    @property
    def description(self) -> str:
        return "Run Nikto web vulnerability scanner for known vulnerabilities and misconfigs."

    @property
    def parameters(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL or host."},
                "args": {"type": "string", "description": "Additional nikto arguments."},
            },
            "required": ["target"],
        }

    def execute(self, **kwargs) -> ToolResult:
        target = kwargs.get("target", "")
        args = kwargs.get("args", "")
        if not target:
            return ToolResult(success=False, output="", error="Target required")
        cmd = ["nikto", "-h", target, "-nointeractive"]
        if args:
            cmd.append(args)
        return self.shell.execute(command=" ".join(cmd), timeout=300)
