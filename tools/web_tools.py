"""Web pentesting tools: curl, directory scan, nikto"""

import shutil
from typing import Any, Dict
from tools.base import BaseTool, ToolResult
from tools.shell import ShellTool
from utils.logger import get_logger

logger = get_logger(__name__)


def _normalize_base_url(url: str) -> str:
    return url.rstrip("/")


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
        url = _normalize_base_url(url)
        requested_tool = tool
        if tool == "gobuster" and shutil.which("gobuster"):
            cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-q", "--no-error"]
            if extensions:
                cmd.extend(["-x", extensions])
        elif tool == "dirb" and shutil.which("dirb"):
            cmd = ["dirb", url, wordlist, "-S"]
        else:
            # Capability-aware fallback: keep scanning instead of failing on missing tools.
            common_paths = [
                "/", "/admin", "/login", "/manager", "/console", "/dashboard",
                "/api", "/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.env",
            ]
            probe = (
                "for path in " + " ".join(common_paths) + "; do "
                f"code=$(curl -s -o /dev/null -w '%{{http_code}}' --max-time 3 '{url}$path' 2>/dev/null); "
                "if [ \"$code\" = '200' ] || [ \"$code\" = '301' ] || [ \"$code\" = '302' ] || [ \"$code\" = '403' ]; then "
                "echo \"$code $path\"; fi; done"
            )
            result = self.shell.execute(command=probe, timeout=45)
            if result.success and result.output.strip():
                result.output = f"[fallback: {requested_tool} unavailable]\n" + result.output
            elif not result.output:
                result.output = f"[fallback: {requested_tool} unavailable]\n(no interesting paths found)"
            return result
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
        if not shutil.which("nikto"):
            fallback = self.shell.execute(
                command=f"curl -s -i -L --max-time 10 '{target}' 2>/dev/null | head -200",
                timeout=20,
            )
            if fallback.success:
                fallback.output = "[fallback: nikto unavailable]\n" + fallback.output
            return fallback
        cmd = ["nikto", "-h", target, "-nointeractive"]
        if args:
            cmd.append(args)
        return self.shell.execute(command=" ".join(cmd), timeout=300)
