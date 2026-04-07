"""File operation tools: read, write, search"""

import os
from typing import Any, Dict
from tools.base import BaseTool, ToolResult
from tools.shell import ShellTool
from utils.logger import get_logger

logger = get_logger(__name__)


class FileReadTool(BaseTool):
    def __init__(self, config: dict = None):
        super().__init__(config)
        self.shell = ShellTool(config=config)

    @property
    def name(self) -> str:
        return "file_read"

    @property
    def description(self) -> str:
        return "Read file contents. Examine configs, source code, credentials."

    @property
    def parameters(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path."},
                "lines": {"type": "string", "description": "Line range: '1-50' or 'tail-100'"},
            },
            "required": ["path"],
        }

    def execute(self, **kwargs) -> ToolResult:
        path = kwargs.get("path", "")
        lines = kwargs.get("lines", "")
        if not path:
            return ToolResult(success=False, output="", error="Path required")
        if lines:
            if lines.startswith("tail-"):
                cmd = f"tail -n {lines[5:]} '{path}'"
            elif "-" in lines:
                parts = lines.split("-")
                cmd = f"sed -n '{parts[0]},{parts[1]}p' '{path}'"
            else:
                cmd = f"cat '{path}'"
        else:
            cmd = f"head -n 1000 '{path}'"
        return self.shell.execute(command=cmd, timeout=10)


class FileWriteTool(BaseTool):
    def __init__(self, config: dict = None):
        super().__init__(config)

    @property
    def name(self) -> str:
        return "file_write"

    @property
    def description(self) -> str:
        return "Write content to a file. Create exploit scripts, configs, save data."

    @property
    def parameters(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path."},
                "content": {"type": "string", "description": "Content to write."},
                "append": {"type": "boolean", "description": "Append mode (default: false)"},
            },
            "required": ["path", "content"],
        }

    def execute(self, **kwargs) -> ToolResult:
        path = kwargs.get("path", "")
        content = kwargs.get("content", "")
        append = kwargs.get("append", False)
        if not path:
            return ToolResult(success=False, output="", error="Path required")
        try:
            mode = "a" if append else "w"
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            with open(path, mode, encoding="utf-8") as f:
                f.write(content)
            action = "appended" if append else "written"
            return ToolResult(success=True, output=f"File {action}: {path} ({len(content)} chars)")
        except Exception as e:
            return ToolResult(success=False, output="", error=f"Write failed: {str(e)}")


class FileSearchTool(BaseTool):
    def __init__(self, config: dict = None):
        super().__init__(config)
        self.shell = ShellTool(config=config)

    @property
    def name(self) -> str:
        return "file_search"

    @property
    def description(self) -> str:
        return "Search for files or content. Use find (locate files) or grep (search content)."

    @property
    def parameters(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["find", "grep"]},
                "pattern": {"type": "string", "description": "Search pattern."},
                "path": {"type": "string", "description": "Directory to search (default: .)"},
                "recursive": {"type": "boolean", "description": "Recursive search (default: true)"},
                "args": {"type": "string", "description": "Additional arguments."},
            },
            "required": ["action", "pattern"],
        }

    def execute(self, **kwargs) -> ToolResult:
        action = kwargs.get("action", "grep")
        pattern = kwargs.get("pattern", "")
        path = kwargs.get("path", ".")
        recursive = kwargs.get("recursive", True)
        args = kwargs.get("args", "")
        if not pattern:
            return ToolResult(success=False, output="", error="Pattern required")
        if action == "find":
            extra = f" {args.strip()}" if args and args.strip() else ""
            cmd = f"find '{path}'{extra} -name '{pattern}' -type f 2>/dev/null | head -100"
        elif action == "grep":
            r_flag = "-r" if recursive else ""
            extra = f" {args.strip()}" if args and args.strip() else ""
            cmd = f"grep -n {r_flag} -i '{pattern}' '{path}'{extra} 2>/dev/null | head -100"
        else:
            return ToolResult(success=False, output="", error=f"Unknown action: {action}")
        return self.shell.execute(command=cmd, timeout=60)
