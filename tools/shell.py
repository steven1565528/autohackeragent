"""Shell command execution tool"""

import re
import subprocess
from typing import Any, Dict, Optional
from tools.base import BaseTool, ToolResult
from utils.logger import get_logger

logger = get_logger(__name__)

DEFAULT_BLOCKED = [r"rm\s+-rf\s+/\s*$", r"mkfs\.", r"dd\s+if=", r":\(\)\{.*\|.*&\}\;:"]


class ShellTool(BaseTool):
    @property
    def name(self) -> str:
        return "shell"

    @property
    def description(self) -> str:
        return ("Execute a shell command on the local system. Use for any CLI operation "
                "without a dedicated tool: cat, grep, python scripts, curl, wget, etc.")

    @property
    def parameters(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Shell command to execute."},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default: 120)."},
                "cwd": {"type": "string", "description": "Working directory (optional)."},
            },
            "required": ["command"],
        }

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.default_timeout = self.config.get("timeout", 120)
        self.max_output_length = self.config.get("max_output_length", 50000)
        blocked = self.config.get("blocked_patterns", [])
        self.blocked_patterns = [re.compile(p) for p in (blocked if blocked else DEFAULT_BLOCKED)]

    def _is_blocked(self, command: str) -> Optional[str]:
        for pattern in self.blocked_patterns:
            if pattern.search(command):
                return f"Command blocked by safety policy: {pattern.pattern}"
        return None

    def _truncate(self, output: str) -> str:
        if len(output) <= self.max_output_length:
            return output
        half = self.max_output_length // 2
        return output[:half] + f"\n\n... [truncated {len(output) - self.max_output_length} chars] ...\n\n" + output[-half:]

    def execute(self, **kwargs) -> ToolResult:
        command = kwargs.get("command", "")
        timeout = kwargs.get("timeout", self.default_timeout)
        cwd = kwargs.get("cwd", None)
        if not command.strip():
            return ToolResult(success=False, output="", error="Command cannot be empty")
        blocked = self._is_blocked(command)
        if blocked:
            return ToolResult(success=False, output="", error=blocked)
        logger.info(f"Shell: {command}")
        try:
            # encoding='utf-8' with errors='replace' prevents UnicodeDecodeError when
            # tools produce non-UTF-8 output (e.g., binary data) on Ubuntu 24 default locale
            result = subprocess.run(
                command, shell=True, capture_output=True,
                encoding='utf-8', errors='replace',
                timeout=timeout, cwd=cwd,
            )
            stdout = self._truncate(result.stdout)
            stderr = self._truncate(result.stderr)
            combined = stdout
            if stderr:
                combined = combined + "\n--- STDERR ---\n" + stderr if combined else stderr
            if not combined:
                combined = "(command completed, no output)"
            return ToolResult(
                success=result.returncode == 0, output=combined,
                error=None if result.returncode == 0 else f"Exit code: {result.returncode}",
                raw_output=result.stdout + result.stderr,
                metadata={"return_code": result.returncode, "command": command},
            )
        except subprocess.TimeoutExpired:
            return ToolResult(success=False, output="", error=f"Timeout ({timeout}s): {command}")
        except Exception as e:
            return ToolResult(success=False, output="", error=f"Execution error: {str(e)}")
