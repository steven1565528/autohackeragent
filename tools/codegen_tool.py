"""
CodeGen Tool - LLM writes and executes custom scripts on-the-fly

This is the core "improvisation" capability:
- LLM analyzes a novel situation
- Writes a Python or Bash script to handle it
- Executes it and gets the result
- All in ONE tool call (no multi-step reasoning needed)

Typical uses during competition:
- Custom exploit scripts for specific CVEs
- Data parsing/extraction from unusual formats
- Chaining multiple operations that no single tool handles
- Reverse engineering binary protocols
- Generating payloads dynamically
"""

import os
import tempfile
import subprocess
from typing import Any, Dict
from tools.base import BaseTool, ToolResult
from utils.logger import get_logger

logger = get_logger(__name__)


class CodeGenTool(BaseTool):
    def __init__(self, config: dict = None):
        super().__init__(config)
        self.work_dir = self.config.get("work_dir", "/tmp/autohacker")
        os.makedirs(self.work_dir, exist_ok=True)

    @property
    def name(self) -> str:
        return "codegen"

    @property
    def description(self) -> str:
        return (
            "Write and execute a custom script when no existing tool/skill fits. "
            "Supports Python3 and Bash. Use this for:\n"
            "- Custom exploits for specific CVEs\n"
            "- Parsing unusual data formats\n"
            "- Chaining complex multi-step operations\n"
            "- Generating/encoding payloads\n"
            "- Reverse shell handlers\n"
            "- Brute-force with custom logic\n"
            "- Any novel situation not covered by built-in skills\n\n"
            "The script has full access to: requests, socket, struct, base64, "
            "hashlib, subprocess, os, sys, re, json, urllib, http.server, etc."
        )

    @property
    def parameters(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "language": {
                    "type": "string",
                    "enum": ["python", "bash"],
                    "description": "Script language: python or bash",
                },
                "code": {
                    "type": "string",
                    "description": "The script code to execute. Write complete, runnable code.",
                },
                "description": {
                    "type": "string",
                    "description": "Brief description of what this script does (for logging).",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Execution timeout in seconds (default: 60).",
                },
                "save_as": {
                    "type": "string",
                    "description": "Optional: save script to this filename for reuse.",
                },
            },
            "required": ["language", "code"],
        }

    def execute(self, **kwargs) -> ToolResult:
        language = kwargs.get("language", "python")
        code = kwargs.get("code", "")
        description = kwargs.get("description", "custom script")
        timeout = kwargs.get("timeout", 60)
        save_as = kwargs.get("save_as", "")

        if not code.strip():
            return ToolResult(success=False, output="", error="Code cannot be empty")

        logger.info(f"CodeGen [{language}]: {description}")

        # Determine file extension and interpreter
        if language == "python":
            ext = ".py"
            interpreter = "python3"
        elif language == "bash":
            ext = ".sh"
            interpreter = "bash"
        else:
            return ToolResult(success=False, output="", error=f"Unsupported language: {language}")

        # Write script to temp file
        script_path = os.path.join(self.work_dir, f"script_{os.getpid()}{ext}")
        if save_as:
            script_path = os.path.join(self.work_dir, save_as)

        try:
            with open(script_path, "w", encoding="utf-8") as f:
                f.write(code)
            os.chmod(script_path, 0o755)

            # Execute
            result = subprocess.run(
                [interpreter, script_path],
                capture_output=True, text=True,
                timeout=timeout, cwd=self.work_dir,
            )

            stdout = result.stdout
            stderr = result.stderr

            # Truncate if too long
            max_len = 50000
            if len(stdout) > max_len:
                stdout = stdout[:max_len // 2] + f"\n...[truncated {len(stdout) - max_len} chars]...\n" + stdout[-max_len // 2:]

            combined = stdout
            if stderr:
                combined += "\n--- STDERR ---\n" + stderr[:5000]

            if not combined.strip():
                combined = "(script completed, no output)"

            return ToolResult(
                success=result.returncode == 0,
                output=combined,
                error=None if result.returncode == 0 else f"Exit code: {result.returncode}",
                metadata={
                    "language": language,
                    "description": description,
                    "script_path": script_path if save_as else None,
                    "return_code": result.returncode,
                },
            )

        except subprocess.TimeoutExpired:
            return ToolResult(success=False, output="", error=f"Script timeout ({timeout}s)")
        except Exception as e:
            return ToolResult(success=False, output="", error=f"Execution error: {str(e)}")
        finally:
            # Clean up temp file (keep if save_as was specified)
            if not save_as and os.path.exists(script_path):
                try:
                    os.remove(script_path)
                except:
                    pass
