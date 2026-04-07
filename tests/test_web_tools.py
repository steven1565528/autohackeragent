"""Tests for web tool fallbacks and file search command construction."""

from tools.base import ToolResult
from tools.file_tools import FileSearchTool
from tools.web_tools import DirScanTool


class TestDirScanFallback:
    def test_dirscan_falls_back_when_scanners_missing(self, monkeypatch):
        tool = DirScanTool()

        monkeypatch.setattr("tools.web_tools.shutil.which", lambda name: None)

        captured = {}

        def fake_execute(command, timeout):
            captured["command"] = command
            captured["timeout"] = timeout
            return ToolResult(success=True, output="200 /admin")

        tool.shell.execute = fake_execute
        result = tool.execute(url="http://example.com/", tool="gobuster")

        assert result.success
        assert "[fallback: gobuster unavailable]" in result.output
        assert "curl -s -o /dev/null" in captured["command"]
        assert "http://example.com$path" in captured["command"]


class TestFileSearchTool:
    def test_find_args_are_inserted_before_name_clause(self, monkeypatch):
        tool = FileSearchTool()
        captured = {}

        def fake_execute(command, timeout):
            captured["command"] = command
            return ToolResult(success=True, output="")

        tool.shell.execute = fake_execute
        tool.execute(action="find", pattern="*.py", path="/tmp", args="-maxdepth 2")

        assert "find '/tmp' -maxdepth 2 -name '*.py' -type f" in captured["command"]
