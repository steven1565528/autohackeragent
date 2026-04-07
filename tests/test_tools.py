"""Unit tests for tools and flag parser"""

import pytest
from tools.base import ToolResult
from utils.flag_parser import FlagParser


class TestFlagParser:
    def test_extract_simple_flag(self):
        flags = FlagParser.extract_flags("The flag is flag{hello_world_123}")
        assert len(flags) == 1
        assert "flag{hello_world_123}" in flags

    def test_extract_multiple_flags(self):
        flags = FlagParser.extract_flags("First: flag{aaa} and second: flag{bbb}")
        assert len(flags) == 2

    def test_no_flag(self):
        flags = FlagParser.extract_flags("There is no flag here")
        assert len(flags) == 0

    def test_contains_flag(self):
        assert FlagParser.contains_flag("flag{test}")
        assert not FlagParser.contains_flag("no flag here")

    def test_validate_flag(self):
        assert FlagParser.validate_flag("flag{valid_flag}")
        assert not FlagParser.validate_flag("not_a_flag")
        assert not FlagParser.validate_flag("")

    def test_rejects_placeholder_flag_examples(self):
        assert FlagParser.extract_flags("Format check uses flag{...}") == []
        assert not FlagParser.contains_flag("Format check uses flag{...}")
        assert not FlagParser.validate_flag("flag{...}")

    def test_rejects_code_snippet_false_positive(self):
        text = "print('FLAG FOUND!')\nflag = re.search(r'flag\\\\{[^}]+\\\\}', body)"
        assert FlagParser.extract_flags(text) == []


class TestToolResult:
    def test_success_result(self):
        result = ToolResult(success=True, output="ok")
        assert str(result) == "ok"

    def test_error_result(self):
        result = ToolResult(success=False, output="", error="failed")
        assert "failed" in str(result)

    def test_truncated_output(self):
        result = ToolResult(success=True, output="x" * 20000)
        truncated = result.truncated_output
        assert len(truncated) < 20000
        assert "truncated" in truncated


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
