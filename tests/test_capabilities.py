from pathlib import Path

from utils.capabilities import resolve_tool_artifacts, summarize_tool_capabilities


def test_summarize_tool_capabilities_formats_available_and_missing():
    summary = summarize_tool_capabilities(
        {
            "curl": {"available": True, "commands": ["curl"], "missing": []},
            "sqlmap": {"available": False, "commands": [], "missing": ["sqlmap"]},
            "shell": {"available": True, "commands": [], "missing": []},
            "exploit": {"available": True, "commands": ["msfconsole", "msfvenom"], "missing": ["searchsploit", "nc"]},
            "_artifacts": {
                "ysoserial": {"available": True, "path": "/tmp/ysoserial.jar", "candidates": ["/tmp/ysoserial.jar"]},
            },
        }
    )
    assert "- curl: available via curl" in summary
    assert "- exploit: available via msfconsole, msfvenom" in summary
    assert "- sqlmap: unavailable (missing sqlmap)" in summary
    assert "- shell: available (built-in)" in summary
    assert "- ysoserial: use /tmp/ysoserial.jar" in summary


def test_resolve_tool_artifacts_prefers_configured_path(tmp_path: Path):
    jar_path = tmp_path / "ysoserial-all.jar"
    jar_path.write_text("jar")
    resolved = resolve_tool_artifacts(
        config={"tools": {"artifacts": {"ysoserial_path": str(jar_path)}}},
        base_dir=str(tmp_path),
    )
    assert resolved["ysoserial"]["available"] is True
    assert resolved["ysoserial"]["path"] == str(jar_path.resolve())


def test_resolve_tool_artifacts_omits_removed_shiro_attack_entry(tmp_path: Path):
    resolved = resolve_tool_artifacts(base_dir=str(tmp_path))
    assert "shiro_attack" not in resolved
