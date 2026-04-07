"""Tests for the skill system"""

import pytest
from tools.base import ToolResult
from skills.engine import SkillEngine, SkillResult


class TestSkillEngine:
    def test_list_skills(self):
        engine = SkillEngine()
        skills = engine.list_skills()
        assert "full_recon" in skills
        assert "web_recon" in skills
        assert "flag_hunt" in skills
        assert "privesc_check" in skills
        assert "credential_harvest" in skills
        assert "lateral_recon" in skills
        assert "web_vuln_quick" in skills
        assert "smb_enum" in skills
        assert "db_enum" in skills
        assert "deep_port_scan" in skills
        assert "runtime_capabilities" in skills
        assert len(skills) == 12

    def test_unknown_skill(self):
        engine = SkillEngine()
        result = engine.execute("nonexistent_skill")
        assert not result.success
        assert "Unknown skill" in result.summary

    def test_skill_result_compact_summary(self):
        result = SkillResult(
            skill_name="test_skill",
            success=True,
            steps_executed=3,
            steps_total=5,
            summary="Test complete",
            open_ports=[{"port": 80, "proto": "tcp"}, {"port": 22, "proto": "tcp"}],
            services=[{"port": 80, "service": "http", "version": "Apache/2.4"}],
            flags_found=["flag{test_123}"],
            vulnerabilities=["SQLi on /login", "Weak password"],
            credentials=[{"user": "admin", "pass": "admin123", "service": "ssh"}],
            interesting_files=["/robots.txt", "/.git/HEAD"],
        )
        summary = result.to_compact_summary()
        assert "test_skill" in summary
        assert "80/tcp" in summary
        assert "22/tcp" in summary
        assert "flag{test_123}" in summary
        assert "SQLi on /login" in summary
        assert "admin:admin123" in summary
        assert "robots.txt" in summary

    def test_skill_result_empty(self):
        result = SkillResult(
            skill_name="empty",
            success=True, steps_executed=0, steps_total=0, summary="Nothing"
        )
        summary = result.to_compact_summary()
        assert "Skill empty Result" in summary
        assert "Nothing" in summary

    def test_skill_descriptions_not_empty(self):
        engine = SkillEngine()
        for name, desc in engine.list_skills().items():
            assert len(desc) > 10, f"Skill {name} has no description"
            assert "Requires:" in desc or "No params" in desc, f"Skill {name} missing param info"


class TestSkillTool:
    def test_import_and_create(self):
        from tools.skill_tool import SkillTool
        tool = SkillTool()
        assert tool.name == "skill"
        assert "full_recon" in tool.description
        assert "web_recon" in tool.description
        assert "runtime_capabilities" in tool.description
        assert tool.parameters["properties"]["name"]["enum"]

    def test_execute_unknown_skill(self):
        from tools.skill_tool import SkillTool
        tool = SkillTool()
        result = tool.execute(name="fake_skill")
        assert not result.success
        assert "Unknown skill" in result.output

    def test_execute_missing_name(self):
        from tools.skill_tool import SkillTool
        tool = SkillTool()
        result = tool.execute()
        assert not result.success


class TestDynamicSkills:
    def test_register_dynamic_skill(self):
        engine = SkillEngine()
        msg = engine.register_dynamic_skill(
            name="test_custom",
            description="Test dynamic skill",
            commands=[
                {"cmd": "echo 'step1'", "timeout": 5, "desc": "step1"},
                {"cmd": "echo 'step2'", "timeout": 5, "desc": "step2"},
            ]
        )
        assert "registered" in msg
        assert "test_custom" in engine._skills

    def test_dynamic_skill_listed(self):
        engine = SkillEngine()
        engine.register_dynamic_skill(
            name="my_exploit",
            description="Custom exploit chain",
            commands=[{"cmd": "echo test", "desc": "test"}]
        )
        # Dynamic skill should be callable
        assert "my_exploit" in engine._skills

    def test_runtime_capabilities_skill_registered(self):
        engine = SkillEngine(config={"tools": {"artifacts": {"ysoserial_path": "./ysoserial-all.jar"}}})
        assert "runtime_capabilities" in engine.list_skills()
        result = engine.execute("runtime_capabilities")
        assert result.success
        assert "Normalized exploit artifacts:" in result.raw_outputs["runtime_capabilities"]


class TestSkillEngineRegressions:
    def test_web_recon_ignores_404_robots(self):
        engine = SkillEngine()

        def fake_run(command, timeout=120):
            if "robots.txt" in command:
                return ToolResult(success=True, output="(command completed, no output)")
            if "sitemap.xml" in command:
                return ToolResult(success=True, output="")
            if "-w '%{http_code}'" in command:
                return ToolResult(success=True, output="404")
            if "for path in /admin /login" in command:
                return ToolResult(success=True, output="(command completed, no output)")
            return ToolResult(success=True, output="")

        engine._run_cmd = fake_run
        result = engine.execute("web_recon", url="http://example.com")
        assert "robots.txt" not in result.interesting_files
        assert result.interesting_files == []

    def test_full_recon_falls_back_to_explicit_port_without_nmap(self, monkeypatch):
        engine = SkillEngine()
        monkeypatch.setattr(engine, "_command_available", lambda name: False if name == "nmap" else True)
        monkeypatch.setattr(engine, "_probe_tcp_port", lambda target, port, timeout=2.0: port == 23333)

        def fake_run(command, timeout=120):
            if "http://127.0.0.1:23333/" in command and "-i -L" in command:
                return ToolResult(success=True, output="HTTP/1.1 200 OK\nServer: Apache-Coyote/1.1\n")
            if "robots.txt" in command:
                return ToolResult(success=True, output="User-agent: *\nDisallow: /admin\n")
            return ToolResult(success=True, output="")

        monkeypatch.setattr(engine, "_run_cmd", fake_run)
        result = engine.execute("full_recon", target="127.0.0.1", port=23333)
        assert any(port["port"] == 23333 for port in result.open_ports)
        assert "23333" in result.summary
        assert "http://127.0.0.1:23333/robots.txt" in result.interesting_files


class TestCodeGenTool:
    def test_import_and_create(self):
        from tools.codegen_tool import CodeGenTool
        tool = CodeGenTool()
        assert tool.name == "codegen"
        assert "python" in tool.description.lower()
        assert "bash" in tool.description.lower()

    def test_empty_code(self):
        from tools.codegen_tool import CodeGenTool
        tool = CodeGenTool()
        result = tool.execute(language="python", code="")
        assert not result.success

    def test_tool_registered(self):
        from tools import TOOL_REGISTRY
        assert "codegen" in TOOL_REGISTRY
        assert "skill" in TOOL_REGISTRY


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
