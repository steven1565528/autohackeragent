"""Tests for the integrated AboutSecurity repository."""

from tools.aboutsecurity_tool import AboutSecurityTool
from utils.aboutsecurity import AboutSecurityRepository


class TestAboutSecurityRepository:
    def test_repository_exists(self):
        repo = AboutSecurityRepository()
        assert repo.exists()
        assert repo.manifest_path.exists()

    def test_manifest_modules(self):
        repo = AboutSecurityRepository()
        modules = repo.list_modules()
        assert "dic" in modules
        assert "payload" in modules
        assert "skills" in modules

    def test_list_skills(self):
        repo = AboutSecurityRepository()
        names = {skill.name for skill in repo.list_skills()}
        assert "recon-full" in names
        assert "sql-injection-methodology" in names

    def test_search_resources(self):
        repo = AboutSecurityRepository()
        results = repo.search_resources(module="payload", query="xss", limit=20)
        assert any("Payload/XSS" in item for item in results)


class TestAboutSecurityTool:
    def test_tool_registered(self):
        from tools import TOOL_REGISTRY

        assert "aboutsecurity" in TOOL_REGISTRY

    def test_search_skills(self):
        tool = AboutSecurityTool()
        result = tool.execute(action="search_skills", query="sql", limit=5)
        assert result.success
        assert "sql-injection-methodology" in result.output

    def test_show_skill(self):
        tool = AboutSecurityTool()
        result = tool.execute(action="show_skill", name="recon-full")
        assert result.success
        assert "Phase 1" in result.output
