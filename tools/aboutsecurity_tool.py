"""Read-only browser for the vendored AboutSecurity repository."""

from typing import Any, Dict

from tools.base import BaseTool, ToolResult
from utils.aboutsecurity import AboutSecurityRepository


class AboutSecurityTool(BaseTool):
    def __init__(self, config: dict = None):
        super().__init__(config)
        self.repo = AboutSecurityRepository(root=self.config.get("repo_path"))

    @property
    def name(self) -> str:
        return "aboutsecurity"

    @property
    def description(self) -> str:
        return (
            "Browse the integrated AboutSecurity knowledge base. "
            "Use this to list methodology skills, search payload/dictionary resources, "
            "or read a specific SKILL.md playbook without modifying upstream content."
        )

    @property
    def parameters(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["list_modules", "list_skills", "search_skills", "show_skill", "search_resources"],
                    "description": "Repository browsing action.",
                },
                "query": {
                    "type": "string",
                    "description": "Keyword for skill/resource search.",
                },
                "category": {
                    "type": "string",
                    "description": "Optional skill category such as recon/exploit/lateral/cloud/general/ctf/tool.",
                },
                "name": {
                    "type": "string",
                    "description": "Skill name or relative path, for show_skill.",
                },
                "module": {
                    "type": "string",
                    "enum": ["dic", "payload", "doc", "tools", "skills"],
                    "description": "Top-level AboutSecurity module for resource search.",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max number of returned results.",
                    "default": 10,
                },
            },
            "required": ["action"],
        }

    def execute(self, **kwargs) -> ToolResult:
        if not self.repo.exists():
            return ToolResult(
                success=False,
                output="",
                error=f"AboutSecurity repository not found at {self.repo.root}",
            )

        action = kwargs.get("action", "")
        limit = max(1, min(int(kwargs.get("limit", 10) or 10), 50))
        category = kwargs.get("category")

        if action == "list_modules":
            modules = self.repo.list_modules()
            if not modules:
                return ToolResult(success=False, output="", error="No manifest/modules found")
            lines = ["AboutSecurity modules:"]
            for name, info in modules.items():
                lines.append(f"- {name}: {info.get('description', '')} ({info.get('path', '')})")
            return ToolResult(success=True, output="\n".join(lines), metadata={"modules": modules})

        if action == "list_skills":
            skills = self.repo.list_skills(category=category)[:limit]
            lines = [f"AboutSecurity skills ({len(skills)} shown):"]
            for skill in skills:
                rel_path = skill.path.relative_to(self.repo.root)
                lines.append(f"- {skill.name} [{skill.category}] - {skill.description} ({rel_path})")
            return ToolResult(success=True, output="\n".join(lines), metadata={"count": len(skills)})

        if action == "search_skills":
            query = kwargs.get("query", "")
            skills = self.repo.search_skills(query=query, category=category, limit=limit)
            lines = [f"Skill search results for: {query or '(all)'}"]
            for skill in skills:
                rel_path = skill.path.relative_to(self.repo.root)
                lines.append(f"- {skill.name} [{skill.category}] - {skill.description} ({rel_path})")
            return ToolResult(success=True, output="\n".join(lines), metadata={"count": len(skills)})

        if action == "show_skill":
            name = kwargs.get("name", "")
            detail = self.repo.read_skill(name)
            if not detail:
                return ToolResult(success=False, output="", error=f"Skill not found: {name}")
            lines = [
                f"Skill: {detail['name']}",
                f"Category: {detail['category']}",
                f"Description: {detail['description']}",
                f"Path: {detail['path']}",
            ]
            if detail["references"]:
                lines.append("References:")
                for ref in detail["references"]:
                    lines.append(f"- {ref}")
            lines.append("")
            lines.append(detail["content"])
            if detail["truncated"]:
                lines.append("\n[truncated]")
            return ToolResult(success=True, output="\n".join(lines), metadata=detail)

        if action == "search_resources":
            module = kwargs.get("module", "")
            query = kwargs.get("query", "")
            results = self.repo.search_resources(module=module, query=query, limit=limit)
            lines = [f"Resource search in {module}: {query or '(all)'}"]
            lines.extend(f"- {item}" for item in results)
            return ToolResult(success=True, output="\n".join(lines), metadata={"count": len(results), "results": results})

        return ToolResult(success=False, output="", error=f"Unknown action: {action}")
