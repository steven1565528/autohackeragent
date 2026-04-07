"""
Skill Tool - Wraps the SkillEngine as a standard BaseTool
so the LLM can invoke skills through the normal tool interface.

Usage in LLM response:
{
    "thought": "Target is new, need full recon first",
    "action": "skill",
    "action_input": {"name": "full_recon", "target": "10.0.0.1"}
}
"""

from typing import Any, Dict
from tools.base import BaseTool, ToolResult
from utils.logger import get_logger

logger = get_logger(__name__)


class SkillTool(BaseTool):
    def __init__(self, config: dict = None):
        super().__init__(config)
        from skills.engine import SkillEngine
        self.engine = SkillEngine(config=config)

    @property
    def name(self) -> str:
        return "skill"

    @property
    def description(self) -> str:
        skill_list = self.engine.list_skills()
        desc_lines = ["Execute a predefined multi-step skill to automate common workflows. "
                      "PREFER skills over individual tools for standard operations - they are "
                      "faster and more thorough.\n\nAvailable skills:"]
        for sname, sdesc in skill_list.items():
            desc_lines.append(f"  - {sname}: {sdesc}")
        return "\n".join(desc_lines)

    @property
    def parameters(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Skill name to execute.",
                    "enum": list(self.engine.list_skills().keys()),
                },
                "target": {
                    "type": "string",
                    "description": "Target IP address (for network skills).",
                },
                "url": {
                    "type": "string",
                    "description": "Target URL (for web skills).",
                },
                "subnet": {
                    "type": "string",
                    "description": "Subnet prefix for lateral_recon, e.g. '10.0.0'.",
                },
                "port": {
                    "type": "integer",
                    "description": "Port number (for db_enum).",
                },
            },
            "required": ["name"],
        }

    def execute(self, **kwargs) -> ToolResult:
        skill_name = kwargs.pop("name", "")
        if not skill_name:
            return ToolResult(
                success=False, output="",
                error=f"Skill name required. Available: {list(self.engine.list_skills().keys())}"
            )

        logger.info(f"Skill invoked: {skill_name} params={kwargs}")
        result = self.engine.execute(skill_name, **kwargs)

        # Convert SkillResult to ToolResult with compact summary
        compact = result.to_compact_summary()

        return ToolResult(
            success=result.success,
            output=compact,
            metadata={
                "skill_name": result.skill_name,
                "steps_executed": result.steps_executed,
                "steps_total": result.steps_total,
                "flags_found": result.flags_found,
                "open_ports": result.open_ports,
                "services": result.services,
                "vulnerabilities": result.vulnerabilities,
                "credentials": result.credentials,
                "interesting_files": result.interesting_files,
            },
        )
