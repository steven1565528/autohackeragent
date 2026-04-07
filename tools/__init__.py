from tools.base import BaseTool, ToolResult
from tools.shell import ShellTool
from tools.nmap_tool import NmapTool
from tools.web_tools import CurlTool, DirScanTool, NiktoTool
from tools.sqli_tool import SqlmapTool
from tools.exploit_tool import ExploitTool
from tools.file_tools import FileReadTool, FileWriteTool, FileSearchTool
from tools.skill_tool import SkillTool
from tools.codegen_tool import CodeGenTool

TOOL_REGISTRY = {
    "shell": ShellTool,
    "nmap": NmapTool,
    "curl": CurlTool,
    "dirscan": DirScanTool,
    "nikto": NiktoTool,
    "sqlmap": SqlmapTool,
    "exploit": ExploitTool,
    "file_read": FileReadTool,
    "file_write": FileWriteTool,
    "file_search": FileSearchTool,
    "skill": SkillTool,
    "codegen": CodeGenTool,
}


def get_all_tools(config: dict = None) -> list:
    tools = []
    for name, cls in TOOL_REGISTRY.items():
        tool_config = {}
        if config and "tools" in config:
            tool_config = config["tools"].get(name, {})
        tools.append(cls(config=tool_config))
    return tools


def get_tool(name: str, config: dict = None) -> BaseTool:
    if name not in TOOL_REGISTRY:
        raise ValueError(f"Unknown tool: {name}, available: {list(TOOL_REGISTRY.keys())}")
    tool_config = {}
    if config and "tools" in config:
        tool_config = config["tools"].get(name, {})
    return TOOL_REGISTRY[name](config=tool_config)
