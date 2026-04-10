"""Runtime capability detection for installed security tools."""

from pathlib import Path
import shutil
from typing import Dict, List, Optional, Union

TOOL_COMMANDS = {
    "shell": [],
    "curl": ["curl"],
    "nmap": ["nmap"],
    # ffuf is available via apt on Ubuntu 24 and is a modern alternative to gobuster/dirb
    "dirscan": ["gobuster", "dirb", "ffuf"],
    "nikto": ["nikto"],
    # whatweb is available via apt and useful for web fingerprinting
    "whatweb": ["whatweb"],
    "sqlmap": ["sqlmap"],
    "exploit": ["searchsploit", "msfconsole", "msfvenom", "nc"],
    "file_read": [],
    "file_write": [],
    "file_search": ["find", "grep"],
    "skill": ["curl", "find", "grep", "nmap"],
    # python3 path is /usr/bin/python3 on Ubuntu 24; detect python3 not pip3
    "codegen": ["python3", "bash"],
}

TOOL_ARTIFACTS = {
    "ysoserial": ["ysoserial-all.jar", "ysoserial.jar", "ysoserial-new.jar"],
}


def get_workspace_root() -> Path:
    return Path(__file__).resolve().parents[1]


def resolve_tool_artifacts(config: Optional[dict] = None, base_dir: Optional[str] = None) -> Dict[str, Dict[str, Union[bool, str, List[str]]]]:
    root = Path(base_dir) if base_dir else get_workspace_root()
    tool_config = (config or {}).get("tools", {})
    configured_paths = tool_config.get("artifacts", {})
    resolved: Dict[str, Dict[str, Union[bool, str, List[str]]]] = {}

    for tool_name, candidates in TOOL_ARTIFACTS.items():
        configured = configured_paths.get(f"{tool_name}_path") or configured_paths.get(tool_name)
        search_paths: List[Path] = []
        if configured:
            configured_path = Path(configured)
            search_paths.append(configured_path if configured_path.is_absolute() else root / configured_path)
        search_paths.extend(root / candidate for candidate in candidates)

        seen: set = set()
        normalized_candidates: List[str] = []
        chosen_path = ""
        for candidate in search_paths:
            candidate_str = str(candidate.resolve()) if candidate.exists() else str(candidate)
            if candidate_str in seen:
                continue
            seen.add(candidate_str)
            normalized_candidates.append(candidate_str)
            if not chosen_path and candidate.exists():
                chosen_path = str(candidate.resolve())

        resolved[tool_name] = {
            "available": bool(chosen_path),
            "path": chosen_path,
            "candidates": normalized_candidates,
        }

    return resolved


def detect_tool_capabilities(config: Optional[dict] = None, base_dir: Optional[str] = None) -> Dict[str, Dict[str, Union[List[str], bool, Dict[str, Dict[str, Union[bool, str, List[str]]]]]]]:
    """Return per-tool availability plus discovered backing commands."""
    capabilities: Dict[str, Dict[str, Union[List[str], bool]]] = {}
    for tool_name, commands in TOOL_COMMANDS.items():
        found = [cmd for cmd in commands if shutil.which(cmd)]
        capabilities[tool_name] = {
            "available": True if not commands else bool(found),
            "commands": found,
            "missing": [cmd for cmd in commands if cmd not in found],
        }
    capabilities["_artifacts"] = resolve_tool_artifacts(config=config, base_dir=base_dir)
    return capabilities


def summarize_tool_capabilities(capabilities: Dict[str, Dict[str, Union[List[str], bool]]]) -> str:
    """Produce a compact prompt-friendly inventory."""
    lines = []
    for tool_name in sorted(capabilities):
        if tool_name.startswith("_"):
            continue
        meta = capabilities[tool_name]
        if meta["available"]:
            commands = meta["commands"]
            if commands:
                lines.append(f"- {tool_name}: available via {', '.join(commands)}")
            else:
                lines.append(f"- {tool_name}: available (built-in)")
        else:
            lines.append(f"- {tool_name}: unavailable (missing {', '.join(meta['missing'])})")
    artifacts = capabilities.get("_artifacts", {})
    if artifacts:
        lines.append("Normalized exploit artifacts:")
        for tool_name in sorted(artifacts):
            meta = artifacts[tool_name]
            if meta["available"]:
                lines.append(f"- {tool_name}: use {meta['path']}")
            else:
                lines.append(f"- {tool_name}: unavailable")
    return "\n".join(lines)
