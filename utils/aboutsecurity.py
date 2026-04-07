"""Helpers for browsing the vendored AboutSecurity knowledge base."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


@dataclass
class AboutSecuritySkill:
    name: str
    description: str
    category: str
    path: Path
    tags: List[str]


class AboutSecurityRepository:
    """Read-only index for the vendored AboutSecurity repository."""

    def __init__(self, root: Optional[str] = None):
        base_dir = Path(__file__).resolve().parents[1]
        self.root = Path(root) if root else base_dir / "resources" / "AboutSecurity"
        self._manifest: Optional[Dict[str, Any]] = None
        self._skills: Optional[List[AboutSecuritySkill]] = None

    def exists(self) -> bool:
        return self.root.exists()

    @property
    def manifest_path(self) -> Path:
        return self.root / "manifest.yaml"

    def load_manifest(self) -> Dict[str, Any]:
        if self._manifest is None:
            if not self.manifest_path.exists():
                self._manifest = {}
            else:
                self._manifest = yaml.safe_load(self.manifest_path.read_text(encoding="utf-8")) or {}
        return self._manifest

    def list_modules(self) -> Dict[str, Dict[str, Any]]:
        manifest = self.load_manifest()
        return manifest.get("modules", {})

    def _parse_skill(self, path: Path) -> AboutSecuritySkill:
        text = path.read_text(encoding="utf-8")
        frontmatter: Dict[str, Any] = {}
        if text.startswith("---\n"):
            _, _, rest = text.partition("---\n")
            fm_text, sep, _ = rest.partition("\n---\n")
            if sep:
                frontmatter = yaml.safe_load(fm_text) or {}
        metadata = frontmatter.get("metadata") or {}
        tags = metadata.get("tags") or ""
        if isinstance(tags, str):
            tag_list = [tag.strip() for tag in tags.split(",") if tag.strip()]
        else:
            tag_list = [str(tag).strip() for tag in tags if str(tag).strip()]
        return AboutSecuritySkill(
            name=frontmatter.get("name") or path.parent.name,
            description=frontmatter.get("description") or "",
            category=metadata.get("category") or path.parent.parent.name,
            path=path,
            tags=tag_list,
        )

    def list_skills(self, category: Optional[str] = None) -> List[AboutSecuritySkill]:
        if self._skills is None:
            skill_paths = sorted(self.root.glob("skills/*/*/SKILL.md"))
            self._skills = [self._parse_skill(path) for path in skill_paths]
        if not category:
            return list(self._skills)
        return [skill for skill in self._skills if skill.category == category]

    def search_skills(self, query: str, category: Optional[str] = None, limit: int = 20) -> List[AboutSecuritySkill]:
        query_lower = query.strip().lower()
        if not query_lower:
            return self.list_skills(category=category)[:limit]
        scored: List[tuple[int, AboutSecuritySkill]] = []
        for skill in self.list_skills(category=category):
            rel_path = str(skill.path.relative_to(self.root)).lower()
            score = 0
            if query_lower == skill.name.lower():
                score += 100
            if query_lower in skill.name.lower():
                score += 60
            if query_lower == skill.category.lower():
                score += 40
            if any(query_lower in tag.lower() for tag in skill.tags):
                score += 25
            if query_lower in skill.description.lower():
                score += 10
            if query_lower in rel_path:
                score += 5
            if score > 0:
                scored.append((score, skill))
        scored.sort(key=lambda item: (-item[0], item[1].name))
        return [skill for _, skill in scored[:limit]]

    def get_skill(self, name_or_path: str) -> Optional[AboutSecuritySkill]:
        needle = name_or_path.strip().lower()
        if not needle:
            return None
        for skill in self.list_skills():
            rel_path = str(skill.path.relative_to(self.root)).lower()
            if needle in {skill.name.lower(), rel_path, skill.path.as_posix().lower()}:
                return skill
        return None

    def read_skill(self, name_or_path: str, max_chars: int = 4000) -> Optional[Dict[str, Any]]:
        skill = self.get_skill(name_or_path)
        if not skill:
            return None
        content = skill.path.read_text(encoding="utf-8")
        references = sorted(str(path.relative_to(self.root)) for path in skill.path.parent.glob("references/*.md"))
        return {
            "name": skill.name,
            "description": skill.description,
            "category": skill.category,
            "tags": skill.tags,
            "path": str(skill.path),
            "references": references,
            "content": content[:max_chars],
            "truncated": len(content) > max_chars,
        }

    def search_resources(self, module: str, query: str, limit: int = 20) -> List[str]:
        module_map = {
            "dic": "Dic",
            "payload": "Payload",
            "doc": "Doc",
            "tools": "Tools",
            "skills": "skills",
        }
        module_dir = module_map.get(module.lower())
        if not module_dir:
            return []
        base = self.root / module_dir
        if not base.exists():
            return []
        query_lower = query.strip().lower()
        results: List[str] = []
        for path in sorted(base.rglob("*")):
            if not path.is_file():
                continue
            rel_path = str(path.relative_to(self.root))
            if not query_lower or query_lower in rel_path.lower():
                results.append(rel_path)
            if len(results) >= limit:
                break
        return results
