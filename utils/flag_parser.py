"""Flag extraction and validation utility"""

import re
from typing import List, Optional
from utils.logger import get_logger

logger = get_logger(__name__)


class FlagParser:
    FLAG_PATTERN = re.compile(r"flag\{[a-zA-Z0-9_\-!@#$%^&*()+=,./?;:'\"><\[\]{}|\\~`]+\}", re.IGNORECASE)
    FLAG_PATTERN_LOOSE = re.compile(r"flag\{.+?\}", re.IGNORECASE | re.DOTALL)
    PLACEHOLDER_TOKENS = {"...", "…", "xxx", "your_flag_here"}

    @classmethod
    def _is_placeholder_flag(cls, flag: str) -> bool:
        lowered = flag.strip().lower()
        if lowered in {"flag{...}", "flag{…}", "flag{xxx}", "flag{your_flag_here}"}:
            return True
        content = lowered[5:-1].strip() if lowered.startswith("flag{") and lowered.endswith("}") else ""
        if not content:
            return True
        if "..." in content or "…" in content:
            return True
        return content in cls.PLACEHOLDER_TOKENS

    @classmethod
    def extract_flags(cls, text: str) -> List[str]:
        flags = set()
        for match in cls.FLAG_PATTERN.finditer(text):
            flag = match.group()
            if cls.validate_flag(flag):
                flags.add(flag)
        if not flags:
            for match in cls.FLAG_PATTERN_LOOSE.finditer(text):
                flag = match.group()
                if "\n" not in flag and len(flag) < 200 and cls.validate_flag(flag):
                    flags.add(flag)
        result = list(flags)
        if result:
            logger.info(f"Extracted {len(result)} flag(s): {result}")
        return result

    @classmethod
    def extract_first_flag(cls, text: str) -> Optional[str]:
        flags = cls.extract_flags(text)
        return flags[0] if flags else None

    @classmethod
    def contains_flag(cls, text: str) -> bool:
        return bool(cls.extract_flags(text))

    @classmethod
    def validate_flag(cls, flag: str) -> bool:
        if not flag:
            return False
        if not flag.startswith("flag{") and not flag.startswith("FLAG{"):
            return False
        if not flag.endswith("}"):
            return False
        content = flag[5:-1]
        if len(content) < 1 or len(content) > 128:
            return False
        if "\n" in content:
            return False
        if cls._is_placeholder_flag(flag):
            return False
        return True
