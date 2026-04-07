"""Tool base class - unified interface for all pentesting tools"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class ToolResult:
    success: bool
    output: str
    error: Optional[str] = None
    raw_output: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        if self.success:
            return self.output
        return f"Error: {self.error}\nOutput: {self.output}"

    @property
    def truncated_output(self) -> str:
        max_len = 8000
        if len(self.output) <= max_len:
            return self.output
        half = max_len // 2
        return (
            self.output[:half]
            + f"\n\n... [truncated {len(self.output) - max_len} chars] ...\n\n"
            + self.output[-half:]
        )


class BaseTool(ABC):
    def __init__(self, config: dict = None):
        self.config = config or {}

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        pass

    @property
    @abstractmethod
    def parameters(self) -> Dict[str, Any]:
        pass

    @abstractmethod
    def execute(self, **kwargs) -> ToolResult:
        pass

    def to_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    def __repr__(self) -> str:
        return f"<Tool: {self.name}>"
