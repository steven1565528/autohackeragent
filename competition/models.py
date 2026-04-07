"""Competition platform data models"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ChallengeZone(str, Enum):
    ZONE_1 = "zone_1"
    ZONE_2 = "zone_2"
    ZONE_3 = "zone_3"
    ZONE_4 = "zone_4"


class ChallengeStatus(str, Enum):
    LOCKED = "locked"
    AVAILABLE = "available"
    RUNNING = "running"
    SOLVED = "solved"
    FAILED = "failed"


class Challenge(BaseModel):
    id: str = Field(description="Challenge ID")
    name: str = Field(default="")
    zone: ChallengeZone = Field(default=ChallengeZone.ZONE_1)
    description: str = Field(default="")
    base_score: int = Field(default=100)
    target_host: str = Field(default="")
    target_port: Optional[int] = Field(default=None)
    status: ChallengeStatus = Field(default=ChallengeStatus.AVAILABLE)
    hint_available: bool = Field(default=True)
    hint_viewed: bool = Field(default=False)
    flags_count: int = Field(default=1)
    submitted_flags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def is_multi_flag(self) -> bool:
        return self.flags_count > 1

    @property
    def target_url(self) -> str:
        if self.target_port:
            return f"http://{self.target_host}:{self.target_port}"
        return f"http://{self.target_host}"


class FlagSubmission(BaseModel):
    challenge_id: str
    flag: str
    submitted_at: datetime = Field(default_factory=datetime.now)


class ChallengeResult(BaseModel):
    challenge_id: str
    success: bool
    score: int = Field(default=0)
    rank: int = Field(default=0)
    message: str = Field(default="")


class HintInfo(BaseModel):
    challenge_id: str
    hint_text: str = Field(default="")
    penalty: float = Field(default=-0.1)


class TeamStatus(BaseModel):
    team_name: str = Field(default="")
    total_score: float = Field(default=0.0)
    solved_challenges: List[str] = Field(default_factory=list)
    current_zone: ChallengeZone = Field(default=ChallengeZone.ZONE_1)
    remaining_attempts_today: int = Field(default=3)
    challenges: List[Challenge] = Field(default_factory=list)
