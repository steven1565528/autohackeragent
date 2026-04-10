"""Competition platform data models

Aligned with the 2nd Tencent Cloud Hackathon Intelligent Penetration API.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, model_validator


class ChallengeZone(str, Enum):
    """Kept for backward-compatibility with planner / prompts."""
    ZONE_1 = "zone_1"
    ZONE_2 = "zone_2"
    ZONE_3 = "zone_3"
    ZONE_4 = "zone_4"


# ---------------------------------------------------------------------------
# Mapping helpers: level (int) <-> ChallengeZone
# ---------------------------------------------------------------------------
_LEVEL_TO_ZONE = {1: ChallengeZone.ZONE_1, 2: ChallengeZone.ZONE_2,
                  3: ChallengeZone.ZONE_3, 4: ChallengeZone.ZONE_4}
_ZONE_TO_LEVEL = {v: k for k, v in _LEVEL_TO_ZONE.items()}


def level_to_zone(level: int) -> ChallengeZone:
    return _LEVEL_TO_ZONE.get(level, ChallengeZone.ZONE_1)


class ChallengeStatus(str, Enum):
    LOCKED = "locked"
    AVAILABLE = "available"
    RUNNING = "running"
    SOLVED = "solved"
    FAILED = "failed"


# ---------------------------------------------------------------------------
# Mapping helpers: API instance_status -> ChallengeStatus
# ---------------------------------------------------------------------------
_INSTANCE_STATUS_MAP = {
    "stopped": ChallengeStatus.AVAILABLE,
    "pending": ChallengeStatus.AVAILABLE,
    "running": ChallengeStatus.RUNNING,
}


def instance_status_to_challenge_status(
    instance_status: str, flag_count: int = 1, flag_got_count: int = 0
) -> ChallengeStatus:
    """Derive a :class:`ChallengeStatus` from the API ``instance_status`` field."""
    if flag_count > 0 and flag_got_count >= flag_count:
        return ChallengeStatus.SOLVED
    return _INSTANCE_STATUS_MAP.get(instance_status, ChallengeStatus.AVAILABLE)


class Challenge(BaseModel):
    """Unified challenge model.

    ``id`` stores the ``code`` value returned by the competition API
    (the unique identifier used in all subsequent API calls).
    """
    id: str = Field(description="Challenge code (unique identifier)")
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
    flags_got_count: int = Field(default=0)
    submitted_flags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    # New fields from the competition API
    difficulty: str = Field(default="easy")
    level: int = Field(default=1)
    total_score: int = Field(default=100)
    total_got_score: int = Field(default=0)
    entrypoint: Optional[List[str]] = Field(default=None)

    @model_validator(mode="after")
    def _sync_level_and_zone(self) -> "Challenge":
        """Keep ``level`` and ``zone`` in sync.

        When a Challenge is constructed with an explicit ``zone`` but the
        default ``level`` (1), derive the level from the zone so that the
        planner can sort by level consistently.
        """
        zone_level = _ZONE_TO_LEVEL.get(self.zone, 1)
        if self.level == 1 and zone_level != 1:
            self.level = zone_level
        return self

    @property
    def is_multi_flag(self) -> bool:
        return self.flags_count > 1

    @property
    def is_solved(self) -> bool:
        return self.flags_count > 0 and self.flags_got_count >= self.flags_count

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
    flag_count: int = Field(default=0)
    flag_got_count: int = Field(default=0)


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
    # New fields from the competition API
    current_level: int = Field(default=1)
    total_challenges: int = Field(default=0)
