"""Task planner for challenge scheduling"""

from typing import Dict, List, Optional
from competition.models import Challenge, ChallengeStatus, ChallengeZone
from utils.logger import get_logger

logger = get_logger(__name__)

_DIFFICULTY_ORDER = {"easy": 0, "medium": 1, "hard": 2}


class TaskPlanner:
    def __init__(self, config: dict = None):
        self.config = config or {}
        self.auto_request_hint = self.config.get("auto_request_hint", False)
        self.hint_threshold = self.config.get("hint_request_threshold", 30)
        self.solved_challenges: set = set()
        self.failed_challenges: Dict[str, int] = {}

    def select_next_challenge(self, challenges: List[Challenge]) -> Optional[Challenge]:
        available = [
            c for c in challenges
            if c.status in (ChallengeStatus.AVAILABLE, ChallengeStatus.RUNNING)
            and c.id not in self.solved_challenges
            and not c.is_solved
        ]
        if not available:
            logger.info("No available challenges")
            return None

        # Primary sort: level (ascending) then difficulty then score (descending).
        available.sort(
            key=lambda c: (
                c.level,
                _DIFFICULTY_ORDER.get(c.difficulty, 99),
                self.failed_challenges.get(c.id, 0),
                -c.base_score,
            )
        )
        selected = available[0]
        logger.info(
            f"Selected: [level {selected.level}] {selected.name} "
            f"(ID: {selected.id}, difficulty: {selected.difficulty})"
        )
        return selected

    def should_request_hint(self, challenge_id: str, current_step: int) -> bool:
        return self.auto_request_hint and current_step >= self.hint_threshold

    def should_skip_challenge(self, challenge_id: str) -> bool:
        return self.failed_challenges.get(challenge_id, 0) >= 3

    def mark_solved(self, challenge_id: str) -> None:
        self.solved_challenges.add(challenge_id)
        logger.info(f"Solved: {challenge_id}")

    def mark_failed(self, challenge_id: str) -> None:
        self.failed_challenges[challenge_id] = self.failed_challenges.get(challenge_id, 0) + 1
        logger.warning(f"Failed (attempt {self.failed_challenges[challenge_id]}): {challenge_id}")

    def get_zone_strategy(self, zone: ChallengeZone) -> str:
        from agent.prompts import ZONE_STRATEGIES
        return ZONE_STRATEGIES.get(zone.value, "")
