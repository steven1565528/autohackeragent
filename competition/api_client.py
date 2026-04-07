"""Competition Platform API Client - placeholder for official API"""

from typing import List, Optional
import httpx
from competition.models import Challenge, ChallengeResult, ChallengeStatus, ChallengeZone, HintInfo, TeamStatus
from utils.logger import get_logger

logger = get_logger(__name__)


class PlatformClient:
    def __init__(self, api_base: str, team_token: str):
        self.api_base = api_base.rstrip("/")
        self.team_token = team_token
        self.client = httpx.Client(
            base_url=self.api_base,
            headers={"Authorization": f"Bearer {team_token}", "Content-Type": "application/json"},
            timeout=30.0,
        )

    def _request(self, method: str, endpoint: str, **kwargs) -> dict:
        try:
            r = self.client.request(method, endpoint, **kwargs)
            r.raise_for_status()
            return r.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"API error [{e.response.status_code}]: {endpoint}")
            raise
        except httpx.RequestError as e:
            logger.error(f"Connection error: {endpoint} - {e}")
            raise

    def get_challenges(self) -> List[Challenge]:
        try:
            data = self._request("GET", "/api/challenges")
            return [Challenge(
                id=i.get("id", ""), name=i.get("name", ""),
                zone=ChallengeZone(i.get("zone", "zone_1")),
                description=i.get("description", ""), base_score=i.get("base_score", 100),
                target_host=i.get("target_host", ""), target_port=i.get("target_port"),
                status=ChallengeStatus(i.get("status", "available")),
                flags_count=i.get("flags_count", 1),
            ) for i in data.get("challenges", [])]
        except Exception as e:
            logger.error(f"Get challenges failed: {e}")
            return []

    def start_challenge(self, challenge_id: str) -> Optional[Challenge]:
        try:
            d = self._request("POST", f"/api/challenges/{challenge_id}/start")
            return Challenge(id=challenge_id, target_host=d.get("target_host", ""),
                           target_port=d.get("target_port"), status=ChallengeStatus.RUNNING)
        except Exception as e:
            logger.error(f"Start failed: {challenge_id} - {e}")
            return None

    def stop_challenge(self, challenge_id: str) -> bool:
        try:
            self._request("POST", f"/api/challenges/{challenge_id}/stop")
            return True
        except:
            return False

    def submit_flag(self, challenge_id: str, flag: str) -> ChallengeResult:
        try:
            d = self._request("POST", f"/api/challenges/{challenge_id}/submit", json={"flag": flag})
            return ChallengeResult(
                challenge_id=challenge_id, success=d.get("correct", False),
                score=d.get("score", 0), rank=d.get("rank", 0), message=d.get("message", ""))
        except Exception as e:
            return ChallengeResult(challenge_id=challenge_id, success=False, message=str(e))

    def get_hint(self, challenge_id: str) -> Optional[HintInfo]:
        logger.warning(f"Requesting hint (-10%): {challenge_id}")
        try:
            d = self._request("GET", f"/api/challenges/{challenge_id}/hint")
            return HintInfo(challenge_id=challenge_id, hint_text=d.get("hint", ""))
        except:
            return None

    def get_team_status(self) -> Optional[TeamStatus]:
        try:
            d = self._request("GET", "/api/team/status")
            return TeamStatus(team_name=d.get("team_name", ""), total_score=d.get("total_score", 0.0),
                            current_zone=ChallengeZone(d.get("current_zone", "zone_1")))
        except:
            return None

    def get_score(self) -> float:
        s = self.get_team_status()
        return s.total_score if s else 0.0

    def close(self) -> None:
        self.client.close()
