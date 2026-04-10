"""Competition Platform API Client

Implements the 2nd Tencent Cloud Hackathon Intelligent Penetration API.

API endpoints
=============
GET  /api/challenges          – list challenges (current + previous levels)
POST /api/start_challenge     – start a challenge instance
POST /api/stop_challenge      – stop a challenge instance
POST /api/submit              – submit a flag
POST /api/hint                – view a challenge hint (-10 % penalty)

Authentication: ``Agent-Token: <token>`` header on every request.
Rate limit: 3 requests per second per team (shared across all endpoints).
"""

import time
from typing import List, Optional

import httpx

from competition.models import (
    Challenge,
    ChallengeResult,
    ChallengeStatus,
    HintInfo,
    TeamStatus,
    instance_status_to_challenge_status,
    level_to_zone,
)
from utils.logger import get_logger

logger = get_logger(__name__)

# Minimum interval between consecutive API calls to stay within the 3 req/s
# limit with a small safety margin.
_MIN_REQUEST_INTERVAL = 0.35  # seconds


class PlatformClient:
    """HTTP client for the official competition platform API."""

    def __init__(self, api_base: str, team_token: str):
        self.api_base = api_base.rstrip("/")
        self.team_token = team_token
        self.client = httpx.Client(
            base_url=self.api_base,
            headers={
                "Agent-Token": team_token,
                "Content-Type": "application/json",
            },
            timeout=30.0,
        )
        self._last_request_ts: float = 0.0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _rate_limit_wait(self) -> None:
        """Enforce a minimum interval between requests to respect the 3/s cap."""
        now = time.monotonic()
        elapsed = now - self._last_request_ts
        if elapsed < _MIN_REQUEST_INTERVAL:
            time.sleep(_MIN_REQUEST_INTERVAL - elapsed)
        self._last_request_ts = time.monotonic()

    def _request(self, method: str, endpoint: str, **kwargs) -> dict:
        """Send a request and return the parsed JSON body.

        Automatically retries once on HTTP 429 (rate-limit) with a 1-second
        back-off.
        """
        self._rate_limit_wait()
        try:
            r = self.client.request(method, endpoint, **kwargs)
            if r.status_code == 429:
                logger.warning("Rate limited – backing off 1 s …")
                time.sleep(1.0)
                self._last_request_ts = time.monotonic()
                r = self.client.request(method, endpoint, **kwargs)
            r.raise_for_status()
            return r.json()
        except httpx.HTTPStatusError as e:
            body = ""
            try:
                body = e.response.text
            except Exception:
                pass
            logger.error(
                f"API error [{e.response.status_code}]: {endpoint} – {body}"
            )
            raise
        except httpx.RequestError as e:
            logger.error(f"Connection error: {endpoint} – {e}")
            raise

    # ------------------------------------------------------------------
    # Helper to parse a single challenge dict from the API
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_challenge(item: dict) -> Challenge:
        """Convert a raw challenge dict from ``GET /api/challenges`` into a
        :class:`Challenge` model instance."""
        code = item.get("code", "")
        level = item.get("level", 1)
        flag_count = item.get("flag_count", 1)
        flag_got_count = item.get("flag_got_count", 0)
        instance_status = item.get("instance_status", "stopped")
        entrypoint = item.get("entrypoint") or []

        # Derive target_host / target_port from the first entrypoint entry.
        target_host = ""
        target_port: Optional[int] = None
        if entrypoint:
            ep = entrypoint[0]
            if ":" in ep:
                parts = ep.rsplit(":", 1)
                target_host = parts[0]
                try:
                    target_port = int(parts[1])
                except ValueError:
                    target_host = ep
            else:
                target_host = ep

        status = instance_status_to_challenge_status(
            instance_status, flag_count, flag_got_count
        )

        return Challenge(
            id=code,
            name=item.get("title", ""),
            zone=level_to_zone(level),
            description=item.get("description", ""),
            base_score=item.get("total_score", 100),
            target_host=target_host,
            target_port=target_port,
            status=status,
            hint_viewed=item.get("hint_viewed", False),
            flags_count=flag_count,
            flags_got_count=flag_got_count,
            difficulty=item.get("difficulty", "easy"),
            level=level,
            total_score=item.get("total_score", 100),
            total_got_score=item.get("total_got_score", 0),
            entrypoint=entrypoint if entrypoint else None,
        )

    # ------------------------------------------------------------------
    # Public API methods
    # ------------------------------------------------------------------

    def get_challenges(self) -> List[Challenge]:
        """``GET /api/challenges`` – Fetch challenges visible at the current level."""
        try:
            resp = self._request("GET", "/api/challenges")
            data = resp.get("data") or {}
            raw_challenges = data.get("challenges", [])
            challenges = [self._parse_challenge(c) for c in raw_challenges]
            current_level = data.get("current_level", 1)
            solved = data.get("solved_challenges", 0)
            total = data.get("total_challenges", 0)
            logger.info(
                f"Challenges: {total} total, {solved} solved, "
                f"current level {current_level}"
            )
            return challenges
        except Exception as e:
            logger.error(f"Get challenges failed: {e}")
            return []

    def start_challenge(self, challenge_id: str) -> Optional[Challenge]:
        """``POST /api/start_challenge`` – Start the instance for *challenge_id*.

        Returns a minimal :class:`Challenge` with ``target_host`` / ``target_port``
        populated from the entrypoint list, or ``None`` on failure.
        """
        try:
            resp = self._request(
                "POST", "/api/start_challenge", json={"code": challenge_id}
            )
            data = resp.get("data")

            # Already completed
            if isinstance(data, dict) and data.get("already_completed"):
                logger.info(
                    f"Challenge {challenge_id} already fully completed."
                )
                return Challenge(
                    id=challenge_id, status=ChallengeStatus.SOLVED
                )

            # data is an entrypoint list (e.g. ["192.168.1.100:8080"])
            entrypoint: List[str] = data if isinstance(data, list) else []
            target_host = ""
            target_port: Optional[int] = None
            if entrypoint:
                ep = entrypoint[0]
                if ":" in ep:
                    parts = ep.rsplit(":", 1)
                    target_host = parts[0]
                    try:
                        target_port = int(parts[1])
                    except ValueError:
                        target_host = ep
                else:
                    target_host = ep

            logger.info(
                f"Started {challenge_id}: {target_host}:{target_port}"
            )
            return Challenge(
                id=challenge_id,
                target_host=target_host,
                target_port=target_port,
                status=ChallengeStatus.RUNNING,
                entrypoint=entrypoint if entrypoint else None,
            )
        except Exception as e:
            logger.error(f"Start failed: {challenge_id} – {e}")
            return None

    def stop_challenge(self, challenge_id: str) -> bool:
        """``POST /api/stop_challenge`` – Stop a running instance."""
        try:
            self._request(
                "POST", "/api/stop_challenge", json={"code": challenge_id}
            )
            logger.info(f"Stopped {challenge_id}")
            return True
        except Exception:
            return False

    def submit_flag(
        self, challenge_id: str, flag: str
    ) -> ChallengeResult:
        """``POST /api/submit`` – Submit a flag answer for *challenge_id*."""
        try:
            resp = self._request(
                "POST",
                "/api/submit",
                json={"code": challenge_id, "flag": flag},
            )
            data = resp.get("data") or {}
            correct = data.get("correct", False)
            message = data.get("message", "")
            flag_count = data.get("flag_count", 0)
            flag_got_count = data.get("flag_got_count", 0)
            score = flag_got_count  # Best approximation; real score in challenges list.
            return ChallengeResult(
                challenge_id=challenge_id,
                success=correct,
                score=score,
                message=message,
                flag_count=flag_count,
                flag_got_count=flag_got_count,
            )
        except Exception as e:
            return ChallengeResult(
                challenge_id=challenge_id, success=False, message=str(e)
            )

    def get_hint(self, challenge_id: str) -> Optional[HintInfo]:
        """``POST /api/hint`` – View the hint for a challenge (-10 % penalty)."""
        logger.warning(f"Requesting hint (−10 %%): {challenge_id}")
        try:
            resp = self._request(
                "POST", "/api/hint", json={"code": challenge_id}
            )
            data = resp.get("data") or {}
            return HintInfo(
                challenge_id=challenge_id,
                hint_text=data.get("hint_content", ""),
            )
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Convenience helpers (kept for backward-compat with agent.core.run)
    # ------------------------------------------------------------------

    def get_team_status(self) -> Optional[TeamStatus]:
        """Derive team status from the challenges endpoint."""
        try:
            resp = self._request("GET", "/api/challenges")
            data = resp.get("data") or {}
            challenges = [
                self._parse_challenge(c)
                for c in data.get("challenges", [])
            ]
            solved_ids = [c.id for c in challenges if c.is_solved]
            return TeamStatus(
                total_score=sum(c.total_got_score for c in challenges),
                solved_challenges=solved_ids,
                current_level=data.get("current_level", 1),
                total_challenges=data.get("total_challenges", 0),
                challenges=challenges,
            )
        except Exception:
            return None

    def get_score(self) -> float:
        s = self.get_team_status()
        return s.total_score if s else 0.0

    def close(self) -> None:
        self.client.close()
