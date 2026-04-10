"""Tests for the competition platform API client (Tencent Cloud Hackathon API)."""

import json
from unittest.mock import MagicMock, patch

import pytest

from competition.api_client import PlatformClient
from competition.models import (
    Challenge,
    ChallengeResult,
    ChallengeStatus,
    ChallengeZone,
    HintInfo,
    level_to_zone,
    instance_status_to_challenge_status,
)


# ---------------------------------------------------------------------------
# Model helpers
# ---------------------------------------------------------------------------


class TestLevelToZone:
    def test_known_levels(self):
        assert level_to_zone(1) == ChallengeZone.ZONE_1
        assert level_to_zone(2) == ChallengeZone.ZONE_2
        assert level_to_zone(3) == ChallengeZone.ZONE_3
        assert level_to_zone(4) == ChallengeZone.ZONE_4

    def test_unknown_level_defaults_to_zone1(self):
        assert level_to_zone(99) == ChallengeZone.ZONE_1


class TestInstanceStatusMapping:
    def test_running(self):
        assert instance_status_to_challenge_status("running") == ChallengeStatus.RUNNING

    def test_stopped(self):
        assert instance_status_to_challenge_status("stopped") == ChallengeStatus.AVAILABLE

    def test_solved_overrides(self):
        assert instance_status_to_challenge_status("running", flag_count=1, flag_got_count=1) == ChallengeStatus.SOLVED


class TestChallengeLevelZoneSync:
    def test_zone_derives_level(self):
        c = Challenge(id="x", zone=ChallengeZone.ZONE_3)
        assert c.level == 3

    def test_explicit_level_preserved(self):
        c = Challenge(id="x", zone=ChallengeZone.ZONE_1, level=4)
        assert c.level == 4

    def test_is_solved(self):
        c = Challenge(id="x", flags_count=2, flags_got_count=2)
        assert c.is_solved is True

    def test_not_solved(self):
        c = Challenge(id="x", flags_count=2, flags_got_count=1)
        assert c.is_solved is False


# ---------------------------------------------------------------------------
# PlatformClient._parse_challenge
# ---------------------------------------------------------------------------


class TestParseChallenge:
    def test_basic_parse(self):
        raw = {
            "title": "Employee Admin",
            "code": "BwAMWQASB1ROWFA",
            "difficulty": "easy",
            "description": "一个后台登录页面",
            "level": 1,
            "total_score": 100,
            "total_got_score": 0,
            "flag_count": 1,
            "flag_got_count": 0,
            "hint_viewed": False,
            "instance_status": "stopped",
            "entrypoint": None,
        }
        c = PlatformClient._parse_challenge(raw)
        assert c.id == "BwAMWQASB1ROWFA"
        assert c.name == "Employee Admin"
        assert c.level == 1
        assert c.zone == ChallengeZone.ZONE_1
        assert c.status == ChallengeStatus.AVAILABLE
        assert c.target_host == ""
        assert c.target_port is None
        assert c.flags_count == 1

    def test_running_with_entrypoint(self):
        raw = {
            "title": "Portal",
            "code": "abc123",
            "difficulty": "medium",
            "description": "...",
            "level": 2,
            "total_score": 200,
            "total_got_score": 100,
            "flag_count": 2,
            "flag_got_count": 1,
            "hint_viewed": True,
            "instance_status": "running",
            "entrypoint": ["192.168.1.100:8080"],
        }
        c = PlatformClient._parse_challenge(raw)
        assert c.id == "abc123"
        assert c.target_host == "192.168.1.100"
        assert c.target_port == 8080
        assert c.status == ChallengeStatus.RUNNING
        assert c.hint_viewed is True

    def test_solved_challenge(self):
        raw = {
            "title": "Done",
            "code": "done1",
            "difficulty": "easy",
            "description": "",
            "level": 1,
            "total_score": 100,
            "total_got_score": 100,
            "flag_count": 1,
            "flag_got_count": 1,
            "hint_viewed": False,
            "instance_status": "stopped",
            "entrypoint": None,
        }
        c = PlatformClient._parse_challenge(raw)
        assert c.status == ChallengeStatus.SOLVED
        assert c.is_solved is True


# ---------------------------------------------------------------------------
# ChallengeResult new fields
# ---------------------------------------------------------------------------


class TestChallengeResult:
    def test_flag_count_fields(self):
        r = ChallengeResult(
            challenge_id="x", success=True, message="ok",
            flag_count=2, flag_got_count=1,
        )
        assert r.flag_count == 2
        assert r.flag_got_count == 1
