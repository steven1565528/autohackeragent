"""Agent integration tests"""

import json
import pytest
from agent.memory import MemoryManager
from agent.planner import TaskPlanner
from competition.models import Challenge, ChallengeZone, ChallengeStatus


class TestMemoryManager:
    def test_basic_operations(self):
        memory = MemoryManager()
        memory.set_challenge("test_001", "192.168.1.1")
        assert memory.challenge_id == "test_001"
        assert memory.target == "192.168.1.1"

    def test_ports_and_services(self):
        memory = MemoryManager()
        memory.add_port("192.168.1.1", 80)
        memory.add_port("192.168.1.1", 443)
        memory.add_service("192.168.1.1", 80, "http Apache/2.4.49")
        assert 80 in memory.open_ports["192.168.1.1"]
        assert 443 in memory.open_ports["192.168.1.1"]
        assert memory.services["192.168.1.1"][80] == "http Apache/2.4.49"

    def test_credentials(self):
        memory = MemoryManager()
        memory.add_credential("admin", "pass123", "ssh")
        memory.add_credential("admin", "pass123", "ssh")
        assert len(memory.credentials) == 1

    def test_flags(self):
        memory = MemoryManager()
        memory.add_flag("flag{test_123}")
        memory.add_flag("flag{test_456}")
        memory.add_flag("flag{test_123}")
        assert len(memory.found_flags) == 2

    def test_conversation(self):
        memory = MemoryManager()
        memory.add_system_message("You are an agent")
        memory.add_user_message("Start")
        memory.add_assistant_message("OK")
        messages = memory.get_messages()
        assert len(messages) == 3
        assert messages[0]["role"] == "system"

    def test_reset(self):
        memory = MemoryManager()
        memory.add_flag("flag{test}")
        memory.add_port("192.168.1.1", 80)
        memory.reset()
        assert len(memory.found_flags) == 0
        assert len(memory.open_ports) == 0


class TestTaskPlanner:
    def _make(self, id, zone, score=100):
        return Challenge(id=id, name=f"C-{id}", zone=zone, base_score=score, status=ChallengeStatus.AVAILABLE)

    def test_zone_priority(self):
        planner = TaskPlanner()
        challenges = [self._make("z2", ChallengeZone.ZONE_2, 200), self._make("z1", ChallengeZone.ZONE_1, 100)]
        assert planner.select_next_challenge(challenges).id == "z1"

    def test_skip_solved(self):
        planner = TaskPlanner()
        planner.mark_solved("z1")
        challenges = [self._make("z1", ChallengeZone.ZONE_1), self._make("z2", ChallengeZone.ZONE_1)]
        assert planner.select_next_challenge(challenges).id == "z2"

    def test_skip_after_failures(self):
        planner = TaskPlanner()
        for _ in range(3):
            planner.mark_failed("z1")
        assert planner.should_skip_challenge("z1")

    def test_no_available(self):
        planner = TaskPlanner()
        planner.mark_solved("z1")
        assert planner.select_next_challenge([self._make("z1", ChallengeZone.ZONE_1)]) is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
