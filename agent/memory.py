"""Context memory management for the agent"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set
from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class Finding:
    category: str
    key: str
    value: str
    source: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def __str__(self) -> str:
        return f"[{self.category}] {self.key}: {self.value}"


class MemoryManager:
    def __init__(self, max_history: int = 30, max_tokens_estimate: int = 100000, pattern_failure_threshold: int = 3):
        self.conversation_history: List[Dict[str, str]] = []
        self.max_history = max_history
        self.max_tokens_estimate = max_tokens_estimate
        self.pattern_failure_threshold = pattern_failure_threshold
        self.findings: List[Finding] = []
        self.found_flags: Set[str] = set()
        self.tried_actions: List[str] = []
        self.credentials: List[Dict[str, str]] = []
        self.open_ports: Dict[str, List[int]] = {}
        self.services: Dict[str, Dict[int, str]] = {}
        self.failed_patterns: Dict[str, int] = {}
        self.low_priority_patterns: Set[str] = set()
        self.last_failed_pattern: str = ""
        self.last_failed_pattern_streak: int = 0
        self.attack_milestones: Set[str] = set()
        self.challenge_id: str = ""
        self.target: str = ""
        self.step_count: int = 0

    def set_challenge(self, challenge_id: str, target: str) -> None:
        self.challenge_id = challenge_id
        self.target = target

    def add_system_message(self, content: str) -> None:
        self.conversation_history.append({"role": "system", "content": content})

    def add_user_message(self, content: str) -> None:
        self.conversation_history.append({"role": "user", "content": content})

    def add_assistant_message(self, content: str) -> None:
        self.conversation_history.append({"role": "assistant", "content": content})

    def get_messages(self) -> List[Dict[str, str]]:
        self._compress_if_needed()
        return self.conversation_history.copy()

    def _compress_if_needed(self) -> None:
        total_chars = sum(len(m["content"]) for m in self.conversation_history)
        estimated_tokens = total_chars * 0.5
        if estimated_tokens > self.max_tokens_estimate or len(self.conversation_history) > self.max_history:
            self._compress()

    def _compress(self) -> None:
        if len(self.conversation_history) <= 4:
            return
        logger.info(f"Compressing history: {len(self.conversation_history)} messages")
        system_msgs = [m for m in self.conversation_history if m["role"] == "system"]
        recent_msgs = self.conversation_history[-20:]
        removed = len(self.conversation_history) - len(system_msgs) - len(recent_msgs)
        if removed > 0:
            summary = self._generate_context_summary()
            self.conversation_history = system_msgs + [
                {"role": "user", "content": f"[History Summary]\n{summary}"}
            ] + recent_msgs
            logger.info(f"Compressed to: {len(self.conversation_history)} messages")

    def _generate_context_summary(self) -> str:
        parts = [f"Target: {self.target}", f"Steps executed: {self.step_count}"]
        if self.open_ports:
            for host, ports in self.open_ports.items():
                parts.append(f"Open ports ({host}): {', '.join(map(str, ports))}")
        if self.services:
            for host, svc in self.services.items():
                for port, service in svc.items():
                    parts.append(f"Service: {host}:{port} -> {service}")
        if self.credentials:
            for cred in self.credentials:
                parts.append(f"Credential: {cred.get('username', '?')}:{cred.get('password', '?')} @ {cred.get('service', '?')}")
        vuln_findings = [f for f in self.findings if f.category == "vulnerability"]
        for f in vuln_findings[-5:]:
            parts.append(f"Vulnerability: {f.key} - {f.value}")
        if self.found_flags:
            parts.append(f"Flags found: {', '.join(self.found_flags)}")
        if self.low_priority_patterns:
            parts.append(f"Low-priority exploit patterns: {', '.join(sorted(self.low_priority_patterns))}")
        if self.attack_milestones:
            parts.append(f"Attack milestones: {', '.join(sorted(self.attack_milestones))}")
        recent = self.tried_actions[-10:]
        if recent:
            parts.append(f"Recent actions: {'; '.join(recent)}")
        return "\n".join(parts)

    def add_finding(self, category: str, key: str, value: str, source: str = "") -> None:
        self.findings.append(Finding(category=category, key=key, value=value, source=source))

    def add_flag(self, flag: str) -> None:
        self.found_flags.add(flag)
        logger.info(f"Flag recorded: {flag}")

    def add_credential(self, username: str, password: str, service: str = "") -> None:
        cred = {"username": username, "password": password, "service": service}
        if cred not in self.credentials:
            self.credentials.append(cred)
            logger.info(f"Credential recorded: {username}:{password} ({service})")

    def add_port(self, host: str, port: int) -> None:
        if host not in self.open_ports:
            self.open_ports[host] = []
        if port not in self.open_ports[host]:
            self.open_ports[host].append(port)

    def add_service(self, host: str, port: int, service: str) -> None:
        if host not in self.services:
            self.services[host] = {}
        self.services[host][port] = service

    def record_action(self, action: str) -> None:
        self.tried_actions.append(action)

    def has_tried(self, action: str) -> bool:
        return action in self.tried_actions

    def get_findings_summary(self) -> str:
        return self._generate_context_summary()

    def get_found_flags(self) -> List[str]:
        return list(self.found_flags)

    def add_attack_milestone(self, milestone_key: str) -> bool:
        if not milestone_key or milestone_key in self.attack_milestones:
            return False
        self.attack_milestones.add(milestone_key)
        return True

    def mark_pattern_failure(self, pattern: str) -> bool:
        if not pattern:
            return False
        if self.last_failed_pattern == pattern:
            self.last_failed_pattern_streak += 1
        else:
            self.last_failed_pattern = pattern
            self.last_failed_pattern_streak = 1
        self.failed_patterns[pattern] = self.last_failed_pattern_streak
        if self.last_failed_pattern_streak >= self.pattern_failure_threshold:
            self.low_priority_patterns.add(pattern)
            return True
        return False

    def mark_pattern_success(self, pattern: str) -> None:
        if not pattern:
            return
        if self.last_failed_pattern == pattern:
            self.last_failed_pattern = ""
            self.last_failed_pattern_streak = 0
        self.failed_patterns.pop(pattern, None)

    def is_low_priority_pattern(self, pattern: str) -> bool:
        return pattern in self.low_priority_patterns

    def export_target_intelligence(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "findings": [
                {
                    "category": finding.category,
                    "key": finding.key,
                    "value": finding.value,
                    "source": finding.source,
                }
                for finding in self.findings
            ],
            "found_flags": list(self.found_flags),
            "tried_actions": list(self.tried_actions),
            "credentials": list(self.credentials),
            "open_ports": {host: list(ports) for host, ports in self.open_ports.items()},
            "services": {host: dict(services) for host, services in self.services.items()},
            "failed_patterns": dict(self.failed_patterns),
            "low_priority_patterns": list(self.low_priority_patterns),
            "attack_milestones": list(self.attack_milestones),
        }

    def import_target_intelligence(self, data: Dict[str, Any]) -> None:
        for finding in data.get("findings", []):
            if not any(
                existing.category == finding.get("category", "")
                and existing.key == finding.get("key", "")
                and existing.value == finding.get("value", "")
                for existing in self.findings
            ):
                self.add_finding(
                    finding.get("category", ""),
                    finding.get("key", ""),
                    finding.get("value", ""),
                    source=finding.get("source", ""),
                )

        for flag in data.get("found_flags", []):
            self.found_flags.add(flag)

        for action in data.get("tried_actions", []):
            if action not in self.tried_actions:
                self.tried_actions.append(action)

        for credential in data.get("credentials", []):
            self.add_credential(
                credential.get("username", ""),
                credential.get("password", ""),
                credential.get("service", ""),
            )

        for host, ports in data.get("open_ports", {}).items():
            for port in ports:
                self.add_port(host, port)

        for host, services in data.get("services", {}).items():
            for port, service in services.items():
                try:
                    normalized_port = int(port)
                except (TypeError, ValueError):
                    normalized_port = port
                self.add_service(host, normalized_port, service)

        for pattern, count in data.get("failed_patterns", {}).items():
            try:
                normalized_count = int(count)
            except (TypeError, ValueError):
                normalized_count = 1
            self.failed_patterns[pattern] = max(self.failed_patterns.get(pattern, 0), normalized_count)

        for pattern in data.get("low_priority_patterns", []):
            self.low_priority_patterns.add(pattern)

        for milestone_key in data.get("attack_milestones", []):
            self.attack_milestones.add(milestone_key)

    def reset(self) -> None:
        self.conversation_history.clear()
        self.findings.clear()
        self.tried_actions.clear()
        self.credentials.clear()
        self.open_ports.clear()
        self.services.clear()
        self.found_flags.clear()
        self.failed_patterns.clear()
        self.low_priority_patterns.clear()
        self.attack_milestones.clear()
        self.last_failed_pattern = ""
        self.last_failed_pattern_streak = 0
        self.last_failed_pattern = ""
        self.last_failed_pattern_streak = 0
        self.step_count = 0
        self.challenge_id = ""
        self.target = ""
        logger.info("Memory reset")
