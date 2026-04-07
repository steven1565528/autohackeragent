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
    def __init__(self, max_history: int = 30, max_tokens_estimate: int = 100000):
        self.conversation_history: List[Dict[str, str]] = []
        self.max_history = max_history
        self.max_tokens_estimate = max_tokens_estimate
        self.findings: List[Finding] = []
        self.found_flags: Set[str] = set()
        self.tried_actions: List[str] = []
        self.credentials: List[Dict[str, str]] = []
        self.open_ports: Dict[str, List[int]] = {}
        self.services: Dict[str, Dict[int, str]] = {}
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

    def reset(self) -> None:
        self.conversation_history.clear()
        self.findings.clear()
        self.tried_actions.clear()
        self.credentials.clear()
        self.open_ports.clear()
        self.services.clear()
        self.found_flags.clear()
        self.step_count = 0
        self.challenge_id = ""
        self.target = ""
        logger.info("Memory reset")
