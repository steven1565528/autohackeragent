"""Agent Core - ReAct Main Loop"""

import json
import ipaddress
import re
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from typing import Any, Dict, List, Optional, Tuple

from agent.llm import LLMClient
from agent.memory import MemoryManager
from agent.planner import TaskPlanner
from agent.prompts import HINT_RECEIVED_PROMPT, STEP_PROMPT, STUCK_PROMPT, SYSTEM_PROMPT, ZONE_STRATEGIES
from competition.api_client import PlatformClient
from competition.models import Challenge, ChallengeResult, ChallengeStatus
from tools import get_all_tools, TOOL_REGISTRY
from tools.base import BaseTool, ToolResult
from utils.flag_parser import FlagParser
from utils.logger import AgentLogger
from utils.capabilities import detect_tool_capabilities, summarize_tool_capabilities
from utils.attack_milestones import infer_attack_milestones
from utils.vuln_hypotheses import infer_vulnerability_hypotheses, summarize_hypotheses

logger = AgentLogger("agent.core")

HTTP_LIKE_PORTS = {80, 81, 88, 443, 591, 8000, 8080, 8081, 8443, 8888, 9000, 9090, 23333}
INVALID_RESPONSE_PROMPT = """Your previous reply did not contain a valid tool action.

Reply with exactly one JSON object using this schema:
{
  "thought": "brief reasoning",
  "action": "one valid tool name or finish",
  "action_input": {"param": "value"}
}

Rules:
- `action` must not be empty
- use only one tool call
- if the last direction is stalled, choose a different tool or strategy
"""

HYPOTHESIS_OVERRIDE_LIMIT = 3


def _extract_balanced_json_object(text: str) -> Optional[str]:
    """Extract the first balanced JSON object while respecting quoted strings."""
    start = text.find("{")
    if start == -1:
        return None

    depth = 0
    in_string = False
    escape = False

    for idx in range(start, len(text)):
        ch = text[idx]
        if escape:
            escape = False
            continue
        if ch == "\\" and in_string:
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:idx + 1]
    return None


def _extract_balanced_fragment(text: str, start: int, opener: str = "{", closer: str = "}") -> Optional[str]:
    """Extract a balanced fragment starting at the provided index."""
    if start < 0 or start >= len(text) or text[start] != opener:
        return None

    depth = 0
    in_string = False
    escape = False

    for idx in range(start, len(text)):
        ch = text[idx]
        if escape:
            escape = False
            continue
        if ch == "\\" and in_string:
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return text[start:idx + 1]
    return None


def _unescape_json_string(value: str) -> str:
    return bytes(value, "utf-8").decode("unicode_escape")


def _salvage_action_response(text: str) -> Optional[Dict[str, Any]]:
    """Best-effort extraction for responses that are JSON-like but malformed."""
    action_match = re.search(r'"action"\s*:\s*"([^"]+)"', text)
    if not action_match:
        return None

    action = action_match.group(1).strip()
    thought_match = re.search(r'"thought"\s*:\s*"((?:\\.|[^"\\])*)"', text, re.DOTALL)
    thought = _unescape_json_string(thought_match.group(1)) if thought_match else text[:500]

    action_input = {}
    ai_match = re.search(r'"action_input"\s*:\s*\{', text)
    if ai_match:
        brace_index = text.find("{", ai_match.start())
        fragment = _extract_balanced_fragment(text, brace_index)
        if fragment:
            try:
                parsed = json.loads(fragment)
                if isinstance(parsed, dict):
                    action_input = parsed
            except json.JSONDecodeError:
                pass

    if not action_input and action == "codegen":
        language_match = re.search(r'"language"\s*:\s*"([^"]+)"', text)
        desc_match = re.search(r'"description"\s*:\s*"((?:\\.|[^"\\])*)"', text, re.DOTALL)
        timeout_match = re.search(r'"timeout"\s*:\s*(\d+)', text)
        save_as_match = re.search(r'"save_as"\s*:\s*"((?:\\.|[^"\\])*)"', text, re.DOTALL)

        code_start = re.search(r'"code"\s*:\s*"', text, re.DOTALL)
        code_value = ""
        if code_start:
            start = code_start.end()
            i = start
            escaped = False
            while i < len(text):
                ch = text[i]
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"' and re.match(r'\s*(,|\})', text[i + 1:]):
                    code_value = text[start:i]
                    break
                i += 1
            if not code_value:
                tail = text[start:]
                end_markers = [tail.find('\n    }'), tail.find('\n  }'), tail.find('\n}')]
                end_markers = [m for m in end_markers if m != -1]
                if end_markers:
                    code_value = tail[:min(end_markers)].rstrip()
                else:
                    code_value = tail.rstrip()

        if language_match and code_value:
            action_input = {
                "language": language_match.group(1),
                "code": _unescape_json_string(code_value),
            }
            if desc_match:
                action_input["description"] = _unescape_json_string(desc_match.group(1))
            if timeout_match:
                action_input["timeout"] = int(timeout_match.group(1))
            if save_as_match:
                action_input["save_as"] = _unescape_json_string(save_as_match.group(1))

    if action_input or action == "finish":
        return {"thought": thought, "action": action, "action_input": action_input, "_salvaged": True}
    return None


class PentestAgent:
    def __init__(self, llm_client: LLMClient, platform_client: PlatformClient, planner: TaskPlanner, config: dict):
        self.llm = llm_client
        self.platform = platform_client
        self.planner = planner
        self.config = config
        ac = config.get("agent", {})
        self.max_steps = ac.get("max_steps_per_challenge", 50)
        self.max_output_length = ac.get("max_output_length", 8000)
        self.auto_hint = ac.get("auto_request_hint", False)
        self.hint_threshold = ac.get("hint_request_threshold", 30)
        self.target_intel_path = Path(
            ac.get("target_intelligence_path", "./state/target_intelligence.json")
        )
        self.tools: Dict[str, BaseTool] = {}
        for tool in get_all_tools(config):
            self.tools[tool.name] = tool
        self.memory = MemoryManager()
        self.capabilities = detect_tool_capabilities(config)
        self.total_flags_submitted = 0
        self.total_flags_correct = 0
        self.target_intelligence: Dict[str, Dict[str, Any]] = {}
        self._load_target_intelligence_store()

    def _load_target_intelligence_store(self) -> None:
        if not self.target_intel_path.exists():
            return
        try:
            data = json.loads(self.target_intel_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                self.target_intelligence = data
                logger.info(
                    f"Loaded target intelligence store: {self.target_intel_path} "
                    f"({len(self.target_intelligence)} targets)"
                )
        except Exception as exc:
            logger.warning(f"Failed to load target intelligence store: {exc}")

    def _persist_target_intelligence_store(self) -> None:
        try:
            self.target_intel_path.parent.mkdir(parents=True, exist_ok=True)
            self.target_intel_path.write_text(
                json.dumps(self.target_intelligence, ensure_ascii=False, indent=2, sort_keys=True),
                encoding="utf-8",
            )
        except Exception as exc:
            logger.warning(f"Failed to persist target intelligence store: {exc}")

    def _snapshot_progress(self) -> Tuple[int, int, int, int, int]:
        return (
            len(self.memory.findings),
            len(self.memory.found_flags),
            len(self.memory.credentials),
            sum(len(ports) for ports in self.memory.open_ports.values()),
            sum(len(services) for services in self.memory.services.values()) + len(self.memory.attack_milestones),
        )

    def _update_attack_milestones(self, texts: List[str]) -> None:
        milestones = infer_attack_milestones(texts)
        for milestone in milestones:
            if self.memory.add_attack_milestone(milestone.key):
                self.memory.add_finding(
                    "milestone",
                    milestone.key,
                    f"{milestone.family}@{milestone.stage} | {'; '.join(milestone.evidence)}",
                    source="attack_milestones",
                )
                logger.info(f"Attack milestone reached: {milestone.key}")

    def _update_vulnerability_hypotheses(self, challenge: Challenge, texts: List[str]) -> None:
        finding_values = [finding.value for finding in self.memory.findings]
        hypotheses = infer_vulnerability_hypotheses(
            observations=texts,
            services=self.memory.services,
            findings=finding_values,
        )
        new_hypotheses = []
        for hypothesis in hypotheses:
            if any(
                finding.category == "hypothesis" and finding.key == hypothesis.key
                for finding in self.memory.findings
            ):
                continue
            self.memory.add_finding(
                "hypothesis",
                hypothesis.key,
                f"{hypothesis.title} | confidence={hypothesis.confidence:.2f} | next={hypothesis.next_step}",
                source="vuln_hypotheses",
            )
            new_hypotheses.append(hypothesis)

        if new_hypotheses:
            summary = summarize_hypotheses(new_hypotheses, limit=2)
            if summary:
                self.memory.add_user_message(summary)
                logger.info(summary)

    def _get_hypothesis_keys(self) -> List[str]:
        return [
            finding.key
            for finding in self.memory.findings
            if finding.category == "hypothesis"
        ]

    def _action_signature(self, action: str, action_input: Dict[str, Any]) -> str:
        return f"{action}({json.dumps(action_input, ensure_ascii=False)[:100]})"

    def _metasploit_available(self) -> bool:
        exploit_capability = self.capabilities.get("exploit", {})
        commands = exploit_capability.get("commands", []) if isinstance(exploit_capability, dict) else []
        return "msfconsole" in commands

    def _choose_framework_action(self, challenge: Challenge) -> Optional[Tuple[str, Dict[str, Any], str]]:
        if not self._metasploit_available():
            return None

        target_url = self._build_target_url(challenge)
        keys = self._get_hypothesis_keys()
        framework_routes: List[Tuple[str, Dict[str, Any], str]] = []

        if "hypothesis:shiro-cve_2016_4437" in keys:
            framework_routes.extend([
                (
                    {"action": "metasploit", "mode": "search", "query": "apache shiro rememberme"},
                    "High-confidence known-CVE signal detected; search Metasploit modules before manual exploit assembly.",
                ),
                (
                    {
                        "action": "metasploit",
                        "mode": "info",
                        "module": "exploit/multi/http/apache_shiro_rememberme_v124_deserialize",
                    },
                    "Inspect the matching Metasploit module and datastore before custom payload work.",
                ),
                (
                    {
                        "action": "metasploit",
                        "mode": "check",
                        "module": "exploit/multi/http/apache_shiro_rememberme_v124_deserialize",
                        "options": {"RHOSTS": challenge.target_host, "RPORT": challenge.target_port or 80, "TARGETURI": "/"},
                        "timeout": 180,
                    },
                    "Run the framework check path before hand-built Shiro probes.",
                ),
            ])

        generic_queries = [
            ("hypothesis:struts2-rce", "struts2", "Struts2 RCE signals detected; search Metasploit modules first."),
            ("hypothesis:spring4shell", "spring4shell", "Spring RCE signals detected; search Metasploit modules first."),
            ("hypothesis:log4shell", "log4shell", "Log4Shell signals detected; search Metasploit modules first."),
            ("hypothesis:fastjson", "fastjson", "Fastjson deserialization signals detected; search Metasploit modules first."),
            ("hypothesis:ssrf-cloud-metadata", "metadata", "SSRF/internal pivot signals detected; inspect Metasploit auxiliary modules first."),
            ("hypothesis:graphql-exposure", "graphql", "GraphQL exposure detected; search Metasploit auxiliary modules before ad-hoc scripts."),
        ]
        for key, query, reason in generic_queries:
            if key in keys:
                framework_routes.append(({"action": "metasploit", "mode": "search", "query": query}, reason))

        if "hypothesis:weak-default-auth" in keys:
            framework_routes.append(
                (
                    {
                        "action": "metasploit",
                        "mode": "search",
                        "query": f"http login {challenge.target_host}",
                    },
                    "Authentication surface detected; search reusable Metasploit modules before custom login brute-force scripts.",
                )
            )

        for action_input, reason in framework_routes:
            action_signature = self._action_signature("exploit", action_input)
            if self.memory.has_tried(action_signature):
                continue
            action_risk = self._assess_action_risk("exploit", action_input)
            pattern_stage_key = (
                f"{action_risk['family']}@{action_risk['stage']}"
                if action_risk["family"] and action_risk["skip_eligible"] == "true"
                else ""
            )
            if pattern_stage_key and self.memory.is_low_priority_pattern(pattern_stage_key):
                continue
            return "exploit", action_input, reason
        return None

    def _choose_hypothesis_action(self, challenge: Challenge) -> Optional[Tuple[str, Dict[str, Any], str]]:
        target = challenge.target_host
        target_url = self._build_target_url(challenge)
        keys = self._get_hypothesis_keys()

        framework_action = self._choose_framework_action(challenge)
        if framework_action:
            return framework_action

        routing_table: List[Tuple[str, str, Dict[str, Any], str]] = [
            (
                "hypothesis:shiro-cve_2016_4437",
                "aboutsecurity",
                {"action": "show_skill", "name": "known-cve-quick-exploit"},
                "High-confidence Shiro CVE hypothesis detected; prioritize the known-CVE playbook before generic probing.",
            ),
            (
                "hypothesis:java-deserialization",
                "aboutsecurity",
                {"action": "show_skill", "name": "java-deserialization-methodology"},
                "Java deserialization signals detected; route to the deserialization methodology.",
            ),
            (
                "hypothesis:ssti",
                "aboutsecurity",
                {"action": "search_skills", "query": "ssti", "category": "exploit"},
                "Template injection signals detected; prioritize SSTI methodology lookup.",
            ),
            (
                "hypothesis:file-upload",
                "aboutsecurity",
                {"action": "search_skills", "query": "file upload", "category": "exploit"},
                "File upload surface detected; prioritize upload methodology before unrelated exploit families.",
            ),
            (
                "hypothesis:xxe",
                "aboutsecurity",
                {"action": "search_skills", "query": "xxe", "category": "exploit"},
                "XML parsing surface detected; prioritize XXE methodology.",
            ),
            (
                "hypothesis:ssrf-cloud-metadata",
                "aboutsecurity",
                {"action": "show_skill", "name": "ssrf-methodology"},
                "SSRF/cloud-metadata signals detected; prioritize SSRF methodology.",
            ),
            (
                "hypothesis:sql-injection",
                "aboutsecurity",
                {"action": "show_skill", "name": "sql-injection-methodology"},
                "SQL injection signals detected; route to the SQLi methodology.",
            ),
            (
                "hypothesis:idor",
                "aboutsecurity",
                {"action": "show_skill", "name": "idor-methodology"},
                "Object-level authorization signals detected; route to IDOR methodology.",
            ),
            (
                "hypothesis:jwt",
                "aboutsecurity",
                {"action": "show_skill", "name": "jwt-attack-methodology"},
                "JWT trust-boundary signals detected; route to JWT methodology.",
            ),
            (
                "hypothesis:oauth-sso",
                "aboutsecurity",
                {"action": "show_skill", "name": "oauth-sso-attack"},
                "OAuth/SSO flow detected; route to OAuth methodology.",
            ),
            (
                "hypothesis:graphql-exposure",
                "aboutsecurity",
                {"action": "search_resources", "module": "skills", "query": "graphql"},
                "GraphQL exposure detected; inspect GraphQL-specific methodology or references.",
            ),
            (
                "hypothesis:weak-default-auth",
                "curl",
                {"url": f"{target_url}/login.jsp"},
                "Weak/default credential hypothesis detected; prioritize authenticated path mapping.",
            ),
            (
                "hypothesis:file-inclusion",
                "skill",
                {"name": "web_vuln_quick", "url": target_url},
                "File-read style signals detected; prioritize quick web vuln validation on the active target.",
            ),
        ]

        for key, action, action_input, reason in routing_table:
            if key not in keys:
                continue
            action_signature = self._action_signature(action, action_input)
            if self.memory.has_tried(action_signature):
                continue
            action_risk = self._assess_action_risk(action, action_input)
            pattern_stage_key = (
                f"{action_risk['family']}@{action_risk['stage']}"
                if action_risk["family"] and action_risk["skip_eligible"] == "true"
                else ""
            )
            if pattern_stage_key and self.memory.is_low_priority_pattern(pattern_stage_key):
                continue
            return action, action_input, reason
        return None

    def _should_override_with_hypothesis(
        self,
        model_action: str,
        model_action_input: Dict[str, Any],
        hypothesis_action: Optional[Tuple[str, Dict[str, Any], str]],
    ) -> bool:
        if not hypothesis_action:
            return False
        routed_action, routed_input, _ = hypothesis_action
        if model_action == routed_action and model_action_input == routed_input:
            return False
        hypothesis_messages = sum(
            1
            for message in self.memory.conversation_history[-12:]
            if "Hypothesis-driven next step:" in message.get("content", "")
        )
        return hypothesis_messages < HYPOTHESIS_OVERRIDE_LIMIT

    def _classify_exploitation_pattern(self, action: str, action_input: Dict[str, Any]) -> str:
        if self._is_auth_establishment_action(action, action_input):
            return ""
        if self._is_session_validation_action(action, action_input):
            return ""
        payload = json.dumps(action_input or {}, ensure_ascii=False).lower()
        keyword_groups = {
            "exploit:shiro_deserialization": ["shiro", "rememberme", "ysoserial", "commonscollections", "deserialization"],
            "exploit:sql_injection": ["sql", "sqli", "union select", "extractvalue", "sqlmap"],
            "exploit:ssrf": ["ssrf", "metadata", "169.254.169.254"],
            "exploit:xss": ["xss", "<script", "onerror=", "svg onload"],
            "exploit:file_inclusion": ["lfi", "rfi", "/etc/passwd", "php://filter", "../"],
            "exploit:jwt_attack": ["jwt", "jwks", "alg=none", "kid"],
        }
        for pattern, keywords in keyword_groups.items():
            if any(keyword in payload for keyword in keywords):
                return pattern

        if action == "skill":
            skill_name = (action_input or {}).get("name", "")
            if skill_name in {"web_vuln_quick", "deep_port_scan", "full_recon", "web_recon"}:
                return ""
        return ""

    def _classify_attack_stage(self, action: str, action_input: Dict[str, Any]) -> str:
        if self._is_auth_establishment_action(action, action_input):
            return "auth"
        if self._is_session_validation_action(action, action_input):
            return "validation"
        if self._is_shiro_exploit_execution_action(action, action_input):
            return "exploit"
        payload = json.dumps(action_input or {}, ensure_ascii=False).lower()
        if action == "aboutsecurity":
            return "methodology"
        if action == "skill":
            skill_name = (action_input or {}).get("name", "")
            if skill_name in {"full_recon", "web_recon", "deep_port_scan"}:
                return "recon"
            if skill_name in {"web_vuln_quick", "db_enum", "smb_enum"}:
                return "validation"
            return "methodology"
        if action == "curl":
            if '"method": "post"' in payload or "rememberme" in payload or "login.jsp" in payload:
                return "auth"
            return "validation"
        if action in {"codegen", "exploit"}:
            return "exploit"
        if action == "shell":
            if any(keyword in payload for keyword in ["ysoserial", "commonscollections", "payload"]):
                return "exploit"
            return "validation"
        return "validation"

    def _target_key(self, challenge: Challenge) -> str:
        if challenge.target_port:
            return f"{challenge.target_host}:{challenge.target_port}"
        return challenge.target_host

    def _load_target_intelligence(self, challenge: Challenge) -> Optional[Dict[str, Any]]:
        key = self._target_key(challenge)
        intel = self.target_intelligence.get(key)
        if not intel:
            return None
        self.memory.import_target_intelligence(intel)
        return intel

    def _save_target_intelligence(self, challenge: Challenge) -> None:
        key = self._target_key(challenge)
        self.target_intelligence[key] = self.memory.export_target_intelligence()
        self._persist_target_intelligence_store()

    def clear_target_intelligence(self, challenge: Challenge) -> bool:
        key = self._target_key(challenge)
        removed = self.target_intelligence.pop(key, None) is not None
        if removed:
            self._persist_target_intelligence_store()
        return removed

    def _normalize_action_input(self, challenge: Challenge, action: str, action_input: Dict[str, Any]) -> Dict[str, Any]:
        """Keep model-supplied targets aligned with the active challenge target."""
        normalized = dict(action_input or {})
        challenge_host = challenge.target_host
        challenge_port = challenge.target_port

        if normalized.get("target") and normalized["target"] != challenge_host:
            logger.warning(f"Correcting target from {normalized['target']} to {challenge_host}")
            normalized["target"] = challenge_host

        for key in ("url", "target"):
            value = normalized.get(key)
            if not isinstance(value, str) or not value.startswith(("http://", "https://")):
                continue
            try:
                parts = urlsplit(value)
            except Exception:
                continue
            original_netloc = parts.netloc
            original_port = parts.port
            if parts.hostname != challenge_host or (challenge_port and original_port and original_port != challenge_port):
                netloc = challenge_host
                if challenge_port:
                    netloc = f"{challenge_host}:{challenge_port}"
                elif original_port:
                    netloc = f"{challenge_host}:{original_port}"
                normalized[key] = urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
                logger.warning(f"Corrected {key} host from {original_netloc} to {netloc}")

        if action == "skill":
            skill_name = normalized.get("name")
            if skill_name == "full_recon":
                normalized["target"] = challenge_host
                if challenge_port:
                    normalized.setdefault("port", challenge_port)
            elif skill_name in {"web_recon", "web_vuln_quick"} and challenge_port:
                normalized.setdefault("url", self._build_target_url(challenge))

        return normalized

    def _build_tools_description(self) -> str:
        parts = []
        for name, tool in self.tools.items():
            pi = json.dumps(tool.parameters.get("properties", {}), indent=2, ensure_ascii=False)
            req = tool.parameters.get("required", [])
            capability = self.capabilities.get(name, {"available": True, "commands": [], "missing": []})
            if capability["available"]:
                if capability["commands"]:
                    availability = f"Availability: installed via {', '.join(capability['commands'])}"
                else:
                    availability = "Availability: built-in / always usable"
            else:
                availability = f"Availability: unavailable; missing {', '.join(capability['missing'])}"
            parts.append(
                f"### {name}\n{tool.description}\n{availability}\nParams:\n```json\n{pi}\n```\nRequired: {req}"
            )
        return "\n\n".join(parts)

    def _build_system_prompt(self, challenge: Challenge) -> str:
        runtime_environment = (
            "Installed tool inventory:\n"
            + summarize_tool_capabilities(self.capabilities)
            + "\nChoose installed tools first and fall back gracefully when a dependency is unavailable."
        )
        callback_host = self.config.get("agent", {}).get("callback_host", "")
        if challenge.target_port:
            runtime_environment += (
                f"\nKnown target scope: host {challenge.target_host} on port {challenge.target_port}."
                " Probe the provided port directly before broad scans."
            )
        if self._is_public_target(challenge):
            runtime_environment += (
                "\nTarget classification: public/cloud-reachable."
                " Do not infer LHOST from local private interfaces like 10.x/172.16-31.x/192.168.x."
                " Prefer in-band validation, bind-shell, or server-side verification over reverse payloads unless a public callback host is explicitly configured."
            )
            if callback_host:
                runtime_environment += f"\nConfigured callback host: {callback_host}"
        system = SYSTEM_PROMPT.format(
            tools_description=self._build_tools_description(),
            runtime_environment=runtime_environment,
        )
        zs = ZONE_STRATEGIES.get(challenge.zone.value, "")
        if zs:
            system += "\n" + zs
        return system

    def _parse_llm_response(self, response: str) -> Dict[str, Any]:
        m = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", response, re.DOTALL)
        js = m.group(1).strip() if m else response.strip()
        candidate = _extract_balanced_json_object(js)
        candidates = [c for c in [candidate, js] if c]
        for payload in candidates:
            try:
                parsed = json.loads(payload)
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                continue
        salvaged = _salvage_action_response(js)
        if salvaged:
            return salvaged
        return {"thought": response, "action": "", "action_input": {}, "_parse_error": True}

    def _build_target_url(self, challenge: Challenge) -> str:
        return challenge.target_url.rstrip("/")

    def _has_tried_action(self, needle: str) -> bool:
        return any(needle in action for action in self.memory.tried_actions)

    def _is_public_target(self, challenge: Challenge) -> bool:
        host = (challenge.target_host or "").strip()
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return True
        return not (ip.is_private or ip.is_loopback or ip.is_link_local)

    def _uses_local_interface_probe(self, action: str, action_input: Dict[str, Any]) -> bool:
        if action != "shell":
            return False
        command = str((action_input or {}).get("command", "")).lower()
        interface_markers = ["ifconfig", "ip addr", "ip a", "networksetup -listallhardwareports"]
        private_ip_markers = ["192.168.", "172.", "10.", "inet "]
        return any(marker in command for marker in interface_markers) and any(marker in command for marker in private_ip_markers)

    def _uses_reverse_callback_without_public_host(self, challenge: Challenge, action: str, action_input: Dict[str, Any]) -> bool:
        if not self._is_public_target(challenge):
            return False
        callback_host = str(self.config.get("agent", {}).get("callback_host", "")).strip()
        payload = json.dumps(action_input or {}, ensure_ascii=False).lower()
        reverse_markers = ["reverse_tcp", "reverse_bash", "reverse_http", "lhost", "callback"]
        if not any(marker in payload for marker in reverse_markers):
            return False
        if callback_host:
            return False
        return True

    def _guard_target_specific_action(self, challenge: Challenge, action: str, action_input: Dict[str, Any]) -> Optional[str]:
        if self._is_public_target(challenge) and self._uses_local_interface_probe(action, action_input):
            return (
                "Blocked cloud-target callback inference: the target is public/cloud-reachable, "
                "so do not inspect local private interfaces to guess LHOST. Prefer in-band verification "
                "or configure a public callback host explicitly."
            )
        if self._uses_reverse_callback_without_public_host(challenge, action, action_input):
            return (
                "Blocked reverse-payload planning on a public/cloud target without a configured public callback host. "
                "Use framework check/in-band validation first, or set agent.callback_host before reverse payloads."
            )
        return None

    def _is_auth_establishment_action(self, action: str, action_input: Dict[str, Any]) -> bool:
        if action != "curl":
            return False
        payload = json.dumps(action_input or {}, ensure_ascii=False).lower()
        url = str((action_input or {}).get("url", "")).lower()
        has_credentials = any(token in payload for token in ["username=", "password=", "\"username\"", "\"password\""])
        login_surface = any(token in url for token in ["/login", "login.jsp"]) or any(
            token in payload for token in ["/login", "login.jsp", "submit=login"]
        )
        session_establishment = '"method": "post"' in payload and (has_credentials or login_surface)
        return session_establishment

    def _is_session_validation_action(self, action: str, action_input: Dict[str, Any]) -> bool:
        if action != "curl":
            return False
        payload = json.dumps(action_input or {}, ensure_ascii=False).lower()
        if self._is_auth_establishment_action(action, action_input):
            return False
        has_session_cookie = any(token in payload for token in ["jsessionid", "rememberme"])
        has_payload_markers = any(token in payload for token in ["aced0005", "ro0ab", "commonscollections", "ysoserial"])
        return has_session_cookie and not has_payload_markers

    def _is_metasploit_discovery_action(self, action: str, action_input: Dict[str, Any]) -> bool:
        if action != "exploit":
            return False
        if (action_input or {}).get("action") != "metasploit":
            return False
        return (action_input or {}).get("mode") in {"search", "info", "show_options", "show_payloads", "show_targets", "commands"}

    def _is_metasploit_check_action(self, action: str, action_input: Dict[str, Any]) -> bool:
        return (
            action == "exploit"
            and (action_input or {}).get("action") == "metasploit"
            and (action_input or {}).get("mode") == "check"
        )

    def _is_shiro_exploit_execution_action(self, action: str, action_input: Dict[str, Any]) -> bool:
        if self._is_metasploit_discovery_action(action, action_input):
            return False
        if self._is_metasploit_check_action(action, action_input):
            return False
        payload = json.dumps(action_input or {}, ensure_ascii=False).lower()
        if action in {"codegen", "exploit"}:
            return any(token in payload for token in ["ysoserial", "commonscollections", "rememberme", "aced0005", "ro0ab", "gadget"])
        if action == "shell":
            return any(token in payload for token in ["ysoserial", "commonscollections", "rememberme", "aced0005", "ro0ab", "gadget", "java -jar"])
        if action == "curl":
            has_session_cookie = "rememberme" in payload
            has_payload_markers = any(token in payload for token in ["aced0005", "ro0ab", "commonscollections", "ysoserial"])
            return has_session_cookie and has_payload_markers
        return False

    def _assess_action_risk(self, action: str, action_input: Dict[str, Any]) -> Dict[str, str]:
        if self._is_auth_establishment_action(action, action_input):
            return {"family": "", "stage": "auth", "mode": "auth-establishment", "skip_eligible": "false"}
        if self._is_session_validation_action(action, action_input):
            return {"family": "", "stage": "validation", "mode": "session-validation", "skip_eligible": "false"}
        if self._is_metasploit_discovery_action(action, action_input):
            return {"family": "", "stage": "framework-discovery", "mode": "framework-discovery", "skip_eligible": "false"}
        if self._is_metasploit_check_action(action, action_input):
            return {
                "family": self._classify_exploitation_pattern(action, action_input),
                "stage": "validation",
                "mode": "framework-check",
                "skip_eligible": "true" if bool(self._classify_exploitation_pattern(action, action_input)) else "false",
            }
        if self._is_shiro_exploit_execution_action(action, action_input):
            return {
                "family": "exploit:shiro_deserialization",
                "stage": "exploit",
                "mode": "payload-execution",
                "skip_eligible": "true",
            }

        exploit_pattern = self._classify_exploitation_pattern(action, action_input)
        attack_stage = self._classify_attack_stage(action, action_input)
        return {
            "family": exploit_pattern,
            "stage": attack_stage,
            "mode": attack_stage or "validation",
            "skip_eligible": "true" if bool(exploit_pattern) else "false",
        }

    def _choose_recovery_action(self, challenge: Challenge, no_progress: int) -> Optional[Tuple[str, Dict[str, Any], str]]:
        target = challenge.target_host
        target_url = self._build_target_url(challenge)
        target_port = challenge.target_port
        is_http_like = bool(target_port and target_port in HTTP_LIKE_PORTS)

        hypothesis_action = self._choose_hypothesis_action(challenge)
        if hypothesis_action:
            return hypothesis_action

        if is_http_like and not self._has_tried_action("skill({\"name\": \"web_recon\""):
            return "skill", {"name": "web_recon", "url": target_url}, "Switching to structured web reconnaissance."

        if is_http_like and no_progress >= 3 and not self._has_tried_action("skill({\"name\": \"web_vuln_quick\""):
            return "skill", {"name": "web_vuln_quick", "url": target_url}, "Web recon stalled, switching to quick vulnerability checks."

        if not self.memory.open_ports.get(target) and not self._has_tried_action("skill({\"name\": \"full_recon\""):
            return "skill", {"name": "full_recon", "target": target}, "No confirmed foothold yet, switching to broader reconnaissance."

        if is_http_like and not self._has_tried_action("curl({\"url\":"):
            return "curl", {"url": target_url}, "Fetching the target homepage to ground the next decision."

        if no_progress >= 4 and not self._has_tried_action("skill({\"name\": \"deep_port_scan\""):
            return "skill", {"name": "deep_port_scan", "target": target}, "Current path is stale, switching to a deeper scan."

        return None

    def _execute_action(self, action: str, action_input: dict) -> ToolResult:
        if action == "finish":
            return ToolResult(success=True, output="Agent finished", metadata=action_input)
        if action not in self.tools:
            return ToolResult(success=False, output="", error=f"Unknown tool: {action}")
        try:
            return self.tools[action].execute(**action_input)
        except Exception as e:
            return ToolResult(success=False, output="", error=f"Tool error: {str(e)}")

    def _check_flags(self, text: str, challenge: Challenge) -> List[str]:
        flags = FlagParser.extract_flags(text)
        new = [f for f in flags if f not in self.memory.found_flags]
        for f in new:
            self.memory.add_flag(f)
            logger.flag_found(f, challenge.id)
        return new

    def _submit_flags(self, flags: List[str], challenge: Challenge) -> List[ChallengeResult]:
        results = []
        for flag in flags:
            if flag in challenge.submitted_flags:
                continue
            try:
                r = self.platform.submit_flag(challenge.id, flag)
                results.append(r)
                challenge.submitted_flags.append(flag)
                self.total_flags_submitted += 1
                if r.success:
                    self.total_flags_correct += 1
                    logger.flag_submitted(flag, True)
                else:
                    logger.flag_submitted(flag, False)
            except Exception as e:
                logger.error(f"Submit failed: {e}")
        return results

    def solve_challenge(self, challenge: Challenge) -> bool:
        logger.challenge_start(challenge.id, challenge.name)
        self.memory.reset()
        self.memory.set_challenge(challenge.id, challenge.target_host)
        self.memory.add_system_message(self._build_system_prompt(challenge))
        ti = challenge.target_host
        if challenge.target_port:
            ti = f"{challenge.target_host}:{challenge.target_port}"
        self.memory.add_user_message(
            f"Target: {ti}\nDescription: {challenge.description or '(Black box)'}\n"
            f"Flags: {challenge.flags_count}\nFormat: flag{{}}\n\n"
            + (
                f"Known scope already includes port {challenge.target_port}. "
                f"Probe this port directly first and prefer installed tools over unavailable broad scanners."
                if challenge.target_port
                else "Start with port scan."
            )
        )
        prior_intel = self._load_target_intelligence(challenge)
        if prior_intel:
            self.memory.add_user_message(
                "Known target intelligence already exists for this host. Reuse it before probing again.\n"
                + self.memory.get_findings_summary()
            )
            logger.info(
                f"Loaded cached intelligence for target {self._target_key(challenge)} "
                f"({len(prior_intel.get('tried_actions', []))} prior actions)"
            )
        no_progress = 0
        last_fc = 0
        solved = False

        step = 1
        invalid_streak = 0
        max_invalid_streak = 8

        while step <= self.max_steps:
            self.memory.step_count = step
            logger.step_start(step, f"(max {self.max_steps})")
            try:
                response = self.llm.chat(messages=self.memory.get_messages())
                self.memory.add_assistant_message(response)
                d = self._parse_llm_response(response)
                thought, action, ai = d.get("thought", ""), d.get("action", ""), d.get("action_input", {})
                logger.thinking(thought)

                if action == "finish":
                    invalid_streak = 0
                    for f in ai.get("flags_found", []):
                        self.memory.add_flag(f)
                    break

                # Do not burn a challenge step on malformed/empty actions.
                if not action or (action not in self.tools and action != "finish"):
                    invalid_streak += 1
                    recovery = self._choose_recovery_action(challenge, no_progress)
                    if recovery and invalid_streak >= 2:
                        action, ai, reason = recovery
                        logger.warning(f"Invalid/empty action from model. {reason}")
                        self.memory.add_user_message(
                            INVALID_RESPONSE_PROMPT
                            + f"\nRecovery hint: prefer `{action}` with {json.dumps(ai, ensure_ascii=False)}"
                        )
                    else:
                        self.memory.add_user_message(INVALID_RESPONSE_PROMPT)
                        if invalid_streak >= max_invalid_streak:
                            logger.error("Too many invalid model responses; aborting challenge.")
                            break
                        continue

                invalid_streak = 0
                if action == "finish":
                    for f in ai.get("flags_found", []):
                        self.memory.add_flag(f)
                    break
                ai = self._normalize_action_input(challenge, action, ai)
                hypothesis_action = self._choose_hypothesis_action(challenge)
                if self._should_override_with_hypothesis(action, ai, hypothesis_action):
                    routed_action, routed_input, routed_reason = hypothesis_action
                    logger.warning(
                        f"Overriding model action with hypothesis-driven route: {routed_reason}"
                    )
                    self.memory.add_user_message(
                        "High-confidence vulnerability hypothesis detected.\n"
                        f"Override next action to `{routed_action}` with {json.dumps(routed_input, ensure_ascii=False)}.\n"
                        f"Reason: {routed_reason}"
                    )
                    action, ai = routed_action, routed_input
                guard_msg = self._guard_target_specific_action(challenge, action, ai)
                if guard_msg:
                    logger.warning(guard_msg)
                    self.memory.record_action(self._action_signature(action, ai))
                    result = ToolResult(success=False, output="", error=guard_msg, metadata={"guarded_action": True})
                    output = str(result)
                    self.memory.add_user_message(guard_msg)
                    logger.observation(output)
                    self.memory.add_user_message(STEP_PROMPT.format(tool_name=action, tool_output=output[:self.max_output_length]))
                    step += 1
                    continue
                action_risk = self._assess_action_risk(action, ai)
                exploit_pattern = action_risk["family"]
                attack_stage = action_risk["stage"]
                skip_eligible = action_risk["skip_eligible"] == "true"
                pattern_stage_key = f"{exploit_pattern}@{attack_stage}" if exploit_pattern else ""
                if skip_eligible and pattern_stage_key and self.memory.is_low_priority_pattern(pattern_stage_key):
                    skip_msg = (
                        f"Skipped low-priority exploit stage: {pattern_stage_key}. "
                        "This stage failed repeatedly on the same target; choose a different stage or vector."
                    )
                    logger.warning(skip_msg)
                    self.memory.record_action(self._action_signature(action, ai))
                    result = ToolResult(success=False, output="", error=skip_msg, metadata={"skipped_pattern": pattern_stage_key})
                    output = str(result)
                    self.memory.add_user_message(skip_msg)
                    logger.observation(output)
                    self.memory.add_user_message(STEP_PROMPT.format(tool_name=action, tool_output=output[:self.max_output_length]))
                    step += 1
                    continue

                progress_before = self._snapshot_progress()
                logger.action(action, json.dumps(ai, ensure_ascii=False)[:200])
                self.memory.record_action(f"{action}({json.dumps(ai, ensure_ascii=False)[:100]})")
                result = self._execute_action(action, ai)
                output = result.truncated_output
                if not result.success and result.error:
                    err_summary = f"Tool error: {result.error}"
                    if result.output:
                        err_summary += f"\n{result.output[:1000]}"
                    self.memory.add_user_message(err_summary)
                logger.observation(output)

                # Auto-ingest structured data from skill results into memory
                if action == "skill" and result.metadata:
                    meta = result.metadata
                    for p in meta.get("open_ports", []):
                        self.memory.add_port(challenge.target_host, p.get("port", 0))
                    for s in meta.get("services", []):
                        self.memory.add_service(
                            challenge.target_host, s.get("port", 0),
                            f"{s.get('service', '')} {s.get('version', '')}".strip()
                        )
                    for v in meta.get("vulnerabilities", []):
                        self.memory.add_finding("vulnerability", "vuln", v, source=meta.get("skill_name", ""))
                    for c in meta.get("credentials", []):
                        self.memory.add_credential(c.get("user", ""), c.get("pass", ""), c.get("service", ""))
                    # Flags from skill metadata
                    for f in meta.get("flags_found", []):
                        self.memory.add_flag(f)
                        logger.flag_found(f, challenge.id)
                self._save_target_intelligence(challenge)
                for text in [output, response]:
                    nf = self._check_flags(text, challenge)
                    if nf:
                        sr = self._submit_flags(nf, challenge)
                        for r in sr:
                            if r.success:
                                solved = True
                                if not challenge.is_multi_flag:
                                    logger.challenge_complete(challenge.id, True, step)
                                    return True
                self._update_attack_milestones([output, response])
                self._update_vulnerability_hypotheses(challenge, [output, response])
                hypothesis_recovery = self._choose_hypothesis_action(challenge)
                if hypothesis_recovery:
                    hra, hrai, hreason = hypothesis_recovery
                    self.memory.add_user_message(
                        f"Hypothesis-driven next step: {hreason}\n"
                        f"Prefer `{hra}` with {json.dumps(hrai, ensure_ascii=False)}"
                    )
                progress_after = self._snapshot_progress()
                gained_intel = progress_after > progress_before
                if skip_eligible and pattern_stage_key:
                    if gained_intel:
                        self.memory.mark_pattern_success(pattern_stage_key)
                    else:
                        downgraded = self.memory.mark_pattern_failure(pattern_stage_key)
                        if downgraded:
                            logger.warning(
                                f"Exploit stage downgraded to low priority: {pattern_stage_key} "
                                f"after {self.memory.failed_patterns.get(pattern_stage_key, 0)} consecutive failures"
                            )
                            self.memory.add_user_message(
                                f"Avoid repeating exploit stage `{pattern_stage_key}` on this target. "
                                "It failed repeatedly without producing new findings; move to a different stage or adjacent hypothesis."
                            )
                self.memory.add_user_message(STEP_PROMPT.format(tool_name=action, tool_output=output[:self.max_output_length]))
                fc = len(self.memory.findings) + len(self.memory.found_flags)
                if fc == last_fc:
                    no_progress += 1
                else:
                    no_progress = 0
                    last_fc = fc
                if no_progress >= 5:
                    self.memory.add_user_message(STUCK_PROMPT.format(steps=step, max_steps=self.max_steps))
                    recovery = self._choose_recovery_action(challenge, no_progress)
                    if recovery:
                        ra, rai, reason = recovery
                        self.memory.add_user_message(
                            f"Direction change suggested: {reason}\n"
                            f"Prefer next action `{ra}` with {json.dumps(rai, ensure_ascii=False)}"
                        )
                    no_progress = 0
                if self.auto_hint and step >= self.hint_threshold and not challenge.hint_viewed and no_progress >= 3:
                    hint = self.platform.get_hint(challenge.id)
                    if hint:
                        challenge.hint_viewed = True
                        self.memory.add_user_message(HINT_RECEIVED_PROMPT.format(hint_text=hint.hint_text))
                step += 1
            except Exception as e:
                logger.error(f"Step {step} error: {str(e)}")
                self.memory.add_user_message(f"Error: {str(e)}\nTry different approach.")
                step += 1
        logger.challenge_complete(challenge.id, solved, self.max_steps)
        self._save_target_intelligence(challenge)
        return solved

    def run(self) -> None:
        logger.info("=" * 60)
        logger.info("Auto-Hacker Agent Starting")
        logger.info("=" * 60)
        try:
            challenges = self.platform.get_challenges()
            if not challenges:
                logger.warning("No challenges found")
                return
            logger.info(f"Found {len(challenges)} challenges")
            while True:
                c = self.planner.select_next_challenge(challenges)
                if not c:
                    logger.info("All challenges processed")
                    break

                # Skip challenges already fully solved
                if c.is_solved:
                    self.planner.mark_solved(c.id)
                    logger.info(f"Challenge {c.id} already solved – skipping")
                    challenges = self.platform.get_challenges()
                    continue

                started = self.platform.start_challenge(c.id)
                if started:
                    if started.status == ChallengeStatus.SOLVED:
                        # The API told us it's already completed
                        self.planner.mark_solved(c.id)
                        logger.info(f"Challenge {c.id} already completed")
                        challenges = self.platform.get_challenges()
                        continue
                    c.target_host = started.target_host
                    c.target_port = started.target_port
                    c.status = ChallengeStatus.RUNNING
                    if started.entrypoint:
                        c.entrypoint = started.entrypoint
                else:
                    logger.warning(f"Could not start {c.id} – skipping")
                    self.planner.mark_failed(c.id)
                    challenges = self.platform.get_challenges()
                    continue

                ok = self.solve_challenge(c)
                if ok:
                    self.planner.mark_solved(c.id)
                    c.status = ChallengeStatus.SOLVED
                else:
                    self.planner.mark_failed(c.id)
                self.platform.stop_challenge(c.id)
                logger.separator()
                challenges = self.platform.get_challenges()
        except KeyboardInterrupt:
            logger.info("Interrupted")
        except Exception as e:
            logger.error(f"Runtime error: {str(e)}")
        finally:
            self._print_summary()

    def _print_summary(self) -> None:
        logger.info("=" * 60)
        logger.info("Summary")
        logger.info(f"  Submitted: {self.total_flags_submitted}  Correct: {self.total_flags_correct}")
        logger.info(f"  Solved: {len(self.planner.solved_challenges)}  Failed: {dict(self.planner.failed_challenges)}")
        usage = self.llm.get_usage_stats()
        for m, s in usage.items():
            logger.info(f"  [{m}] calls={s['calls']} tokens={s['total_tokens']}")
        logger.info("=" * 60)
