"""Agent Core - ReAct Main Loop"""

import json
import re
from typing import Any, Dict, List, Optional

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

logger = AgentLogger("agent.core")


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
        self.tools: Dict[str, BaseTool] = {}
        for tool in get_all_tools(config):
            self.tools[tool.name] = tool
        self.memory = MemoryManager()
        self.total_flags_submitted = 0
        self.total_flags_correct = 0

    def _build_tools_description(self) -> str:
        parts = []
        for name, tool in self.tools.items():
            pi = json.dumps(tool.parameters.get("properties", {}), indent=2, ensure_ascii=False)
            req = tool.parameters.get("required", [])
            parts.append(f"### {name}\n{tool.description}\nParams:\n```json\n{pi}\n```\nRequired: {req}")
        return "\n\n".join(parts)

    def _build_system_prompt(self, challenge: Challenge) -> str:
        system = SYSTEM_PROMPT.format(tools_description=self._build_tools_description())
        zs = ZONE_STRATEGIES.get(challenge.zone.value, "")
        if zs:
            system += "\n" + zs
        return system

    def _parse_llm_response(self, response: str) -> Dict[str, Any]:
        m = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", response, re.DOTALL)
        js = m.group(1).strip() if m else response.strip()
        bm = re.search(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", js, re.DOTALL)
        if bm:
            js = bm.group()
        try:
            return json.loads(js)
        except json.JSONDecodeError:
            try:
                return json.loads(js.replace("'", '"'))
            except json.JSONDecodeError:
                return {"thought": response, "action": "shell", "action_input": {"command": "echo 'Parse error'"}}

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
            f"Flags: {challenge.flags_count}\nFormat: flag{{}}\n\nStart with port scan."
        )
        no_progress = 0
        last_fc = 0
        solved = False

        for step in range(1, self.max_steps + 1):
            self.memory.step_count = step
            logger.step_start(step, f"(max {self.max_steps})")
            try:
                response = self.llm.chat(messages=self.memory.get_messages())
                self.memory.add_assistant_message(response)
                d = self._parse_llm_response(response)
                thought, action, ai = d.get("thought", ""), d.get("action", ""), d.get("action_input", {})
                logger.thinking(thought)
                if action == "finish":
                    for f in ai.get("flags_found", []):
                        self.memory.add_flag(f)
                    break
                logger.action(action, json.dumps(ai, ensure_ascii=False)[:200])
                self.memory.record_action(f"{action}({json.dumps(ai, ensure_ascii=False)[:100]})")
                result = self._execute_action(action, ai)
                output = result.truncated_output
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
                self.memory.add_user_message(STEP_PROMPT.format(tool_name=action, tool_output=output[:self.max_output_length]))
                fc = len(self.memory.findings) + len(self.memory.found_flags)
                if fc == last_fc:
                    no_progress += 1
                else:
                    no_progress = 0
                    last_fc = fc
                if no_progress >= 5:
                    self.memory.add_user_message(STUCK_PROMPT.format(steps=step, max_steps=self.max_steps))
                    no_progress = 0
                if self.auto_hint and step >= self.hint_threshold and not challenge.hint_viewed and no_progress >= 3:
                    hint = self.platform.get_hint(challenge.id)
                    if hint:
                        challenge.hint_viewed = True
                        self.memory.add_user_message(HINT_RECEIVED_PROMPT.format(hint_text=hint.hint_text))
            except Exception as e:
                logger.error(f"Step {step} error: {str(e)}")
                self.memory.add_user_message(f"Error: {str(e)}\nTry different approach.")
        logger.challenge_complete(challenge.id, solved, self.max_steps)
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
                started = self.platform.start_challenge(c.id)
                if started:
                    c.target_host = started.target_host
                    c.target_port = started.target_port
                    c.status = ChallengeStatus.RUNNING
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
