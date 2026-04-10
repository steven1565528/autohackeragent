import argparse
import os
from pathlib import Path

import yaml
from dotenv import load_dotenv

from agent.llm import LLMClient
from agent.core import PentestAgent
from agent.planner import TaskPlanner
from competition.api_client import PlatformClient
from competition.models import Challenge, ChallengeResult
from utils.capabilities import detect_tool_capabilities
from utils.flag_parser import FlagParser
from utils.logger import get_logger, setup_logging

logger = get_logger("main")


class DebugPlatformClient:
    """Minimal platform stub for single-target debug runs."""

    def submit_flag(self, challenge_id: str, flag: str) -> ChallengeResult:
        if not FlagParser.validate_flag(flag):
            return ChallengeResult(
                challenge_id=challenge_id,
                success=False,
                message="Debug mode: rejected placeholder or invalid flag",
            )
        return ChallengeResult(
            challenge_id=challenge_id,
            success=True,
            message="Debug mode: flag accepted locally",
        )

    def get_hint(self, challenge_id: str):
        return None

    def close(self) -> None:
        return None


def load_config(config_path: str = "config.yaml") -> dict:
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def run_self_check(config: dict) -> int:
    print("== Auto-Hacker Self Check ==")
    print(f"Config file: {Path('config.yaml').resolve()}")
    print(f"Active model: {config.get('llm', {}).get('active_model', '')}")

    env_checks = [
        "DEEPSEEK_API_KEY",
        "ZHIPU_API_KEY",
        "OPENAI_API_KEY",
        "DASHSCOPE_API_KEY",
        "VOLCENGINE_API_KEY",
        "QIANFAN_API_KEY",
    ]
    print("\nEnvironment:")
    for key in env_checks:
        print(f"- {key}: {'set' if os.getenv(key) else 'missing'}")

    print("\nRuntime tools:")
    capabilities = detect_tool_capabilities(config)
    missing_any = False
    for tool_name in sorted(capabilities):
        if tool_name.startswith("_"):
            continue
        meta = capabilities[tool_name]
        if meta["available"]:
            commands = ", ".join(meta["commands"]) if meta["commands"] else "built-in"
            print(f"- {tool_name}: OK ({commands})")
        else:
            missing_any = True
            print(f"- {tool_name}: MISSING ({', '.join(meta['missing'])})")
    artifacts = capabilities.get("_artifacts", {})
    if artifacts:
        print("\nNormalized artifacts:")
        for name in sorted(artifacts):
            meta = artifacts[name]
            print(f"- {name}: {meta['path'] if meta['available'] else 'missing'}")

    venv_python = Path(".venv/bin/python")
    print("\nWorkspace:")
    print(f"- venv python: {'present' if venv_python.exists() else 'missing'}")
    print(f"- logs dir: {'present' if Path('logs').exists() else 'missing'}")
    print(f"- .env file: {'present' if Path('.env').exists() else 'missing'}")
    print(f"- AboutSecurity: {'present' if Path('resources/AboutSecurity/manifest.yaml').exists() else 'missing'}")

    return 1 if missing_any else 0


def main():
    parser = argparse.ArgumentParser(description="Auto-Hacker Pentest Agent")
    parser.add_argument("--target", type=str, help="Target IP or URL (required in --debug mode)")
    parser.add_argument("--port", type=int, help="Target Port")
    parser.add_argument("--model", type=str, help="LLM model to use")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--list-models", action="store_true", help="List available models and exit")
    parser.add_argument("--self-check", action="store_true", help="Check env, tools, and config readiness")
    
    args = parser.parse_args()
    
    # Load environment variables (API keys)
    load_dotenv()
    config = load_config("config.yaml")
    setup_logging(
        log_dir=config.get("logging", {}).get("log_dir", "./logs"),
        level=config.get("logging", {}).get("level", "INFO"),
    )

    if args.model:
        config.setdefault("llm", {})["active_model"] = args.model

    llm_client = LLMClient(config.get("llm", {}))

    if args.list_models:
        for model_name in llm_client.list_models():
            print(model_name)
        return

    if args.self_check:
        raise SystemExit(run_self_check(config))
    
    logger.info(f"Starting Auto-Hacker Agent")
    logger.info(f"Model: {config.get('llm', {}).get('active_model', '')}")

    planner = TaskPlanner(config.get("agent", {}))

    if args.debug:
        if not args.target:
            parser.error("--target is required when using --debug")

        logger.info(f"Target: {args.target}")
        challenge = Challenge(
            id="debug-chal-1",
            name="Debug Challenge",
            description=f"Find the flag on target {args.target}",
            target_host=args.target,
            target_port=args.port,
            base_score=100,
        )
        agent = PentestAgent(
            llm_client=llm_client,
            platform_client=DebugPlatformClient(),
            planner=planner,
            config=config,
        )
        success = agent.solve_challenge(challenge)
        if success:
            logger.info("Challenge completed successfully!")
            print("\nFLAG FOUND")
            for flag in agent.memory.found_flags:
                print(f"-> {flag}")
        else:
            logger.warning("Failed to find the flag within step limit.")
        return

    # Resolve platform settings: env vars take precedence over config.yaml.
    platform_cfg = config.get("platform", {})
    server_host = os.getenv("SERVER_HOST") or platform_cfg.get("server_host", "") or platform_cfg.get("api_base", "")
    agent_token = os.getenv("AGENT_TOKEN") or os.getenv("PLATFORM_TEAM_TOKEN") or platform_cfg.get("agent_token", "") or platform_cfg.get("team_token", "")
    # Ensure the base URL has a scheme
    if server_host and not server_host.startswith(("http://", "https://")):
        server_host = f"http://{server_host}"
    if not server_host or not agent_token:
        logger.error("Platform config missing: set SERVER_HOST and AGENT_TOKEN env vars or config.yaml platform section")
        return
    logger.info(f"Platform: {server_host}")
    platform = PlatformClient(
        api_base=server_host,
        team_token=agent_token,
    )
    try:
        agent = PentestAgent(
            llm_client=llm_client,
            platform_client=platform,
            planner=planner,
            config=config,
        )
        agent.run()
    finally:
        platform.close()

if __name__ == "__main__":
    main()
