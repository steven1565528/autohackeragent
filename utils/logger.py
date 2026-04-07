"""Structured logging system with Rich console output"""

import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

THEME = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "tool": "bold magenta",
    "llm": "bold blue",
    "flag": "bold yellow on red",
})

console = Console(theme=THEME)


def setup_logging(log_dir: str = "./logs", level: str = "INFO") -> None:
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_path / f"agent_{timestamp}.log"

    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        "%(asctime)s | %(name)-20s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(file_formatter)

    rich_handler = RichHandler(
        console=console, show_time=True, show_path=False,
        markup=True, rich_tracebacks=True,
    )
    rich_handler.setLevel(getattr(logging, level.upper(), logging.INFO))

    root_logger.addHandler(file_handler)
    root_logger.addHandler(rich_handler)

    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("litellm").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


class AgentLogger:
    def __init__(self, name: str = "agent"):
        self.logger = get_logger(name)
        self._step_count = 0

    def step_start(self, step_num: int, description: str) -> None:
        self._step_count = step_num
        self.logger.info(f"[bold]=== Step {step_num} ===[/bold] {description}")

    def thinking(self, thought: str) -> None:
        self.logger.info(f"[llm]Thinking:[/llm] {thought[:500]}")

    def action(self, tool_name: str, params: str) -> None:
        self.logger.info(f"[tool]Action:[/tool] {tool_name}({params[:200]})")

    def observation(self, result: str, truncate: int = 500) -> None:
        display = result[:truncate] + "..." if len(result) > truncate else result
        self.logger.info(f"Observation: {display}")

    def flag_found(self, flag: str, challenge_id: str = "") -> None:
        self.logger.info(f"[flag]FLAG FOUND![/flag] {flag} (challenge: {challenge_id})")

    def flag_submitted(self, flag: str, success: bool) -> None:
        if success:
            self.logger.info(f"[success]FLAG ACCEPTED:[/success] {flag}")
        else:
            self.logger.warning(f"[warning]FLAG REJECTED:[/warning] {flag}")

    def challenge_start(self, challenge_id: str, name: str) -> None:
        self.logger.info(f"[bold cyan]===== Challenge: {name} (ID: {challenge_id}) =====[/bold cyan]")

    def challenge_complete(self, challenge_id: str, success: bool, steps: int) -> None:
        status = "[success]SOLVED[/success]" if success else "[warning]INCOMPLETE[/warning]"
        self.logger.info(f"Challenge {challenge_id} {status} | {steps} steps")

    def error(self, message: str, exc: Optional[Exception] = None) -> None:
        self.logger.error(f"[error]ERROR:[/error] {message}")
        if exc:
            self.logger.exception(exc)

    def warning(self, message: str) -> None:
        self.logger.warning(f"[warning]WARNING:[/warning] {message}")

    def info(self, message: str) -> None:
        self.logger.info(message)

    def separator(self) -> None:
        self.logger.info("-" * 60)
