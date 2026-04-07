import os
import sys
import argparse
from dotenv import load_dotenv

from agent.core import PentestAgent
from competition.models import Challenge
from utils.logger import get_logger

logger = get_logger("main")

def main():
    parser = argparse.ArgumentParser(description="Auto-Hacker Pentest Agent")
    parser.add_argument("--target", type=str, required=True, help="Target IP or URL")
    parser.add_argument("--port", type=int, help="Target Port")
    parser.add_argument("--model", type=str, default="glm-4-plus", help="LLM model to use")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    
    args = parser.parse_args()
    
    # Load environment variables (API keys)
    load_dotenv()
    
    logger.info(f"Starting Auto-Hacker Agent")
    logger.info(f"Target: {args.target}")
    logger.info(f"Model: {args.model}")
    
    # Configure the agent
    config = {
        "llm": {
            "active_model": args.model
        },
        "debug": args.debug
    }
    
    # Create challenge object
    challenge = Challenge(
        id="debug-chal-1",
        title="Debug Challenge",
        description=f"Find the flag on target {args.target}",
        target_host=args.target,
        target_port=args.port,
        score=100
    )
    
    # Init and run agent
    agent = PentestAgent(config=config)
    success = agent.run(challenge)
    
    if success:
        logger.info(f"Challenge completed successfully!")
        print("\n🎉 FLAG FOUND!")
        for flag in agent.memory.found_flags:
            print(f"-> {flag}")
    else:
        logger.warning(f"Failed to find the flag within step limit.")

if __name__ == "__main__":
    main()
