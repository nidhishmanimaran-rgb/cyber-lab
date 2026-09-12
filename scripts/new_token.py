from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.core.config import generate_api_token


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a secure Cyber Command Center API token.")
    parser.add_argument("--bytes", type=int, default=32, help="Token entropy size in bytes (default: 32).")
    args = parser.parse_args()
    print(generate_api_token(args.bytes))


if __name__ == "__main__":
    main()
