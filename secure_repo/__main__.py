"""Allows running the tool with ``python -m secure_repo``."""

from secure_repo.cli.main import main

if __name__ == "__main__":
    raise SystemExit(main())
