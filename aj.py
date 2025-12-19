#!/usr/bin/env python3
import sys
from core.database import init_db, DB_FILE
from core.shell_commands import AuditCommandHandler, style


def main():
    # Ensure DB is ready
    init_db()

    handler = AuditCommandHandler()
    print("Welcome to The Audit Journal (aj). Type 'help' for commands.")
    print(f"Database file is: {DB_FILE}")

    while True:
        try:
            text = handler.session.prompt(handler.get_prompt_tokens(), style=style)
            if not text.strip():
                continue

            parts = text.split()
            cmd = parts[0].lower()
            args = " ".join(parts[1:]) if len(parts) > 1 else ""

            if cmd in ["exit", "quit"]:
                handler.do_close("")  # Close session properly
                break

            # Look for the method in the handler
            method = getattr(handler, f"do_{cmd}", None)
            if method:
                method(args)
            else:
                print(f"Unknown command: {cmd}")

        except (KeyboardInterrupt, EOFError):
            break


if __name__ == "__main__":
    main()
