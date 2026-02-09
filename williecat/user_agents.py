"""User-agent rotation helpers."""
from __future__ import annotations

import random

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/121.0",
    "curl/8.5.0",
]

FALLBACK_USER_AGENT = "Williecat/1.0"


def random_user_agent() -> str:
    """Return a randomized user-agent with a fallback if rotation fails."""

    try:
        return random.choice(USER_AGENTS)
    except Exception:
        return FALLBACK_USER_AGENT
