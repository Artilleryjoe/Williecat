"""Robots.txt and sitemap discovery module."""
from __future__ import annotations

from typing import Dict, List
from urllib.parse import urljoin

from ..core import ModuleResult, ReconContext, ReconModule
from ..user_agents import random_user_agent

MAX_RULES = 25
MAX_SITEMAPS = 25


class RobotsProbeModule(ReconModule):
    """Collect robots.txt directives and declared sitemap URLs."""

    name = "robots"
    description = "Passive robots.txt and sitemap discovery."

    def run(self, context: ReconContext) -> ModuleResult:
        base_url = context.base_url or (f"https://{context.domain}" if context.domain else None)
        if not base_url:
            return ModuleResult.failure(self.name, "A domain or URL is required for robots discovery.")

        robots_url = urljoin(_ensure_trailing_slash(base_url), "/robots.txt")
        headers = {"User-Agent": random_user_agent()}

        try:
            response = context.session.get(robots_url, headers=headers, timeout=context.timeout)
        except Exception as exc:  # pragma: no cover - defensive
            return ModuleResult.from_exception(self.name, exc)

        warnings: List[str] = []
        if response.status_code == 404:
            return ModuleResult(self.name, None, warnings=["robots.txt was not found."])
        if response.status_code >= 400:
            return ModuleResult.failure(self.name, f"robots.txt returned HTTP {response.status_code}")

        data = _parse_robots(response.text, str(response.url))
        if not data["rules"] and not data["sitemaps"]:
            warnings.append("robots.txt contained no crawl directives or sitemaps.")
        return ModuleResult(self.name, data, warnings=warnings)


def _ensure_trailing_slash(url: str) -> str:
    return url if url.endswith("/") else f"{url}/"


def _parse_robots(content: str, robots_url: str) -> Dict[str, object]:
    rules: List[Dict[str, str]] = []
    sitemaps: List[str] = []
    current_agents: List[str] = []
    crawl_delay: str | None = None

    for raw_line in content.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, value = [part.strip() for part in line.split(":", 1)]
        key_lower = key.lower()

        if key_lower == "user-agent":
            current_agents = [value or "*"]
            continue
        if key_lower == "sitemap" and value:
            if len(sitemaps) < MAX_SITEMAPS:
                sitemaps.append(urljoin(robots_url, value))
            continue
        if key_lower == "crawl-delay" and value:
            crawl_delay = value
            continue
        if key_lower in {"allow", "disallow"} and len(rules) < MAX_RULES:
            rules.append(
                {
                    "agent": ", ".join(current_agents) if current_agents else "*",
                    "directive": key_lower,
                    "path": value or "/",
                }
            )

    return {
        "robots_url": robots_url,
        "sitemaps": sitemaps,
        "crawl_delay": crawl_delay,
        "rules": rules,
    }
