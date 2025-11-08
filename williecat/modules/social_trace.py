"""Social media and OSINT trace module."""
from __future__ import annotations

from typing import Any, Dict, List

from . import ModuleResult, ReconContext, ReconModule

HN_SEARCH = "https://hn.algolia.com/api/v1/search"
REDDIT_SEARCH = "https://www.reddit.com/search.json"


class SocialTraceModule(ReconModule):
    """Search for domain mentions across community platforms."""

    name = "social"
    description = "Passive OSINT mentions from Reddit and Hacker News."

    def run(self, context: ReconContext) -> ModuleResult:
        if not context.domain:
            return ModuleResult(self.name, None, error="Domain is required for social tracing.")

        session = context.session
        hits: List[Dict[str, Any]] = []

        hits.extend(_search_hacker_news(session, context))
        hits.extend(_search_reddit(session, context))

        if not hits:
            return ModuleResult(self.name, None, warnings=["No social mentions discovered."])
        return ModuleResult(self.name, hits)


def _search_hacker_news(session, context: ReconContext) -> List[Dict[str, Any]]:
    try:
        response = session.get(
            HN_SEARCH,
            params={"query": context.domain, "tags": "story"},
            timeout=context.timeout,
        )
        response.raise_for_status()
        payload = response.json()
    except Exception:  # pragma: no cover - network failure
        return []

    hits: List[Dict[str, Any]] = []
    for hit in payload.get("hits", [])[:5]:
        title = hit.get("title")
        url = hit.get("url") or hit.get("story_url")
        if title and url:
            hits.append({"source": "HackerNews", "title": title, "url": url})
    return hits


def _search_reddit(session, context: ReconContext) -> List[Dict[str, Any]]:
    headers = {"User-Agent": "WilliecatRecon/1.0"}
    try:
        response = session.get(
            REDDIT_SEARCH,
            params={"q": context.domain, "limit": 5, "sort": "new", "type": "link"},
            headers=headers,
            timeout=context.timeout,
        )
        response.raise_for_status()
        payload = response.json()
    except Exception:  # pragma: no cover - network failure
        return []

    hits: List[Dict[str, Any]] = []
    for child in payload.get("data", {}).get("children", []):
        data = child.get("data", {})
        title = data.get("title")
        url = data.get("url")
        if title and url:
            hits.append({
                "source": "Reddit",
                "title": title,
                "url": url,
                "subreddit": data.get("subreddit"),
            })
    return hits
