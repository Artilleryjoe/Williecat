"""Built-in demonstration dataset for Williecat."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Tuple

from .core import ModuleResult, ReconContext


DEMO_DOMAIN = "demo.williecat.io"
DEMO_IP = "203.0.113.42"
DEMO_URL = f"https://{DEMO_DOMAIN}"


def load_demo_run() -> Tuple[ReconContext, List[ModuleResult]]:
    """Return a context and canned results for offline demos."""

    context = ReconContext(
        domain=DEMO_DOMAIN,
        ip_address=DEMO_IP,
        base_url=DEMO_URL,
        timeout=5.0,
        session=None,
    )
    timestamp = datetime(2024, 11, 8, 4, 46, 53, tzinfo=timezone.utc).isoformat()

    results = [
        ModuleResult(
            "whois",
            {
                "domain": DEMO_DOMAIN,
                "status": ["clientTransferProhibited", "clientUpdateProhibited"],
                "registrar": "Example Registrar LLC",
                "events": {
                    "registration": "2023-10-02T12:15:00Z",
                    "expiration": "2024-10-02T12:15:00Z",
                    "last changed": timestamp,
                },
                "nameservers": ["ns1.demo-cat.net", "ns2.demo-cat.net"],
            },
        ),
        ModuleResult(
            "headers",
            {
                "url": DEMO_URL,
                "method": "HEAD",
                "status_code": 200,
                "server": "nginx/1.25.2",
                "powered_by": "Williecat Showcase",
                "user_agent": "Williecat/POC",
                "cookies": {"session": "demo"},
                "security_headers": {
                    "strict-transport-security": "max-age=63072000; includeSubDomains",
                    "content-security-policy": "default-src 'self'",
                    "x-content-type-options": "nosniff",
                },
            },
            warnings=["HEAD not supported – performed safe GET fallback."],
        ),
        ModuleResult(
            "dns",
            {
                "A": [DEMO_IP],
                "AAAA": ["2001:db8::42"],
                "MX": ["5 inbound.demo.williecat.io"],
                "NS": ["ns1.demo-cat.net", "ns2.demo-cat.net"],
            },
        ),
        ModuleResult(
            "certs",
            [
                {
                    "common_name": DEMO_DOMAIN,
                    "name_value": DEMO_DOMAIN,
                    "issuer_name": "C=US, O=Demo Trust CA, CN=Demo Trust TLS CA",
                    "not_before": "2024-09-01T00:00:00",
                    "not_after": "2024-12-01T00:00:00",
                }
            ],
        ),
        ModuleResult(
            "ip",
            {
                "ip": DEMO_IP,
                "hostname": "edge.demo.williecat.io",
                "city": "San Francisco",
                "region": "California",
                "country": "US",
                "loc": "37.7749,-122.4194",
                "org": "AS65500 Demo Transit",
                "asn": {
                    "asn": "AS65500",
                    "name": "Demo Transit LLC",
                    "route": "203.0.113.0/24",
                },
                "bogon": False,
            },
        ),
        ModuleResult(
            "social",
            [
                {
                    "source": "HackerNews",
                    "title": "Launch of demo.williecat.io passive recon portal",
                    "url": "https://news.ycombinator.com/item?id=424242",
                },
                {
                    "source": "Reddit",
                    "title": "Quiet OSINT workflows with Williecat",
                    "url": "https://www.reddit.com/r/osint/comments/abc123/quiet_cats/",
                    "subreddit": "r/osint",
                },
            ],
        ),
    ]
    return context, results
