# Williecat – Reconnaissance with Instinct

Williecat is a modular reconnaissance and OSINT assistant designed to gather
passive intelligence before you make any loud moves. Built as a tribute to
Willie the cat, the toolkit focuses on stealthy collection, structured
reporting, and extensibility.

## Features

- **WHOIS + RDAP:** Discover registration, expiration, and nameserver data via
  public RDAP services.
- **Passive DNS:** Enumerate A/AAAA/MX/NS/TXT records using DNS over HTTPS.
- **Certificate Transparency:** Scrape recent certificates from `crt.sh` for
  additional domains and hostnames.
- **Header Sniffer:** Capture HTTP headers, security directives, and cookies.
- **IP Intelligence:** Pull ASN and geolocation data from ipinfo.io.
- **Social Trace:** Look for mentions across Reddit and Hacker News.
- **Reporting:** Export findings in Markdown or JSON for downstream analysis.

## Installation

Williecat relies only on the Python standard library. Clone the repository and
run the tool with Python 3.10 or newer.

## Usage

```bash
python -m williecat --domain example.com --modules whois,dns,certs,headers --output recon_report.md
```

### Command-line options

Run `python -m williecat --help` to view all arguments. Key flags include:

- `--domain` – Domain name to investigate.
- `--ip` – IP address to enrich (auto-resolved if omitted and `--domain` is
  supplied).
- `--url` – Full URL for HTTP header collection.
- `--modules` – Comma-separated list of modules to execute (defaults to all).
- `--output` – Path to write a Markdown report.
- `--json-output` – Path to write raw JSON results.
- `--timeout` – Network timeout (seconds).
- `--list-modules` – List available modules and exit.

## Extending Williecat

Modules live in `williecat/modules/`. Each module subclasses `ReconModule` and
returns a `ModuleResult`. Register new modules by adding them to
`get_module_registry()` in `williecat/modules/__init__.py`.

## License

Williecat is released under the MIT license. Use responsibly and honor the
stealthy spirit of Willie—gather quietly, act with precision.

## Tribute to Willie

Willie was the office sentry who inspired this project—an endlessly curious
tabby who could map every corner of a room with a single sweep of his tail.
When he wasn't overseeing reconnaissance runs from the top of a dresser, he was
curled up beside a stack of language books, reminding us that observation and
patience are the heart of good intelligence work. May every quiet scan and
carefully documented lead carry forward his calm focus and gentle paws.
