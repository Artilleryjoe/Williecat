"""CLI and reporting tests for Williecat."""

import json

from williecat import cli
from williecat import demo
from williecat.modules import reporter


def test_demo_mode_writes_outputs_and_log(tmp_path, monkeypatch):
    pawprints = tmp_path / "pawprints.log"
    monkeypatch.setenv(cli.PAWPRINTS_ENV_VAR, str(pawprints))

    markdown_path = tmp_path / "report.md"
    json_path = tmp_path / "report.json"

    exit_code = cli.main(
        [
            "--demo",
            "--quiet",
            "--output",
            str(markdown_path),
            "--json-output",
            str(json_path),
        ]
    )

    assert exit_code == 0
    assert markdown_path.exists()
    assert json_path.exists()

    payload = json.loads(json_path.read_text())
    assert any(entry["module"] == "whois" for entry in payload)

    log_record = json.loads(pawprints.read_text().splitlines()[-1])
    assert log_record["domain"] == demo.DEMO_DOMAIN
    assert log_record["output"] == str(markdown_path)
    assert log_record["json_output"] == str(json_path)


def test_render_markdown_contains_demo_data():
    context, results = demo.load_demo_run()

    markdown = reporter.render_markdown(context, results)

    assert f"# Williecat Recon Report – {demo.DEMO_DOMAIN}" in markdown
    assert "WHOIS" in markdown
    assert "Example Registrar LLC" in markdown
    assert "*Warnings:*" in markdown


def test_resolve_pawprints_env_override(monkeypatch, tmp_path):
    override_path = tmp_path / "custom.log"
    monkeypatch.setenv(cli.PAWPRINTS_ENV_VAR, str(override_path))

    resolved = cli._resolve_pawprints_path()

    assert resolved == override_path


def test_modules_help_uses_hyphenated_comma_separated():
    parser = cli.build_parser()

    modules_action = next(action for action in parser._actions if action.dest == "modules")

    assert "Comma-separated" in modules_action.help
