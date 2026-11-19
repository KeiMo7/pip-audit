"""
End-to-end tests for explainable fix mode (`--fix --explain`).

These tests drive the real CLI with an in-memory vulnerability service and
on-disk requirement files, but no virtualenv or network access.
"""

from __future__ import annotations

import json

from packaging.version import Version

import pip_audit._cli
from pip_audit._service.interface import VulnerabilityResult, VulnerabilityService


def _vuln(id: str, fix_versions, aliases=None):
    return VulnerabilityResult(
        id=id,
        description="offline",
        fix_versions=[v if isinstance(v, Version) else Version(v) for v in fix_versions],
        aliases=aliases or set(),
    )


class _Service(VulnerabilityService):
    """Vulnerability table keyed by (canonical name, version)."""

    def __init__(self, table):
        self._table = table

    def query(self, spec):
        key = (spec.canonical_name, str(spec.version))
        return spec, list(self._table.get(key, []))


def _run_cli(monkeypatch, args, service):
    parser = pip_audit._cli._parser()
    monkeypatch.setattr(pip_audit._cli, "_parse_args", lambda *a: parser.parse_args(args))

    class _FakeService:
        DEFAULT_OSV_URL = "http://invalid.local"

        def __new__(cls, *a, **kw):
            return service

    monkeypatch.setattr(pip_audit._cli, "PyPIService", _FakeService)
    monkeypatch.setattr(pip_audit._cli, "OsvService", _FakeService)
    monkeypatch.setattr(pip_audit._cli, "EcosystemsService", _FakeService)
    # The CLI exits 1 only when some package remains unfixed; a fully fixed
    # run returns normally. Both are valid outcomes for these tests.
    try:
        pip_audit._cli.audit()
    except SystemExit as exc:
        return exc.code
    return 0


def test_explain_fix_writes_and_reaudits_clean(monkeypatch, req_file, capsys):
    path = req_file()
    path.write_text("foo==1.0.0\n")

    table = {
        ("foo", "1.0.0"): [_vuln("V1", ["1.2.0"])],
        ("foo", "1.2.0"): [],
    }

    _run_cli(
        monkeypatch,
        ["--fix", "--explain", "-r", str(path), "--disable-pip", "--no-deps",
             "-s", "pypi", "--format", "json", "--progress-spinner", "off"],
        _Service(table),
    )

    # Manifest rewritten to the verified-clean version.
    assert "foo==1.2.0" in path.read_text()

    captured = capsys.readouterr()
    assert "Fix advice classification: upgrade=1" in captured.err
    out = json.loads(captured.out)
    # Legacy schema preserved...
    assert out["fixes"][0]["new_version"] == "1.2.0"
    # ...and the additive advice block carries the evidence.
    advice = out["fix_advice"][0]
    assert advice["classification"] == "upgrade"
    assert advice["vulnerability_ids"] == ["V1"]
    assert advice["chosen_version"] == "1.2.0"
    assert advice["affected_ranges"][0]["upper"] == "1.2.0"
    assert advice["reason"]


def test_explain_unparsable_manifest_rejects_whole_run(monkeypatch, req_file):
    path = req_file()
    path.write_text("@@@@\n")
    before = path.read_bytes()

    _run_cli(
        monkeypatch,
        ["--fix", "--explain", "-r", str(path), "--disable-pip", "--no-deps",
             "-s", "pypi", "--progress-spinner", "off"],
        _Service({}),
    )

    assert path.read_bytes() == before


def test_explain_post_fix_hit_rolls_back(monkeypatch, req_file):
    path = req_file()
    path.write_text("foo==1.0.0\n")
    before = path.read_bytes()

    # The engine believes 1.2.0 is clean at resolution time, but the final
    # re-audit reports a hit: the batch must roll back.
    table = {
        ("foo", "1.0.0"): [_vuln("V1", ["1.2.0"])],
        ("foo", "1.2.0"): [],
    }
    service = _Service(table)

    real_query = service.query

    def flaky_query(spec):
        _, vulns = real_query(spec)
        if spec.canonical_name == "foo" and str(spec.version) == "1.2.0":
            # Only the post-write verification query (after the file changed).
            if "foo==1.2.0" in path.read_text():
                return spec, [_vuln("V2", ["1.3.0"])]
        return spec, vulns

    service.query = flaky_query  # type: ignore[method-assign]

    _run_cli(
        monkeypatch,
        ["--fix", "--explain", "-r", str(path), "--disable-pip", "--no-deps",
             "-s", "pypi", "--progress-spinner", "off"],
        service,
    )

    assert path.read_bytes() == before


def test_explain_undeterminable_when_no_fix_points(monkeypatch, req_file, capsys):
    path = req_file()
    path.write_text("foo==1.0.0\n")
    before = path.read_bytes()
    table = {("foo", "1.0.0"): [_vuln("V1", [])]}

    _run_cli(
        monkeypatch,
        ["--fix", "--explain", "-r", str(path), "--disable-pip", "--no-deps",
             "-s", "pypi", "--format", "json", "--progress-spinner", "off"],
        _Service(table),
    )

    assert path.read_bytes() == before
    out = json.loads(capsys.readouterr().out)
    assert out["fix_advice"][0]["classification"] == "undeterminable"


def test_legacy_mode_output_has_no_advice_block(monkeypatch, req_file, capsys):
    path = req_file()
    path.write_text("foo==1.0.0\n")
    table = {
        ("foo", "1.0.0"): [_vuln("V1", ["1.2.0"])],
        ("foo", "1.2.0"): [],
    }

    _run_cli(
        monkeypatch,
        ["--fix", "-r", str(path), "--disable-pip", "--no-deps",
             "-s", "pypi", "--format", "json", "--progress-spinner", "off"],
        _Service(table),
    )

    out = json.loads(capsys.readouterr().out)
    assert "fix_advice" not in out
    assert out["fixes"][0]["new_version"] == "1.2.0"
