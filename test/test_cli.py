import errno
import json
import os
from datetime import datetime, timedelta
from pathlib import Path

import pretend  # type: ignore
import pytest

import pip_audit._cli
from pip_audit._cli import (
    OutputFormatChoice,
    ProgressSpinnerChoice,
    VulnerabilityAliasChoice,
    VulnerabilityDescriptionChoice,
    VulnerabilityServiceChoice,
)


def _local_db(path, entries, **kwargs):
    doc = {
        "format_version": 1,
        "generated_at": (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "vuln_count": len(entries),
        "vulns": entries,
    }
    doc.update(kwargs)
    path.write_text(json.dumps(doc))
    return path


def _db_entry(id, name, introduced, fixed, severity=None):
    entry = {
        "id": id,
        "summary": f"summary of {id}",
        "affected": [
            {
                "package": {"name": name, "ecosystem": "PyPI"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": introduced}, {"fixed": fixed}]}
                ],
            }
        ],
    }
    if severity is not None:
        entry["severity"] = severity
    return entry


def _run_audit(monkeypatch, args):
    parser = pip_audit._cli._parser()
    monkeypatch.setattr(pip_audit._cli, "_parse_args", lambda *a: parser.parse_args(args))
    try:
        pip_audit._cli.audit()
    except SystemExit as e:
        return e.code if e.code is not None else 0
    return 0


def test_offline_end_to_end(tmp_path, capsys, monkeypatch):
    req = tmp_path / "reqs.txt"
    req.write_text("foo==1.0.0\nbar==2.0.0\n")
    db = _local_db(
        tmp_path / "db.json",
        [_db_entry("PYSEC-0000-1", "foo", "0", "1.1.0", severity="HIGH")],
    )

    code = _run_audit(
        monkeypatch,
        [
            "--offline",
            "--local-db",
            str(db),
            "-r",
            str(req),
            "-f",
            "json",
            "--progress-spinner",
            "off",
        ],
    )

    # Vulnerabilities were found, so the exit code is 1.
    assert code == 1
    captured = capsys.readouterr()
    assert "Found 1 known vulnerability in 1 package" in captured.err

    report = json.loads(captured.out)
    deps = {d["name"]: d for d in report["dependencies"]}
    # The offline report has the same structure as an online one, with the
    # severity label passed through verbatim.
    assert deps["foo"]["vulns"][0]["id"] == "PYSEC-0000-1"
    assert deps["foo"]["vulns"][0]["severity"] == "HIGH"
    assert deps["foo"]["vulns"][0]["fix_versions"] == ["1.1.0"]
    assert deps["bar"]["vulns"] == []


def test_offline_missing_database_degrades(tmp_path, capsys, monkeypatch):
    req = tmp_path / "reqs.txt"
    req.write_text("foo==1.0.0\n")

    code = _run_audit(
        monkeypatch,
        [
            "--offline",
            "--local-db",
            str(tmp_path / "missing.json"),
            "-r",
            str(req),
            "-f",
            "json",
            "--progress-spinner",
            "off",
        ],
    )

    # Degraded mode lists dependencies without auditing them, and says so.
    assert code == 0
    captured = capsys.readouterr()
    assert "Local vulnerability database unavailable" in captured.err
    report = json.loads(captured.out)
    (dep,) = report["dependencies"]
    assert dep["name"] == "foo"
    assert "not audited" in dep["skip_reason"]


def test_offline_requires_local_db(monkeypatch):
    code = _run_audit(monkeypatch, ["--offline"])
    assert code == 2  # argparse usage error


def test_offline_truncated_database_fails_without_report(tmp_path, capsys, monkeypatch):
    req = tmp_path / "reqs.txt"
    req.write_text("foo==1.0.0\n")
    db = _local_db(tmp_path / "db.json", [_db_entry("PYSEC-0000-1", "foo", "0", "1.1.0")])
    # Truncate the database file.
    raw = db.read_text()
    db.write_text(raw[: len(raw) // 2])

    output = tmp_path / "report.json"
    code = _run_audit(
        monkeypatch,
        [
            "--offline",
            "--local-db",
            str(db),
            "-r",
            str(req),
            "-f",
            "json",
            "-o",
            str(output),
            "--progress-spinner",
            "off",
        ],
    )

    # A truncated database is a hard failure, and no half-finished report
    # is left behind at the official output path.
    assert code == 1
    assert not output.exists()


def test_offline_write_failure_preserves_partial(tmp_path, monkeypatch):
    output = tmp_path / "report.json"

    real_replace = os.replace

    def flaky_replace(src, dst):
        # The atomic rename into place fails (e.g. disk full); the
        # best-effort preservation rename succeeds.
        if Path(dst) == output:
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_replace(src, dst)

    monkeypatch.setattr(pip_audit._cli.os, "replace", flaky_replace)

    with pytest.raises(SystemExit) as excinfo:
        pip_audit._cli._write_output(output, '{"dependencies": []}')

    assert excinfo.value.code == 1
    # The official report path was never populated, but the completed
    # content is preserved for forensics.
    assert not output.exists()
    partial = tmp_path / "report.json.partial"
    assert partial.read_text() == '{"dependencies": []}\n'


def test_offline_stale_database_warns(tmp_path, caplog, monkeypatch):
    req = tmp_path / "reqs.txt"
    req.write_text("foo==1.0.0\n")
    db = _local_db(
        tmp_path / "db.json",
        [],
        generated_at=(datetime.now() - timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )

    with caplog.at_level("WARNING", logger="pip_audit"):
        code = _run_audit(
            monkeypatch,
            [
                "--offline",
                "--local-db",
                str(db),
                "-r",
                str(req),
                "--progress-spinner",
                "off",
            ],
        )

    assert code == 0
    assert any("stale" in r.getMessage() for r in caplog.records)


class TestOutputFormatChoice:
    def test_to_format_is_exhaustive(self):
        for choice in OutputFormatChoice:
            assert choice.to_format(False, False) is not None
            assert choice.to_format(True, True) is not None
            assert choice.to_format(False, True) is not None
            assert choice.to_format(True, False) is not None

    def test_str(self):
        for choice in OutputFormatChoice:
            assert str(choice) == choice.value


class TestVulnerabilityServiceChoice:
    def test_str(self):
        for choice in VulnerabilityServiceChoice:
            assert str(choice) == choice.value


class TestVulnerabilityDescriptionChoice:
    def test_to_bool_is_exhaustive(self):
        for choice in VulnerabilityDescriptionChoice:
            assert choice.to_bool(OutputFormatChoice.Json) in {True, False}

    def test_auto_to_bool_for_json(self):
        assert VulnerabilityDescriptionChoice.Auto.to_bool(OutputFormatChoice.Json) is True

    def test_str(self):
        for choice in VulnerabilityDescriptionChoice:
            assert str(choice) == choice.value


class TestVulnerabilityAliasChoice:
    def test_to_bool_is_exhaustive(self):
        for choice in VulnerabilityAliasChoice:
            assert choice.to_bool(OutputFormatChoice.Json) in {True, False}
            assert choice.to_bool(OutputFormatChoice.Markdown) in {True, False}
            assert choice.to_bool(OutputFormatChoice.Columns) in {True, False}
            assert choice.to_bool(OutputFormatChoice.CycloneDxJson) in {True, False}
            assert choice.to_bool(OutputFormatChoice.CycloneDxXml) in {True, False}

    def test_auto_to_bool_for_json(self):
        assert VulnerabilityAliasChoice.Auto.to_bool(OutputFormatChoice.Json) is True

    def test_str(self):
        for choice in VulnerabilityAliasChoice:
            assert str(choice) == choice.value


class TestProgressSpinnerChoice:
    def test_bool(self):
        assert bool(ProgressSpinnerChoice.On)
        assert not bool(ProgressSpinnerChoice.Off)

    def test_str(self):
        for choice in ProgressSpinnerChoice:
            assert str(choice) == choice.value


@pytest.mark.parametrize(
    "args, vuln_count, pkg_count, expected",
    [
        ([], 1, 1, "Found 1 known vulnerability in 1 package"),
        ([], 2, 1, "Found 2 known vulnerabilities in 1 package"),
        ([], 2, 2, "Found 2 known vulnerabilities in 2 packages"),
        (
            ["--ignore-vuln", "bar"],
            2,
            2,
            "Found 2 known vulnerabilities, ignored 1 in 2 packages",
        ),
        (["--fix"], 1, 1, "fixed 1 vulnerability in 1 package"),
        (["--fix"], 2, 1, "fixed 2 vulnerabilities in 1 package"),
        (["--fix"], 2, 2, "fixed 2 vulnerabilities in 2 packages"),
        ([], 0, 0, "No known vulnerabilities found"),
        (["--ignore-vuln", "bar"], 0, 1, "No known vulnerabilities found, 1 ignored"),
    ],
)
def test_plurals(capsys, monkeypatch, args, vuln_count, pkg_count, expected):
    dummysource = pretend.stub(fix=lambda a: None)
    monkeypatch.setattr(pip_audit._cli, "PipSource", lambda *a, **kw: dummysource)

    parser = pip_audit._cli._parser()
    monkeypatch.setattr(pip_audit._cli, "_parse_args", lambda *a: parser.parse_args(args))

    result = [
        (
            pretend.stub(
                is_skipped=lambda: False,
                name="something" + str(i),
                canonical_name="something" + str(i),
                version=1,
            ),
            [
                pretend.stub(
                    fix_versions=[2],
                    id="foo",
                    aliases=set(),
                    has_any_id=lambda x: False,
                )
            ]
            * (vuln_count // pkg_count),
        )
        for i in range(pkg_count)
    ]

    if "--ignore-vuln" in args:
        result[0][1].append(pretend.stub(id="bar", aliases=set(), has_any_id=lambda x: True))

    auditor = pretend.stub(audit=lambda a: result)
    monkeypatch.setattr(pip_audit._cli, "Auditor", lambda *a, **kw: auditor)

    resolve_fix_versions = [
        pretend.stub(is_skipped=lambda: False, dep=spec, version=2) for spec, _ in result
    ]
    monkeypatch.setattr(pip_audit._cli, "resolve_fix_versions", lambda *a: resolve_fix_versions)

    try:
        pip_audit._cli.audit()
    except SystemExit:
        pass

    captured = capsys.readouterr()
    assert expected in captured.err


@pytest.mark.parametrize(
    "vuln_count, pkg_count, skip_count, print_format",
    [
        (1, 1, 0, True),
        (2, 1, 0, True),
        (2, 2, 0, True),
        (0, 0, 0, False),
        (0, 1, 0, False),
        # If there are no vulnerabilities but a dependency has been skipped, we
        # should print the formatted result
        (0, 0, 1, True),
    ],
)
def test_print_format(monkeypatch, vuln_count, pkg_count, skip_count, print_format):
    dummysource = pretend.stub(fix=lambda a: None)
    monkeypatch.setattr(pip_audit._cli, "PipSource", lambda *a, **kw: dummysource)

    dummyformat = pretend.stub(
        format=pretend.call_recorder(lambda _result, _fixes: None),
        is_manifest=False,
    )
    monkeypatch.setattr(pip_audit._cli, "ColumnsFormat", lambda *a, **kw: dummyformat)

    parser = pip_audit._cli._parser()
    monkeypatch.setattr(pip_audit._cli, "_parse_args", lambda *a: parser.parse_args([]))

    result = [
        (
            pretend.stub(
                is_skipped=lambda: False,
                name="something" + str(i),
                canonical_name="something" + str(i),
                version=1,
            ),
            [
                pretend.stub(
                    fix_versions=[2],
                    id="foo",
                    aliases=set(),
                    has_any_id=lambda x: False,
                )
            ]
            * (vuln_count // pkg_count),
        )
        for i in range(pkg_count)
    ]
    result.extend(
        (
            pretend.stub(
                is_skipped=lambda: True,
                name="skipped " + str(i),
                canonical_name="skipped " + str(i),
                version=1,
                skip_reason="reason " + str(i),
            ),
            [],
        )
        for i in range(skip_count)
    )

    auditor = pretend.stub(audit=lambda a: result)
    monkeypatch.setattr(pip_audit._cli, "Auditor", lambda *a, **kw: auditor)

    resolve_fix_versions = [
        pretend.stub(is_skipped=lambda: False, dep=spec, version=2) for spec, _ in result
    ]
    monkeypatch.setattr(pip_audit._cli, "resolve_fix_versions", lambda *a: resolve_fix_versions)

    try:
        pip_audit._cli.audit()
    except SystemExit:
        pass

    assert bool(dummyformat.format.calls) == print_format


def test_environment_variable(monkeypatch):
    """Environment variables set before execution change CLI option default."""
    monkeypatch.setenv("PIP_AUDIT_DESC", "off")
    monkeypatch.setenv("PIP_AUDIT_FORMAT", "markdown")
    monkeypatch.setenv("PIP_AUDIT_OUTPUT", "/tmp/fake")
    monkeypatch.setenv("PIP_AUDIT_PROGRESS_SPINNER", "off")
    monkeypatch.setenv("PIP_AUDIT_VULNERABILITY_SERVICE", "osv")

    parser = pip_audit._cli._parser()
    monkeypatch.setattr(pip_audit._cli, "_parse_args", lambda *a: parser.parse_args([]))
    args = pip_audit._cli._parse_args(parser, [])

    assert args.desc == VulnerabilityDescriptionChoice.Off
    assert args.format == OutputFormatChoice.Markdown
    assert args.output == Path("/tmp/fake")
    assert not args.progress_spinner
    assert args.vulnerability_service == VulnerabilityServiceChoice.Osv
