from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from packaging.version import Version

from pip_audit._audit import Auditor, diff_results
from pip_audit._dependency_source import DependencySource
from pip_audit._dependency_source.requirement import RequirementSource
from pip_audit._format.json import JsonFormat
from pip_audit._service.interface import (
    ResolvedDependency,
    SkippedDependency,
    VulnerabilityResult,
    severity_rank,
)
from pip_audit._service.local import LocalDatabaseError, LocalService
from pip_audit._service.osv import OsvService

_FRESH = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
_STALE = (datetime.now() - timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _entry(
    id: str,
    name: str = "foo",
    *,
    aliases: list[str] | None = None,
    severity: str | None = None,
    introduced: str | None = None,
    fixed: str | None = None,
    last_affected: str | None = None,
    versions: list[str] | None = None,
    summary: str = "a test vulnerability",
) -> dict:
    affected: dict = {"package": {"name": name, "ecosystem": "PyPI"}}
    events = []
    if introduced is not None:
        events.append({"introduced": introduced})
    if fixed is not None:
        events.append({"fixed": fixed})
    if last_affected is not None:
        events.append({"last_affected": last_affected})
    if events:
        affected["ranges"] = [{"type": "ECOSYSTEM", "events": events}]
    if versions is not None:
        affected["versions"] = versions

    entry: dict = {
        "id": id,
        "summary": summary,
        "published": "2026-01-01T00:00:00Z",
        "affected": [affected],
    }
    if aliases:
        entry["aliases"] = aliases
    if severity is not None:
        entry["severity"] = severity
    return entry


def _write_db(
    path: Path,
    entries: list[dict],
    *,
    generated_at: str | None = _FRESH,
    vuln_count: int | None = None,
) -> Path:
    doc: dict = {
        "format_version": 1,
        "vulns": entries,
        "vuln_count": vuln_count if vuln_count is not None else len(entries),
    }
    if generated_at is not None:
        doc["generated_at"] = generated_at
    path.write_text(json.dumps(doc))
    return path


def _query(svc: LocalService, name: str, version: str):
    return svc.query(ResolvedDependency(name, Version(version)))


def _ids(result) -> list[str]:
    _, vulns = result
    return [v.id for v in vulns]


class TestLocalServiceMatching:
    def test_offline_match_structure(self, tmp_path):
        db = _write_db(
            tmp_path / "db.json",
            [
                _entry(
                    "PYSEC-0000-1",
                    aliases=["CVE-0000-0001"],
                    severity="HIGH",
                    introduced="1.0.0",
                    fixed="1.1.0",
                )
            ],
        )
        svc = LocalService(db)

        dep, vulns = _query(svc, "foo", "1.0.5")
        assert dep == ResolvedDependency("foo", Version("1.0.5"))
        assert len(vulns) == 1

        vuln = vulns[0]
        # Same conclusion structure as the online path.
        assert isinstance(vuln, VulnerabilityResult)
        assert vuln.id == "PYSEC-0000-1"
        assert vuln.aliases == {"CVE-0000-0001"}
        assert vuln.fix_versions == [Version("1.1.0")]
        assert vuln.description == "a test vulnerability"
        assert vuln.published == datetime(2026, 1, 1)
        # Severity is passed through verbatim.
        assert vuln.severity == "HIGH"

    def test_offline_version_ranges(self, tmp_path):
        db = _write_db(
            tmp_path / "db.json",
            [
                _entry("PYSEC-0000-1", introduced="1.0.0", fixed="1.1.0"),
                _entry("PYSEC-0000-2", versions=["1.5.0", "1.5.1"]),
                _entry("PYSEC-0000-3", introduced="2.0.0", last_affected="2.0.9"),
            ],
        )
        svc = LocalService(db)

        assert _ids(_query(svc, "foo", "1.0.0")) == ["PYSEC-0000-1"]
        assert _ids(_query(svc, "foo", "1.0.99")) == ["PYSEC-0000-1"]
        assert _ids(_query(svc, "foo", "1.1.0")) == []  # fixed version is not affected
        assert _ids(_query(svc, "foo", "1.5.1")) == ["PYSEC-0000-2"]
        assert _ids(_query(svc, "foo", "1.5.2")) == []
        assert _ids(_query(svc, "foo", "2.0.9")) == ["PYSEC-0000-3"]
        assert _ids(_query(svc, "foo", "2.1.0")) == []

    def test_offline_unknown_package_and_other_ecosystem(self, tmp_path):
        entry = _entry("PYSEC-0000-1", introduced="0", fixed="9.9")
        entry["affected"].append(
            {
                "package": {"name": "foo", "ecosystem": "npm"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.9"}]}
                ],
            }
        )
        db = _write_db(tmp_path / "db.json", [entry])
        svc = LocalService(db)

        assert _ids(_query(svc, "not-in-db", "1.0.0")) == []
        # The npm affected-entry must not produce a (PyPI) result.
        _, vulns = _query(svc, "foo", "1.0.0")
        assert [v.id for v in vulns] == ["PYSEC-0000-1"]
        assert vulns[0].fix_versions == [Version("9.9")]

    def test_offline_canonicalizes_names(self, tmp_path):
        db = _write_db(
            tmp_path / "db.json",
            [_entry("PYSEC-0000-1", name="my-pkg", introduced="0", fixed="1.0")],
        )
        svc = LocalService(db)
        assert _ids(_query(svc, "My_Pkg", "0.5")) == ["PYSEC-0000-1"]

    def test_offline_withdrawn_entries_skipped(self, tmp_path):
        entry = _entry("PYSEC-0000-1", introduced="0", fixed="1.0")
        entry["withdrawn"] = "2026-02-01T00:00:00Z"
        db = _write_db(tmp_path / "db.json", [entry])
        svc = LocalService(db)
        assert _ids(_query(svc, "foo", "0.5")) == []


class TestLocalServiceStaleness:
    def test_stale_database_flagged(self, tmp_path, caplog):
        db = _write_db(tmp_path / "db.json", [], generated_at=_STALE)
        with caplog.at_level("WARNING", logger="pip_audit._service.local"):
            svc = LocalService(db)

        assert svc.stale is True
        messages = [r.getMessage() for r in caplog.records]
        assert any("stale" in m and "outdated" in m for m in messages)

    def test_fresh_database_not_stale(self, tmp_path, caplog):
        db = _write_db(tmp_path / "db.json", [], generated_at=_FRESH)
        with caplog.at_level("WARNING", logger="pip_audit._service.local"):
            svc = LocalService(db)

        assert svc.stale is False
        assert not caplog.records

    def test_missing_timestamp_is_stale(self, tmp_path, caplog):
        db = _write_db(tmp_path / "db.json", [], generated_at=None)
        with caplog.at_level("WARNING", logger="pip_audit._service.local"):
            svc = LocalService(db)

        assert svc.stale is True
        assert any("no generation timestamp" in r.getMessage() for r in caplog.records)


class TestLocalServiceMerging:
    def test_multiple_hits_merged_keeping_worst_severity(self, tmp_path):
        # Two records for the same underlying vulnerability, linked by
        # aliases, carrying different severity labels.
        db = _write_db(
            tmp_path / "db.json",
            [
                _entry(
                    "PYSEC-0000-1",
                    aliases=["CVE-0000-0001"],
                    severity="LOW",
                    introduced="0",
                    fixed="1.0",
                ),
                _entry(
                    "CVE-0000-0001",
                    aliases=["PYSEC-0000-1"],
                    severity="CRITICAL",
                    introduced="0",
                    fixed="1.0",
                ),
            ],
        )
        svc = LocalService(db)

        class Source(DependencySource):
            def collect(self):
                yield ResolvedDependency("foo", Version("0.5"))

            def fix(self, _):
                raise NotImplementedError

        auditor = Auditor(svc)
        results = dict(auditor.audit(Source()))

        dep = ResolvedDependency("foo", Version("0.5"))
        assert len(results[dep]) == 1

        merged = results[dep][0]
        # PYSEC IDs are prioritized as the primary ID.
        assert merged.id == "PYSEC-0000-1"
        assert merged.aliases == {"CVE-0000-0001"}
        # The most severe label survives the merge.
        assert merged.severity == "CRITICAL"

    def test_merging_is_idempotent(self, tmp_path):
        db = _write_db(
            tmp_path / "db.json",
            [
                _entry("PYSEC-0000-1", severity="HIGH", introduced="0", fixed="1.0"),
                _entry("PYSEC-0000-2", severity="LOW", introduced="0", fixed="1.0"),
            ],
        )
        svc = LocalService(db)

        class Source(DependencySource):
            def collect(self):
                yield ResolvedDependency("foo", Version("0.5"))

            def fix(self, _):
                raise NotImplementedError

        auditor = Auditor(svc)
        first = dict(auditor.audit(Source()))
        second = dict(auditor.audit(Source()))

        # Re-running the same batch produces exactly the same entries.
        assert first == second
        dep = ResolvedDependency("foo", Version("0.5"))
        assert [v.id for v in second[dep]] == ["PYSEC-0000-1", "PYSEC-0000-2"]

    def test_duplicate_database_entries_deduplicated(self, tmp_path):
        entry = _entry("PYSEC-0000-1", severity="HIGH", introduced="0", fixed="1.0")
        db = _write_db(tmp_path / "db.json", [entry, dict(entry)])
        svc = LocalService(db)
        assert _ids(_query(svc, "foo", "0.5")) == ["PYSEC-0000-1"]


class TestLocalServiceSeverityOrdering:
    def test_results_sorted_by_shared_severity_ranking(self, tmp_path):
        db = _write_db(
            tmp_path / "db.json",
            [
                _entry("PYSEC-0000-1", severity="LOW", introduced="0", fixed="1.0"),
                _entry("PYSEC-0000-2", severity="CRITICAL", introduced="0", fixed="1.0"),
                _entry("PYSEC-0000-3", severity="HIGH", introduced="0", fixed="1.0"),
                _entry("PYSEC-0000-4", introduced="0", fixed="1.0"),  # no severity
            ],
        )
        svc = LocalService(db)
        assert _ids(_query(svc, "foo", "0.5")) == [
            "PYSEC-0000-2",
            "PYSEC-0000-3",
            "PYSEC-0000-1",
            "PYSEC-0000-4",
        ]

    def test_severity_rank_is_order_independent_for_merges(self):
        low = VulnerabilityResult(
            id="PYSEC-0",
            description="fake",
            fix_versions=[],
            aliases={"CVE-0"},
            severity="LOW",
        )
        critical = VulnerabilityResult(
            id="CVE-0",
            description="fake",
            fix_versions=[],
            aliases={"PYSEC-0"},
            severity="CRITICAL",
        )

        assert severity_rank("CRITICAL") > severity_rank("HIGH") > severity_rank("LOW")
        assert severity_rank(None) == 0
        # Whichever side of the merge we start from, the worst label wins
        # and labels are never rewritten.
        assert low.merge_aliases(critical).severity == "CRITICAL"
        assert critical.merge_aliases(low).severity == "CRITICAL"


class TestLocalServiceIntegrity:
    def test_truncated_database_is_a_hard_error(self, tmp_path):
        db = _write_db(
            tmp_path / "db.json",
            [_entry("PYSEC-0000-1", introduced="0", fixed="1.0")],
        )
        # Simulate a truncated write.
        raw = db.read_text()
        db.write_text(raw[: len(raw) // 2])

        with pytest.raises(LocalDatabaseError, match="malformed or truncated"):
            LocalService(db)

    def test_count_mismatch_is_a_hard_error(self, tmp_path):
        # A cleanly-written but incomplete database (e.g. an interrupted
        # generator) must not be treated as authoritative either.
        db = _write_db(
            tmp_path / "db.json",
            [_entry("PYSEC-0000-1", introduced="0", fixed="1.0")],
            vuln_count=2,
        )
        with pytest.raises(LocalDatabaseError, match="truncated"):
            LocalService(db)

    def test_unsupported_format_version_is_a_hard_error(self, tmp_path):
        db = _write_db(tmp_path / "db.json", [])
        doc = json.loads(db.read_text())
        doc["format_version"] = 999
        db.write_text(json.dumps(doc))

        with pytest.raises(LocalDatabaseError, match="unsupported format version"):
            LocalService(db)

    def test_malformed_entry_is_a_hard_error(self, tmp_path):
        db = _write_db(tmp_path / "db.json", [{"no_id": True}])
        with pytest.raises(LocalDatabaseError, match="malformed entry"):
            LocalService(db)

    def test_invalid_version_in_database_is_a_hard_error(self, tmp_path):
        db = _write_db(
            tmp_path / "db.json",
            [_entry("PYSEC-0000-1", introduced="not.a.version!!", fixed="1.0")],
        )
        svc = LocalService(db)
        with pytest.raises(LocalDatabaseError, match="invalid version"):
            _query(svc, "foo", "0.5")


class TestLocalServiceDegradation:
    def test_missing_database_degrades_to_list_only(self, tmp_path, caplog):
        missing = tmp_path / "does-not-exist.json"
        with caplog.at_level("WARNING", logger="pip_audit._service.local"):
            svc = LocalService(missing)

        assert svc.degraded is True
        assert svc.degraded_reason is not None
        assert any("unavailable" in r.getMessage() for r in caplog.records)

        # Dependencies are listed (as skipped, with an explicit reason)
        # rather than audited.
        dep, vulns = svc.query(ResolvedDependency("foo", Version("1.0")))
        assert vulns == []
        assert isinstance(dep, SkippedDependency)
        assert dep.name == "foo"
        assert "not audited" in dep.skip_reason

    def test_degraded_mode_never_queries(self, tmp_path):
        svc = LocalService(tmp_path / "missing.json")
        results = dict(
            svc.query_all(
                iter(
                    [
                        ResolvedDependency("foo", Version("1.0")),
                        ResolvedDependency("bar", Version("2.0")),
                    ]
                )
            )
        )
        assert len(results) == 2
        assert all(d.is_skipped() for d in results)


class TestOfflineOnlineParity:
    def test_offline_results_match_online_results(self, tmp_path, monkeypatch):
        # The same OSV records, served by a (mocked) online OSV service and
        # by a local database file, must produce the same set of conclusions
        # for each dependency.
        entries = [
            _entry("PYSEC-0000-1", introduced="1.0.0", fixed="1.1.0"),
            _entry("PYSEC-0000-2", versions=["1.0.5"]),
            _entry("PYSEC-0000-3", introduced="2.0.0", fixed="2.1.0"),
        ]
        # Independent, hand-written expectation table: which entries the
        # "server" returns for each queried version.
        online_table = {
            "1.0.5": ["PYSEC-0000-1", "PYSEC-0000-2"],
            "1.2.0": [],
            "2.0.5": ["PYSEC-0000-3"],
        }
        by_id = {e["id"]: e for e in entries}

        class MockResponse:
            def __init__(self, vulns):
                self._vulns = vulns

            def raise_for_status(self):
                pass

            def json(self):
                return {"vulns": self._vulns} if self._vulns else {}

        class MockSession:
            def post(self, url, data, **kwargs):
                query = json.loads(data)
                assert query["package"]["name"] == "foo"
                ids = online_table[query["version"]]
                return MockResponse([by_id[i] for i in ids])

        online = OsvService()
        monkeypatch.setattr(online, "session", MockSession())

        offline = LocalService(_write_db(tmp_path / "db.json", entries))

        for version, expected_ids in online_table.items():
            dep = ResolvedDependency("foo", Version(version))
            _, online_vulns = online.query(dep)
            _, offline_vulns = offline.query(dep)

            # The set of conclusions is identical across the two modes.
            assert {v.id for v in offline_vulns} == {v.id for v in online_vulns}
            assert {v.id for v in offline_vulns} == set(expected_ids)
            # Fix versions agree between the two paths as well.
            assert {v.id: v.fix_versions for v in offline_vulns} == {
                v.id: v.fix_versions for v in online_vulns
            }


class TestOfflineRequirementCollection:
    def test_bad_constraints_listed_individually(self, tmp_path):
        req = tmp_path / "reqs.txt"
        req.write_text(
            "good==1.0.0\nunpinned>=1.0\nnot-a-pin~=2.0\nbroken==not.a.version!!\n!!!garbage===\n"
        )
        source = RequirementSource([req], no_deps=True, disable_pip=True, skip_invalid=True)
        collected = list(source.collect())

        resolved = [d for d in collected if not d.is_skipped()]
        skipped = [d for d in collected if d.is_skipped()]

        # The batch does not fail: the good dependency is collected and
        # every bad constraint is listed individually.
        assert resolved == [ResolvedDependency("good", Version("1.0.0"))]
        assert len(skipped) == 4

        reasons = {d.name: d.skip_reason for d in skipped}
        # Each failure can be located to the specific dependency/constraint.
        assert ">=1.0" in reasons["unpinned"]
        assert "~=2.0" in reasons["not-a-pin"]
        assert "line 4" in reasons["broken==not.a.version!!"]
        assert "line 5" in reasons["!!!garbage==="]

    def test_unparseable_pinned_version_skipped(self):
        # A specifier that parses as a requirement but whose pinned version
        # is unparseable is reported individually in tolerant mode.
        class FakeReq:
            is_editable = False
            hash_options: list = []
            req = object()
            marker = None
            name = "broken"
            specifier = "==not.a.version!!"
            is_url = False

            def __str__(self):
                return "broken==not.a.version!!"

            def dumps(self):
                return str(self)

        source = RequirementSource([], no_deps=True, disable_pip=True, skip_invalid=True)
        collected = list(source._collect_preresolved_deps(iter([FakeReq()]), False))

        assert len(collected) == 1
        assert collected[0].is_skipped()
        assert collected[0].name == "broken"
        assert "not.a.version!!" in collected[0].skip_reason

    def test_duplicate_across_manifests_deduplicated_with_sources(self, tmp_path):
        req1 = tmp_path / "reqs1.txt"
        req2 = tmp_path / "reqs2.txt"
        req1.write_text("foo==1.0.0\nbar==2.0.0\n")
        req2.write_text("foo==1.0.0\nbaz==3.0.0\n")

        source = RequirementSource([req1, req2], no_deps=True, disable_pip=True, skip_invalid=True)
        resolved = [d for d in source.collect() if not d.is_skipped()]

        # `foo` appears in both manifests but is collected exactly once,
        # with both origin markers retained.
        foos = [d for d in resolved if d.name == "foo"]
        assert len(foos) == 1
        assert foos[0].sources == {str(req1), str(req2)}
        # Origin markers don't affect identity.
        assert foos[0] == ResolvedDependency("foo", Version("1.0.0"))
        assert hash(foos[0]) == hash(ResolvedDependency("foo", Version("1.0.0")))

    def test_conflicting_duplicates_skipped_in_tolerant_mode(self, tmp_path):
        req = tmp_path / "reqs.txt"
        req.write_text("foo==1.0.0\nfoo==2.0.0\n")
        source = RequirementSource([req], no_deps=True, disable_pip=True, skip_invalid=True)
        collected = list(source.collect())
        assert len(collected) == 1
        assert collected[0].is_skipped()
        assert "conflicting" in collected[0].skip_reason

    def test_mixed_batch_reports_both_kinds(self, tmp_path):
        req = tmp_path / "reqs.txt"
        req.write_text("good==1.0.0\nunpinned>=1.0\n")
        db = _write_db(
            tmp_path / "db.json",
            [_entry("PYSEC-0000-1", name="good", introduced="0", fixed="2.0")],
        )

        source = RequirementSource([req], no_deps=True, disable_pip=True, skip_invalid=True)
        auditor = Auditor(LocalService(db))
        results = dict(auditor.audit(source))

        resolved = [d for d in results if not d.is_skipped()]
        skipped = [d for d in results if d.is_skipped()]
        # Both kinds of outcome appear in the same report.
        assert resolved == [ResolvedDependency("good", Version("1.0.0"))]
        assert [v.id for v in results[resolved[0]]] == ["PYSEC-0000-1"]
        assert len(skipped) == 1 and skipped[0].name == "unpinned"


class TestDatabaseUpdateDiff:
    def test_diff_shows_added_and_removed_entries(self, tmp_path):
        deps = [
            ResolvedDependency("foo", Version("1.0.0")),
            ResolvedDependency("bar", Version("2.0.0")),
        ]

        db_v1 = _write_db(
            tmp_path / "db-v1.json",
            [
                _entry("PYSEC-0000-1", name="foo", introduced="0", fixed="2.0"),
                _entry("PYSEC-0000-2", name="bar", introduced="0", fixed="3.0"),
            ],
        )
        # After the update: the foo entry is gone (e.g. withdrawn), the bar
        # entry is unchanged, and a new foo entry appears.
        db_v2 = _write_db(
            tmp_path / "db-v2.json",
            [
                _entry("PYSEC-0000-2", name="bar", introduced="0", fixed="3.0"),
                _entry("PYSEC-0000-9", name="foo", introduced="0", fixed="1.5"),
            ],
        )

        before = dict(LocalService(db_v1).query_all(iter(deps)))
        after = dict(LocalService(db_v2).query_all(iter(deps)))

        diff = diff_results(before, after)

        added = [(d.name, v.id) for d, v in diff.added]
        removed = [(d.name, v.id) for d, v in diff.removed]
        assert added == [("foo", "PYSEC-0000-9")]
        assert removed == [("foo", "PYSEC-0000-1")]

    def test_diff_of_identical_results_is_empty(self, tmp_path):
        deps = [ResolvedDependency("foo", Version("1.0.0"))]
        db = _write_db(
            tmp_path / "db.json",
            [_entry("PYSEC-0000-1", name="foo", introduced="0", fixed="2.0")],
        )
        result = dict(LocalService(db).query_all(iter(deps)))
        diff = diff_results(result, result)
        assert diff.added == [] and diff.removed == []


class TestOfflineReporting:
    def test_json_format_passes_severity_and_sources_through(self):
        dep = ResolvedDependency("foo", Version("1.0.0"), sources={"a.txt", "b.txt"})
        vuln = VulnerabilityResult(
            id="PYSEC-0000-1",
            description="fake",
            fix_versions=[Version("2.0.0")],
            aliases={"CVE-0000-0001"},
            severity="CRITICAL",
        )
        output = json.loads(JsonFormat(True, True).format({dep: [vuln]}, []))

        (out_dep,) = output["dependencies"]
        # Severity and IDs are emitted verbatim; origin markers are sorted.
        assert out_dep["vulns"][0]["severity"] == "CRITICAL"
        assert out_dep["vulns"][0]["id"] == "PYSEC-0000-1"
        assert out_dep["sources"] == ["a.txt", "b.txt"]

    def test_json_format_unchanged_without_offline_fields(self):
        dep = ResolvedDependency("foo", Version("1.0.0"))
        vuln = VulnerabilityResult(
            id="PYSEC-0000-1",
            description="fake",
            fix_versions=[Version("2.0.0")],
            aliases=set(),
        )
        output = json.loads(JsonFormat(True, True).format({dep: [vuln]}, []))

        (out_dep,) = output["dependencies"]
        assert "severity" not in out_dep["vulns"][0]
        assert "sources" not in out_dep

    def test_no_sensitive_info_in_public_logs(self, tmp_path, caplog):
        secret_req = tmp_path / "secret-manifest.txt"
        secret_req.write_text("sensitive-pkg==1.0.0\n")
        db = _write_db(
            tmp_path / "db.json",
            [_entry("PYSEC-0000-1", name="sensitive-pkg", introduced="0", fixed="2.0")],
            generated_at=_STALE,
        )

        source = RequirementSource([secret_req], no_deps=True, disable_pip=True, skip_invalid=True)
        with caplog.at_level("WARNING"):
            auditor = Auditor(LocalService(db))
            dict(auditor.audit(source))

        for record in caplog.records:
            if record.levelno < 30:  # below WARNING
                continue
            message = record.getMessage()
            assert "sensitive-pkg" not in message
            assert "secret-manifest" not in message
            assert str(tmp_path) not in message
