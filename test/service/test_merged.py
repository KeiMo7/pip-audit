import itertools
from datetime import datetime

import pytest
from packaging.version import Version

from pip_audit._audit import Auditor
from pip_audit._service.interface import (
    ServiceError,
    SkippedDependency,
    VulnerabilityResult,
    VulnerabilityService,
)
from pip_audit._service.merged import MergedVulnerabilityService


def _result(id, aliases=(), description="stub", fix_versions=(), published=None):
    return VulnerabilityResult(
        id=id,
        description=description,
        fix_versions=list(fix_versions),
        aliases=set(aliases),
        published=published,
    )


def _legacy_fields(result):
    return (
        result.id,
        result.description,
        result.fix_versions,
        result.aliases,
        result.published,
    )


class _StaticService(VulnerabilityService):
    """
    An offline fake service that returns fixed results per dependency name.
    """

    def __init__(self, results_by_name):
        self.results_by_name = results_by_name
        self.queries = []

    def query(self, spec):
        self.queries.append(spec)
        return spec, list(self.results_by_name.get(spec.name, []))


class _FailingService(VulnerabilityService):
    def __init__(self, error=None):
        self.queries = []
        self.error = error if error is not None else ServiceError("boom")

    def query(self, spec):
        self.queries.append(spec)
        raise self.error


# Three fixed offline responses covering an identifier chain, complementary
# fields, and conflicting fields, for the same dependency "foo".
def _three_source_services():
    pypi = _StaticService(
        {
            "foo": [
                _result(
                    "PYSEC-2024-100",
                    aliases={"CVE-2024-0100"},
                    description="N/A",
                    fix_versions=[Version("1.1.0")],
                    published=datetime(2024, 2, 1),
                )
            ]
        }
    )
    osv = _StaticService(
        {
            "foo": [
                _result(
                    "CVE-2024-0100",
                    aliases={"GHSA-aaaa-bbbb"},
                    description="a longer and more complete description",
                    fix_versions=[Version("1.2.0")],
                    published=datetime(2024, 1, 1),
                )
            ]
        }
    )
    esms = _StaticService(
        {
            "foo": [
                _result(
                    "GHSA-aaaa-bbbb",
                    description="short",
                    fix_versions=[],
                    published=None,
                )
            ]
        }
    )
    return [("pypi", pypi), ("osv", osv), ("esms", esms)]


def test_merged_service_merges_across_sources(spec):
    services = _three_source_services()
    service = MergedVulnerabilityService(services)

    dep, vulns = service.query(spec("1.0.0"))

    assert len(vulns) == 1
    (vuln,) = vulns
    assert vuln.id == "PYSEC-2024-100"
    assert vuln.aliases == {"CVE-2024-0100", "GHSA-aaaa-bbbb"}
    assert vuln.fix_versions == [Version("1.1.0"), Version("1.2.0")]
    assert vuln.description == "a longer and more complete description"
    assert vuln.published == datetime(2024, 1, 1)
    assert vuln.sources == {"pypi", "osv", "esms"}
    assert not service.partial
    assert service.failed_sources == []


def test_merged_service_queries_each_source_once(spec):
    services = _three_source_services()
    service = MergedVulnerabilityService(services)

    list(service.query_all(iter([spec("1.0.0"), spec("1.0.1")])))

    # Each source is queried at most once per dependency: the merge logic
    # never re-pulls a source.
    for _name, fake in services:
        assert len(fake.queries) == 2


def test_merged_service_output_is_order_independent(spec):
    expected = None
    for permuted in itertools.permutations(_three_source_services()):
        service = MergedVulnerabilityService(list(permuted))
        _, vulns = service.query(spec("1.0.0"))
        snapshot = [(_legacy_fields(v), v.sources) for v in vulns]
        if expected is None:
            expected = snapshot
        else:
            assert snapshot == expected


def test_merged_service_tolerates_source_failure(spec):
    pypi = _StaticService(
        {
            "foo": [
                _result(
                    "PYSEC-2024-100",
                    description="a vulnerability",
                    fix_versions=[Version("1.1.0")],
                )
            ]
        }
    )
    failing = _FailingService()
    service = MergedVulnerabilityService([("pypi", pypi), ("osv", failing)])

    dep, vulns = service.query(spec("1.0.0"))

    # The healthy source's results are still produced...
    assert len(vulns) == 1
    assert vulns[0].id == "PYSEC-2024-100"
    assert vulns[0].sources == {"pypi"}
    # ...and the audit is marked incomplete.
    assert service.partial
    assert service.failed_sources == ["osv"]


def test_merged_service_marks_source_unavailable_after_threshold(spec):
    pypi = _StaticService({"foo": []})
    failing = _FailingService()
    service = MergedVulnerabilityService(
        [("pypi", pypi), ("osv", failing)], max_consecutive_failures=3
    )

    for _ in range(5):
        service.query(spec("1.0.0"))

    # The failing source was queried exactly up to the threshold, then
    # marked unavailable and skipped.
    assert len(failing.queries) == 3
    assert len(pypi.queries) == 5
    assert service.partial
    assert service.failed_sources == ["osv"]


def test_merged_service_success_resets_consecutive_failures(spec):
    class FlakyService(VulnerabilityService):
        def __init__(self):
            self.calls = 0

        def query(self, spec):
            self.calls += 1
            if self.calls % 3 != 0:
                raise ServiceError("flaky")
            return spec, []

    flaky = FlakyService()
    pypi = _StaticService({"foo": []})
    service = MergedVulnerabilityService(
        [("pypi", pypi), ("osv", flaky)], max_consecutive_failures=3
    )

    for _ in range(6):
        service.query(spec("1.0.0"))

    # Two failures, then a success resetting the counter, then two more
    # failures: never three in a row, so the source stays available.
    assert flaky.calls == 6


def test_merged_service_all_sources_failed_raises(spec):
    service = MergedVulnerabilityService([("pypi", _FailingService()), ("osv", _FailingService())])

    # All sources failing must be an explicit failure, not an empty result.
    with pytest.raises(ServiceError):
        service.query(spec("1.0.0"))


def test_merged_service_all_sources_unavailable_raises(spec):
    service = MergedVulnerabilityService(
        [("pypi", _FailingService()), ("osv", _FailingService())],
        max_consecutive_failures=1,
    )

    # The first query marks both sources unavailable...
    with pytest.raises(ServiceError):
        service.query(spec("1.0.0"))

    # ...and subsequent queries fail immediately instead of reporting
    # an empty audit.
    with pytest.raises(ServiceError):
        service.query(spec("1.0.0"))


def test_merged_service_skipped_dependency(spec):
    service = MergedVulnerabilityService(
        [("pypi", _StaticService({})), ("osv", _StaticService({}))]
    )
    skipped = SkippedDependency(name="foo", skip_reason="unit test")

    dep, vulns = service.query(skipped)

    assert dep is skipped
    assert vulns == []


def test_merged_service_propagates_source_level_skip(spec):
    skipped = SkippedDependency(name="foo", skip_reason="not on PyPI")
    pypi = _StaticService({})
    pypi.query = lambda spec: (skipped, [])
    osv = _StaticService({})
    osv.query = lambda spec: (skipped, [])
    service = MergedVulnerabilityService([("pypi", pypi), ("osv", osv)])

    dep, vulns = service.query(spec("1.0.0"))

    assert dep.is_skipped()
    assert vulns == []


def test_merged_service_successful_empty_source_wins_over_skip(spec):
    # One source skips the dependency, but another audits it successfully
    # (finding nothing): the audit stands.
    skipped = SkippedDependency(name="foo", skip_reason="not on PyPI")
    pypi = _StaticService({})
    pypi.query = lambda spec: (skipped, [])
    service = MergedVulnerabilityService([("pypi", pypi), ("osv", _StaticService({}))])

    dep, vulns = service.query(spec("1.0.0"))

    assert not dep.is_skipped()
    assert vulns == []


def test_merged_service_requires_services():
    with pytest.raises(ValueError):
        MergedVulnerabilityService([])

    with pytest.raises(ValueError):
        MergedVulnerabilityService([("pypi", _StaticService({})), ("pypi", _StaticService({}))])


def test_merged_service_single_source_matches_legacy(spec, dep_source):
    # A single-source audit through the merging pipeline must produce exactly
    # the same legacy fields as the current implementation, field by field.
    raw_results = [
        _result(
            "PYSEC-2024-100",
            aliases={"CVE-2024-0100"},
            description="a vulnerability",
            fix_versions=[Version("1.1.0")],
            published=datetime(2024, 1, 1),
        ),
        _result(
            "PYSEC-2024-101",
            description="another vulnerability",
            fix_versions=[Version("2.0.0")],
        ),
    ]
    inner = _StaticService({"foo": raw_results})

    baseline = list(Auditor(inner).audit(dep_source()))
    merged = list(Auditor(MergedVulnerabilityService([("pypi", inner)])).audit(dep_source()))

    assert len(baseline) == len(merged) == 1
    baseline_vulns = sorted(baseline[0][1], key=lambda v: v.id)
    merged_vulns = sorted(merged[0][1], key=lambda v: v.id)
    for want, got in zip(baseline_vulns, merged_vulns):
        assert _legacy_fields(got) == _legacy_fields(want)
        assert got.sources == {"pypi"}


def test_merged_service_counts_malformed_fields(spec):
    bad = VulnerabilityResult(
        id="PYSEC-2024-100",
        description="stub",
        fix_versions=["bogus"],
        aliases=set(),
        published="",
    )
    service = MergedVulnerabilityService(
        [("pypi", _StaticService({"foo": [bad]})), ("osv", _StaticService({}))]
    )

    _, vulns = service.query(spec("1.0.0"))

    # The malformed fields are skipped, the result itself is kept.
    assert len(vulns) == 1
    assert vulns[0].fix_versions == []
    assert vulns[0].published is None
    assert service.warning_count == 2
