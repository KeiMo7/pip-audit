"""
Tests for the explainable, constraint-aware fix-advice engine.

These tests are fully offline: every vulnerability service is an in-memory
double, and every manifest constraint is constructed directly.
"""

from __future__ import annotations

import pytest
from packaging.specifiers import SpecifierSet
from packaging.version import Version

from pip_audit._constraints import (
    ConstraintSnapshotError,
    PackageConstraint,
    snapshot_from_requirement_strings,
    snapshot_from_requirement_files,
)
from pip_audit._fix import (
    ResolvedFixVersion,
    SkippedFixVersion,
    advice_to_fix_version,
    resolve_fix_advice,
    resolve_fix_versions,
    resolve_fix_versions_explained,
)
from pip_audit._fix_advice import (
    AdviceClassification,
    CandidateExclusionReason,
    infer_affected_range,
    resolve_advice,
)
from pip_audit._service import (
    Dependency,
    ResolvedDependency,
    VulnerabilityResult,
    VulnerabilityService,
)
from pip_audit._service.interface import ServiceError


def _vuln(id: str, fix_versions: list[Version], aliases: set[str] | None = None) -> VulnerabilityResult:
    return VulnerabilityResult(
        id=id,
        description="offline test result",
        fix_versions=fix_versions,
        aliases=aliases or set(),
    )


class _ScriptedService(VulnerabilityService):
    """
    A service whose vulnerability table maps package versions to the
    advisories reported at that version.
    """

    def __init__(self, table: dict[Version, list[VulnerabilityResult]] | None = None):
        self._table = table or {}
        self.queries: list[Version] = []

    def query(self, spec: Dependency):
        spec = _as_resolved(spec)
        self.queries.append(spec.version)
        return spec, list(self._table.get(spec.version, []))


class _UnreachableService(VulnerabilityService):
    def query(self, spec: Dependency):
        raise ServiceError("source unreachable")


def _as_resolved(spec: Dependency) -> ResolvedDependency:
    return spec if isinstance(spec, ResolvedDependency) else ResolvedDependency(spec.name, Version("0"))


def _constraint(name: str, specifier: str, source: str = "req.txt:1") -> PackageConstraint:
    return PackageConstraint(name=name, specifier=SpecifierSet(specifier), source=source)


# ---------------------------------------------------------------------------
# 1. Unsorted fix points: ordering must not affect the stable branch choice.
# ---------------------------------------------------------------------------


def test_unsorted_fix_points_choose_nearest_branch():
    service = _ScriptedService()
    dep = ResolvedDependency("foo", Version("1.0.0"))
    # Deliberately shuffled, with the 2.x backport out of order.
    vulns = [_vuln("V1", [Version("2.0.0"), Version("1.0.5"), Version("1.1.0")])]

    advice = resolve_advice(service, dep, vulns)

    assert advice.classification is AdviceClassification.Upgrade
    assert advice.chosen_version == Version("1.0.5")
    # Deterministic across repeated runs and input orderings.
    shuffled = _vuln("V1", list(reversed(vulns[0].fix_versions)))
    again = resolve_advice(service, dep, [shuffled])
    assert again.chosen_version == advice.chosen_version
    superseded = {e.version: e for e in advice.excluded}
    assert superseded[Version("1.1.0")].reason is CandidateExclusionReason.Superseded
    assert superseded[Version("2.0.0")].reason is CandidateExclusionReason.Superseded


def test_unsorted_fix_points_affected_range_derived():
    dep = Version("1.0.2")
    rng = infer_affected_range(dep, [Version("2.0.0"), Version("1.0.5"), Version("1.1.0")])
    assert rng.derived is True
    assert rng.lower is None
    assert rng.upper == Version("1.0.5")
    assert str(rng) == "[*, 1.0.5)"


# ---------------------------------------------------------------------------
# 2. Cross-branch fixes: nearest fix on the current branch, never global min.
# ---------------------------------------------------------------------------


def test_cross_branch_prefers_backport_over_major_upgrade():
    service = _ScriptedService()
    dep = ResolvedDependency("foo", Version("1.5.2"))
    # 1.5.3 is the maintenance-branch backport; 2.0.1 is the next major line.
    vulns = [_vuln("V1", [Version("2.0.1"), Version("1.5.3")])]

    advice = resolve_advice(service, dep, vulns)

    assert advice.chosen_version == Version("1.5.3")
    assert any(
        e.version == Version("2.0.1")
        and e.reason is CandidateExclusionReason.Superseded
        for e in advice.excluded
    )


def test_cross_branch_lower_bound_inferred_from_neighbor():
    # Current version sits between two fix points; the preceding fix point
    # becomes the inferred lower bound of the affected range.
    rng = infer_affected_range(Version("1.5.2"), [Version("1.4.0"), Version("1.5.3"), Version("2.0.0")])
    assert (rng.lower, rng.upper) == (Version("1.4.0"), Version("1.5.3"))


def test_global_minimum_fix_point_must_not_downgrade_newer_branch():
    # The old heuristic took the first fix point greater than the current one
    # from an unsorted list. Here the global minimum (1.10.5) is on an older
    # release line and would downgrade a 2.5.x install.
    service = _ScriptedService()
    dep = ResolvedDependency("pkg", Version("2.5.2"))
    vulns = [_vuln("V1", [Version("1.10.5"), Version("2.5.3")])]

    advice = resolve_advice(service, dep, vulns)

    assert advice.chosen_version == Version("2.5.3")
    rng = advice.affected_ranges[0]
    assert (rng.lower, rng.upper) == (Version("1.10.5"), Version("2.5.3"))
    # The older-line fix is documented as a rejected candidate: it is at or
    # below the current version, so it cannot be an upgrade target.
    assert any(
        e.version == Version("1.10.5")
        and e.reason is CandidateExclusionReason.NotGreater
        for e in advice.excluded
    )


# ---------------------------------------------------------------------------
# 3. Pre-release candidates and withdrawn (invalid) fix points.
# ---------------------------------------------------------------------------


def test_prerelease_candidate_is_flagged_but_stable_prefers_stable():
    service = _ScriptedService()
    dep = ResolvedDependency("foo", Version("1.0.0"))
    # 1.1.0a1 is a pre-release; 1.1.0 is the stable release on the same branch.
    vulns = [_vuln("V1", [Version("1.1.0a1"), Version("1.1.0")])]

    advice = resolve_advice(service, dep, vulns)

    assert advice.chosen_version == Version("1.1.0")
    assert advice.excluded  # the alpha is recorded as superseded


def test_prerelease_only_candidate_is_marked_with_evidence():
    service = _ScriptedService()
    dep = ResolvedDependency("foo", Version("1.0.0"))
    vulns = [_vuln("V1", [Version("1.1.0a1")])]

    advice = resolve_advice(service, dep, vulns)

    assert advice.chosen_version == Version("1.1.0a1")
    assert any(
        e.version == Version("1.1.0a1")
        and e.reason is CandidateExclusionReason.Prerelease
        for e in advice.excluded
    )


def test_withdrawn_invalid_fix_point_degrades_to_undeterminable():
    service = _ScriptedService()
    dep = ResolvedDependency("foo", Version("1.0.0"))
    # A withdrawn/garbled upstream entry arrives as an unparseable string.
    vuln = _vuln("V1", [])
    object.__setattr__(vuln, "fix_versions", ["not-a-version"])  # type: ignore[misc]

    advice = resolve_advice(service, dep, [vuln])

    assert advice.classification is AdviceClassification.Undeterminable
    assert any(
        e.reason is CandidateExclusionReason.InvalidVersion for e in advice.excluded
    )
    # Original hit retained.
    assert {v.id for v in advice.raw_results} == {"V1"}


# ---------------------------------------------------------------------------
# 4. Current version above every fix point: fixed/undeterminable, never
#    "no fix version" error.
# ---------------------------------------------------------------------------


def test_current_above_all_fix_points_is_fixed():
    service = _ScriptedService()
    dep = ResolvedDependency("foo", Version("3.0.0"))
    vulns = [_vuln("V1", [Version("1.0.0"), Version("2.0.0")])]

    advice = resolve_advice(service, dep, vulns)

    assert advice.classification is AdviceClassification.Fixed
    assert advice.chosen_version == Version("3.0.0")
    assert "V1" in advice.vulnerability_ids


# ---------------------------------------------------------------------------
# 5. Manifest upper bound crossed by the fix point: explicit conflict.
# ---------------------------------------------------------------------------


def test_fix_crossing_upper_bound_is_constraint_conflict():
    service = _ScriptedService()
    dep = ResolvedDependency("foo", Version("1.0.0"))
    vulns = [_vuln("V1", [Version("2.0.0")])]
    constraints = [_constraint("foo", "<2.0.0", source="requirements.txt:4")]

    advice = resolve_advice(service, dep, vulns, constraints=constraints)

    assert advice.classification is AdviceClassification.ConstraintConflict
    assert advice.chosen_version is None
    assert advice.blocking_constraints[0].source == "requirements.txt:4"
    assert any(
        e.reason is CandidateExclusionReason.BlockedByConstraint for e in advice.excluded
    )
    assert "relax" in advice.reason


def test_constraint_inside_range_allows_upgrade():
    service = _ScriptedService()
    dep = ResolvedDependency("foo", Version("1.0.0"))
    vulns = [_vuln("V1", [Version("1.5.0")])]
    constraints = [_constraint("foo", "<2.0.0")]

    advice = resolve_advice(service, dep, vulns, constraints=constraints)

    assert advice.classification is AdviceClassification.Upgrade
    assert advice.chosen_version == Version("1.5.0")


# ---------------------------------------------------------------------------
# 6. Two dependencies pulling against each other: mutual conflict report.
# ---------------------------------------------------------------------------


def test_mutual_conflict_lists_both_constraints():
    service = _ScriptedService()
    foo = ResolvedDependency("foo", Version("1.0.0"))
    bar = ResolvedDependency("bar", Version("1.0.0"))
    result: dict[Dependency, list[VulnerabilityResult]] = {
        foo: [_vuln("V-foo", [Version("2.0.0")])],
        bar: [_vuln("V-bar", [Version("3.0.0")])],
    }
    constraints = {
        "foo": [_constraint("foo", "<2.0.0", source="requirements.txt:1")],
        "bar": [_constraint("bar", "<3.0.0", source="requirements.txt:2")],
    }

    advice = list(resolve_fix_advice(service, result, constraints=constraints))
    by_name = {a.dep.canonical_name: a for a in advice}

    assert by_name["foo"].classification is AdviceClassification.ConstraintConflict
    assert by_name["bar"].classification is AdviceClassification.ConstraintConflict
    # Each side carries the other side's blocking constraint.
    foo_others = {entry[0] for entry in by_name["foo"].mutual_conflicts}
    bar_others = {entry[0] for entry in by_name["bar"].mutual_conflicts}
    assert foo_others == {"bar"}
    assert bar_others == {"foo"}


# ---------------------------------------------------------------------------
# 7. Post-resolution re-audit zero-hit; candidates still vulnerable advance.
# ---------------------------------------------------------------------------


def test_reaudit_advances_past_still_vulnerable_candidate():
    # 1.1.0 is a documented fix point for V1 but itself carries V2; the loop
    # must advance to 1.2.0 and only accept once the service reports clean.
    table = {
        Version("1.0.0"): [_vuln("V1", [Version("1.1.0"), Version("1.2.0")])],
        Version("1.1.0"): [_vuln("V2", [Version("1.2.0")])],
        Version("1.2.0"): [],
    }
    service = _ScriptedService(table)
    dep = ResolvedDependency("foo", Version("1.0.0"))

    advice = resolve_advice(service, dep, list(table[Version("1.0.0")]))

    assert advice.classification is AdviceClassification.Upgrade
    assert advice.chosen_version == Version("1.2.0")
    assert any(
        e.version == Version("1.1.0")
        and e.reason is CandidateExclusionReason.ReauditVulnerable
        for e in advice.excluded
    )
    assert service.queries[-1] == Version("1.2.0")


def test_reaudit_budget_is_bounded():
    # Every candidate version stays vulnerable forever.
    table = {
        Version(f"1.{i}.0"): [_vuln(f"V{i}", [Version(f"1.{i + 1}.0")])]
        for i in range(20)
    }
    service = _ScriptedService(table)
    dep = ResolvedDependency("foo", Version("1.0.0"))

    advice = resolve_advice(
        service,
        dep,
        [_vuln("V0", [Version("1.1.0")])],
        max_reaudit_iterations=3,
    )

    assert advice.classification is AdviceClassification.Undeterminable
    assert "re-audit limit of 3" in advice.reason
    # Bounded number of service queries.
    assert len(service.queries) <= 3


# ---------------------------------------------------------------------------
# 8. Source unreachable / missing fields: undeterminable, raw hits retained.
# ---------------------------------------------------------------------------


def test_unreachable_source_degrades_to_undeterminable():
    dep = ResolvedDependency("foo", Version("1.0.0"))
    vulns = [_vuln("V1", [Version("1.1.0")])]

    advice = resolve_advice(_UnreachableService(), dep, vulns)

    assert advice.classification is AdviceClassification.Undeterminable
    assert "unreachable" in advice.reason
    assert {v.id for v in advice.raw_results} == {"V1"}


def test_missing_fix_points_is_undeterminable_but_others_continue():
    service = _ScriptedService()
    good_dep = ResolvedDependency("good", Version("1.0.0"))
    broken_dep = ResolvedDependency("broken", Version("1.0.0")
    )
    result: dict[Dependency, list[VulnerabilityResult]] = {
        good_dep: [_vuln("V-good", [Version("1.1.0")])],
        broken_dep: [_vuln("V-broken", [])],
    }

    advice = list(resolve_fix_advice(service, result))
    by_name = {a.dep.canonical_name: a for a in advice}

    assert by_name["good"].classification is AdviceClassification.Upgrade
    assert by_name["broken"].classification is AdviceClassification.Undeterminable
    assert {v.id for v in by_name["broken"].raw_results} == {"V-broken"}


# ---------------------------------------------------------------------------
# 9. Multiple hits on one dependency merge to the minimum viable version.
# ---------------------------------------------------------------------------


def test_multiple_hits_merge_to_minimum_satisfying_version():
    service = _ScriptedService()
    dep = ResolvedDependency("foo", Version("1.0.0"))
    vulns = [
        _vuln("V1", [Version("1.2.0")]),
        _vuln("V2", [Version("1.5.0")], aliases={"CVE-1"}),
    ]

    advice = resolve_advice(service, dep, vulns)

    assert advice.chosen_version == Version("1.5.0")
    assert advice.vulnerability_ids == {"V1", "V2", "CVE-1"}
    assert any(
        e.version == Version("1.2.0")
        and e.reason is CandidateExclusionReason.Superseded
        for e in advice.excluded
    )


# ---------------------------------------------------------------------------
# 10. Four-class output and legacy compatibility projection.
# ---------------------------------------------------------------------------


def test_advice_projects_to_legacy_fix_version_types():
    service = _ScriptedService()
    dep = ResolvedDependency("foo", Version("1.0.0"))

    upgrade = resolve_advice(service, dep, [_vuln("V1", [Version("1.1.0")])])
    legacy = advice_to_fix_version(upgrade)
    assert legacy == ResolvedFixVersion(dep=dep, version=Version("1.1.0"))
    assert not legacy.is_skipped()

    conflict = resolve_advice(
        service, dep, [_vuln("V1", [Version("2.0.0")])],
        constraints=[_constraint("foo", "<2")],
    )
    legacy_skip = advice_to_fix_version(conflict)
    assert isinstance(legacy_skip, SkippedFixVersion)
    assert legacy_skip.dep == dep
    assert legacy_skip.is_skipped()


def test_legacy_resolve_fix_versions_behavior_unchanged(vuln_service):
    dep = ResolvedDependency(name="foo", version=Version("0.5.0"))
    result: dict[Dependency, list[VulnerabilityResult]] = {
        dep: [_vuln("fake-id", [Version("1.0.0")])]
    }
    fixes = list(resolve_fix_versions(vuln_service(), result))
    assert fixes == [ResolvedFixVersion(dep=dep, version=Version("1.1.0"))]


def test_skipped_dependencies_are_ignored_like_legacy():
    from pip_audit._service import SkippedDependency

    service = _ScriptedService()
    skipped = SkippedDependency(name="foo", skip_reason="editable")
    result: dict[Dependency, list[VulnerabilityResult]] = {
        skipped: [_vuln("V1", [Version("1.0.0")])],
    }
    assert list(resolve_fix_advice(service, result)) == []
    assert list(resolve_fix_versions(service, result)) == []


# ---------------------------------------------------------------------------
# Every classification carries a human-readable reason and an evidence trail.
# ---------------------------------------------------------------------------


def test_every_classification_has_reason_and_evidence():
    service = _ScriptedService()
    dep = ResolvedDependency("foo", Version("1.0.0"))

    cases = [
        # upgrade
        ([_vuln("V1", [Version("1.1.0")])], {}, AdviceClassification.Upgrade),
        # constraint conflict
        ([_vuln("V1", [Version("2.0.0")])],
         {"foo": [_constraint("foo", "<2")]}, AdviceClassification.ConstraintConflict),
        # undeterminable
        ([_vuln("V1", [])], {}, AdviceClassification.Undeterminable),
        # fixed (current above every fix point)
        None,
    ]

    for vulns, extra, expected in cases[:3]:
        advice = resolve_advice(service, dep, vulns, constraints=extra.get("foo", []))
        assert advice.classification is expected
        assert advice.reason
        assert advice.vulnerability_ids
        assert advice.affected_ranges

    fixed = resolve_advice(
        service, ResolvedDependency("foo", Version("3.0.0")),
        [_vuln("V1", [Version("1.0.0"), Version("2.0.0")])],
    )
    assert fixed.classification is AdviceClassification.Fixed
    assert fixed.reason


def test_classification_tally_is_recomputable_from_advice():
    service = _ScriptedService()
    result: dict[Dependency, list[VulnerabilityResult]] = {
        ResolvedDependency("a", Version("1.0.0")): [_vuln("Va", [Version("1.1.0")])],
        ResolvedDependency("b", Version("1.0.0")): [_vuln("Vb", [])],
        ResolvedDependency("c", Version("1.0.0")): [_vuln("Vc", [Version("2.0.0")])],
    }
    constraints = {"c": [_constraint("c", "<2")]}

    advice = list(resolve_fix_advice(service, result, constraints=constraints))
    tally: dict[str, int] = {}
    for a in advice:
        tally[a.classification.value] = tally.get(a.classification.value, 0) + 1

    assert tally == {
        AdviceClassification.Upgrade.value: 1,
        AdviceClassification.Undeterminable.value: 1,
        AdviceClassification.ConstraintConflict.value: 1,
    }
    assert sum(tally.values()) == len(advice)


def test_explained_pairs_legacy_and_advice(vuln_service):
    dep = ResolvedDependency(name="foo", version=Version("0.5.0"))
    result: dict[Dependency, list[VulnerabilityResult]] = {
        dep: [_vuln("fake-id", [Version("1.0.0")])]
    }
    paired = list(resolve_fix_versions_explained(vuln_service(), result))
    assert len(paired) == 1
    legacy, advice = paired[0]
    assert legacy == ResolvedFixVersion(dep=dep, version=Version("1.1.0"))
    assert advice.classification is AdviceClassification.Upgrade
    assert "fake-id" in advice.vulnerability_ids


# ---------------------------------------------------------------------------
# Local version segments follow PEP 440, not string ordering.
# ---------------------------------------------------------------------------


def test_local_and_pep440_ordering():
    # String ordering would put "1.10.0" before "1.9.0"; PEP 440 does not.
    rng = infer_affected_range(Version("1.9.1"), [Version("1.10.0"), Version("1.9.2")])
    assert rng.upper == Version("1.9.2")

    rng_local = infer_affected_range(
        Version("1.0.0+local.1"), [Version("1.0.1"), Version("1.0.0+local.2")]
    )
    assert rng_local.upper == Version("1.0.0+local.2")


# ---------------------------------------------------------------------------
# Offline constraint snapshots from requirement strings and files.
# ---------------------------------------------------------------------------


def test_snapshot_from_requirement_strings():
    snapshot = snapshot_from_requirement_strings(
        ["foo<2.0", "bar>=1.0 # comment", "# whole-line comment"]
    )
    assert "foo" in snapshot and "bar" in snapshot
    assert str(snapshot["foo"][0].specifier) == "<2.0"
    assert snapshot["bar"][0].blocks(Version("0.9"))
    assert not snapshot["bar"][0].blocks(Version("1.5"))


def test_snapshot_rejects_conflicting_duplicates(req_file):
    path = req_file()
    path.write_text("foo<2.0\nfoo>=3.0\n")
    with pytest.raises(ConstraintSnapshotError):
        snapshot_from_requirement_files([path])


def test_snapshot_tolerates_identical_duplicates(req_file):
    path = req_file()
    path.write_text("foo<2.0\nfoo<2.0\n")
    snapshot = snapshot_from_requirement_files([path])
    assert len(snapshot["foo"]) == 2


# ---------------------------------------------------------------------------
# End-to-end through a real RequirementSource snapshot: an upper bound that
# every fix point crosses must report a conflict without touching the file.
# ---------------------------------------------------------------------------


def test_requirement_source_conflict_keeps_manifest_bytes(req_file):
    from pip_audit._dependency_source.requirement import RequirementSource

    path = req_file()
    original = "foo<1.1.0\n"
    path.write_text(original)
    before = path.read_bytes()

    source = RequirementSource([path])
    constraints = source.constraint_snapshot()

    service = _ScriptedService()
    dep = ResolvedDependency("foo", Version("1.0.0"))
    result: dict[Dependency, list[VulnerabilityResult]] = {
        dep: [_vuln("V1", [Version("1.2.0"), Version("2.0.0")])]
    }

    advice = list(resolve_fix_advice(service, result, constraints=constraints))
    assert len(advice) == 1
    assert advice[0].classification is AdviceClassification.ConstraintConflict
    assert advice[0].blocking_constraints[0].specifier == SpecifierSet("<1.1.0")

    # No fix was applied and the manifest is byte-for-byte untouched.
    assert path.read_bytes() == before
    # The legacy projection is a skip, never an uninstallable version.
    legacy = advice_to_fix_version(advice[0])
    assert isinstance(legacy, SkippedFixVersion)
