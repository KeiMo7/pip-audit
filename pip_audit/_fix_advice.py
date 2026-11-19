"""
Explainable, constraint-aware fix-advice resolution.

This module is the successor to the naive "first fix version greater than the
current version" heuristic in `pip_audit._fix`. Every piece of advice it emits
carries the evidence needed to audit the decision:

* the affected version range (derived from neighboring fix points when the
  vulnerability source does not provide one);
* the vulnerability identifiers that motivated the advice;
* the fix point that was chosen and every candidate that was rejected, with
  the reason for each rejection;
* the manifest constraints that block installation, when no candidate fits.

All version comparisons go through `packaging.version.Version`, i.e. PEP 440
ordering including pre-release and local-version segments. Nothing in this
module performs network access: range inference and constraint checking are
fully offline; the only I/O is re-querying the supplied vulnerability service,
which may itself be cached/offline.
"""

from __future__ import annotations

import enum
import logging
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, replace
from typing import cast

from packaging.version import InvalidVersion, Version

from pip_audit._constraints import PackageConstraint
from pip_audit._service import (
    Dependency,
    ResolvedDependency,
    VulnerabilityResult,
    VulnerabilityService,
)
from pip_audit._service.interface import ServiceError
from pip_audit._state import AuditState

logger = logging.getLogger(__name__)

# Upper bound on the number of service re-queries performed while chasing a
# fix version that is itself vulnerable. This keeps advice generation bounded
# on large dependency graphs and against adversarial fix-point lists.
DEFAULT_MAX_REAUDIT_ITERATIONS = 10


class AdviceClassification(str, enum.Enum):
    """
    The four externally visible classifications of a piece of fix advice.

    * `Fixed`           – the current version is already above every published
                          fix point, i.e. the advisory does not apply to it.
    * `Upgrade`         – a concrete installable fix version was resolved.
    * `ConstraintConflict` – a fix exists but the manifest constraints exclude
                          every candidate; the manifest must be relaxed.
    * `Undeterminable`  – the available data does not support a decision
                          (missing/broken advisory fields, unreachable source,
                          or the re-audit budget was exhausted).
    """

    Fixed = "fixed"
    Upgrade = "upgrade"
    ConstraintConflict = "constraint-conflict"
    Undeterminable = "undeterminable"


class CandidateExclusionReason(str, enum.Enum):
    """
    Why an individual fix-point candidate was rejected.
    """

    NotGreater = "not-greater-than-current"
    Prerelease = "pre-release-not-accepted"
    Duplicate = "duplicate-fix-point"
    ReauditVulnerable = "re-audit-still-vulnerable"
    BlockedByConstraint = "blocked-by-manifest-constraint"
    Superseded = "superseded-by-later-branch-fix"
    InvalidVersion = "invalid-version"


@dataclass(frozen=True)
class AffectedRange:
    """
    The version interval in which an advisory applies.

    Ranges are derived offline. `lower`/`upper` may be `None`, meaning the
    interval is open on that side. `derived` records whether the bounds had to
    be inferred from neighboring fix points rather than read from the advisory.
    """

    lower: Version | None
    upper: Version | None
    derived: bool = True

    def __str__(self) -> str:
        lo = "*" if self.lower is None else str(self.lower)
        hi = "*" if self.upper is None else str(self.upper)
        return f"[{lo}, {hi})"


@dataclass(frozen=True)
class ExcludedCandidate:
    """
    A rejected fix-point candidate together with the reason for rejection.
    """

    version: Version | None
    reason: CandidateExclusionReason
    detail: str
    vulnerability_ids: frozenset[str] = frozenset()


@dataclass(frozen=True)
class FixAdvice:
    """
    An explainable fix recommendation for a single dependency.

    All fields are additive with respect to the legacy
    `ResolvedFixVersion`/`SkippedFixVersion` pair.
    """

    dep: ResolvedDependency
    classification: AdviceClassification
    vulnerability_ids: frozenset[str]
    affected_ranges: tuple[AffectedRange, ...]
    chosen_version: Version | None
    excluded: tuple[ExcludedCandidate, ...]
    blocking_constraints: tuple[PackageConstraint, ...] = ()
    mutual_conflicts: tuple[tuple[str, str, str], ...] = ()
    reason: str = ""
    # The raw vulnerability hits that produced this advice, retained verbatim
    # so undeterminable outcomes never lose the original finding.
    raw_results: tuple[VulnerabilityResult, ...] = ()

    def is_skipped(self) -> bool:
        """
        Mirror `FixVersion.is_skipped`: conflict and undeterminable advice
        cannot be applied automatically.
        """
        return self.classification in (
            AdviceClassification.ConstraintConflict,
            AdviceClassification.Undeterminable,
        )


@dataclass(frozen=True)
class _ParsedFixPoints:
    valid: tuple[Version, ...]
    invalid: tuple[ExcludedCandidate, ...]


def _parse_fix_points(vuln: VulnerabilityResult) -> _ParsedFixPoints:
    """
    Normalize one advisory's fix-point list.

    The upstream list is not trusted to be sorted, unique, or even parseable.
    PEP 440 `Version` construction provides the ecosystem ordering (including
    pre-release and local segments); unparseable entries are recorded as
    exclusions rather than crashing the whole dependency's resolution.
    """
    valid: list[Version] = []
    invalid: list[ExcludedCandidate] = []
    ids = frozenset({vuln.id, *vuln.aliases})

    # Upstream data is not guaranteed to be well-typed even though the service
    # interface declares `Version`, so treat entries as opaque objects here.
    raw_points: list[object] = list(vuln.fix_versions)
    for raw in raw_points:
        if isinstance(raw, Version):
            version = raw
        else:
            try:
                version = Version(str(raw))
            except InvalidVersion as e:
                invalid.append(
                    ExcludedCandidate(
                        version=None,
                        reason=CandidateExclusionReason.InvalidVersion,
                        detail=f"fix point {raw!r} is not a valid PEP 440 version: {e}",
                        vulnerability_ids=ids,
                    )
                )
                continue
        valid.append(version)
    return _ParsedFixPoints(tuple(valid), tuple(invalid))


def infer_affected_range(
    current: Version, fix_points: Sequence[Version]
) -> AffectedRange:
    """
    Infer the affected range of `current` from an ordered set of fix points.

    With only "fixed at" data, the defensible interpretation is that each fix
    point closes the interval opened by the preceding fix point: the current
    version is affected on the maintenance branch whose fix point is the
    smallest one strictly greater than it. This works entirely offline.
    """
    ordered = sorted(set(fix_points))
    upper = next((fp for fp in ordered if fp > current), None)
    if upper is None:
        # Above every published fix point: the advisory data cannot place the
        # current version in an affected interval.
        idx = len(ordered)
    else:
        idx = ordered.index(upper)
    lower = ordered[idx - 1] if idx > 0 else None
    return AffectedRange(lower=lower, upper=upper, derived=True)


def _branch_fix_point(
    current: Version,
    fix_points: Sequence[Version],
    exclusions: list[ExcludedCandidate],
    ids: frozenset[str],
) -> Version | None:
    """
    Select the fix point on the current version's maintenance branch.

    The "nearest" fix point — the smallest fix point strictly greater than the
    current version under PEP 440 ordering — is the fix on the branch the
    current version lives on. Taking the global minimum instead would yank a
    1.5.x install onto a 2.x release line that maintained its own backport.

    Pre-release fix points are only chosen when no stable (non pre-release)
    candidate exists on the branch: a pre-release that shares a release
    segment with a later stable release is an abandoned preview, not the
    maintained fix.
    """
    ordered = sorted(set(fix_points))
    greater = [fp for fp in ordered if fp > current]
    not_greater = [fp for fp in ordered if fp <= current]
    # Fix points at or below the current version can never be an upgrade;
    # record them so a globally-minimum fix point on an older release line is
    # explained rather than silently ignored.
    for older in not_greater:
        exclusions.append(
            ExcludedCandidate(
                version=older,
                reason=CandidateExclusionReason.NotGreater,
                detail=(
                    f"fix point {older} is at or below the current version {current} and "
                    "cannot be an upgrade target"
                ),
                vulnerability_ids=ids,
            )
        )
    if not greater:
        return None

    stable_greater = [fp for fp in greater if not fp.is_prerelease]
    chosen_pool = stable_greater if stable_greater else greater
    chosen = chosen_pool[0]

    # Record every skipped fix point as a deliberate choice, making the
    # branch/pre-release decision auditable.
    for other in greater:
        if other == chosen:
            continue
        if other.is_prerelease and stable_greater:
            reason = CandidateExclusionReason.Prerelease
            detail = (
                f"pre-release fix point {other} has a stable successor on the same branch; "
                f"{chosen} is preferred"
            )
        else:
            reason = CandidateExclusionReason.Superseded
            detail = (
                f"fix point {other} is on a newer maintenance branch than the current "
                f"version {current}; {chosen} is the nearest fix on this branch"
            )
        exclusions.append(
            ExcludedCandidate(
                version=other,
                reason=reason,
                detail=detail,
                vulnerability_ids=ids,
            )
        )
    return chosen


def _merge_excluded(existing: list[ExcludedCandidate]) -> tuple[ExcludedCandidate, ...]:
    """
    Deduplicate exclusion records while preserving first-seen order.
    """
    seen: set[tuple[Version | None, CandidateExclusionReason, str]] = set()
    merged: list[ExcludedCandidate] = []
    for exc in existing:
        key = (exc.version, exc.reason, exc.detail)
        if key in seen:
            continue
        seen.add(key)
        merged.append(exc)
    return tuple(merged)


def _blocking(
    constraints: Sequence[PackageConstraint], version: Version
) -> list[PackageConstraint]:
    return [c for c in constraints if c.blocks(version)]


def _undeterminable(
    dep: ResolvedDependency,
    vulns: Sequence[VulnerabilityResult],
    ranges: list[AffectedRange],
    excluded: list[ExcludedCandidate],
    reason: str,
) -> FixAdvice:
    return FixAdvice(
        dep=dep,
        classification=AdviceClassification.Undeterminable,
        vulnerability_ids=frozenset(v.id for v in vulns),
        affected_ranges=tuple(ranges),
        chosen_version=None,
        excluded=_merge_excluded(excluded),
        reason=reason,
        raw_results=tuple(vulns),
    )


def resolve_advice(
    service: VulnerabilityService,
    dep: ResolvedDependency,
    vulns: list[VulnerabilityResult],
    *,
    constraints: Sequence[PackageConstraint] = (),
    state: AuditState = AuditState(),
    max_reaudit_iterations: int = DEFAULT_MAX_REAUDIT_ITERATIONS,
) -> FixAdvice:
    """
    Resolve a single dependency's vulnerabilities into explainable fix advice.

    See the module docstring for the evidence contract. This routine never
    raises on malformed advisory data: damaged entries degrade to
    `Undeterminable` while the original hits are retained on `raw_results`.
    """
    all_ids = (
        frozenset().union(*({v.id, *v.aliases} for v in vulns))
        if vulns
        else frozenset()
    )
    excluded: list[ExcludedCandidate] = []
    ranges: list[AffectedRange] = []

    # ---- 1. Validate advisory entries and collect usable fix points. --------
    per_vuln_points: dict[str, tuple[Version, ...]] = {}
    for vuln in vulns:
        parsed = _parse_fix_points(vuln)
        excluded.extend(parsed.invalid)
        if not parsed.valid:
            # No usable fix point (missing list or every entry damaged): this
            # entry alone makes an automatic decision impossible.
            if not vuln.fix_versions:
                reason = (
                    f"failed to fix dependency {dep.name} ({dep.version}), unable to find fix "
                    f"version for vulnerability {vuln.id}"
                )
            else:
                reason = (
                    f"failed to fix dependency {dep.name} ({dep.version}): every published fix "
                    f"point for vulnerability {vuln.id} is malformed"
                )
            ranges.append(
                AffectedRange(lower=None, upper=None, derived=True)
            )
            return _undeterminable(dep, vulns, ranges, excluded, reason)
        per_vuln_points[vuln.id] = parsed.valid
        ranges.append(infer_affected_range(dep.version, parsed.valid))

    # ---- 2. Branch-aware candidate per advisory. ----------------------------
    branch_choices: dict[str, Version] = {}
    for vuln in vulns:
        points = per_vuln_points[vuln.id]
        ids = frozenset({vuln.id, *vuln.aliases})
        choice = _branch_fix_point(dep.version, points, excluded, ids)
        if choice is None:
            # Current version is above every fix point of this advisory. If
            # every advisory agrees, the finding is not applicable; otherwise
            # another entry still drives an upgrade.
            continue
        branch_choices[vuln.id] = choice

    if not branch_choices:
        # All advisories' fix points are at or below the current version.
        return FixAdvice(
            dep=dep,
            classification=AdviceClassification.Fixed,
            vulnerability_ids=all_ids,
            affected_ranges=tuple(ranges),
            chosen_version=dep.version,
            excluded=_merge_excluded(excluded),
            reason=(
                f"{dep.name} {dep.version} is at or above every published fix point; "
                "the advisory's affected range does not cover this version"
            ),
            raw_results=tuple(vulns),
        )

    # ---- 3. Merge multiple hits: the minimum version satisfying all. --------
    candidate = max(branch_choices.values())
    # Record the per-advisory branch fix points that lose the merge.
    for vid, choice in branch_choices.items():
        if choice < candidate:
            excluded.append(
                ExcludedCandidate(
                    version=choice,
                    reason=CandidateExclusionReason.Superseded,
                    detail=(
                        f"branch fix {choice} for {vid} does not satisfy all hits; "
                        f"{candidate} is the minimum version covering every advisory"
                    ),
                    vulnerability_ids=frozenset({vid}),
                )
            )

    # ---- 4. Bounded re-audit loop with constraint checking. -----------------
    current_version = candidate
    tried: set[Version] = set()
    last_vuln_ids: frozenset[str] = frozenset()

    for iteration in range(max_reaudit_iterations):
        state.update_state(
            f"Resolving fix version for {dep.name}, checking {current_version}"
        )

        # Constraint gate: never recommend a version the manifest cannot install.
        blocked = _blocking(constraints, current_version)
        if blocked:
            for constraint in blocked:
                excluded.append(
                    ExcludedCandidate(
                        version=current_version,
                        reason=CandidateExclusionReason.BlockedByConstraint,
                        detail=(
                            f"{constraint.source} constrains {constraint.name} with "
                            f"{constraint.specifier}, which excludes {current_version}"
                        ),
                        vulnerability_ids=all_ids,
                    )
                )
            return FixAdvice(
                dep=dep,
                classification=AdviceClassification.ConstraintConflict,
                vulnerability_ids=all_ids,
                affected_ranges=tuple(ranges),
                chosen_version=None,
                excluded=_merge_excluded(excluded),
                blocking_constraints=tuple(blocked),
                reason=(
                    f"no fix version for {dep.name} is installable under the manifest "
                    f"constraints; the manifest upper bound must be relaxed to allow "
                    f"{current_version} or later"
                ),
                raw_results=tuple(vulns),
            )

        if current_version.is_prerelease:
            excluded.append(
                ExcludedCandidate(
                    version=current_version,
                    reason=CandidateExclusionReason.Prerelease,
                    detail=(
                        f"{current_version} is a pre-release and no stable fix is documented; "
                        "it is retained only because no alternative candidate exists"
                    ),
                    vulnerability_ids=all_ids,
                )
            )

        if current_version in tried:
            return _undeterminable(
                dep,
                vulns,
                ranges,
                excluded,
                f"fix resolution for {dep.name} cycled back to {current_version}",
            )
        tried.add(current_version)

        try:
            _, reaudit = service.query(ResolvedDependency(dep.name, current_version))
        except ServiceError as e:
            return _undeterminable(
                dep,
                vulns,
                ranges,
                excluded,
                f"vulnerability source unavailable while re-auditing {current_version}: {e}",
            )

        if not reaudit:
            return FixAdvice(
                dep=dep,
                classification=AdviceClassification.Upgrade,
                vulnerability_ids=all_ids,
                affected_ranges=tuple(ranges),
                chosen_version=current_version,
                excluded=_merge_excluded(excluded),
                reason=(
                    f"upgrading {dep.name} {dep.version} to {current_version} clears all "
                    f"{len(all_ids)} matching advisories and re-audits clean"
                ),
                raw_results=tuple(vulns),
            )

        # Still vulnerable: record the failed candidate and advance to the
        # nearest branch fix point of whichever advisory remains.
        last_vuln_ids = frozenset(v.id for v in reaudit)
        excluded.append(
            ExcludedCandidate(
                version=current_version,
                reason=CandidateExclusionReason.ReauditVulnerable,
                detail=(
                    f"re-audit of {current_version} still reports "
                    f"{', '.join(sorted(last_vuln_ids))}"
                ),
                vulnerability_ids=last_vuln_ids,
            )
        )

        next_points: list[Version] = []
        damaged = False
        for remaining in reaudit:
            parsed = _parse_fix_points(remaining)
            excluded.extend(parsed.invalid)
            if not parsed.valid:
                damaged = True
                continue
            choice = _branch_fix_point(
                current_version,
                parsed.valid,
                excluded,
                frozenset({remaining.id, *remaining.aliases}),
            )
            if choice is not None:
                next_points.append(choice)

        if damaged and not next_points:
            return _undeterminable(
                dep,
                vulns,
                ranges,
                excluded,
                f"re-audit of {current_version} surfaced an advisory with no usable fix point",
            )
        if not next_points:
            # Remaining advisories have no fix point above the candidate.
            return _undeterminable(
                dep,
                vulns,
                ranges,
                excluded,
                (
                    f"re-audit of {current_version} still reports "
                    f"{', '.join(sorted(last_vuln_ids))} and no later fix point exists"
                ),
            )

        current_version = max(next_points)

    # Budget exhausted.
    return _undeterminable(
        dep,
        vulns,
        ranges,
        excluded,
        (
            f"fix resolution for {dep.name} exceeded the re-audit limit of "
            f"{max_reaudit_iterations}; last checked {current_version} which still reports "
            f"{', '.join(sorted(last_vuln_ids)) or 'vulnerabilities'}"
        ),
    )


def resolve_all_advice(
    service: VulnerabilityService,
    result: dict[Dependency, list[VulnerabilityResult]],
    *,
    constraints: dict[str, list[PackageConstraint]] | None = None,
    state: AuditState = AuditState(),
    max_reaudit_iterations: int = DEFAULT_MAX_REAUDIT_ITERATIONS,
) -> Iterator[FixAdvice]:
    """
    Resolve fix advice for every vulnerable dependency in `result`.

    Skipped dependencies and dependency-free entries are ignored, matching the
    legacy `resolve_fix_versions` behavior. Constraint conflicts between two
    dependencies (each side blocked by the manifest the other's upgrade also
    has to satisfy) are reported together with both constraints listed.
    """
    constraints = constraints or {}
    advice_by_name: dict[str, FixAdvice] = {}

    for dep, vulns in result.items():
        if dep.is_skipped() or not vulns:
            continue
        dep = cast(ResolvedDependency, dep)
        dep_constraints = constraints.get(dep.canonical_name, [])
        advice = resolve_advice(
            service,
            dep,
            vulns,
            constraints=dep_constraints,
            state=state,
            max_reaudit_iterations=max_reaudit_iterations,
        )
        advice_by_name[dep.canonical_name] = advice

    # Cross-dependency mutual-conflict linkage: every constraint-blocked
    # package is shown the constraints blocking every other blocked package,
    # so both sides of a tug-of-war are visible on each report.
    blocked = {
        name: a
        for name, a in advice_by_name.items()
        if a.classification is AdviceClassification.ConstraintConflict
    }
    if len(blocked) > 1:
        for name, advice in blocked.items():
            others = tuple(
                (
                    other_name,
                    str(c.specifier),
                    c.source,
                )
                for other_name, other in blocked.items()
                if other_name != name
                for c in other.blocking_constraints
            )
            if others:
                advice_by_name[name] = replace(
                    advice,
                    mutual_conflicts=others,
                    reason=(
                        advice.reason
                        + "; additionally blocked alongside "
                        + ", ".join(sorted({o[0] for o in others}))
                    ),
                )

    yield from advice_by_name.values()
