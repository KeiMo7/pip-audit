"""
Field-level merging of vulnerability results from multiple sources.

This module is the single implementation point for every conflict-resolution
rule used when combining vulnerability results that different sources report
for the same underlying vulnerability:

* Clustering (deduplication) is purely identifier-based: two results belong to
  the same cluster iff their identifier sets (`{id} | aliases`, normalized)
  are connected, transitively. Field values never influence clustering, so
  clusters never split over field differences and cyclic alias relations
  converge.
* The primary identifier is chosen by identifier-scheme priority
  (`PYSEC` > `CVE` > everything else), then lexicographically. It never
  depends on the order in which sources or results were supplied.
* Identifiers are normalized (case, surrounding whitespace) for comparison,
  but the original spelling is preserved for display.
* `fix_versions` are unioned, deduplicated and sorted; a source that lacks
  the field never clears another source's data.
* `description` conflicts resolve by: most complete (non-placeholder) first,
  then longest, then highest-priority source.
* `published` resolves to the earliest non-empty value, or stays empty.
* Every merged result records the set of sources that contributed to it.

All rules are total and deterministic: shuffling source order or result
order yields exactly the same merged output.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any

from packaging.version import InvalidVersion, Version

from pip_audit._service.interface import VulnerabilityID, VulnerabilityResult, VulnerabilityService

logger = logging.getLogger(__name__)

# Fixed, source-name-based priority ranking, used as the final tie-break when
# merging conflicting fields. It is deliberately keyed by source identity
# (not configuration order) so that the merged output does not depend on the
# order in which sources were supplied.
_SOURCE_PRIORITY: dict[str, int] = {
    "pypi": 3,
    "osv": 2,
    "esms": 1,
}


def source_priority(source: str) -> int:
    """
    Return the merge priority of the named source. Higher wins.
    """
    return _SOURCE_PRIORITY.get(source, 0)


def normalize_id(id: str) -> str:
    """
    Return the comparison form of a vulnerability identifier.

    Identifiers are compared case-insensitively and ignoring surrounding
    whitespace; the original spelling is always preserved for display.
    """
    return id.strip().casefold()


def _scheme_priority(normalized_id: str) -> int:
    """
    Return the identifier-scheme priority of a normalized identifier.
    """
    if normalized_id.startswith("pysec"):
        return 1
    if normalized_id.startswith("cve"):
        return 2
    return 3


def _primary_id_key(display_id: str) -> tuple[int, str, str]:
    """
    The total ordering key for primary-identifier selection: scheme priority
    first, then lexicographic (on the normalized form, with the original
    spelling as the final tie-break for full determinism).
    """
    normalized = normalize_id(display_id)
    return (_scheme_priority(normalized), normalized, display_id)


@dataclass
class MergeStats:
    """
    Counters for anomalies encountered while merging.
    """

    malformed_fields: int = 0
    """
    The number of malformed individual fields that were skipped (rather than
    discarding the result they belonged to).
    """


def _sanitize_fix_versions(
    source: str, result: VulnerabilityResult, stats: MergeStats
) -> list[Version]:
    fix_versions: list[Version] = []
    # NOTE: typed as `Any` so that ill-typed data from a misbehaving source
    # is handled at runtime instead of being assumed away.
    raw_fix_version: Any
    for raw_fix_version in result.fix_versions:
        if isinstance(raw_fix_version, Version):
            fix_versions.append(raw_fix_version)
            continue
        # Defensive: a source handed us something that isn't a `Version`.
        # Skip just this field value instead of discarding the whole result.
        try:
            fix_versions.append(Version(str(raw_fix_version)))
        except InvalidVersion:
            logger.warning(
                f"{source}: dropping unparseable fix version "
                f"{raw_fix_version!r} for {result.id}; keeping the rest of the result"
            )
            stats.malformed_fields += 1
    return sorted(set(fix_versions))


def _sanitize_published(
    source: str, result: VulnerabilityResult, stats: MergeStats
) -> datetime | None:
    # NOTE: typed as `Any` so that ill-typed data from a misbehaving source
    # is handled at runtime instead of being assumed away.
    published: Any = result.published
    if published is None or isinstance(published, datetime):
        return published
    # Defensive: a source handed us a raw (or empty) timestamp string.
    # Skip just this field instead of discarding the whole result.
    if isinstance(published, str):
        if not published.strip():
            logger.warning(
                f"{source}: dropping empty published timestamp for {result.id}; "
                "keeping the rest of the result"
            )
            stats.malformed_fields += 1
            return None
        try:
            return VulnerabilityService._parse_rfc3339(published)
        except ValueError:
            pass
    logger.warning(
        f"{source}: dropping malformed published timestamp "
        f"{published!r} for {result.id}; keeping the rest of the result"
    )
    stats.malformed_fields += 1
    return None


def sanitize_result(
    source: str, result: VulnerabilityResult, stats: MergeStats
) -> VulnerabilityResult:
    """
    Return a copy of `result` with malformed individual fields dropped.

    A malformed field (an unparseable version, an empty timestamp) never
    discards the whole result; it is skipped and counted in `stats`.
    """
    return replace(
        result,
        fix_versions=_sanitize_fix_versions(source, result, stats),
        published=_sanitize_published(source, result, stats),
    )


def _description_completeness(description: str) -> int:
    """
    Score a description's completeness: placeholder descriptions
    (empty or "N/A") score lower than any real content.
    """
    stripped = description.strip()
    if not stripped or stripped == "N/A":
        return 0
    return 1


def _select_description(sourced_results: list[tuple[str, VulnerabilityResult]]) -> str:
    """
    Choose the description for a merged result: most complete first, then
    longest, then highest-priority source. The source name and the text
    itself are final tie-breaks so the choice is fully deterministic.
    """
    return max(
        sourced_results,
        key=lambda sr: (
            _description_completeness(sr[1].description),
            len(sr[1].description),
            source_priority(sr[0]),
            sr[0],
            sr[1].description,
        ),
    )[1].description


class _UnionFind:
    """
    A union-find over normalized identifiers, with deterministic root choice
    (the lexicographically smaller root always wins) so that clustering does
    not depend on the order of operations. Cycles converge by construction.
    """

    def __init__(self) -> None:
        self._parent: dict[str, str] = {}

    def find(self, item: str) -> str:
        self._parent.setdefault(item, item)
        root = item
        while self._parent[root] != root:
            root = self._parent[root]
        # Path compression.
        while self._parent[item] != root:
            self._parent[item], item = root, self._parent[item]
        return root

    def union(self, left: str, right: str) -> None:
        left_root, right_root = self.find(left), self.find(right)
        if left_root == right_root:
            return
        if left_root < right_root:
            self._parent[right_root] = left_root
        else:
            self._parent[left_root] = right_root


def _merge_cluster(cluster: list[tuple[str, VulnerabilityResult]]) -> VulnerabilityResult:
    """
    Merge all (source, result) pairs of a single identifier cluster into one
    `VulnerabilityResult`, applying each field's conflict-resolution rule.
    """
    # Collect every identifier spelling in the cluster, choosing one
    # deterministic original spelling per normalized identifier for display.
    spellings: dict[str, VulnerabilityID] = {}
    for _source, result in cluster:
        for original in {result.id, *result.aliases}:
            normalized = normalize_id(original)
            if normalized not in spellings:
                spellings[normalized] = original
            else:
                spellings[normalized] = min(spellings[normalized], original)

    display_ids = sorted(spellings.values(), key=_primary_id_key)
    primary = display_ids[0]
    # No identifier may disappear: every merged-in identifier that isn't the
    # primary becomes an alias.
    aliases = set(display_ids[1:])

    # Union of fix versions; a source missing the field contributes nothing
    # and therefore cannot clear another source's list.
    fix_versions = sorted({fv for _source, result in cluster for fv in result.fix_versions})

    description = _select_description(cluster)

    published_values = [r.published for _s, r in cluster if r.published is not None]
    published = min(published_values) if published_values else None

    sources = frozenset(source for source, _result in cluster)

    return VulnerabilityResult(
        id=primary,
        description=description,
        fix_versions=fix_versions,
        aliases=aliases,
        published=published,
        sources=sources,
    )


def merge_results(
    sourced_results: Iterable[tuple[str, VulnerabilityResult]],
    stats: MergeStats | None = None,
) -> list[VulnerabilityResult]:
    """
    Merge `(source, result)` pairs from one or more vulnerability sources into
    a single deduplicated, deterministically ordered list of results.

    The output does not depend on the order of `sourced_results`: shuffling
    sources or individual results yields the same merged list.
    """
    if stats is None:
        stats = MergeStats()

    sourced = [
        (source, sanitize_result(source, result, stats)) for source, result in sourced_results
    ]

    # Cluster purely on normalized identifiers: union every identifier that
    # appears in the same result, then group results by their cluster root.
    union_find = _UnionFind()
    for _source, result in sourced:
        ids = [normalize_id(id) for id in {result.id, *result.aliases}]
        for other in ids[1:]:
            union_find.union(ids[0], other)

    clusters: dict[str, list[tuple[str, VulnerabilityResult]]] = {}
    for source, result in sourced:
        root = union_find.find(normalize_id(result.id))
        clusters.setdefault(root, []).append((source, result))

    merged = [_merge_cluster(cluster) for cluster in clusters.values()]
    merged.sort(key=lambda result: _primary_id_key(result.id))
    return merged
