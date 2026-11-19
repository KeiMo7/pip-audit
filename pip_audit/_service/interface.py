"""
Interfaces for interacting with vulnerability services, i.e. sources
of vulnerability information for fully resolved Python packages.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any, NewType

from packaging.utils import canonicalize_name
from packaging.version import Version

VulnerabilityID = NewType("VulnerabilityID", str)

# Canonical severity ranking, shared by every vulnerability service (online
# and offline alike) so that severity-based ordering is consistent regardless
# of where the vulnerability data came from.
#
# NOTE: This ranking is only ever used to *compare* two severities (e.g. to
# keep the most severe one when merging results). Severity labels themselves
# are always passed through verbatim, never rewritten.
_SEVERITY_RANKS = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "moderate": 2,
    "low": 1,
}


def severity_rank(severity: str | None) -> int:
    """
    Return the canonical rank for a severity label.

    Unknown or missing severities rank lowest; the label itself is always
    preserved as-is wherever it is emitted.
    """
    if severity is None:
        return 0
    return _SEVERITY_RANKS.get(severity.lower(), 0)


def _id_comparison_key(id: str) -> int:
    if id.startswith("PYSEC"):
        return 1
    elif id.startswith("CVE"):
        return 2
    return 3


@dataclass(frozen=True)
class Dependency:
    """
    Represents an abstract Python package.

    This class cannot be constructed directly.
    """

    name: str
    """
    The package's **uncanonicalized** name.

    Use the `canonicalized_name` property when a canonicalized form is necessary.
    """

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        """
        A stub constructor that always fails.
        """
        raise NotImplementedError

    # TODO(ww): Use functools.cached_property when supported Python is 3.8+.
    @property
    def canonical_name(self) -> str:
        """
        The `Dependency`'s PEP-503 canonicalized name.
        """
        return canonicalize_name(self.name)

    def is_skipped(self) -> bool:
        """
        Check whether the `Dependency` was skipped by the audit.
        """
        return self.__class__ is SkippedDependency


@dataclass(frozen=True)
class ResolvedDependency(Dependency):
    """
    Represents a fully resolved Python package.
    """

    version: Version

    sources: frozenset[str] = field(default=frozenset(), compare=False)
    """
    The set of dependency manifests (e.g. requirements files) this dependency
    was collected from.

    This is informational only: it does not participate in equality or
    hashing, so the same dependency collected from multiple manifests is
    still deduplicated while retaining its origin markers.
    """


@dataclass(frozen=True)
class SkippedDependency(Dependency):
    """
    Represents a Python package that was unable to be audited and therefore, skipped.
    """

    skip_reason: str


@dataclass(frozen=True)
class VulnerabilityResult:
    """
    Represents a "result" from a vulnerability service, indicating a vulnerability
    in some Python package.
    """

    id: VulnerabilityID
    """
    A service-provided identifier for the vulnerability.
    """

    description: str
    """
    A human-readable description of the vulnerability.
    """

    fix_versions: list[Version]
    """
    A list of versions that can be upgraded to that resolve the vulnerability.
    """

    aliases: set[VulnerabilityID]
    """
    A set of aliases (alternative identifiers) for this result.
    """

    published: datetime | None = None
    """
    When the vulnerability was first published.
    """

    severity: str | None = None
    """
    The severity label for this vulnerability, exactly as provided by the
    vulnerability source (e.g. a local database). Passed through verbatim;
    `None` when the source does not provide one.
    """

    @classmethod
    def create(
        cls,
        ids: list[VulnerabilityID],
        description: str,
        fix_versions: list[Version],
        published: datetime | None,
        severity: str | None = None,
    ) -> VulnerabilityResult:
        """
        Instantiates a `VulnerabilityResult` with the given data, prioritizing
        PYSEC and CVE vulnerability IDs for the primary identifier.
        """

        ids.sort(key=_id_comparison_key)
        return cls(ids[0], description, fix_versions, set(ids[1:]), published, severity)

    def alias_of(self, other: VulnerabilityResult) -> bool:
        """
        Returns whether this result is an "alias" of another result.

        Two results are said to be aliases if their respective sets of
        `{id, *aliases}` intersect at all. A result is therefore its own alias.
        """
        return bool((self.aliases | {self.id}).intersection(other.aliases | {other.id}))

    def merge_aliases(self, other: VulnerabilityResult) -> VulnerabilityResult:
        """
        Merge `other`'s aliases into this result, returning a new result.

        When both results carry a severity label, the most severe one is
        kept (using the shared `severity_rank` ordering); labels themselves
        are never rewritten. Merging is idempotent: merging the same pair
        of results any number of times yields the same result.
        """

        # Our own ID should never occur in the alias set.
        aliases = self.aliases | other.aliases - {self.id}
        severity = self.severity
        if severity_rank(other.severity) > severity_rank(self.severity):
            severity = other.severity
        return replace(self, aliases=aliases, severity=severity)

    def has_any_id(self, ids: set[str]) -> bool:
        """
        Returns whether ids intersects with {id} | aliases.
        """
        return bool(ids & (self.aliases | {self.id}))


class VulnerabilityService(ABC):
    """
    Represents an abstract provider of Python package vulnerability information.
    """

    @abstractmethod
    def query(
        self, spec: Dependency
    ) -> tuple[Dependency, list[VulnerabilityResult]]:  # pragma: no cover
        """
        Query the `VulnerabilityService` for information about the given `Dependency`,
        returning a list of `VulnerabilityResult`.
        """
        raise NotImplementedError

    def query_all(
        self, specs: Iterator[Dependency]
    ) -> Iterator[tuple[Dependency, list[VulnerabilityResult]]]:
        """
        Query the vulnerability service for information on multiple dependencies.

        `VulnerabilityService` implementations can override this implementation with
        a more optimized one, if they support batched or bulk requests.
        """
        for spec in specs:
            yield self.query(spec)

    @staticmethod
    def _parse_rfc3339(dt: str | None) -> datetime | None:
        if dt is None:
            return None

        # NOTE: OSV's schema says timestamps are RFC3339 but strptime
        # has no way to indicate an optional field (like `%f`), so
        # we have to try-and-retry with the two different expected formats.
        # See: https://github.com/google/osv.dev/issues/857
        try:
            return datetime.strptime(dt, "%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError:
            return datetime.strptime(dt, "%Y-%m-%dT%H:%M:%SZ")


class ServiceError(Exception):
    """
    Raised when a `VulnerabilityService` fails, for any reason.

    Concrete implementations of `VulnerabilityService` are expected to subclass
    this exception to provide more context.
    """

    pass


class ConnectionError(ServiceError):
    """
    A specialization of `ServiceError` specifically for cases where the
    vulnerability service is unreachable or offline.
    """

    pass
