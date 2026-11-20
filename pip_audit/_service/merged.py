"""
A `VulnerabilityService` that queries multiple upstream services for the same
dependency and merges their results into a single, field-level-merged view.
"""

from __future__ import annotations

import logging

from pip_audit._merge import MergeStats, merge_results
from pip_audit._service.interface import (
    Dependency,
    ServiceError,
    VulnerabilityResult,
    VulnerabilityService,
)

logger = logging.getLogger(__name__)

DEFAULT_MAX_CONSECUTIVE_FAILURES = 3
"""
The number of consecutive query failures after which a source is marked
unavailable and skipped for the rest of the audit.
"""


class MergedVulnerabilityService(VulnerabilityService):
    """
    A `VulnerabilityService` that fans each query out to multiple wrapped
    services and merges their results with `pip_audit._merge.merge_results`.

    Failure behavior:

    * A source that fails a query is noted; the remaining sources still
      produce results, and the service is marked `partial` for the rest of
      the audit.
    * A source that fails `max_consecutive_failures` queries in a row is
      marked unavailable and skipped for the rest of the audit.
    * If every available source fails for a dependency, `ServiceError` is
      raised: an audit with no working sources must fail explicitly rather
      than report "no vulnerabilities".
    """

    def __init__(
        self,
        services: list[tuple[str, VulnerabilityService]],
        max_consecutive_failures: int = DEFAULT_MAX_CONSECUTIVE_FAILURES,
    ):
        """
        Create a new `MergedVulnerabilityService`.

        `services` is a list of `(name, service)` pairs. The order only
        affects querying, never the merged output.

        `max_consecutive_failures` controls how many consecutive failures a
        source may have before it is marked unavailable.
        """
        if not services:
            raise ValueError("MergedVulnerabilityService requires at least one service")
        names = [name for name, _service in services]
        if len(set(names)) != len(names):
            raise ValueError(f"Duplicate vulnerability service names: {names}")

        self._services = list(services)
        self._max_consecutive_failures = max_consecutive_failures
        self._consecutive_failures = dict.fromkeys(names, 0)
        self._unavailable: set[str] = set()
        self._failed_sources: set[str] = set()
        self._stats = MergeStats()

    @property
    def partial(self) -> bool:
        """
        Whether any source has failed during this audit, meaning the results
        produced are potentially incomplete.
        """
        return bool(self._failed_sources)

    @property
    def failed_sources(self) -> list[str]:
        """
        The names of all sources that have failed at least once, sorted.
        """
        return sorted(self._failed_sources)

    @property
    def warning_count(self) -> int:
        """
        The number of malformed individual fields skipped while merging.
        """
        return self._stats.malformed_fields

    def query(self, spec: Dependency) -> tuple[Dependency, list[VulnerabilityResult]]:
        """
        Query every available wrapped service for the given `Dependency`
        (at most once each) and merge their results.

        See `VulnerabilityService.query`.
        """
        if spec.is_skipped():
            return spec, []

        available = [
            (name, service) for name, service in self._services if name not in self._unavailable
        ]
        if not available:
            raise ServiceError(
                "All vulnerability services are unavailable "
                f"(failed: {', '.join(self.failed_sources)}); cannot audit {spec.name}"
            )

        sourced: list[tuple[str, VulnerabilityResult]] = []
        failures = 0
        successes = 0
        skipped: Dependency | None = None
        for name, service in available:
            try:
                dep, results = service.query(spec)
            except ServiceError as e:
                logger.warning(f"Vulnerability service {name} failed for {spec.name}: {e}")
                failures += 1
                self._failed_sources.add(name)
                self._consecutive_failures[name] += 1
                if self._consecutive_failures[name] >= self._max_consecutive_failures:
                    self._unavailable.add(name)
                    logger.warning(
                        f"Vulnerability service {name} marked unavailable after "
                        f"{self._consecutive_failures[name]} consecutive failures; "
                        "continuing without it"
                    )
                continue

            self._consecutive_failures[name] = 0
            if dep.is_skipped():
                # The source couldn't map this dependency (e.g. unknown on
                # PyPI). Not a failure, but also not a result.
                skipped = skipped if skipped is not None else dep
                continue
            successes += 1
            sourced.extend((name, result) for result in results)

        if successes:
            return spec, merge_results(sourced, self._stats)

        if failures == len(available):
            raise ServiceError(
                f"All vulnerability services failed while auditing {spec.name}; "
                "refusing to report an empty result"
            )

        # No source produced results, but at least one skipped the dependency
        # rather than failing: propagate the skip.
        if skipped is not None:
            return skipped, []
        return spec, []
