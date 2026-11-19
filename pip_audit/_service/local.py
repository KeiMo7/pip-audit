"""
Functionality for auditing dependencies against a local vulnerability
database, without any network access ("offline mode").

The local database is a single JSON document that reuses the OSV schema for
its vulnerability entries, so that record interpretation is shared with the
online `OsvService` path:

```json
{
  "format_version": 1,
  "generated_at": "2026-11-01T00:00:00Z",
  "vuln_count": 2,
  "vulns": [
    {
      "id": "PYSEC-0000-1",
      "aliases": ["CVE-0000-0001"],
      "summary": "example vulnerability",
      "severity": "HIGH",
      "published": "2026-01-01T00:00:00Z",
      "affected": [
        {
          "package": {"name": "example", "ecosystem": "PyPI"},
          "ranges": [
            {"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "1.2"}]}
          ]
        }
      ]
    }
  ]
}
```

Each entry is a standard OSV v1 record with one optional extension: a
top-level `severity` string, which is passed through to results verbatim.

Integrity guarantees:

* `format_version` must be present and supported;
* "vuln_count", when present, must match the actual number of entries —
  a mismatch (e.g. a truncated file) is a hard error, never an empty database;
* any parse failure of the file or an entry is a hard `LocalDatabaseError`.

When the database file is simply absent, the service degrades instead of
failing: every dependency is reported as skipped ("listed, not audited")
with an explicit reason.
"""

from __future__ import annotations

import json
import logging
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, cast

from packaging.version import InvalidVersion, Version

from pip_audit._service.interface import (
    Dependency,
    ResolvedDependency,
    ServiceError,
    SkippedDependency,
    VulnerabilityResult,
    VulnerabilityService,
    severity_rank,
)
from pip_audit._service.osv import _result_from_osv_vuln

logger = logging.getLogger(__name__)

LOCAL_DB_FORMAT_VERSION = 1
"""
The only local database `format_version` this implementation can read.
"""

DEFAULT_MAX_DB_AGE = timedelta(days=30)
"""
The default maximum age of a local database before its results are flagged
as potentially outdated.
"""


class LocalDatabaseError(ServiceError):
    """
    Raised when the local vulnerability database cannot be loaded or is
    structurally invalid (truncated, wrong format version, malformed entry).
    """

    pass


def _version_in_events(version: Version, events: list[dict[str, Any]], context: str) -> bool:
    """
    Return whether `version` is affected according to an OSV `events` list.

    `context` identifies the entry being evaluated (for error messages only).
    """

    def _parse(raw: str) -> Version:
        try:
            return Version(raw)
        except InvalidVersion as iv:
            raise LocalDatabaseError(
                f"local vulnerability database entry {context} contains an invalid version: {raw}"
            ) from iv

    introduced: Version | None = None
    for event in events:
        if "introduced" in event:
            introduced = _parse(event["introduced"])
        elif "fixed" in event:
            if introduced is not None and introduced <= version < _parse(event["fixed"]):
                return True
            introduced = None
        elif "last_affected" in event:
            if introduced is not None and introduced <= version <= _parse(event["last_affected"]):
                return True
            introduced = None
        elif "limit" in event:
            # `limit` events are rare in the PyPI ecosystem; we don't try to
            # interpret them and conservatively ignore them.
            logger.debug(f"ignoring 'limit' event in local database entry {context}")
    return False


def _entry_affects_version(vuln: dict[str, Any], canonical_name: str, version: Version) -> bool:
    """
    Return whether the given OSV-schema entry affects `version` of the
    package named `canonical_name`.
    """
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name") != canonical_name or pkg.get("ecosystem") != "PyPI":
            continue

        # An explicit `versions` list takes part in the union of affected
        # versions, alongside any ranges.
        versions = affected.get("versions")
        if versions is not None and str(version) in versions:
            return True

        for ranges in affected.get("ranges", []):
            if ranges.get("type") != "ECOSYSTEM":
                continue
            if _version_in_events(version, ranges.get("events", []), vuln.get("id", "<unknown>")):
                return True

    return False


class LocalService(VulnerabilityService):
    """
    An implementation of `VulnerabilityService` that matches dependencies
    against a local vulnerability database file, performing no network
    access whatsoever.

    If the database file does not exist, the service degrades: queries
    return each dependency as skipped with an explicit reason, so that the
    final report lists the dependencies without auditing them.
    """

    def __init__(
        self,
        db_path: Path,
        *,
        max_db_age: timedelta = DEFAULT_MAX_DB_AGE,
        now: datetime | None = None,
    ) -> None:
        """
        Create a new `LocalService`.

        `db_path` is the path to the local vulnerability database.

        `max_db_age` controls how old the database may become before results
        are flagged as stale.

        `now` overrides the current time (used for staleness checks); mainly
        useful for testing.
        """
        self._db_path = db_path
        self._max_db_age = max_db_age
        # NOTE: `generated_at` timestamps are parsed as naive UTC, so we
        # compare against a naive UTC "now".
        self._now = now if now is not None else datetime.now(tz=timezone.utc).replace(tzinfo=None)
        self._index: dict[str, list[dict[str, Any]]] = {}
        self.generated_at: datetime | None = None
        self.degraded = False
        self.degraded_reason: str | None = None

        if not db_path.is_file():
            self.degraded = True
            self.degraded_reason = "local vulnerability database is not available"
            # NOTE: dependency names and filesystem paths are kept out of
            # non-debug logs, since logs may be shared publicly.
            logger.debug(f"local vulnerability database not found: {db_path}")
            logger.warning(
                "local vulnerability database is unavailable; "
                "dependencies will be listed without being audited"
            )
            return

        self.generated_at = self._load(db_path)

        if self.generated_at is None:
            self.stale = True
            logger.warning(
                "local vulnerability database has no generation timestamp; "
                "audit results may be outdated"
            )
        else:
            self.stale = (self._now - self.generated_at) > self._max_db_age
            if self.stale:
                age_days = (self._now - self.generated_at).days
                logger.warning(
                    f"local vulnerability database is stale "
                    f"(generated {self.generated_at.isoformat()}, {age_days} days old); "
                    f"audit results may be outdated"
                )

    def _load(self, db_path: Path) -> datetime | None:
        """
        Load and validate the local database, indexing its entries by
        canonical package name. Returns the database's generation timestamp,
        or `None` if it doesn't have one.
        """
        try:
            raw = db_path.read_text()
        except OSError as e:
            raise LocalDatabaseError(
                f"could not read local vulnerability database {db_path}: {e}"
            ) from e

        try:
            doc = json.loads(raw)
        except json.JSONDecodeError as e:
            # A truncated or otherwise corrupted database must never be
            # treated as an empty one.
            raise LocalDatabaseError(
                f"local vulnerability database {db_path} is malformed or truncated: {e}"
            ) from e

        if not isinstance(doc, dict):
            raise LocalDatabaseError(
                f"local vulnerability database {db_path} is invalid: expected a JSON object"
            )

        format_version = doc.get("format_version")
        if format_version != LOCAL_DB_FORMAT_VERSION:
            raise LocalDatabaseError(
                f"local vulnerability database {db_path} has unsupported format version: "
                f"{format_version!r} (expected {LOCAL_DB_FORMAT_VERSION})"
            )

        vulns = doc.get("vulns")
        if not isinstance(vulns, list):
            raise LocalDatabaseError(
                f"local vulnerability database {db_path} is invalid: 'vulns' must be a list"
            )

        vuln_count = doc.get("vuln_count")
        if vuln_count is not None and vuln_count != len(vulns):
            raise LocalDatabaseError(
                f"local vulnerability database {db_path} appears truncated: "
                f"declares {vuln_count} entries but contains {len(vulns)} entries"
            )

        generated_at = doc.get("generated_at")
        parsed_generated_at: datetime | None = None
        if generated_at is not None:
            try:
                parsed_generated_at = self._parse_rfc3339(generated_at)
            except ValueError as ve:
                raise LocalDatabaseError(
                    f"local vulnerability database {db_path} has an invalid "
                    f"'generated_at' timestamp: {generated_at!r}"
                ) from ve

        for i, entry in enumerate(vulns):
            if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
                raise LocalDatabaseError(
                    f"local vulnerability database {db_path} contains a malformed entry "
                    f"at index {i}"
                )
            for affected in entry.get("affected", []):
                pkg = affected.get("package", {})
                if pkg.get("ecosystem") != "PyPI" or "name" not in pkg:
                    continue
                self._index.setdefault(pkg["name"], []).append(entry)

        return parsed_generated_at

    def query(self, spec: Dependency) -> tuple[Dependency, list[VulnerabilityResult]]:
        """
        Match the given `Dependency` against the local vulnerability database.

        See `VulnerabilityService.query`.
        """
        if spec.is_skipped():
            return spec, []

        if self.degraded:
            return (
                SkippedDependency(
                    name=spec.name,
                    skip_reason="not audited: local vulnerability database unavailable",
                ),
                [],
            )

        spec = cast(ResolvedDependency, spec)

        # Multiple database entries may describe the same vulnerability (e.g.
        # under different IDs); deduplicate by primary ID, merging aliases
        # and keeping the most severe severity label.
        results: dict[str, VulnerabilityResult] = {}
        for entry in self._index.get(spec.canonical_name, []):
            if not _entry_affects_version(entry, spec.canonical_name, spec.version):
                continue

            # Shared record interpretation with the online OSV path.
            result = _result_from_osv_vuln(entry, spec.canonical_name)
            if result is None:
                continue

            # The severity label is passed through verbatim.
            severity = entry.get("severity")
            if severity is not None:
                result = replace(result, severity=severity)

            previous = results.get(result.id)
            if previous is not None:
                results[result.id] = previous.merge_aliases(result)
            else:
                results[result.id] = result

        # Deterministic ordering: most severe first, then by ID. This uses
        # the same canonical severity ranking as the rest of the tool.
        ordered = sorted(results.values(), key=lambda r: (-severity_rank(r.severity), r.id))
        return spec, ordered
