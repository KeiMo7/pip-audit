"""
Offline extraction of the version constraints that a dependency source places on
its packages.

The fix-resolution engine uses these constraints to decide whether a candidate
fix version is actually installable under the project's own manifest, without
contacting any online service.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import Version
from pip_requirements_parser import RequirementsFile

logger = logging.getLogger(__name__)


def _is_pinned(specifier: SpecifierSet) -> bool:
    """
    Return whether a specifier set consists solely of exact `==` pins.

    Such a line is the one the fix step rewrites; it is not an upper bound.
    """
    specs = list(specifier)
    return bool(specs) and all(s.operator == "==" for s in specs)


@dataclass(frozen=True)
class PackageConstraint:
    """
    A single manifest-declared constraint on one package.

    `source` is a human-readable origin (typically a file path and line number),
    kept so that conflict reports can show both sides of a mutual conflict.

    `pinned` marks an exact (`==`) specifier. Pins are the lines the fix step
    rewrites, so they never block an upgrade; only range constraints (upper
    bounds, exclusions, compatible-release caps) can make a fix uninstallable.
    """

    name: str
    specifier: SpecifierSet
    source: str
    pinned: bool = False

    def blocks(self, version: Version) -> bool:
        """
        Return whether the given version is excluded by this constraint.

        Exact pins never block: a fix rewrites the pin itself. Pre-release
        rules follow the default `SpecifierSet.contains` behavior: a
        prerelease is only accepted when the specifier itself mentions one.
        """
        if self.pinned:
            return False
        return not self.specifier.contains(version, prereleases=True)


class ConstraintSnapshotError(Exception):
    """
    Raised when a manifest cannot be parsed into a constraint snapshot.

    Callers treat this as a fatal, whole-run condition: no partial fixes are
    written when the underlying constraints cannot be trusted.
    """

    pass


@runtime_checkable
class ConstraintProvider(Protocol):
    """
    An object capable of producing an offline constraint snapshot for itself.
    """

    def constraint_snapshot(self) -> dict[str, list[PackageConstraint]]:
        """
        Return a mapping of canonical package names to their declared constraints.

        Raises `ConstraintSnapshotError` if the underlying manifest is unparsable
        or contains conflicting duplicate declarations.
        """
        ...


def snapshot_from_requirement_files(
    filenames: list[Path],
) -> dict[str, list[PackageConstraint]]:
    """
    Build a constraint snapshot from one or more `requirements.txt`-style files.

    Duplicate declarations for the same package are tolerated only when their
    specifiers are identical (matching the audit-time behavior in
    `RequirementSource`); conflicting duplicates reject the whole snapshot.
    """
    snapshot: dict[str, list[PackageConstraint]] = {}

    for filename in filenames:
        try:
            rf = RequirementsFile.from_file(filename)
        except OSError as e:
            raise ConstraintSnapshotError(
                f"could not read requirements file {filename} for constraint analysis: {e}"
            ) from e

        for invalid in rf.invalid_lines:
            raise ConstraintSnapshotError(
                f"requirement file {filename} contains invalid specifier at "
                f"line {invalid.line_number}: {invalid.error_message}"
            )

        for req in rf.requirements:
            if req.req is None or req.name is None:
                # URL/unnamed requirements carry no usable version constraint.
                continue
            if req.marker is not None and not req.marker.evaluate():
                continue

            name = canonicalize_name(req.name)
            constraint = PackageConstraint(
                name=name,
                specifier=req.specifier,
                source=f"{filename}:{req.requirement_line.line_number}",
                pinned=_is_pinned(req.specifier),
            )
            previous = snapshot.get(name)
            if previous is not None and any(
                c.specifier != constraint.specifier for c in previous
            ):
                raise ConstraintSnapshotError(
                    f"package {name} has conflicting duplicate requirements: "
                    f"{constraint.source} declares {constraint.specifier}, but "
                    f"{previous[0].source} declares {previous[0].specifier}"
                )
            snapshot.setdefault(name, []).append(constraint)

    return snapshot


def merge_snapshots(
    snapshots: list[dict[str, list[PackageConstraint]]],
) -> dict[str, list[PackageConstraint]]:
    """
    Merge several constraint snapshots, preserving every origin for each package.
    """
    merged: dict[str, list[PackageConstraint]] = {}
    for snapshot in snapshots:
        for name, constraints in snapshot.items():
            merged.setdefault(name, []).extend(constraints)
    return merged


def snapshot_from_requirement_strings(
    lines: list[str], source: str = "<inline>"
) -> dict[str, list[PackageConstraint]]:
    """
    Build a constraint snapshot from PEP 508 requirement strings.

    This is primarily used by tests and by sources that keep their dependencies
    as an in-memory list (e.g. `pyproject.toml`'s `project.dependencies`).
    """
    snapshot: dict[str, list[PackageConstraint]] = {}
    for line_no, line in enumerate(lines, start=1):
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        # PEP 508 `Requirement` does not accept trailing comments; strip an
        # inline comment the same way a requirements parser would.
        if " #" in text:
            text = text.split(" #", 1)[0].strip()
        try:
            req = Requirement(text)
        except InvalidRequirement as e:
            raise ConstraintSnapshotError(
                f"{source}:{line_no}: invalid requirement {text!r}: {e}"
            ) from e
        name = canonicalize_name(req.name)
        snapshot.setdefault(name, []).append(
            PackageConstraint(
                name=name,
                specifier=req.specifier,
                source=f"{source}:{line_no}",
                pinned=_is_pinned(req.specifier),
            )
        )
    return snapshot
