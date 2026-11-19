"""
Interfaces for interacting with "dependency sources", i.e. sources
of fully resolved Python dependency trees.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator

from pip_audit._constraints import PackageConstraint
from pip_audit._fix import ResolvedFixVersion
from pip_audit._service import Dependency

PYPI_URL = "https://pypi.org/simple/"


class DependencySource(ABC):
    """
    Represents an abstract source of fully-resolved Python dependencies.

    Individual concrete dependency sources (e.g. `pip list`) are expected
    to subclass `DependencySource` and implement it in their terms.
    """

    @abstractmethod
    def collect(self) -> Iterator[Dependency]:  # pragma: no cover
        """
        Yield the dependencies in this source.
        """
        raise NotImplementedError

    @abstractmethod
    def fix(self, fix_version: ResolvedFixVersion) -> None:  # pragma: no cover
        """
        Upgrade a dependency to the given fix version.
        """
        raise NotImplementedError

    def constraint_snapshot(self) -> dict[str, list[PackageConstraint]]:
        """
        Return the manifest-declared version constraints for this source.

        Sources without a version manifest (e.g. a live `pip` environment)
        return an empty snapshot, which means "no additional constraints".
        Sources backed by a manifest override this to parse it offline; a
        parse failure or a conflicting duplicate declaration raises
        `ConstraintSnapshotError`, which callers treat as fatal so that no
        partial fix is ever written.
        """
        return {}


class DependencySourceError(Exception):
    """
    Raised when a `DependencySource` fails to provide its dependencies.

    Concrete implementations are expected to subclass this exception to
    provide more context.
    """

    pass


class DependencyFixError(Exception):
    """
    Raised when a `DependencySource` fails to perform a "fix" operation, i.e.
    fails to upgrade a package to a different version.

    Concrete implementations are expected to subclass this exception to provide
    more context.
    """

    pass


class InvalidRequirementSpecifier(DependencySourceError):
    """
    A `DependencySourceError` specialized for the case of a non-PEP 440 requirements
    specifier.
    """

    pass
