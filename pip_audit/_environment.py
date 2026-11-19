"""
Target environment descriptions and marker evaluation.

This module is the single source of truth for "which environment are we
auditing for": dependency sources, filtering logic, and report formatters
all share the `TargetEnvironment` description created here.

A `TargetEnvironment` is parsed from a user-supplied description of the
form:

    python_version=3.11;sys_platform=linux;extra=security;extra=tests

and is used to evaluate PEP 508 environment markers against the *target*
environment rather than the machine running the audit. Markers that cannot
be decided against the description (unknown variables, invalid comparisons,
evaluation errors) are reported as "unevaluated" instead of being silently
treated as true or false.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Set as AbstractSet
from dataclasses import dataclass

from packaging.markers import (
    Marker,
    UndefinedComparison,
    UndefinedEnvironmentName,
    _evaluate_markers,
)
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

logger = logging.getLogger(__name__)

# Environment keys recognized in a target environment description. These
# mirror the keys produced by `packaging.markers.default_environment()`, so
# any standard marker variable is describable. `extra` is handled separately
# since a target environment can request multiple extras at once.
_KNOWN_ENVIRONMENT_KEYS = frozenset(
    {
        "implementation_name",
        "implementation_version",
        "os_name",
        "platform_machine",
        "platform_python_implementation",
        "platform_release",
        "platform_system",
        "platform_version",
        "python_full_version",
        "python_version",
        "sys_platform",
    }
)

# Keys whose values must be valid PEP 440 versions.
_VERSION_VALUED_KEYS = frozenset(
    {
        "implementation_version",
        "python_full_version",
        "python_version",
    }
)

# Environment values are simple tokens. Restricting the charset keeps the
# description reproducible and prevents sensitive material (such as index
# URLs with embedded credentials) from being smuggled into reports and logs
# through the environment description.
_VALUE_RE = re.compile(r"^[A-Za-z0-9._+-]+$")


class TargetEnvironmentError(Exception):
    """
    Raised when a target environment description is invalid.

    Callers are expected to treat this as fatal: an invalid description must
    never silently degrade into evaluating against the current machine.
    """

    pass


@dataclass(frozen=True)
class MarkerEvaluation:
    """
    The outcome of evaluating a marker against a `TargetEnvironment`.

    `value` is `True` or `False` for a definitive outcome, or `None` when the
    marker could not be evaluated against the target environment. In the
    latter case `reason` explains why.
    """

    value: bool | None
    reason: str | None = None

    @property
    def is_unevaluated(self) -> bool:
        """
        Whether the marker could not be evaluated to a definitive boolean.
        """
        return self.value is None


@dataclass(frozen=True)
class TargetEnvironment:
    """
    An immutable description of the environment an audit targets.

    `values` holds the marker environment as sorted key-value pairs (sorted
    so that descriptions and reports are deterministic). `extras` holds the
    set of extras requested for optional-dependency expansion.
    """

    values: tuple[tuple[str, str], ...]
    extras: frozenset[str]

    @classmethod
    def from_string(cls, spec: str) -> TargetEnvironment:
        """
        Parse a target environment description of the form
        `key=value;key=value;extra=name`.

        Raises `TargetEnvironmentError` on any malformed input; callers
        should treat this as fatal rather than falling back to the current
        machine's environment.
        """
        if spec is None or not spec.strip():
            raise TargetEnvironmentError("target environment description is empty")

        values: dict[str, str] = {}
        extras: set[str] = set()
        for pair in spec.split(";"):
            pair = pair.strip()
            if not pair:
                continue
            key, sep, value = pair.partition("=")
            if not sep:
                raise TargetEnvironmentError(
                    f"invalid environment pair {pair!r}: expected key=value"
                )
            key = key.strip()
            value = value.strip()
            if key == "extra":
                if not value:
                    raise TargetEnvironmentError("extra name must not be empty")
                extras.add(canonicalize_name(value))
                continue
            if key not in _KNOWN_ENVIRONMENT_KEYS:
                raise TargetEnvironmentError(
                    f"unknown environment key {key!r}: expected one of "
                    f"{', '.join(sorted(_KNOWN_ENVIRONMENT_KEYS))}, extra"
                )
            if key in values:
                raise TargetEnvironmentError(f"duplicate environment key {key!r}")
            if not value or not _VALUE_RE.match(value):
                # NOTE: we deliberately do not echo the offending value, since
                # it may contain sensitive material.
                raise TargetEnvironmentError(
                    f"invalid value for environment key {key!r}: only letters, digits, "
                    "and the characters . _ + - are allowed"
                )
            if key in _VERSION_VALUED_KEYS:
                try:
                    Version(value)
                except InvalidVersion:
                    raise TargetEnvironmentError(
                        f"environment key {key!r} must be a valid PEP 440 version"
                    ) from None
            values[key] = value

        if not values and not extras:
            raise TargetEnvironmentError("target environment description is empty")

        return cls(values=tuple(sorted(values.items())), extras=frozenset(extras))

    def describe(self) -> str:
        """
        Render this environment as a canonical, deterministic description
        string, suitable for reports and logs.
        """
        parts = [f"{key}={value}" for key, value in self.values]
        parts.extend(f"extra={extra}" for extra in sorted(self.extras))
        return ";".join(parts)

    def as_report_dict(self) -> dict[str, object]:
        """
        Render this environment as a JSON-serializable mapping for reports.
        """
        report: dict[str, object] = dict(self.values)
        if self.extras:
            report["extras"] = sorted(self.extras)
        return report

    def evaluate_marker(self, marker: Marker) -> MarkerEvaluation:
        """
        Evaluate `marker` against this target environment.

        The marker is evaluated once per requested extra (or once with an
        empty `extra` if none were requested) and is considered applicable if
        it holds for any of them. Any failure to decide the marker (unknown
        environment variables, undefined comparisons, or unexpected errors)
        yields an unevaluated result with an explanatory reason, never a
        guessed boolean.
        """
        extras = sorted(self.extras) or [""]
        for extra in extras:
            environment: dict[str, str | AbstractSet[str]] = dict(self.values)
            environment["extra"] = extra
            try:
                # NOTE: we deliberately evaluate the marker's parsed form
                # against exactly our own environment instead of calling
                # `Marker.evaluate`, which would merge in the current
                # machine's environment for any key we did not specify.
                result = _evaluate_markers(marker._markers, environment)
            except UndefinedEnvironmentName as e:
                return MarkerEvaluation(
                    None,
                    f"marker references a variable not present in the target environment: {e}",
                )
            except KeyError as e:
                # Older versions of `packaging` surface missing variables as
                # `KeyError` rather than `UndefinedEnvironmentName`.
                return MarkerEvaluation(
                    None,
                    f"marker references a variable not present in the target environment: {e}",
                )
            except UndefinedComparison as e:
                return MarkerEvaluation(None, f"marker comparison is undefined: {e}")
            except Exception as e:  # noqa: BLE001
                return MarkerEvaluation(
                    None, f"marker could not be evaluated: {type(e).__name__}: {e}"
                )
            if result:
                return MarkerEvaluation(True)
        return MarkerEvaluation(False)
