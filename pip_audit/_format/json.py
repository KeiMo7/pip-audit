"""
Functionality for formatting vulnerability results as an array of JSON objects.
"""

from __future__ import annotations

import json
from typing import Any, cast

import pip_audit._fix as fix
import pip_audit._service as service

from .interface import VulnerabilityFormat


class JsonFormat(VulnerabilityFormat):
    """
    An implementation of `VulnerabilityFormat` that formats vulnerability results as an array of
    JSON objects.
    """

    def __init__(
        self,
        output_desc: bool,
        output_aliases: bool,
        advice: Any = None,
    ):
        """
        Create a new `JsonFormat`.

        `output_desc` is a flag to determine whether descriptions for each vulnerability should be
        included in the output as they can be quite long and make the output difficult to read.

        `output_aliases` is a flag to determine whether aliases (such as CVEs) for each
        vulnerability should be included in the output.

        `advice` is either a list of `FixAdvice` objects or a zero-argument
        callable returning the current list (the latter supports callers that
        reassign the list after constructing the formatter). Their
        explanation fields are appended under a separate `fix_advice` key,
        leaving the legacy `fixes` schema unchanged.
        """
        self.output_desc = output_desc
        self.output_aliases = output_aliases
        self._advice_provider = advice if callable(advice) else (lambda: advice or [])

    @property
    def is_manifest(self) -> bool:
        """
        See `VulnerabilityFormat.is_manifest`.
        """
        return True

    def format(
        self,
        result: dict[service.Dependency, list[service.VulnerabilityResult]],
        fixes: list[fix.FixVersion],
    ) -> str:
        """
        Returns a JSON formatted string for a given mapping of dependencies to vulnerability
        results.

        See `VulnerabilityFormat.format`.
        """
        output_json: dict[str, Any] = {
            "dependencies": [self._format_dep(dep, vulns) for dep, vulns in result.items()],
            "fixes": [self._format_fix(f) for f in fixes],
        }
        advice = self._advice_provider()
        if advice:
            # Additive-only: the legacy keys above keep their exact schema.
            output_json["fix_advice"] = [self._format_advice(a) for a in advice]
        return json.dumps(output_json)

    def _format_advice(self, advice: Any) -> dict[str, Any]:
        return {
            "name": advice.dep.canonical_name,
            "classification": advice.classification.value,
            "vulnerability_ids": sorted(advice.vulnerability_ids),
            "affected_ranges": [
                {
                    "lower": None if r.lower is None else str(r.lower),
                    "upper": None if r.upper is None else str(r.upper),
                    "derived": r.derived,
                }
                for r in advice.affected_ranges
            ],
            "chosen_version": (
                None if advice.chosen_version is None else str(advice.chosen_version)
            ),
            "excluded_candidates": [
                {
                    "version": None if e.version is None else str(e.version),
                    "reason": e.reason.value,
                    "detail": e.detail,
                }
                for e in advice.excluded
            ],
            "blocking_constraints": [
                {"specifier": str(c.specifier), "source": c.source}
                for c in advice.blocking_constraints
            ],
            "mutual_conflicts": [
                {"name": name, "specifier": specifier, "source": source}
                for name, specifier, source in advice.mutual_conflicts
            ],
            "reason": advice.reason,
        }

    def _format_dep(
        self, dep: service.Dependency, vulns: list[service.VulnerabilityResult]
    ) -> dict[str, Any]:
        if dep.is_skipped():
            dep = cast(service.SkippedDependency, dep)
            return {
                "name": dep.canonical_name,
                "skip_reason": dep.skip_reason,
            }

        dep = cast(service.ResolvedDependency, dep)
        return {
            "name": dep.canonical_name,
            "version": str(dep.version),
            "vulns": [self._format_vuln(vuln) for vuln in vulns],
        }

    def _format_vuln(self, vuln: service.VulnerabilityResult) -> dict[str, Any]:
        vuln_json = {
            "id": vuln.id,
            "fix_versions": [str(version) for version in vuln.fix_versions],
        }
        if self.output_aliases:
            vuln_json["aliases"] = list(vuln.aliases)
        if self.output_desc:
            vuln_json["description"] = vuln.description
        return vuln_json

    def _format_fix(self, fix_version: fix.FixVersion) -> dict[str, Any]:
        if fix_version.is_skipped():
            fix_version = cast(fix.SkippedFixVersion, fix_version)
            return {
                "name": fix_version.dep.canonical_name,
                "version": str(fix_version.dep.version),
                "skip_reason": fix_version.skip_reason,
            }
        fix_version = cast(fix.ResolvedFixVersion, fix_version)
        return {
            "name": fix_version.dep.canonical_name,
            "old_version": str(fix_version.dep.version),
            "new_version": str(fix_version.version),
        }
