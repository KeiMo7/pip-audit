import itertools
from datetime import datetime

import pytest
from packaging.version import Version

from pip_audit._merge import MergeStats, merge_results, normalize_id, source_priority
from pip_audit._service.interface import VulnerabilityResult


def _result(id, aliases=(), description="stub", fix_versions=(), published=None):
    return VulnerabilityResult(
        id=id,
        description=description,
        fix_versions=list(fix_versions),
        aliases=set(aliases),
        published=published,
    )


def _legacy_fields(result):
    """
    The fields that existed before multi-source merging, as a comparable tuple.
    """
    return (
        result.id,
        result.description,
        result.fix_versions,
        result.aliases,
        result.published,
    )


class TestNormalizeId:
    def test_case_and_whitespace(self):
        assert normalize_id("  CVE-2024-0001 ") == "cve-2024-0001"
        assert normalize_id("PYSEC-2024-1") == "pysec-2024-1"

    def test_source_priority_is_fixed(self):
        # Source priority derives from source identity, not position.
        assert source_priority("pypi") > source_priority("osv")
        assert source_priority("osv") > source_priority("esms")
        assert source_priority("unknown-source") == 0


class TestMergeIdentifierChains:
    # Three fixed offline "responses": source A knows PYSEC<->CVE, source B
    # knows CVE<->GHSA, source C knows GHSA alone. The chain A-B-C must
    # collapse into a single result.
    RESPONSES = [
        (
            "source-a",
            [
                _result(
                    "PYSEC-2024-1",
                    aliases={"CVE-2024-0001"},
                    description="chain vulnerability",
                    fix_versions=[Version("1.1.0")],
                )
            ],
        ),
        (
            "source-b",
            [
                _result(
                    "CVE-2024-0001",
                    aliases={"GHSA-xxxx-yyyy"},
                    description="chain vulnerability",
                    fix_versions=[Version("1.1.0")],
                )
            ],
        ),
        (
            "source-c",
            [
                _result(
                    "GHSA-xxxx-yyyy",
                    description="chain vulnerability",
                    fix_versions=[Version("1.1.0")],
                )
            ],
        ),
    ]

    def test_transitive_dedupe(self):
        merged = merge_results(
            [(source, result) for source, results in self.RESPONSES for result in results]
        )

        assert len(merged) == 1
        (result,) = merged
        # Primary ID: PYSEC wins by scheme priority.
        assert result.id == "PYSEC-2024-1"
        # No identifier may disappear.
        assert result.aliases == {"CVE-2024-0001", "GHSA-xxxx-yyyy"}
        # Every contributing source is recorded.
        assert result.sources == {"source-a", "source-b", "source-c"}

    def test_cyclic_aliases_converge(self):
        # A <-> B <-> C <-> A with disagreeing "primary" identifiers must
        # still converge to a single result.
        sourced = [
            ("a", _result("PYSEC-2024-9", aliases={"CVE-2024-0009"})),
            ("b", _result("CVE-2024-0009", aliases={"GHSA-cyclic"})),
            ("c", _result("GHSA-cyclic", aliases={"PYSEC-2024-9"})),
        ]

        merged = merge_results(sourced)

        assert len(merged) == 1
        assert merged[0].id == "PYSEC-2024-9"
        assert merged[0].aliases == {"CVE-2024-0009", "GHSA-cyclic"}

    def test_id_normalization_merges_spelling_variants(self):
        sourced = [
            ("a", _result("PYSEC-2024-2", aliases={"cve-2024-0002 "})),
            ("b", _result("CVE-2024-0002", description="from b")),
        ]

        merged = merge_results(sourced)

        assert len(merged) == 1
        assert merged[0].id == "PYSEC-2024-2"
        # The two spellings normalize to the same identifier, so exactly one
        # original spelling is preserved for display.
        assert len(merged[0].aliases) == 1
        assert normalize_id(next(iter(merged[0].aliases))) == "cve-2024-0002"


class TestMergeFieldComplement:
    # Field-complementary responses: each source fills in what the other
    # lacks.
    RESPONSES = [
        (
            "pypi",
            [
                _result(
                    "PYSEC-2024-3",
                    aliases={"CVE-2024-0003"},
                    description="N/A",
                    fix_versions=[Version("1.1.0"), Version("1.2.0")],
                    published=None,
                )
            ],
        ),
        (
            "osv",
            [
                _result(
                    "CVE-2024-0003",
                    description="a real description",
                    fix_versions=[Version("1.2.0"), Version("1.3.0")],
                    published=datetime(2024, 1, 2, 3, 4, 5),
                )
            ],
        ),
    ]

    def test_fields_complement_each_other(self):
        merged = merge_results(
            [(source, result) for source, results in self.RESPONSES for result in results]
        )

        assert len(merged) == 1
        (result,) = merged
        # Fix versions: union, deduplicated, sorted; a source missing the
        # field never clears it.
        assert result.fix_versions == [Version("1.1.0"), Version("1.2.0"), Version("1.3.0")]
        # Description: the complete one beats the "N/A" placeholder.
        assert result.description == "a real description"
        # Published: the only non-empty value is kept.
        assert result.published == datetime(2024, 1, 2, 3, 4, 5)
        assert result.sources == {"pypi", "osv"}

    def test_missing_fix_versions_do_not_clear(self):
        sourced = [
            ("a", _result("PYSEC-2024-4", fix_versions=[Version("2.0.0")])),
            ("b", _result("PYSEC-2024-4", fix_versions=[])),
        ]

        merged = merge_results(sourced)

        assert merged[0].fix_versions == [Version("2.0.0")]


class TestMergeFieldConflict:
    # Conflicting responses: same vulnerability, disagreeing fields.
    RESPONSES = [
        (
            "pypi",
            [
                _result(
                    "PYSEC-2024-5",
                    aliases={"CVE-2024-0005"},
                    description="short",
                    published=datetime(2024, 5, 1),
                )
            ],
        ),
        (
            "osv",
            [
                _result(
                    "CVE-2024-0005",
                    description="a much longer and more detailed description",
                    published=datetime(2024, 3, 1),
                )
            ],
        ),
    ]

    def test_longer_description_wins(self):
        merged = merge_results(
            [(source, result) for source, results in self.RESPONSES for result in results]
        )

        assert len(merged) == 1
        assert merged[0].description == "a much longer and more detailed description"

    def test_earliest_published_wins(self):
        merged = merge_results(
            [(source, result) for source, results in self.RESPONSES for result in results]
        )

        assert merged[0].published == datetime(2024, 3, 1)

    def test_all_empty_published_stays_empty(self):
        sourced = [
            ("a", _result("PYSEC-2024-6", published=None)),
            ("b", _result("PYSEC-2024-6", published=None)),
        ]

        merged = merge_results(sourced)

        assert merged[0].published is None

    def test_source_priority_breaks_description_ties(self):
        # Equal completeness and length: the higher-priority source wins,
        # regardless of input order.
        sourced = [
            ("osv", _result("CVE-2024-0007", description="aaaa")),
            ("pypi", _result("CVE-2024-0007", description="bbbb")),
        ]

        for permuted in (sourced, list(reversed(sourced))):
            merged = merge_results(permuted)
            assert merged[0].description == "bbbb"  # pypi outranks osv

    def test_completeness_beats_length(self):
        # A short real description beats a long placeholder.
        sourced = [
            ("a", _result("CVE-2024-0008", description="N/A")),
            ("b", _result("CVE-2024-0008", description="x")),
        ]

        merged = merge_results(sourced)

        assert merged[0].description == "x"


class TestMergePrimaryIdSelection:
    def test_scheme_priority_then_lexicographic(self):
        sourced = [
            ("a", _result("ZZZ-9", aliases={"CVE-2024-9999", "CVE-2024-1111"})),
            ("b", _result("CVE-2024-1111", aliases={"PYSEC-2024-2"})),
            ("c", _result("PYSEC-2024-1", aliases={"PYSEC-2024-2"})),
        ]

        merged = merge_results(sourced)

        assert len(merged) == 1
        # PYSEC beats CVE beats everything else; lexicographic within a scheme.
        assert merged[0].id == "PYSEC-2024-1"
        assert merged[0].aliases == {
            "PYSEC-2024-2",
            "CVE-2024-1111",
            "CVE-2024-9999",
            "ZZZ-9",
        }

    def test_same_scheme_is_lexicographic(self):
        sourced = [
            ("a", _result("GHSA-bbbb", aliases={"GHSA-cccc"})),
            ("b", _result("GHSA-aaaa", aliases={"GHSA-bbbb"})),
        ]

        merged = merge_results(sourced)

        assert len(merged) == 1
        assert merged[0].id == "GHSA-aaaa"


class TestMergeOrderIndependence:
    RESPONSES = [
        (
            "pypi",
            [
                _result(
                    "PYSEC-2024-10",
                    aliases={"CVE-2024-0010"},
                    description="pypi description",
                    fix_versions=[Version("1.1.0")],
                    published=datetime(2024, 2, 1),
                ),
                _result(
                    "PYSEC-2024-11",
                    description="another vulnerability",
                    fix_versions=[Version("3.0.0")],
                ),
            ],
        ),
        (
            "osv",
            [
                _result(
                    "CVE-2024-0010",
                    aliases={"GHSA-0010"},
                    description="a longer osv description",
                    fix_versions=[Version("1.2.0")],
                    published=datetime(2024, 1, 1),
                ),
                _result(
                    "GHSA-0011",
                    aliases={"PYSEC-2024-11"},
                    description="another vulnerability",
                    fix_versions=[Version("3.1.0")],
                ),
            ],
        ),
        (
            "esms",
            [
                _result(
                    "GHSA-0010",
                    description="N/A",
                    fix_versions=[],
                    published=None,
                )
            ],
        ),
    ]

    def _expected(self):
        merged = merge_results(
            [(source, result) for source, results in self.RESPONSES for result in results]
        )
        return merged

    def test_shuffling_sources_and_results_is_stable(self):
        expected = self._expected()

        for source_permutation in itertools.permutations(self.RESPONSES):
            # Also reverse the order of results within each source.
            sourced = []
            for source, results in source_permutation:
                sourced.extend((source, result) for result in reversed(results))

            merged = merge_results(sourced)

            assert [r.id for r in merged] == [r.id for r in expected]
            for got, want in zip(merged, expected):
                assert _legacy_fields(got) == _legacy_fields(want)
                assert got.sources == want.sources

    def test_distinct_vulnerabilities_do_not_split(self):
        # Two unrelated vulnerabilities stay separate; clustering is purely
        # identifier-based and never splits over field differences.
        merged = self._expected()

        assert len(merged) == 2
        by_id = {r.id: r for r in merged}
        assert by_id["PYSEC-2024-10"].aliases == {"CVE-2024-0010", "GHSA-0010"}
        assert by_id["PYSEC-2024-10"].fix_versions == [Version("1.1.0"), Version("1.2.0")]
        assert by_id["PYSEC-2024-10"].published == datetime(2024, 1, 1)
        assert by_id["PYSEC-2024-10"].sources == {"pypi", "osv", "esms"}
        assert by_id["PYSEC-2024-11"].aliases == {"GHSA-0011"}
        assert by_id["PYSEC-2024-11"].fix_versions == [Version("3.0.0"), Version("3.1.0")]


class TestMergeMalformedFields:
    def test_malformed_fields_are_skipped_and_counted(self):
        stats = MergeStats()
        good = _result(
            "PYSEC-2024-20",
            fix_versions=[Version("1.0.0")],
            published=datetime(2024, 1, 1),
        )
        # A result with a malformed fix version and an empty timestamp:
        # the fields are dropped, the result is kept.
        bad = VulnerabilityResult(
            id="CVE-2024-0020",
            description="stub",
            fix_versions=["not-a-version", Version("2.0.0")],
            aliases={"PYSEC-2024-20"},
            published="",
        )

        merged = merge_results([("a", good), ("b", bad)], stats)

        assert len(merged) == 1
        assert merged[0].fix_versions == [Version("1.0.0"), Version("2.0.0")]
        assert merged[0].published == datetime(2024, 1, 1)
        assert stats.malformed_fields == 2

    def test_malformed_timestamp_string_is_dropped(self):
        stats = MergeStats()
        result = VulnerabilityResult(
            id="PYSEC-2024-21",
            description="stub",
            fix_versions=[],
            aliases=set(),
            published="not a timestamp",
        )

        merged = merge_results([("a", result)], stats)

        assert merged[0].published is None
        assert stats.malformed_fields == 1

    def test_parseable_string_timestamp_is_kept(self):
        result = VulnerabilityResult(
            id="PYSEC-2024-22",
            description="stub",
            fix_versions=[],
            aliases=set(),
            published="2024-01-02T03:04:05Z",
        )

        merged = merge_results([("a", result)])

        assert merged[0].published == datetime(2024, 1, 2, 3, 4, 5)


class TestMergeSingleSource:
    @pytest.mark.parametrize(
        "results",
        [
            [
                _result(
                    "PYSEC-2024-30",
                    aliases={"CVE-2024-0030"},
                    description="a vulnerability",
                    fix_versions=[Version("1.1.0")],
                    published=datetime(2024, 1, 1),
                ),
                _result(
                    "PYSEC-2024-31",
                    description="another vulnerability",
                    fix_versions=[Version("2.0.0"), Version("2.1.0")],
                ),
            ]
        ],
    )
    def test_single_source_matches_legacy_fields(self, results):
        # With a single source, every legacy field of the merged output is
        # identical to the input; only `sources` is added.
        merged = merge_results([("pypi", result) for result in results])

        assert len(merged) == len(results)
        for got, want in zip(merged, results):
            assert _legacy_fields(got) == _legacy_fields(want)
            assert got.sources == {"pypi"}
