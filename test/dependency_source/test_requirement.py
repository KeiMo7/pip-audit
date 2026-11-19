from __future__ import annotations

import os
import sys
from email.message import EmailMessage
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory
from threading import Thread

import pretend  # type: ignore
import pytest
from packaging.version import Version

from pip_audit._audit import Auditor
from pip_audit._dependency_source import (
    PYPI_URL,
    DependencyFixError,
    DependencySourceError,
    requirement,
)
from pip_audit._environment import TargetEnvironment
from pip_audit._fix import ResolvedFixVersion
from pip_audit._service import ResolvedDependency, SkippedDependency, UnevaluatedDependency
from pip_audit._state import AuditState
from pip_audit._virtual_env import VirtualEnv, VirtualEnvError


def get_metadata_mock():
    return EmailMessage()


def _init_requirement(
    files: list[tuple[Path, str]],
    **kwargs,
) -> requirement.RequirementSource:
    paths: list[Path] = []
    for path, contents in files:
        with open(path, mode="w") as f:
            f.write(contents)
        paths.append(path)
    return requirement.RequirementSource(paths, **kwargs)


@pytest.mark.online
def test_requirement_source(req_file):
    source = _init_requirement([(req_file(), "flask==2.0.1")])
    specs = list(source.collect())
    assert ResolvedDependency("Flask", Version("2.0.1")) in specs


@pytest.mark.online
def test_requirement_source_multiple_files(req_file):
    source = _init_requirement(
        [
            (req_file(), "flask==2.0.1"),
            (req_file(), "requests==2.8.1"),
            (req_file(), "pip-api==0.0.22\npackaging==21.0"),
        ]
    )
    specs = list(source.collect())
    assert ResolvedDependency("Flask", Version("2.0.1")) in specs
    assert ResolvedDependency("requests", Version("2.8.1")) in specs
    assert ResolvedDependency("pip-api", Version("0.0.22")) in specs
    assert ResolvedDependency("packaging", Version("21.0")) in specs


def test_requirement_source_impossible_resolution(req_file):
    source = _init_requirement([(req_file(), "flask==2.0.1\nflask==2.0.0")])

    with pytest.raises(DependencySourceError):
        list(source.collect())


def test_requirement_source_virtualenv_error(monkeypatch, req_file):
    class MockVirtualEnv:
        def __init__(
            self,
            install_args: list[str],
            index_url: str,
            extra_index_url: list[str],
            state: AuditState,
        ) -> None:
            pass

        def create(self, dir: Path) -> None:
            raise VirtualEnvError

    source = _init_requirement(
        [
            (
                req_file(),
                "flask==2.0.1",
            )
        ]
    )
    monkeypatch.setattr(requirement, "VirtualEnv", MockVirtualEnv)

    with pytest.raises(DependencySourceError):
        list(source.collect())


@pytest.mark.online
def test_requirement_source_duplicate_dependencies(req_file):
    # Return the same requirements for both files
    source = _init_requirement([(req_file(), "flask==2.0.1"), (req_file(), "flask==2.0.1")])

    specs = list(source.collect())

    # If the dependency list has duplicates, then converting to a set will reduce the length of the
    # collection
    assert len(specs) == len(set(specs))


def test_requirement_source_invalid_lines(req_file):
    source = _init_requirement([(req_file(), "a#b#c")])

    with pytest.raises(DependencySourceError):
        list(source.collect())


@pytest.mark.online
def test_requirement_source_git(req_file):
    source = _init_requirement(
        [
            (
                req_file(),
                "git+https://github.com/pypa/sampleproject.git@5d277956b5a571dac16b28db74e5f2b780d9af5f",
            )
        ]
    )

    specs = list(source.collect())
    assert ResolvedDependency(name="sampleproject", version=Version("3.0.0")) in specs


@pytest.mark.online
def test_requirement_source_url(req_file):
    source = _init_requirement(
        [
            (
                req_file(),
                "https://github.com/pallets/flask/archive/refs/tags/2.0.1.tar.gz\n",
            )
        ],
    )

    specs = list(source.collect())
    assert (
        ResolvedDependency(
            name="Flask",
            version=Version("2.0.1"),
        )
        in specs
    )


@pytest.mark.online
def test_requirement_source_multiple_indexes(req_file):
    source = _init_requirement(
        [(req_file(), "flask==2.0.1")],
        index_url=PYPI_URL,
        extra_index_urls=["https://test.pypi.org/simple/"],
    )
    specs = list(source.collect())
    assert ResolvedDependency("Flask", Version("2.0.1")) in specs


def _check_fixes(
    input_reqs: list[str],
    expected_reqs: list[str],
    req_paths: list[Path],
    fixes: list[ResolvedFixVersion],
) -> None:
    # Populate the requirements files
    for input_req, req_path in zip(input_reqs, req_paths, strict=True):
        with open(req_path, "w") as f:
            print(input_req, file=f)

    source = requirement.RequirementSource(req_paths)
    for fix in fixes:
        source.fix(fix)

    # Check the requirements files
    for expected_req, req_path in zip(expected_reqs, req_paths, strict=True):
        with open(req_path) as f:
            # NOTE: We don't make any guarantees about non-semantic whitespace
            # preservation, hence the strip.
            assert expected_req == f.read().strip()


def test_requirement_source_fix(req_file):
    _check_fixes(
        ["flask==0.5"],
        ["flask==1.0"],
        [req_file()],
        [
            ResolvedFixVersion(
                dep=ResolvedDependency(name="flask", version=Version("0.5")),
                version=Version("1.0"),
            )
        ],
    )


def test_requirement_source_fix_roundtrip(req_file):
    req_path = req_file()
    with open(req_path, "w") as f:
        f.write("flask==0.5")

    source = requirement.RequirementSource([req_path])
    specs = list(source.collect())

    flask_dep: ResolvedDependency | None = None
    for spec in specs:
        if isinstance(spec, ResolvedDependency) and spec.canonical_name == "flask":
            flask_dep = spec
            break
    assert flask_dep is not None
    assert flask_dep == ResolvedDependency(name="Flask", version=Version("0.5"))

    flask_fix = ResolvedFixVersion(dep=flask_dep, version=Version("1.0"))
    source.fix(flask_fix)

    with open(req_path) as f:
        assert f.read().strip() == "flask==1.0"


def test_requirement_source_fix_roundtrip_non_canonical_name(req_file):
    req_path = req_file()
    with open(req_path, "w") as f:
        f.write("Flask==0.5")

    source = requirement.RequirementSource([req_path])
    specs = list(source.collect())

    flask_dep: ResolvedDependency | None = None
    for spec in specs:
        if isinstance(spec, ResolvedDependency) and spec.canonical_name == "flask":
            flask_dep = spec
            break
    assert flask_dep is not None
    assert flask_dep == ResolvedDependency(name="Flask", version=Version("0.5"))

    flask_fix = ResolvedFixVersion(dep=flask_dep, version=Version("1.0"))
    source.fix(flask_fix)

    with open(req_path) as f:
        assert f.read().strip() == "Flask==1.0"


def test_requirement_source_fix_multiple_files(req_file):
    _check_fixes(
        ["flask==0.5", "requests==2.0\nflask==0.5"],
        ["flask==1.0", "requests==2.0\nflask==1.0"],
        [req_file(), req_file()],
        [
            ResolvedFixVersion(
                dep=ResolvedDependency(name="flask", version=Version("0.5")),
                version=Version("1.0"),
            )
        ],
    )


def test_requirement_source_fix_specifier_match(req_file):
    _check_fixes(
        ["flask<1.0", "requests==2.0\nflask<=0.6"],
        ["flask==1.0", "requests==2.0\nflask==1.0"],
        [req_file(), req_file()],
        [
            ResolvedFixVersion(
                dep=ResolvedDependency(name="flask", version=Version("0.5")),
                version=Version("1.0"),
            )
        ],
    )


def test_requirement_source_fix_specifier_no_match(req_file):
    # In order to make a fix, the specifier must match the current version and NOT the resolved fix
    # version. If the specifier matches both, we don't apply the fix since installing from the given
    # requirements file would already install the fixed version.
    _check_fixes(
        ["flask>=0.5", "requests==2.0\nflask<2.0"],
        ["flask>=0.5", "requests==2.0\nflask<2.0"],
        [req_file(), req_file()],
        [
            ResolvedFixVersion(
                dep=ResolvedDependency(name="flask", version=Version("0.5")),
                version=Version("1.0"),
            )
        ],
    )


def test_requirement_source_fix_preserve_marker(req_file):
    # `pip-requirements-parser` preserves requirements with markers that don't apply to the current
    # environment.
    _check_fixes(
        [
            'flask<1.0; python_version > "2.7"',
            'requests==2.0\nflask<=0.6; python_version <= "2.7"',
        ],
        [
            'flask==1.0; python_version > "2.7"',
            'requests==2.0\nflask==1.0; python_version <= "2.7"',
        ],
        [req_file(), req_file()],
        [
            ResolvedFixVersion(
                dep=ResolvedDependency(name="flask", version=Version("0.5")),
                version=Version("1.0"),
            )
        ],
    )


def test_requirement_source_fix_comments(req_file):
    _check_fixes(
        [
            "# comment here\nflask==0.5",
            "requests==2.0\n# another comment\nflask==0.5",
        ],
        ["# comment here\nflask==1.0", "requests==2.0\n# another comment\nflask==1.0"],
        [req_file(), req_file()],
        [
            ResolvedFixVersion(
                dep=ResolvedDependency(name="flask", version=Version("0.5")),
                version=Version("1.0"),
            )
        ],
    )


def test_requirement_source_fix_parse_failure(monkeypatch, req_file):
    logger = pretend.stub(warning=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(requirement, "logger", logger)

    # If we encounter multiple of the same package in the requirements file, we will throw a parsing
    # error
    input_reqs = ["flask==0.5", "flask==0.5\nrequests==2.0\nflask==0.3"]
    req_paths = [req_file(), req_file()]

    # Populate the requirements files
    for input_req, req_path in zip(input_reqs, req_paths, strict=True):
        with open(req_path, "w") as f:
            f.write(input_req)

    source = requirement.RequirementSource(req_paths)
    with pytest.raises(DependencyFixError):
        source.fix(
            ResolvedFixVersion(
                dep=ResolvedDependency(name="flask", version=Version("0.5")),
                version=Version("1.0"),
            )
        )
    assert len(logger.warning.calls) == 1

    # Check that the requirements files remain unchanged
    # If we encounter a failure while applying a fix, the fix should be rolled back from all files
    for expected_req, req_path in zip(input_reqs, req_paths, strict=True):
        with open(req_path) as f:
            assert expected_req == f.read().strip()


def test_requirement_source_fix_rollback_failure(monkeypatch, req_file):
    logger = pretend.stub(warning=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(requirement, "logger", logger)

    # If we encounter multiple of the same package in the requirements file, we will throw a parsing
    # error
    input_reqs = ["flask==0.5", "flask==0.5\nrequests==2.0\nflask==0.3"]
    req_paths = [req_file(), req_file()]

    # Populate the requirements files
    for input_req, req_path in zip(input_reqs, req_paths, strict=True):
        with open(req_path, "w") as f:
            f.write(input_req)

    # Simulate an error being raised during file recovery
    def mock_seek(*_args, **_kwargs):
        raise OSError

    from tempfile import _TemporaryFileWrapper

    monkeypatch.setattr(_TemporaryFileWrapper, "seek", mock_seek, raising=False)

    source = requirement.RequirementSource(req_paths)
    with pytest.raises(DependencyFixError):
        source.fix(
            ResolvedFixVersion(
                dep=ResolvedDependency(name="flask", version=Version("0.5")),
                version=Version("1.0"),
            )
        )
    # One for the parsing error and one for each file that we failed to rollback
    assert len(logger.warning.calls) == 3

    # We couldn't move the original requirements files back so we should expect a partially applied
    # fix. The first requirements file contains the fix, while the second one doesn't since we were
    # in the process of writing it out and didn't flush.
    expected_reqs = ["flask==1.0", "flask==0.5\nrequests==2.0\nflask==0.3"]
    for expected_req, req_path in zip(expected_reqs, req_paths, strict=True):
        with open(req_path) as f:
            assert expected_req == f.read().strip()


@pytest.mark.online
def test_requirement_source_require_hashes(req_file):
    source = _init_requirement(
        [
            (
                req_file(),
                "wheel==0.38.1 "
                "--hash=sha256:7a95f9a8dc0924ef318bd55b616112c70903192f524d120acc614f59547a9e1f\n"
                "setuptools==67.0.0 "
                "--hash=sha256:9d790961ba6219e9ff7d9557622d2fe136816a264dd01d5997cfc057d804853d",
            )
        ],
        require_hashes=True,
    )

    specs = list(source.collect())
    assert specs == [
        ResolvedDependency(name="wheel", version=Version("0.38.1")),
        ResolvedDependency(name="setuptools", version=Version("67.0.0")),
    ]


@pytest.mark.online
def test_requirement_source_require_hashes_not_fully_resolved(req_file):
    # When using `--require-hashes`, `pip` requires a fully resolved list of requirements. If it
    # finds a subdependency that is not listed in the requirements file, it will raise an error.
    #
    # In the case of Flask, this package has lots of subdependencies that aren't listed here so we
    # expect an error.
    source = _init_requirement(
        [
            (
                req_file(),
                "flask==2.0.1 "
                "--hash=sha256:a6209ca15eb63fc9385f38e452704113d679511d9574d09b2cf9183ae7d20dc9",
            )
        ],
        require_hashes=True,
    )

    with pytest.raises(DependencySourceError):
        list(source.collect())


def test_requirement_source_require_hashes_missing(req_file):
    source = _init_requirement([(req_file(), "wheel==0.38.1")], require_hashes=True)

    # All requirements must be hashed when collecting with `require-hashes`
    with pytest.raises(DependencySourceError):
        list(source.collect())


def test_requirement_source_require_hashes_inferred(req_file):
    source = _init_requirement(
        [
            (
                req_file(),
                "wheel==0.38.1 "
                "--hash=sha256:7a95f9a8dc0924ef318bd55b616112c70903192f524d120acc614f59547a9e1f\n"
                "setuptools==67.0.0",
            )
        ]
    )

    # If at least one requirement is hashed, this infers `require-hashes`
    with pytest.raises(DependencySourceError):
        list(source.collect())


def test_requirement_source_require_hashes_unpinned(req_file):
    source = _init_requirement(
        [
            (
                req_file(),
                "missing\n"
                "wheel==0.38.1 "
                "--hash=sha256:7a95f9a8dc0924ef318bd55b616112c70903192f524d120acc614f59547a9e1f\n"
                "setuptools<=67.0.0 "
                "--hash=sha256:9d790961ba6219e9ff7d9557622d2fe136816a264dd01d5997cfc057d804853d",
            )
        ]
    )

    # When hashed dependencies are provided, all dependencies must be explicitly pinned to an exact
    # version number
    with pytest.raises(DependencySourceError):
        list(source.collect())


def test_requirement_source_require_hashes_incorrect_hash(req_file):
    source = _init_requirement(
        [
            (
                req_file(),
                "wheel==0.38.1 "
                "--hash=sha256:7a95f9a8dc0924ef318bd55b616112c70903192f524d120acc614f59547a9e1f\n"
                "setuptools<=67.0.0 "
                "--hash=sha256:setuptools-hash",
            )
        ]
    )

    # The `setuptools` hash is incorrect.
    with pytest.raises(DependencySourceError):
        list(source.collect())


def test_requirement_source_disable_pip_editable_skip(req_file):
    source = _init_requirement(
        [(req_file(), "-e file:flask.py#egg=flask==2.0.1")],
        disable_pip=True,
        no_deps=True,
        skip_editable=True,
    )

    specs = list(source.collect())
    assert specs == [SkippedDependency(name="flask", skip_reason="requirement marked as editable")]


def test_requirement_source_disable_pip_editable_skip_with_hashes(req_file):
    source = _init_requirement(
        [
            (
                req_file(),
                "-e file:.\n"
                "wheel==0.38.1 "
                "--hash=sha256:"
                "7a95f9a8dc0924ef318bd55b616112c70903192f524d120acc614f59547a9e1f",
            )
        ],
        disable_pip=True,
        no_deps=True,
        skip_editable=True,
    )

    specs = list(source.collect())
    assert specs == [
        SkippedDependency(name="-e file:.", skip_reason="requirement marked as editable"),
        ResolvedDependency(name="wheel", version=Version("0.38.1")),
    ]


def test_requirement_source_disable_pip_duplicate_dependencies(req_file):
    source = _init_requirement(
        [(req_file(), "flask==1.0\nflask==1.0")], disable_pip=True, no_deps=True
    )

    specs = list(source.collect())

    # If the dependency list has duplicates, then converting to a set will reduce the length of the
    # collection
    assert len(specs) == len(set(specs))


def test_requirement_source_disable_pip_duplicate_dependencies_with_extras(req_file):
    source = _init_requirement(
        [(req_file(), "aiohttp==3.9\naiohttp[speedups]==3.9")],
        disable_pip=True,
        no_deps=True,
    )

    specs = list(source.collect())

    # If the dependency list has duplicates, then converting to a set will reduce the length of the
    # collection
    assert len(specs) == len(set(specs))


def test_requirement_source_disable_pip_duplicate_dependencies_diff_specifier(req_file):
    source = _init_requirement(
        [(req_file(), "flask==1.0\nflask==2.0")], disable_pip=True, no_deps=True
    )

    with pytest.raises(DependencySourceError):
        list(source.collect())


def test_requirement_source_no_double_open(monkeypatch, req_file):
    source = _init_requirement([(req_file(), "flask==2.0.1")])

    # Intercept the calls to `NamedTemporaryFile` to get a handle on each file object.
    tmp_files = []

    def named_temp_file(*args, **kwargs):
        tmp_file = NamedTemporaryFile(*args, **kwargs)
        tmp_files.append(tmp_file)
        return tmp_file

    monkeypatch.setattr(
        requirement,
        "NamedTemporaryFile",
        named_temp_file,
    )

    # Intercept the `VirtualEnv` constructor to check that all file handles are closed prior to
    # the `pip` invocation.
    #
    # `pip` will open the file so we need to ensure that we've closed it.
    def virtual_env(*args, **kwargs):
        for tmp_file in tmp_files:
            assert tmp_file.closed
        return VirtualEnv(*args, **kwargs)

    monkeypatch.setattr(requirement, "VirtualEnv", virtual_env)

    specs = list(source.collect())
    assert ResolvedDependency("Flask", Version("2.0.1")) in specs


@pytest.mark.skipif(sys.platform == "win32", reason="os.mkfifo does not exists on windows")
def test_requirement_source_fifo():
    with TemporaryDirectory() as tmp_dir:
        fifo_path = Path(os.path.join(tmp_dir, "fifo"))
        os.mkfifo(fifo_path)

        def write_to_fifo():
            with open(fifo_path, "w") as f:
                f.write("flask==2.0.1")

        # Make sure we wait for the thread to be done regardless of whether an
        # error gets thrown
        t = Thread(target=write_to_fifo)
        t.start()
        try:
            source = requirement.RequirementSource([fifo_path])
            specs = list(source.collect())
        finally:
            t.join()

    assert ResolvedDependency("Flask", Version("2.0.1")) in specs


def test_requirement_source_fix_explicit_subdep(monkeypatch, req_file):
    logger = pretend.stub(warning=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(requirement, "logger", logger)

    source = _init_requirement([(req_file(), "flask==2.0.1")])
    flask_deps = source.collect()

    # Firstly, get a handle on the `jinja2` dependency. The version cannot be hardcoded since it
    # depends what versions are available on PyPI when dependency resolution runs.
    jinja_dep: ResolvedDependency | None = None
    for dep in flask_deps:
        if isinstance(dep, ResolvedDependency) and dep.canonical_name == "jinja2":
            jinja_dep = dep
            break
    assert jinja_dep is not None

    # Check that the `jinja2` dependency is explicitly added to the requirements file with an
    # associated comment.
    _check_fixes(
        ["flask==2.0.1"],
        ["flask==2.0.1\n    # pip-audit: subdependency explicitly fixed\njinja2==4.0.0"],
        [req_file()],
        [
            ResolvedFixVersion(
                dep=jinja_dep,
                version=Version("4.0.0"),
            )
        ],
    )

    # When explicitly listing a fixed subdependency, we issue a warning.
    assert len(logger.warning.calls) == 1


def test_requirement_source_fix_explicit_subdep_multiple_reqs(req_file):
    # Recreate the vulnerable subdependency case.
    source = _init_requirement([(req_file(), "flask==2.0.1")])
    flask_deps = source.collect()
    jinja_dep: ResolvedDependency | None = None
    for dep in flask_deps:
        if isinstance(dep, ResolvedDependency) and dep.canonical_name == "jinja2":
            jinja_dep = dep
            break
    assert jinja_dep is not None

    # This time our requirements file also lists `django-jinja`, another requirement that depends on
    # `jinja2`. We're expecting that the comment generated above the `jinja2` requirement that gets
    # added into the file will list both `flask` and `django-jinja` as sources.
    _check_fixes(
        ["flask==2.0.1\ndjango-jinja==1.0"],
        [
            "flask==2.0.1\ndjango-jinja==1.0\n"
            "    # pip-audit: subdependency explicitly fixed\n"
            "jinja2==4.0.0"
        ],
        [req_file()],
        [
            ResolvedFixVersion(
                dep=jinja_dep,
                version=Version("4.0.0"),
            )
        ],
    )


def test_requirement_source_fix_explicit_subdep_resolver_error(req_file):
    # Recreate the vulnerable subdependency case.
    source = _init_requirement([(req_file(), "flask==2.0.1")])
    flask_deps = source.collect()
    jinja_dep: ResolvedDependency | None = None
    for dep in flask_deps:
        if isinstance(dep, ResolvedDependency) and dep.canonical_name == "jinja2":
            jinja_dep = dep
            break
    assert jinja_dep is not None

    # Dependee requirements are a attached to each dependency. We no longer resolve dependencies
    # as part of `--fix` so we shouldn't call into dependency resolution.
    mock_resolver = pretend.stub(resolve=pretend.call_recorder(lambda _reqs, _req_hashes: []))
    source.fix(
        ResolvedFixVersion(
            dep=jinja_dep,
            version=Version("4.0.0"),
        )
    )
    assert len(mock_resolver.resolve.calls) == 0


def test_requirement_source_fix_explicit_subdep_comment_retention(req_file):
    # This test is regression testing a weakness in the previous fix implementation.
    #
    # When fixing a subdependency and explicitly adding it to the requirements file, we add a
    # comment above the line to explain its presence since it's unusual to explicitly pin a
    # subdependency like this.
    #
    # When we "fix" dependencies, we parse the requirements file and write it back out with the
    # relevant line amended or added. When we used `pip-api` for requirements parsing, our fix logic
    # had the unfortunate side effect of stripping comments from the file. Importantly, when we
    # applied subdependency fixes, the automated comments used to be removed by any subsequent
    # fixes.
    #
    # Since we've switching `pip-requirements-parser`, we should no longer have this issue.

    # Recreate the vulnerable subdependency case.
    source = _init_requirement([(req_file(), "flask==2.0.1")])
    flask_deps = source.collect()
    jinja_dep: ResolvedDependency | None = None
    for dep in flask_deps:
        if isinstance(dep, ResolvedDependency) and dep.canonical_name == "jinja2":
            jinja_dep = dep
            break
    assert jinja_dep is not None

    # Now place a fix for the top-level `flask` requirement after the `jinja2` subdependency fix.
    #
    # When applying the `flask` fix, `pip-audit` reparses the requirements file, and writes it back
    # out with the fixed `flask` version with the comments preserved.
    #
    # One quirk is that comment indentation isn't preserved (the automated comment was originally
    # indented with 4 spaces).
    _check_fixes(
        ["flask==2.0.1"],
        ["flask==3.0.0\n# pip-audit: subdependency explicitly fixed\njinja2==4.0.0"],
        [req_file()],
        [
            ResolvedFixVersion(
                dep=jinja_dep,
                version=Version("4.0.0"),
            ),
            ResolvedFixVersion(
                dep=ResolvedDependency(name="flask", version=Version("2.0.1")),
                version=Version("3.0.0"),
            ),
        ],
    )


def test_requirement_source_fix_invalid_lines(req_file):
    source = _init_requirement([(req_file(), "a#b#c\nflask==0.5")])
    with pytest.raises(DependencyFixError):
        source.fix(
            ResolvedFixVersion(
                dep=ResolvedDependency(name="flask", version=Version("0.5")),
                version=Version("1.0"),
            )
        )


def test_requirement_source_disable_pip(req_file):
    source = _init_requirement([(req_file(), "flask==2.0.1")], disable_pip=True, no_deps=True)

    specs = list(source.collect())
    assert specs == [ResolvedDependency("flask", Version("2.0.1"))]


def test_requirement_source_disable_pip_without_no_deps(req_file):
    # In order to use `--disable-pip`, the requirements file must either be hashed or `--no-deps`
    # must be provided.
    #
    # Since neither is true, we expect a failure.
    source = _init_requirement(
        [(req_file(), "flask==2.0.1")],
        disable_pip=True,
    )

    with pytest.raises(
        DependencySourceError,
        match="the --disable-pip flag can only be used with a hashed requirements files or if the "
        "--no-deps flag has been provided",
    ):
        list(source.collect())


def test_requirement_source_disable_pip_hashes_without_no_deps(req_file):
    # In this case, `--no-deps` is not provided but since the requirements file is hashed, providing
    # `--disable-pip` is valid.
    source = _init_requirement(
        [
            (
                req_file(),
                "flask==2.0.1 "
                "--hash=sha256:a6209ca15eb63fc9385f38e452704113d679511d9574d09b2cf9183ae7d20dc9",
            )
        ],
        disable_pip=True,
    )

    specs = list(source.collect())
    assert specs == [ResolvedDependency("flask", Version("2.0.1"))]


def test_requirement_source_disable_pip_incomplete_hashes(req_file):
    # In this case, `--no-deps` is not provided but since the requirements file is hashed, providing
    # `--disable-pip` is valid.
    source = _init_requirement(
        [
            (
                req_file(),
                "flask==2.0.1 "
                "--hash=sha256:a6209ca15eb63fc9385f38e452704113d679511d9574d09b2cf9183ae7d20dc9\n"
                "requests==1.0",
            )
        ],
        disable_pip=True,
    )

    with pytest.raises(
        DependencySourceError, match="requirement requests==1.0 does not contain a hash"
    ):
        list(source.collect())


def test_requirement_source_disable_pip_unpinned(req_file):
    source = _init_requirement(
        [(req_file(), "flask\nrequests==1.0")], disable_pip=True, no_deps=True
    )

    # When dependency resolution is disabled, all requirements must be pinned.
    with pytest.raises(DependencySourceError):
        list(source.collect())


def test_requirement_source_disable_pip_not_exact_version(req_file):
    source = _init_requirement(
        [(req_file(), "flask==1.0\nrequests>=1.0")], disable_pip=True, no_deps=True
    )

    # When dependency resolution is disabled, all requirements must be pinned.
    with pytest.raises(DependencySourceError):
        list(source.collect())


def test_requirement_source_disable_pip_unpinned_url(req_file):
    source = _init_requirement(
        [
            (
                req_file(),
                "https://github.com/pallets/flask/archive/refs/tags/2.0.1.tar.gz#egg=flask\n",
            )
        ],
        disable_pip=True,
        no_deps=True,
    )

    assert list(source.collect()) == [
        SkippedDependency(
            name="flask",
            skip_reason="URL requirements cannot be pinned to a specific package version",
        )
    ]


def test_requirement_source_disable_pip_editable_with_egg_fragment(req_file):
    source = _init_requirement(
        [(req_file(), "-e file:flask.py#egg=flask==2.0.1")],
        disable_pip=True,
        no_deps=True,
    )

    specs = list(source.collect())
    assert (
        SkippedDependency(
            name="flask",
            skip_reason="URL requirements cannot be pinned to a specific package version",
        )
        in specs
    )


def test_requirement_source_disable_pip_editable_without_egg_fragment(req_file):
    source = _init_requirement([(req_file(), "-e file:flask.py")], disable_pip=True, no_deps=True)

    specs = list(source.collect())
    assert (
        SkippedDependency(
            name="-e file:flask.py",
            skip_reason="could not deduce package version from URL requirement",
        )
        in specs
    )


def _target_env(spec: str) -> TargetEnvironment:
    return TargetEnvironment.from_string(spec)


def test_requirement_source_target_env_marker_outcomes(req_file):
    # A fixed manifest covering the three marker outcomes: each kind must
    # land in its own place.
    source = _init_requirement(
        [
            (
                req_file(),
                "flask==2.0.1\n"
                'winonly==1.0; sys_platform == "win32"\n'
                'pyreq==1.2; python_version >= "3.10"\n'
                'mystery==1.0; os_name == "posix"\n',
            )
        ],
        disable_pip=True,
        no_deps=True,
        target_environment=_target_env("python_version=3.11;sys_platform=linux"),
    )

    specs = list(source.collect())

    # Markers that evaluate to true are collected as usual.
    resolved = [s for s in specs if isinstance(s, ResolvedDependency)]
    assert {s.name for s in resolved} == {"flask", "pyreq"}

    # Markers that evaluate to false (winonly) are excluded.
    assert "winonly" not in {s.name for s in specs}

    # Markers that cannot be decided are their own category: visible and
    # countable, with an explanatory reason, and never confused with skips.
    unevaluated = [s for s in specs if isinstance(s, UnevaluatedDependency)]
    assert len(unevaluated) == 1
    assert unevaluated[0].name == "mystery"
    assert "os_name" in unevaluated[0].unevaluated_reason
    assert not any(isinstance(s, SkippedDependency) for s in specs)

    # The source records the environment it evaluated against.
    assert source.resolved_target_environment is not None
    assert source.resolved_target_environment.describe() == "python_version=3.11;sys_platform=linux"


def test_requirement_source_target_env_different_environments(req_file):
    # The same manifest, evaluated against two different target environments,
    # yields different but explainable dependency sets.
    manifest = (
        "common==3.0\n"
        'winonly==1.0; sys_platform == "win32"\n'
        'linonly==2.0; sys_platform == "linux"\n'
        'legacy==4.0; python_version < "3.10"\n'
    )

    def resolved_names(env_spec):
        source = _init_requirement(
            [(req_file(), manifest)],
            disable_pip=True,
            no_deps=True,
            target_environment=_target_env(env_spec),
        )
        return {s.name for s in source.collect() if isinstance(s, ResolvedDependency)}

    linux_modern = resolved_names("python_version=3.11;sys_platform=linux")
    windows_legacy = resolved_names("python_version=3.9;sys_platform=win32")

    assert linux_modern == {"common", "linonly"}
    assert windows_legacy == {"common", "winonly", "legacy"}
    # Every difference between the two runs is explained by a marker on the
    # corresponding requirement line.
    assert linux_modern.symmetric_difference(windows_legacy) == {
        "linonly",
        "winonly",
        "legacy",
    }


def test_requirement_source_target_env_deterministic(req_file):
    # Repeating the audit under the same target environment must produce
    # identical conclusions in an identical order.
    manifest = (
        "flask==2.0.1\n"
        'winonly==1.0; sys_platform == "win32"\n'
        'mystery==1.0; os_name == "posix"\n'
        "base[sec]==1.0\n"
        'secdep==2.0; extra == "sec"\n'
    )

    def collect():
        source = _init_requirement(
            [(req_file(), manifest)],
            disable_pip=True,
            no_deps=True,
            target_environment=_target_env("python_version=3.11;sys_platform=linux"),
        )
        return list(source.collect())

    first = collect()
    second = collect()
    assert first == second
    assert [s.name for s in first] == [s.name for s in second]


def test_requirement_source_target_env_extras_closure(req_file):
    # Optional dependencies are expanded into a closure consistent with the
    # target environment: extras requested transitively by included
    # requirements are included, others are not.
    manifest = (
        "base[sec]==1.0\n"
        'secdep==2.0; extra == "sec"\n'
        'chain[two]==3.0; extra == "sec"\n'
        'chaindep==4.0; extra == "two"\n'
        'otherdep==5.0; extra == "other"\n'
    )

    source = _init_requirement(
        [(req_file(), manifest)],
        disable_pip=True,
        no_deps=True,
        target_environment=_target_env("python_version=3.11;sys_platform=linux"),
    )
    specs = list(source.collect())
    resolved = {s.name for s in specs if isinstance(s, ResolvedDependency)}

    # `base[sec]` pulls in `secdep`; `chain[two]` (included via `sec`) pulls
    # in `chaindep`; nothing requests `other`, so `otherdep` is excluded.
    assert resolved == {"base", "secdep", "chain", "chaindep"}

    # The resolved environment records the expanded closure.
    assert source.resolved_target_environment.extras == frozenset({"sec", "two"})


def test_requirement_source_target_env_extras_cycle_terminates(req_file):
    # A cycle in the extras graph terminates (the closure is a monotone
    # fixpoint) and includes both ends of the cycle.
    manifest = 'a[x]==1.0; extra == "y"\nb[y]==2.0; extra == "x"\nroot[y]==3.0\n'
    source = _init_requirement(
        [(req_file(), manifest)],
        disable_pip=True,
        no_deps=True,
        target_environment=_target_env("python_version=3.11"),
    )
    resolved = {s.name for s in source.collect() if isinstance(s, ResolvedDependency)}
    assert resolved == {"a", "b", "root"}


def test_requirement_source_target_env_extras_closure_limit(req_file, monkeypatch):
    # If the closure fails to converge within the iteration bound, the
    # failure is reported explicitly instead of hanging.
    monkeypatch.setattr(requirement, "MAX_EXTRAS_CLOSURE_ITERATIONS", 2)
    manifest = (
        "d0[e1]==1.0\n"
        'd1[e2]==1.0; extra == "e1"\n'
        'd2[e3]==1.0; extra == "e2"\n'
        'd3[e4]==1.0; extra == "e3"\n'
    )
    source = _init_requirement(
        [(req_file(), manifest)],
        disable_pip=True,
        no_deps=True,
        target_environment=_target_env("python_version=3.11"),
    )
    with pytest.raises(DependencySourceError, match="extras closure did not converge"):
        list(source.collect())


def test_requirement_source_target_env_unevaluated_not_matched(req_file, monkeypatch):
    # Unevaluated dependencies must not participate in vulnerability
    # matching: the auditor never queries the service for them.
    source = _init_requirement(
        [(req_file(), 'mystery==1.0; os_name == "posix"\n')],
        disable_pip=True,
        no_deps=True,
        target_environment=_target_env("python_version=3.11"),
    )

    class ExplodingService:
        def query_all(self, specs):
            for spec in specs:
                assert spec.is_unevaluated()
                yield spec, []

    auditor = Auditor(ExplodingService())
    results = list(auditor.audit(source))
    assert len(results) == 1
    dep, vulns = results[0]
    assert isinstance(dep, UnevaluatedDependency)
    assert vulns == []


def test_requirement_source_without_target_env_unchanged(req_file):
    # Without a target environment, collection behaves exactly as before:
    # markers are evaluated against the current machine and no resolved
    # environment is recorded.
    source = _init_requirement([(req_file(), "flask==2.0.1")], disable_pip=True, no_deps=True)
    specs = list(source.collect())
    assert specs == [ResolvedDependency("flask", Version("2.0.1"))]
    assert source.resolved_target_environment is None


def test_requirement_source_target_env_requires_disable_pip(req_file):
    # A target environment on the `pip`-resolution path would silently
    # evaluate markers against the current machine; the source refuses to
    # degrade instead.
    source = _init_requirement(
        [(req_file(), "flask==2.0.1")],
        no_deps=True,
        target_environment=_target_env("python_version=3.11"),
    )
    with pytest.raises(DependencySourceError, match="target environment"):
        list(source.collect())
