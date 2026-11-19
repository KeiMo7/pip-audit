import pytest
from packaging.markers import Marker

from pip_audit._environment import TargetEnvironment, TargetEnvironmentError


class TestTargetEnvironmentFromString:
    def test_valid(self):
        env = TargetEnvironment.from_string("python_version=3.11;sys_platform=linux")
        assert dict(env.values) == {"python_version": "3.11", "sys_platform": "linux"}
        assert env.extras == frozenset()

    def test_valid_with_extras(self):
        env = TargetEnvironment.from_string(
            "python_version=3.11;extra=security;extra=Tests;sys_platform=linux"
        )
        assert dict(env.values) == {"python_version": "3.11", "sys_platform": "linux"}
        # extras are canonicalized
        assert env.extras == frozenset({"security", "tests"})

    def test_whitespace_and_empty_pairs_tolerated(self):
        env = TargetEnvironment.from_string(" python_version = 3.11 ; ; sys_platform=linux ")
        assert dict(env.values) == {"python_version": "3.11", "sys_platform": "linux"}

    @pytest.mark.parametrize(
        "spec",
        [
            # empty descriptions
            "",
            "   ",
            ";",
            # not a key=value pair
            "bogus",
            "python_version",
            # unknown keys (including near-miss typos)
            "python-version=3.11",
            "python==3.11",
            # duplicate keys
            "python_version=3.11;python_version=3.12",
            # empty values
            "python_version=",
            "extra=",
            # invalid versions
            "python_version=three",
            "python_full_version=3.x",
            # values outside the token charset; notably anything that could
            # smuggle a URL or credentials into reports and logs
            "python_version=3.11@evil",
            "sys_platform=https://user:pw@internal.example.com",
            "os_name=my os",
        ],
    )
    def test_invalid(self, spec):
        with pytest.raises(TargetEnvironmentError):
            TargetEnvironment.from_string(spec)

    def test_invalid_value_not_echoed(self):
        # The error message must not leak the offending value, since it may
        # contain sensitive material.
        secret = "https://user:hunter2@internal.example.com"
        with pytest.raises(TargetEnvironmentError) as excinfo:
            TargetEnvironment.from_string(f"sys_platform={secret}")
        assert secret not in str(excinfo.value)
        assert "hunter2" not in str(excinfo.value)

    def test_describe_is_canonical(self):
        # Key order in the input does not affect the canonical description.
        env1 = TargetEnvironment.from_string("sys_platform=linux;python_version=3.11")
        env2 = TargetEnvironment.from_string("python_version=3.11;sys_platform=linux")
        assert env1 == env2
        assert env1.describe() == "python_version=3.11;sys_platform=linux"
        assert env1.describe() == env2.describe()

    def test_describe_includes_extras_sorted(self):
        env = TargetEnvironment.from_string("python_version=3.11;extra=b;extra=a")
        assert env.describe() == "python_version=3.11;extra=a;extra=b"

    def test_as_report_dict(self):
        env = TargetEnvironment.from_string("python_version=3.11;sys_platform=linux;extra=sec")
        assert env.as_report_dict() == {
            "python_version": "3.11",
            "sys_platform": "linux",
            "extras": ["sec"],
        }


class TestEvaluateMarker:
    def test_true(self):
        env = TargetEnvironment.from_string("python_version=3.11;sys_platform=linux")
        evaluation = env.evaluate_marker(Marker('python_version >= "3.10"'))
        assert evaluation.value is True
        assert not evaluation.is_unevaluated

    def test_false(self):
        env = TargetEnvironment.from_string("python_version=3.11;sys_platform=linux")
        evaluation = env.evaluate_marker(Marker('sys_platform == "win32"'))
        assert evaluation.value is False
        assert not evaluation.is_unevaluated

    def test_compound(self):
        env = TargetEnvironment.from_string("python_version=3.11;sys_platform=linux")
        evaluation = env.evaluate_marker(
            Marker('python_version >= "3.10" and sys_platform == "linux"')
        )
        assert evaluation.value is True

    def test_unevaluated_unknown_variable(self):
        # `os_name` is not part of the target environment description, so the
        # marker cannot be decided: it must come back unevaluated, never as a
        # guessed boolean (and never filled in from the current machine).
        env = TargetEnvironment.from_string("python_version=3.11")
        evaluation = env.evaluate_marker(Marker('os_name == "posix"'))
        assert evaluation.is_unevaluated
        assert "os_name" in evaluation.reason

    def test_unevaluated_evaluation_error(self, monkeypatch):
        # An unexpected failure while evaluating a marker is reported as
        # unevaluated (with a reason), never as a guessed boolean and never
        # propagated to abort the whole audit.
        import pip_audit._environment as environment

        def explode(_markers, _environment):
            raise ValueError("synthetic evaluation failure")

        monkeypatch.setattr(environment, "_evaluate_markers", explode)
        env = TargetEnvironment.from_string("python_version=3.11")
        evaluation = env.evaluate_marker(Marker('python_version >= "3.10"'))
        assert evaluation.is_unevaluated
        assert "synthetic evaluation failure" in evaluation.reason

    def test_extra_markers(self):
        env = TargetEnvironment.from_string("python_version=3.11;extra=security")
        assert env.evaluate_marker(Marker('extra == "security"')).value is True
        assert env.evaluate_marker(Marker('extra == "tests"')).value is False

    def test_extra_markers_without_extras(self):
        # With no extras requested, `extra == ...` markers are false (not
        # unevaluated), matching pip's own treatment of extras.
        env = TargetEnvironment.from_string("python_version=3.11")
        assert env.evaluate_marker(Marker('extra == "security"')).value is False

    def test_does_not_fall_back_to_current_machine(self):
        # A marker that would be true on the machine running the audit must
        # still be unevaluated when the target environment doesn't describe
        # the variable it references.
        env = TargetEnvironment.from_string("python_version=3.11")
        evaluation = env.evaluate_marker(Marker('sys_platform == "linux"'))
        assert evaluation.is_unevaluated
