import json

import pytest
from packaging.version import Version

import pip_audit._format as format
import pip_audit._service as service
from pip_audit._environment import TargetEnvironment


@pytest.mark.parametrize("output_desc, output_aliases", ([True, False], [True, False]))
def test_json_manifest(output_desc, output_aliases):
    fmt = format.JsonFormat(output_desc, output_aliases)

    assert fmt.is_manifest


def test_json(vuln_data):
    json_format = format.JsonFormat(True, True)
    expected_json = {
        "dependencies": [
            {
                "name": "foo",
                "version": "1.0",
                "vulns": [
                    {
                        "id": "VULN-0",
                        "fix_versions": [
                            "1.1",
                            "1.4",
                        ],
                        "aliases": ["CVE-0000-00000"],
                        "description": "The first vulnerability",
                    },
                    {
                        "id": "VULN-1",
                        "fix_versions": ["1.0"],
                        "aliases": ["CVE-0000-00001"],
                        "description": "The second vulnerability",
                    },
                ],
            },
            {
                "name": "bar",
                "version": "0.1",
                "vulns": [
                    {
                        "id": "VULN-2",
                        "fix_versions": [],
                        "aliases": ["CVE-0000-00002"],
                        "description": "The third vulnerability",
                    }
                ],
            },
        ],
        "fixes": [],
    }
    assert json_format.format(vuln_data, []) == json.dumps(expected_json)


def test_json_no_desc(vuln_data):
    json_format = format.JsonFormat(False, True)
    expected_json = {
        "dependencies": [
            {
                "name": "foo",
                "version": "1.0",
                "vulns": [
                    {
                        "id": "VULN-0",
                        "fix_versions": [
                            "1.1",
                            "1.4",
                        ],
                        "aliases": ["CVE-0000-00000"],
                    },
                    {
                        "id": "VULN-1",
                        "fix_versions": ["1.0"],
                        "aliases": ["CVE-0000-00001"],
                    },
                ],
            },
            {
                "name": "bar",
                "version": "0.1",
                "vulns": [
                    {
                        "id": "VULN-2",
                        "fix_versions": [],
                        "aliases": ["CVE-0000-00002"],
                    }
                ],
            },
        ],
        "fixes": [],
    }
    assert json_format.format(vuln_data, []) == json.dumps(expected_json)


def test_json_no_desc_no_aliases(vuln_data):
    json_format = format.JsonFormat(False, False)
    expected_json = {
        "dependencies": [
            {
                "name": "foo",
                "version": "1.0",
                "vulns": [
                    {
                        "id": "VULN-0",
                        "fix_versions": [
                            "1.1",
                            "1.4",
                        ],
                    },
                    {
                        "id": "VULN-1",
                        "fix_versions": ["1.0"],
                    },
                ],
            },
            {
                "name": "bar",
                "version": "0.1",
                "vulns": [
                    {
                        "id": "VULN-2",
                        "fix_versions": [],
                    }
                ],
            },
        ],
        "fixes": [],
    }
    assert json_format.format(vuln_data, []) == json.dumps(expected_json)


def test_json_skipped_dep(vuln_data_skipped_dep):
    json_format = format.JsonFormat(False, True)
    expected_json = {
        "dependencies": [
            {
                "name": "foo",
                "version": "1.0",
                "vulns": [
                    {
                        "id": "VULN-0",
                        "fix_versions": [
                            "1.1",
                            "1.4",
                        ],
                        "aliases": ["CVE-0000-00000"],
                    },
                ],
            },
            {
                "name": "bar",
                "skip_reason": "skip-reason",
            },
        ],
        "fixes": [],
    }
    assert json_format.format(vuln_data_skipped_dep, []) == json.dumps(expected_json)


def test_json_fix(vuln_data, fix_data):
    json_format = format.JsonFormat(True, True)
    expected_json = {
        "dependencies": [
            {
                "name": "foo",
                "version": "1.0",
                "vulns": [
                    {
                        "id": "VULN-0",
                        "fix_versions": [
                            "1.1",
                            "1.4",
                        ],
                        "aliases": ["CVE-0000-00000"],
                        "description": "The first vulnerability",
                    },
                    {
                        "id": "VULN-1",
                        "fix_versions": ["1.0"],
                        "aliases": ["CVE-0000-00001"],
                        "description": "The second vulnerability",
                    },
                ],
            },
            {
                "name": "bar",
                "version": "0.1",
                "vulns": [
                    {
                        "id": "VULN-2",
                        "fix_versions": [],
                        "aliases": ["CVE-0000-00002"],
                        "description": "The third vulnerability",
                    }
                ],
            },
        ],
        "fixes": [
            {
                "name": "foo",
                "old_version": "1.0",
                "new_version": "1.8",
            },
            {
                "name": "bar",
                "old_version": "0.1",
                "new_version": "0.3",
            },
        ],
    }
    assert json_format.format(vuln_data, fix_data) == json.dumps(expected_json)


def test_json_skipped_fix(vuln_data, skipped_fix_data):
    json_format = format.JsonFormat(True, True)
    expected_json = {
        "dependencies": [
            {
                "name": "foo",
                "version": "1.0",
                "vulns": [
                    {
                        "id": "VULN-0",
                        "fix_versions": [
                            "1.1",
                            "1.4",
                        ],
                        "aliases": ["CVE-0000-00000"],
                        "description": "The first vulnerability",
                    },
                    {
                        "id": "VULN-1",
                        "fix_versions": ["1.0"],
                        "aliases": ["CVE-0000-00001"],
                        "description": "The second vulnerability",
                    },
                ],
            },
            {
                "name": "bar",
                "version": "0.1",
                "vulns": [
                    {
                        "id": "VULN-2",
                        "fix_versions": [],
                        "aliases": ["CVE-0000-00002"],
                        "description": "The third vulnerability",
                    }
                ],
            },
        ],
        "fixes": [
            {
                "name": "foo",
                "old_version": "1.0",
                "new_version": "1.8",
            },
            {"name": "bar", "version": "0.1", "skip_reason": "skip-reason"},
        ],
    }
    assert json_format.format(vuln_data, skipped_fix_data) == json.dumps(expected_json)


def test_json_unevaluated_dep():
    json_format = format.JsonFormat(True, True)
    result = {
        service.UnevaluatedDependency(
            name="mystery", unevaluated_reason="marker references a variable"
        ): [],
    }
    expected = {
        "dependencies": [
            {
                "name": "mystery",
                "unevaluated_reason": "marker references a variable",
            }
        ],
        "fixes": [],
    }
    assert json_format.format(result, []) == json.dumps(expected)


def test_json_target_environment():
    json_format = format.JsonFormat(True, True)
    json_format.target_environment = TargetEnvironment.from_string(
        "python_version=3.11;sys_platform=linux;extra=sec"
    )
    result = {
        service.ResolvedDependency(name="foo", version=Version("1.0")): [],
    }
    expected = {
        "target_environment": {
            "python_version": "3.11",
            "sys_platform": "linux",
            "extras": ["sec"],
        },
        "dependencies": [{"name": "foo", "version": "1.0", "vulns": []}],
        "fixes": [],
    }
    assert json_format.format(result, []) == json.dumps(expected)


def test_json_no_target_environment_by_default():
    # Without a target environment, the output is unchanged: no new field.
    json_format = format.JsonFormat(True, True)
    result = {
        service.ResolvedDependency(name="foo", version=Version("1.0")): [],
    }
    output = json.loads(json_format.format(result, []))
    assert "target_environment" not in output
