import pytest
from anchore_engine.services.policy_engine.engine.policy.gates import vulnerabilities


class FakeVuln:
    """
    A fake for ImagePackageVulnerability:
    """

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)

class TestDeterminePkgClass:

    def test_non_github_defaults(self):
        vuln_obj = FakeVuln(vulnerability_namespace_name='RHEL')
        result = vulnerabilities.determine_pkg_class(vuln_obj)
        assert result == 'os'

    def test_github_os(self):
        vuln_obj = FakeVuln(vulnerability_namespace_name='github:os')
        result = vulnerabilities.determine_pkg_class(vuln_obj)
        assert result == 'os'


    @pytest.mark.parametrize('namespace', [
        'github:python',
        'github:composer',
        'github:gem',
        'github:java',
        'github:npm',
        'github:nuget',
        'github:foo'
    ])
    def test_github_non_os(self, namespace):
        vuln_obj = FakeVuln(vulnerability_namespace_name=namespace)
        result = vulnerabilities.determine_pkg_class(vuln_obj)
        assert result == 'non-os'
