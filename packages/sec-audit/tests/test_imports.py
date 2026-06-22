"""import_string error disambiguation and build_from_import_string
signature-based config passing without masking constructor bugs."""

import pytest

import sec_audit.core.imports as imports_mod
from sec_audit.core.exceptions import AuditImportError
from sec_audit.core.imports import import_string


def test_import_string_rejects_bad_path():
    with pytest.raises(AuditImportError, match='module.attr'):
        import_string('nodot')


def test_import_string_reports_missing_attribute():
    with pytest.raises(AuditImportError, match='does not exist'):
        import_string('json.does_not_exist_attr')


def test_import_string_reports_missing_module():
    with pytest.raises(AuditImportError, match='not found'):
        import_string('definitely_missing_module_xyz.attr')


def test_import_string_distinguishes_missing_dependency(monkeypatch):
    # The requested module exists but fails to import a missing dependency.
    def fake_import(name):
        raise ModuleNotFoundError(
            "No module named 'transitive_dep'", name='transitive_dep'
        )

    monkeypatch.setattr(imports_mod, 'import_module', fake_import)
    with pytest.raises(AuditImportError, match='missing dependency'):
        import_string('a.b.attr')


def test_build_passes_config_when_accepted(monkeypatch):
    class Target:
        def __init__(self, config=None):
            self.config = config

    monkeypatch.setattr(imports_mod, 'import_string', lambda path: Target)
    obj = imports_mod.build_from_import_string('x.Target', {'k': 'v'})
    assert obj.config == {'k': 'v'}


def test_build_omits_config_when_not_accepted(monkeypatch):
    class Target:
        def __init__(self):
            self.built = True

    monkeypatch.setattr(imports_mod, 'import_string', lambda path: Target)
    obj = imports_mod.build_from_import_string('x.Target', {'k': 'v'})
    assert obj.built is True


def test_build_uses_from_config_when_present(monkeypatch):
    class Target:
        @classmethod
        def from_config(cls, config):
            instance = cls.__new__(cls)
            instance.cfg = config
            return instance

    monkeypatch.setattr(imports_mod, 'import_string', lambda path: Target)
    obj = imports_mod.build_from_import_string('x.Target', {'a': 1})
    assert obj.cfg == {'a': 1}


def test_build_does_not_mask_constructor_typeerror(monkeypatch):
    # a real TypeError from the constructor must propagate, not be retried
    # with no args into a broken object.
    class Target:
        def __init__(self, config=None):
            raise TypeError('real bug in __init__')

    monkeypatch.setattr(imports_mod, 'import_string', lambda path: Target)
    with pytest.raises(TypeError, match='real bug in __init__'):
        imports_mod.build_from_import_string('x.Target')


def test_build_from_import_string_removed_from_core_public_api():
    # #M4: unused in the shipped runtime, so it is no longer re-exported from
    # the package. It remains importable from its module for tests/callers.
    import sec_audit.core as core

    assert 'build_from_import_string' not in core.__all__
    assert not hasattr(core, 'build_from_import_string')
    assert hasattr(imports_mod, 'build_from_import_string')
