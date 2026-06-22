"""Core standalone import checks.

Run these in an environment where ONLY ``sec-audit`` is installed (no
``django-sec-audit``). They assert that every shipped ``sec_audit.core`` module
imports without pulling in the dependent subpackages or Django.
"""

import importlib
import pkgutil
import sys

import pytest
import sec_audit

_SHIPPED = {'core'}


def _foundation_modules():
    names = []
    for _finder, name, _ispkg in pkgutil.walk_packages(
        sec_audit.__path__, prefix='sec_audit.'
    ):
        parts = name.split('.')
        if len(parts) >= 2 and parts[1] in _SHIPPED:
            names.append(name)
    return names


@pytest.mark.parametrize('module_name', _foundation_modules())
def test_every_shipped_foundation_module_imports(module_name):
    importlib.import_module(module_name)


def test_foundation_does_not_import_dependent_subpackages():
    """In a fresh interpreter, importing every foundation module must not pull in
    any dependent subpackage (rules/enforcement/dashboard/integrations/django) or
    Django. Run in a subprocess so the assertion reflects the foundation's own
    transitive imports, not modules loaded by other tests in this session.

    This only holds in an environment where ONLY ``sec-audit`` is installed. When
    ``django-sec-audit`` is also installed (e.g. the combined dev venv, or any real
    Django consumer), its ``src/`` is on ``sys.path`` via the editable install,
    so ``pkgutil.walk_packages`` legitimately discovers the dependent
    subpackages. CI runs this against a foundation-only environment."""
    import importlib.metadata

    try:
        importlib.metadata.distribution('django-sec-audit')
    except importlib.metadata.PackageNotFoundError:
        pass
    else:
        pytest.skip(
            'foundation isolation requires a sec-audit-only environment '
            '(django-sec-audit is installed)'
        )

    import subprocess

    code = (
        'import importlib, pkgutil, sys, sec_audit\n'
        'shipped = {"core"}\n'
        'for _f, name, _p in pkgutil.walk_packages(sec_audit.__path__, "sec_audit."):\n'
        '    if name.split(".")[1] in shipped:\n'
        '        importlib.import_module(name)\n'
        'imported = {m.split(".")[1] for m in sys.modules '
        'if m.startswith("sec_audit.") and len(m.split(".")) > 1}\n'
        'dependent = {"rules","enforcement","dashboard","integrations","django"}\n'
        'leaked = imported & dependent\n'
        'print("LEAKED=" + ",".join(sorted(leaked)))\n'
        'print("HAS_DJANGO=" + str("django" in sys.modules))\n'
    )
    result = subprocess.run(
        [sys.executable, '-c', code], capture_output=True, text=True, check=True
    )
    out = result.stdout
    assert 'LEAKED=' in out, out
    leaked = out.split('LEAKED=', 1)[1].splitlines()[0]
    assert leaked == '', f'foundation imports dependent subpackages: {leaked}'
    assert 'HAS_DJANGO=True' not in out, 'foundation imports django'
